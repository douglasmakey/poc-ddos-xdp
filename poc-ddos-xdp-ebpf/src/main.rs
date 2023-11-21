#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    cty::c_void,
    helpers::{bpf_get_smp_processor_id, bpf_map_lookup_percpu_elem},
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

// This is a per-CPU array that will be used to store the number of packets received on each CPU core.
#[map]
static mut COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

// The threshold is the number of maximum packets that can be received before the honeypot is activated
const THRESHOLD: u32 = 2000;
// Hardcoded number of CPU cores
const CPU_CORES: u32 = 12;

#[derive(Debug)]
enum ExecutionError {
    PointerOverflow,
    PointerOutOfBounds,
    FailedToGetCounter,
}

#[inline(always)]
fn get_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ExecutionError> {
    // Get the start and end of the packet data and the size of the type we're trying to access
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // Ensure the pointer doesn't overflow to prevent undefined behavior and ensure the pointer is not out of bounds
    let new_ptr = start
        .checked_add(offset)
        .ok_or(ExecutionError::PointerOverflow)?;

    if new_ptr
        .checked_add(len)
        .ok_or(ExecutionError::PointerOverflow)?
        > end
    {
        return Err(ExecutionError::PointerOutOfBounds);
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn get_mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ExecutionError> {
    let ptr: *const T = get_ptr_at(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[inline(always)]
fn get_total_cpu_counter(cpu_cores: u32) -> u32 {
    let mut sum: u32 = 0;
    for cpu in 0..cpu_cores {
        let c = unsafe {
            bpf_map_lookup_percpu_elem(
                // Casting a mutable reference of COUNTER to a mutable raw pointer
                // of type `c_void`. This is required by the function we are calling.
                &mut COUNTER as *mut _ as *mut c_void,
                // Creating a constant raw pointer to a 0 value. This represents the key
                // in the per-CPU map for which we are retrieving the value.
                &0 as *const _ as *const c_void,
                // The current CPU core index in the loop.
                cpu,
            )
        };

        // Check if the returned pointer is not null, which would mean a successful lookup.
        if !c.is_null() {
            unsafe {
                // Cast the void pointer to a mutable u32 pointer and dereference it to get the value.
                let counter = &mut *(c as *mut u32);
                sum += *counter;
            }
        }
    }
    sum
}

#[xdp]
pub fn poc_ddos_xdp(ctx: XdpContext) -> u32 {
    match try_poc_ddos_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_poc_ddos_xdp(ctx: XdpContext) -> Result<u32, ExecutionError> {
    // Use pointer arithmetic to obtain a raw pointer to the Ethernet header at the start of the XdpContext data.
    let eth_hdr: *mut EthHdr = get_mut_ptr_at(&ctx, 0)?;

    // Check the EtherType of the packet. If it's not an IPv4 packet, pass it along without further processing
    // We have to use unsafe here because we're dereferencing a raw pointer
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Using Ethernet header length, obtain a pointer to the IPv4 header which immediately follows the Ethernet header
    let ip_hdr: *mut Ipv4Hdr = get_mut_ptr_at(&ctx, EthHdr::LEN)?;

    // Check the protocol of the IPv4 packet. If it's not UDP, pass it along without further processing
    match unsafe { (*ip_hdr).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Using the IPv4 header length, obtain a pointer to the UDP header which immediately follows the IPv4 header
    let udp_hdr: *const UdpHdr = get_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let port = u16::from_be(unsafe { (*udp_hdr).dest });

    // If the port is 53, pass it along without further processing.
    // Port 53 is typically used for DNS (Domain Name System) traffic.
    // DNS is a critical service for network operations, and we don't want to interfere with it.
    if port == 53 {
        return Ok(xdp_action::XDP_PASS);
    }

    let total = get_total_cpu_counter(CPU_CORES);
    if total >= THRESHOLD {
        unsafe {
            // Change the destination MAC addresses and Ip to the honeypot
            (*eth_hdr).dst_addr = [0xF0, 0x2F, 0x4B, 0x14, 0x2D, 0x78];
            (*ip_hdr).dst_addr = u32::from_be_bytes([192, 168, 2, 37]).to_be();
            // Change the Mac address of the packet to the current interface MAC address
            (*eth_hdr).src_addr = [0xbc, 0x09, 0x1b, 0x98, 0x40, 0xae];

            // Get the current CPU core index
            let cpu = bpf_get_smp_processor_id();

            info!(
                &ctx,
                "CPU: {} is redirecting UDP packet to honeypot at ip: {:i} and mac: {:mac}",
                cpu,
                u32::from_be((*ip_hdr).dst_addr),
                (*eth_hdr).dst_addr
            );
        }
        return Ok(xdp_action::XDP_TX);
    }

    unsafe {
        // Get a mutable pointer to our packet counter
        let counter = COUNTER
            .get_ptr_mut(0)
            .ok_or(ExecutionError::FailedToGetCounter)?;

        // If our counter is below the threshold, increment it
        if *counter < THRESHOLD {
            *counter += 1;
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

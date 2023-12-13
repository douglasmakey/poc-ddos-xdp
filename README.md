
# Harnessing eBPF and XDP for DDoS Mitigation - A Rust Adventure with rust-aya

In my last [article](https://www.kungfudev.com/blog/2023/11/08/beginner-guide-to-xdp-crafting-xdp-based-firewall-with-bcc), we embarked on an XDP adventure, creating a basic firewall that filtered SSH traffic based on IP addresses. That exploration just skimmed the surface of XDP's capabilities, showing how we can determine a packet's fate by simply dropping unwanted packets using the XDP action **XDP_DROP**.

This time, we're diving a bit deeper into the realm of XDP, but with a twist. We're not just blocking packets; we're going to modify them to create more interactive applications. And to add an extra layer of excitement, I'm switching from `Python` BCC to the [rust-aya]() library in `Rust`. Why? Because I'm currently learning Rust and I want to apply it to add a fresh perspective to this journey. Plus, why not have a bit more fun with it?

In this article, our experiment will focus on a basic DDoS mitigation technique against `UDP flood attacks`. Since this is also an introduction to crafting eBPF programs with Rust, we'll keep things straightforward and avoid more complex aspects. I plan to delve into those in a future post, where I'll explore creating a more complex PoCs like load balancer using XDP and Rust.

Our DDoS mitigation approach will be straightforward. We'll set up a program that counts the number of incoming UDP packets. For this, we'll utilize a `PerCpuArray` eBPF map. Once the count hits a certain threshold, indicating potential flood traffic, our program will redirect these packets to a `honeypot` device using the XDP action **XDP_TX**. This device, part of my local network, could either analyze these packets further or simply discard them. This setup aims to protect our system while gathering data on the flood attack.

> A honeypot in cybersecurity is a system intended to mimic likely targets of cyberattacks to detect, deflect, or study hacking attempts.

## Understanding UDP Floods: The Basics of a Common DDoS Attack Strategy

A UDP flood is a kind of DDoS attack where a server gets bombarded with lots of UDP packets. The goal is to overwhelm the server.

```text
+--------+                                      +--------+
| Client |                                      | Server |
+--------+                                      +--------+
    |                                                |
    |                                                |
    |---------------- Legitimate Traffic ------------|
    |                                                |
+-----------+                                        |
| Attackers |                                        |
+-----------+                                        |
    | UDP Flood Attack                               |
    |------------------Bad UDP-----------------------|                         
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |------------------Bad UDP-----------------------|
    |---------------UDP Flood Attack---------------->|
```


Here's what happens when a server gets a UDP packet:

1. **Check for Listening Programs**: The server looks to see if there's any program waiting for packets on the port the UDP packet arrived at.
2. **ICMP Response**: If there's no program on that port, the server sends back an ICMP packet—kind of like a 'return to sender' note—saying the destination was unreachable.

This back-and-forth uses up a lot of the server's resources. When it's hit by a flood of UDP packets, it can get overloaded quickly. This is where our DDoS mitigation approach comes in to relieve the server from this unnecessary strain.

It's worth noting that in `real-world` scenarios, cloud providers and large-scale networks employ a variety of sophisticated techniques to combat DDoS attacks, including firewalls, optimized operating system configurations, and the use of Content Delivery Networks (CDNs). These methods are designed to detect, mitigate, and resolve such issues effectively. However, for the purposes of our discussion and to keep our experiment focused and manageable, we'll assume a simpler scenario. This approach allows us to concentrate on the specific aspects of XDP and eBPF in handling UDP flood attacks without delving into the more complex and varied strategies used in real-world, large-scale environments.
## Understanding `PerCpuArray` in eBPF

In my previous article about [IPv4 Socket Surveillance](https://www.kungfudev.com/blog/2023/10/22/ipv4-socket-surveillance-tracing-using-kprobe-kretprobe-maps-bcc#maps), we explored eBPF maps. These maps are key for storing data in the kernel space and for communication between user-space and kernel-space, as well as between different eBPF programs. We've mostly focused on a common map type known as the hashmap (`BPF_MAP_TYPE_HASH`). Another familiar one is the array (`BPF_MAP_TYPE_ARRAY`).

Both of these map types have a special version called `PERCPU`. As the name suggests, the main difference between `PERCPU` and `non-PERCPU` maps lies in how they handle memory. `PERCPU` maps allocate separate memory areas for each `CPU`, which helps in avoiding conflicts when multiple CPUs access the map simultaneously. This is in contrast to `non-PERCPU` maps, which use the same memory region for all CPUs.


`BPF_MAP_TYPE_PERCPU_ARRAY`

```txt
   CPU 0   |   CPU 1   |   CPU 2   |   CPU 3
-----------|-----------|-----------|-----------
[         ]|[         ]|[         ]|[         ]
[ Data 0  ]|[ Data 1  ]|[ Data 2  ]|[ Data 3  ]
[         ]|[         ]|[         ]|[         ]
-----------|-----------|-----------|-----------

```

In our DDoS mitigation effort, opting for a `PerCpuArray` brings the significant advantage of reducing contention while also simplifying our approach. Usually, in a high-traffic scenario, if we used a shared data structure, we'd need to implement complex locking mechanisms or atomic operations to manage concurrent access. These methods, while effective, can add overhead and complexity. Locks can lead to performance bottlenecks, and atomic operations, although faster than locks, still incur a cost in terms of processing time.

With `PerCpuArray`, each CPU core works with its own separate data instance. This design inherently avoids the need for locks or atomic operations since there's no contention between CPUs. Each CPU updates its own counter independently, streamlining the process. Thus, not only does this reduce the risk of performance bottlenecks, but it also simplifies the code, making it more maintainable and less prone to bugs that are often associated with concurrency control. This choice aligns well with our goal of creating a simple and reliable DDoS mitigation strategy, leveraging the strengths of eBPF and XDP in handling high-volume network traffic.

## Experimenting with UDP Flood Attack Mitigation

In the first article of this series, we talked about different projects in eBPF programming and how you can use various languages for eBPF programs in user-space. But when it comes to kernel-space, our choices are fewer. Rust is one of these options, letting us write eBPF programs for both user-space and kernel-space.

For our new experiment, we'll be using `rust-aya`, a library that lets us write eBPF programs in Rust for both user-space and kernel-space. Rust-aya offers helpful tools, including a project scaffolding generator with `cargo-generate`, making it easier to start new projects. You can find a clear and useful guide on how to get started with rust-aya [here](https://aya-rs.dev/book/).

To begin our project, we'll use this scaffolding command:

```bash
cargo generate --name poc-ddos-xdp -d program_type=xdp https://github.com/aya-rs/aya-template
```

The scaffolding provided by rust-aya includes everything we need to start building our program. By specifying the program type in the command, as we did with `program_type=xdp`, it sets up the necessary base for that specific type of program. For more detailed information on how all this works, it's a good idea to check out the documentation on the rust-aya [website](https://aya-rs.dev/book/).

When we enter the generated project, we'll find three key components in the workspace: `poc-ddos-xdp-common`, `poc-ddos-xdp`, and `poc-ddos-xdp-ebpf`. The most important ones for our purposes are the latter two. `poc-ddos-xdp-ebpf` represents the part of our code that will run in kernel space – this is our eBPF program. `poc-ddos-xdp`, on the other hand, is the user-space application. Here's what the project structure looks like:

```bash
$ ll
...
-rw-r--r--  1 douglasmakey douglasmakey    71 Nov 18 15:29 Cargo.toml
drwxrwxr-x  3 douglasmakey douglasmakey  4096 Nov 18 15:29 poc-ddos-xdp/
drwxrwxr-x  3 douglasmakey douglasmakey  4096 Nov 18 15:29 poc-ddos-xdp-common/
drwxrwxr-x  6 douglasmakey douglasmakey  4096 Nov 18 15:51 poc-ddos-xdp-ebpf/
drwxrwxr-x  4 douglasmakey douglasmakey  4096 Nov 18 15:31 target/
...
```

This setup is typical for `rust-aya` projects and helps in organizing the code effectively between the user-space and kernel-space components.
### User-Space Component: 'poc-ddos-xdp'

In the `/poc-ddos-xdp/src/main.rs` file of our user-space component, we don't need to make any changes. However, let's highlight an interesting aspect of the code:

```rust
use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}
```

This code snippet demonstrates how `clap` is used for parsing command-line arguments. In XDP programming, specifying the network interface for attaching the program is crucial. Here, a simple structure is created to manage this, complete with an argument (`iface`) to set the network interface. This approach simplifies the process of specifying the interface when running the program.

```rust
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/poc-ddos-xdp"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/poc-ddos-xdp"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("poc_ddos_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

```

This part of the code is where the magic happens in linking our user-space application with the eBPF program. It's divided into two main sections, depending on whether we're in debug mode or not:

1. **Loading the eBPF Program:**
    - In debug mode (`#[cfg(debug_assertions)]`), it loads the eBPF program from the debug build directory.
    - In release mode (`#[cfg(not(debug_assertions))]`), it loads from the release build directory.
    
    This distinction ensures that the correct version of the eBPF program is loaded based on our build configuration.
    
1. **Setting Up the eBPF Program:**
    - It initializes a logger for the eBPF program. This logger is useful for debugging purposes but can fail if all log statements are removed from the eBPF code.
    - The `program` variable holds our eBPF program, identified by the name `poc_ddos_xdp`. This is where we get a handle to the eBPF program to interact with it.
    - Next, the program is loaded into the kernel using `program.load()?`.
    - Finally, the eBPF program is attached to the specified network interface (`opt.iface`) using `program.attach(...)`. The `XdpFlags::default()` indicates that it uses the default settings for attaching, which can be changed if needed.

### Kernel-Space Component: 'poc-ddos-xdp-ebpf'

Let's dive into the heart of our project: the `kernel-space` component in `/poc-ddos-xdp-ebpf/src/main.rs`. This is where the real action happens and where we are going to implement all the logic.

In the `user-space` component we saw earlier, our program loads something called `poc_ddos_xdp`. This is our eBPF program that we're going to run in the kernel. Let's look at a key part of this program:

```rust
#[xdp]
pub fn poc_ddos_xdp(ctx: XdpContext) -> u32 {
    match try_poc_ddos_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
```

>   If you're new to Rust, `match` is a powerful control flow operator used for pattern matching. It allows you to compare a value against a series of patterns and execute code based on which pattern matches. This is similar to a switch-case statement in other languages but more flexible and robust.

This code is the main function of our eBPF program. Key points to note:

- `#[xdp]` marks the function as an XDP program for the kernel.
- `poc_ddos_xdp` takes `XdpContext` as an argument, which gives us the context of the network packet we're dealing with.
- The function calls `try_poc_ddos_xdp(ctx)` for packet handling logic.

As I mentioned at the beginning of the article, this will be a simple implementation. I am going to explain the parts of `try_poc_ddos_xdp`, which are very similar to those in my last article where we created an XDP program using `C`.

Like our `C` XDP program, the first step in processing a received network packet is to dissect its structure, layer by layer. To do this in Rust, we are going to use this function:

```rust
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
```

> The `#[inline(always)]` attribute in Rust advises the compiler to replace every call to the function with the function's code itself.

> `Result<T, E>` and the `?` operator work together seamlessly to handle errors elegantly. The `Result` type is an enum that represents either success (`Ok`) or failure (`Err`). When you use the `?` operator on a `Result`, it does two things:
> 
> 1. **Unwraps the `Ok` Value**: If the `Result` is `Ok`, `?` unwraps it and gives you the value inside, letting your code proceed smoothly.
> 2. **Early Returns on `Err`**: If the `Result` is `Err`, `?` automatically returns this error from the current function, saving you from writing explicit `match` statements or `if let` constructs to handle errors.

Remember the pointer arithmetic we discussed? This Rust function does something similar. It calculates pointers within the packet's bounds to access specific parts safely, avoiding any overflow or out-of-bounds errors.

In simpler terms, we're checking to ensure the packet is of the correct length. We validate the length of type `T` (which could be an Ethernet header, IP header, etc.) against the packet's boundaries. If all checks pass, the function returns a constant raw pointer to `T`. This means we get a direct pointer to the data within the packet, allowing us to read or analyze it as needed.

> In Rust, raw pointers offer a way to directly interact with memory, similar to pointers in languages like C. There are two types of raw pointers in Rust:
> 
> 1. `*const T`: A constant pointer for reading data without modification.
> 2. `*mut T`: A mutable pointer for reading and modifying data.
> 
> Raw pointers provide direct memory access, often used in low-level system programming, but they require careful handling due to the risks involved.

In this instance, our eBPF program requires the ability to modify packet data, not just read it. To achieve this. The function `get_mut_ptr_at` provides us with a mutable raw pointer (`*mut T`). This enables us to alter the packet data as needed.

```rust

#[inline(always)]
fn get_mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ExecutionError> {
    let ptr: *const T = get_ptr_at(ctx, offset)?;
    Ok(ptr as *mut T)
}
```

Now that we can read and write data to our packet, let's proceed with some checks:

```rust
fn try_poc_ddos_xdp(ctx: XdpContext) -> Result<u32, ExecutionError> {
    let eth_hdr: *mut EthHdr = get_mut_ptr_at(&ctx, 0)?;
    // If it's not an IPv4 packet, pass it along without further processing
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    
    let ip_hdr: *mut Ipv4Hdr = get_mut_ptr_at(&ctx, EthHdr::LEN)?;
    // Check the protocol of the IPv4 packet. If it's not UDP, pass it along without further processing
    match unsafe { (*ip_hdr).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    ...
}
```

> The code uses the `unsafe` keyword because it involves direct manipulation of memory through raw pointers, an operation that Rust's safety rules normally prevent. This is necessary for low-level tasks like processing network packets in eBPF programs, where precise control over memory is required.
> https://doc.rust-lang.org/nomicon/meet-safe-and-unsafe.html

In this code, we first validate if the packet is an `IPv4 packet` by examining the ether_type in the Ethernet header. If it's not IPv4, the packet is passed through without further processing. Then, we look at the IPv4 header to check if it's a `UDP packet`. Non-UDP packets are also allowed to pass. This way, our program focuses only on IPv4 UDP packets.

Our program aims to mitigate UDP flood attacks, but we need to ensure it doesn't block crucial `DNS traffic`. To achieve this, we check if the UDP packet is for DNS resolution, using port `53`. If a packet is destined for this port, we allow it to pass through unimpeded, ensuring our system can still resolve DNS queries. This way, we strike a balance between security and functionality.

```rust
    // Using the IPv4 header length, obtain a pointer to the UDP header
    let udp_hdr: *const UdpHdr = get_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let port = u16::from_be(unsafe { (*udp_hdr).dest });

    // If the port is 53, pass it along without further processing.
    if port == 53 {
        return Ok(xdp_action::XDP_PASS);
    }
```

At this stage in our program, we've identified that the packet in question is a UDP packet that's not part of a DNS query. In the context of our simple example, we're assuming that our server isn't running any UDP-based services or expecting UDP traffic. Therefore, `we treat all such UDP packets as potentially malicious`, part of a DDoS attack. Now, let's focus on how we count these packets to monitor for flooding activity:

```rust
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
```

This code accesses and increments a packet counter. We're using a `PerCpuArray` map named `COUNTER`, and we check if the count of non-DNS UDP packets has reached a threshold. If it's under the threshold, we increment it. This way, we track potential flood traffic.

This approach is very basic. In real-world scenarios, more sophisticated methods like time-based windows with reset mechanisms are typically used. However, for the purposes of this demonstration, we're going to stick to a simpler method.

We know that our `PerCpuArray` map creates a separate instance for each CPU. This means each CPU increments its own counter in its dedicated memory space. To determine if the combined total from all instances has reached our threshold, we'll use an eBPF helper function: `bpf_map_lookup_percpu_elem`. This helper allows us to aggregate the counts from each CPU instance, helping us assess if the threshold has been crossed.

> The `bpf_map_lookup_percpu_elem()` helper can be used to lookup the array value for a specific CPU. Returns value on success, or `NULL` if no entry was found or `cpu` is invalid
> https://docs.kernel.org/bpf/map_array.html#bpf-map-lookup-percpu-elem

In our Rust using the `aya-ebpf` library, we have a `helpers` module that provides functions similar to eBPF helpers. With it, we can calculate the total number of packets across all CPUs. We're aware that without a locking mechanism, the data we read might not be perfectly accurate. But for our purposes, it's sufficient. The function `get_total_cpu_counter` iterates over all CPU cores, summing up the packet counts stored in the `COUNTER` map for each core. Even though we're accessing this data without locks, it gives us a good enough overview of the total packet count.

```rust
#[inline(always)]
fn get_total_cpu_counter(cpu_cores: u32) -> u32 {
    let mut sum: u32 = 0;
    for cpu in 0..cpu_cores {
        let c = unsafe {
            bpf_map_lookup_percpu_elem(
                &mut COUNTER as *mut _ as *mut c_void,
                &0 as *const _ as *const c_void,
                cpu,
            )
        };
        
        if !c.is_null() {
            unsafe {
                let counter = &mut *(c as *mut u32);
                sum += *counter;
            }
        }
    }
    sum
}
```

>   In this function, the multiple `*mut as` casts are used to convert pointers between different types. Specifically, `&mut COUNTER as *mut _ as *mut c_void` is casting the mutable reference to `COUNTER` to a mutable raw pointer (`*mut _`), and then to a generic mutable void pointer (`*mut c_void`). This is done to meet the type requirements of the `bpf_map_lookup_percpu_elem` function. The same for `&0 as *const _ as *const c_void`. These conversions are necessary for interacting with the eBPF map at a low level.

Now, we'll check if the packet count has reached our set threshold. If so, as previously mentioned, we'll redirect the packets to the honeypot. In this example, the honeypot's IP address is `192.168.2.37`, and its MAC address is `f0:2f:4b:14:2d:78`. These values can be found using the `ip addr` command.

So if the total packet count surpasses our threshold, it's time to reroute the packets. Here's how we do it:

```rust
    let total = get_total_cpu_counter();
    if total >= THRESHOLD {
        unsafe {
            // Change the destination MAC addresses and Ip to the honeypot
            (*eth_hdr).dst_addr = [0xF0, 0x2F, 0x4B, 0x14, 0x2D, 0x78];
            (*ip_hdr).dst_addr = u32::from_be_bytes([192, 168, 2, 37]).to_be();
            // Set Mac address of the packet to the current interface MAC address
            (*eth_hdr).src_addr = [0xbc, 0x09, 0x1b, 0x98, 0x40, 0xae];

			let cpu = bpf_get_smp_processor_id();
            info!(
                &ctx,
                "CPU: {} is redirecting UDP packet to honeypot ip: {:i}, mac: {:mac}",
                cpu,
                u32::from_be((*ip_hdr).dst_addr),
                (*eth_hdr).dst_addr
            );
        }
        
        return Ok(xdp_action::XDP_TX);
    }
```

> `XDP_TX` is a return code in XDP programs, used to quickly send a network packet back out of the same network interface it arrived on. This allows for fast redirection or modification of packets at a low level in the network stack, offering a high-performance way to handle network traffic.

In this block, we're directly manipulating the packet's Ethernet and IP headers to change its destination. This effectively reroutes the packet to the specified `honeypot`, helping to mitigate the potential DDoS attack. The `unsafe` block is needed again because we're directly modifying memory locations, a necessary step when working at the packet level in eBPF programs.

```txt
+----------+      +-----------+      +----------+
| Attacker | ---> | Server    | ---> | Honeypot |
|          |      | eBPF/XDP  |      |          |
+----------+      +-----------+      +----------+
      UDP Packet      |              IP: 192.168.2.37
                      |              MAC: f0:2f:4b:14:2d:78
                [Packet Redirected]

```

You might wonder, "Aren't we changing the IP header? What about the checksum?" Good point! In typical scenarios, modifying the IP header requires recalculating the checksum to maintain packet integrity. However, for this demonstration, we're less concerned about the checksum. Since we're redirecting to a honeypot for either discarding or further analysis, and we understand our infrastructure environment, we could potentially recalculate the checksum back to its original state if needed. But for now, our focus is on demonstrating the redirection mechanism itself.

We're now set to deploy our XDP program and effectively redirect UDP flood attack packets to our honeypot. For a deeper dive and hands-on experience, all the code discussed is available in my  [repository](https://github.com/douglasmakey/poc-ddos-xdp). Feel free to explore, experiment, and comments :D!

### Running our DDoS Mitigation

When we run our XDP program on the server, we'll observe that as soon as the packet count reaches the threshold, the packets are automatically redirected to the honeypot.

```bash
RUST_LOG=info cargo xtask run -- --iface wlp5s0
...
[2023-11-21T08:31:18Z INFO  poc_ddos_xdp] Waiting for Ctrl-C...
[2023-11-21T08:44:27Z INFO  poc_ddos_xdp] CPU: 9 is redirecting UDP packet to honeypot at ip: 192.168.2.37 and mac: f0:2f:4b:14:2d:78
[2023-11-21T08:44:27Z INFO  poc_ddos_xdp] CPU: 4 is redirecting UDP packet to honeypot at ip: 192.168.2.37 and mac: f0:2f:4b:14:2d:78
[2023-11-21T08:44:27Z INFO  poc_ddos_xdp] CPU: 7 is redirecting UDP packet to honeypot at ip: 192.168.2.37 and mac: f0:2f:4b:14:2d:78
...
```

I monitored UDP traffic on the honeypot using `tcpdump`, specifically looking for traffic on port 3000. This traffic originated from another machine in my network, which I set up to continuously send messages using the command `while true; do echo 'message' | nc -w1 -u 192.168.2.107 3000; done`, where `192.168.2.107` is the IP of my server. The `tcpdump` output shows various UDP packets being redirected to the honeypot.

```bash
$ tcpdump -i en0 udp port 3000
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on en0, link-type EN10MB (Ethernet), snapshot length 524288 bytes
03:42:04.145995 IP douglass-mbp.61003 > dlm.hbci: UDP, length 8
03:42:04.236480 IP douglass-mbp.59614 > dlm.hbci: UDP, length 8
03:42:04.251248 IP douglass-mbp.53251 > dlm.hbci: UDP, length 8
03:42:04.264551 IP douglass-mbp.54707 > dlm.hbci: UDP, length 8
03:42:04.278199 IP douglass-mbp.59236 > dlm.hbci: UDP, length 8
03:42:04.291955 IP douglass-mbp.50962 > dlm.hbci: UDP, length 8
03:42:04.306631 IP douglass-mbp.52865 > dlm.hbci: UDP, length 8
03:42:05.324404 IP douglass-mbp.51187 > dlm.hbci: UDP, length 8
03:42:05.470089 IP douglass-mbp.54581 > dlm.hbci: UDP, length 8
03:43:53.526325 IP douglass-mbp.61372 > dlm.hbci: UDP, length 8
```

### Inspecting the map.

After running our eBPF program, we could use `bpftool` to get insights into our `PERCPU` map. First, we find the ID of our map "COUNTER":

```bash
$ sudo bpftool map list | grep COUNTER
1000: percpu_array  name COUNTER  flags 0x0
```

Then, we can observe the current values in the map, which are `u32` integers representing packet counts per CPU:

```bash
$ sudo bpftool map dump id 1000 -p
[{
        "key": ["0x00","0x00","0x00","0x00"],
        "values": [{
                "cpu": 1,
                "value": ["0x0f","0x00","0x00","0x00"] // u32 value: 15
            },{
                "cpu": 2,
                "value": ["0x05","0x00","0x00","0x00"] // u32 value: 5
            },{
                "cpu": 3,
                "value": ["0x61","0x00","0x00","0x00"] // u32 value: 97
            },{
                "cpu": 4,
                "value": ["0x17","0x00","0x00","0x00"] // u32 value: 23
            },{
                "cpu": 5,
                "value": ["0x3b","0x00","0x00","0x00"] // u32 value: 59
            }
            ...
        ]
    }
]

```

Each `value` entry shows the count of UDP packets handled by the corresponding CPU. The comments next to each `value` show their decimal representation, giving us a clearer picture of the packet distribution across the CPUs. This is a practical way to monitor the effectiveness of our DDoS mitigation strategy.

## To conclude

In this project, we've used hardcoded values for elements like the number of CPUs and the threshold, along with a basic mechanism for the threshold counter. This was done to keep our proof of concept straightforward and avoid unnecessary complexity. Of course, there's much more to explore and deeper complexities in eBPF and XDP programming that we haven't touched upon yet. But for now, I'm happy with our progress and eager to dive deeper into this fascinating area in the future

Thank you for reading along. This blog is a part of my learning journey and your feedback is highly valued. There's more to explore and share regarding eBPF, so stay tuned for upcoming posts. Your insights and experiences are welcome as we learn and grow together in this domain. **Happy coding!**

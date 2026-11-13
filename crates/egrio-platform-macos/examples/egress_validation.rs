//! Read-only physical-interface guard check. Creates unconnected UDP sockets;
//! does not install capture, change routes, or send any network traffic.
#[cfg(target_os = "macos")]
fn main() -> Result<(), String> {
    use egrio_core::{EgressSocketContext, EgressSocketGuard};
    use std::os::fd::AsRawFd;
    let guard = egrio_platform_macos::MacosEgressInterfaceBinder::capture()?;
    let mut results = Vec::new();
    for (local, remote, level, option) in [
        ("0.0.0.0:0", "1.1.1.1", libc::IPPROTO_IP, libc::IP_BOUND_IF),
        (
            "[::]:0",
            "2606:4700:4700::1111",
            libc::IPPROTO_IPV6,
            libc::IPV6_BOUND_IF,
        ),
    ] {
        let socket = std::net::UdpSocket::bind(local).map_err(|e| e.to_string())?;
        match guard.protect_socket(
            socket.as_raw_fd(),
            EgressSocketContext::for_remote(remote.parse().unwrap()),
        ) {
            Ok(bound) => {
                let mut observed = 0u32;
                let mut size = std::mem::size_of_val(&observed) as libc::socklen_t;
                if unsafe {
                    libc::getsockopt(
                        socket.as_raw_fd(),
                        level,
                        option,
                        std::ptr::from_mut(&mut observed).cast(),
                        &mut size,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                if bound.interface_index != Some(observed) || observed == 0 {
                    return Err("socket guard bound an unexpected interface".into());
                }
                results.push(
                    serde_json::json!({"family":remote,"interface_index":observed,"verified":true}),
                );
            }
            Err(error) => {
                results.push(serde_json::json!({"family":remote,"verified":false,"error":error}))
            }
        }
    }
    if !results.iter().any(|row| row["verified"] == true) {
        return Err("no physical family could be bound".into());
    }
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macOS egress validation requires macOS");
    std::process::exit(1);
}

//! By hand, as root on a Mac: opens a TUN session the way the service does,
//! counts what the system routes into it for a while, and closes it. While
//! it runs both halves of each family and the default resolver point at the
//! utun and nothing forwards, so the Mac is offline for those seconds.
//! `sudo target/debug/examples/tun_session <seconds> [excluded-prefix...]`

#[cfg(target_os = "macos")]
fn main() -> Result<(), String> {
    use std::io::Read;

    let mut arguments = std::env::args().skip(1);
    let seconds: u64 = arguments
        .next()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(10);
    let excluded = arguments
        .map(|prefix| prefix.parse().map_err(|error| format!("{prefix}: {error}")))
        .collect::<Result<Vec<_>, String>>()?;
    let (session, open) = egrio_platform_macos::MacosTunSession::open(
        egrio_platform_macos::MACOS_TUN_MTU,
        &excluded,
        &[],
    )?;
    println!(
        "open: {} (index {}), mtu {}",
        open.interface_name, open.interface_index, open.mtu
    );
    let mut socket = std::fs::File::from(open.socket);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let (mut packets, mut bytes, mut largest) = (0u64, 0u64, 0usize);
    let mut buffer = vec![0u8; 70_000];
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(deadline - std::time::Instant::now());
        let _ = stop.send(());
    });
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: sets a read timeout on the utun socket.
    unsafe {
        libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(&socket),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        );
    }
    while stopped.try_recv().is_err() {
        match socket.read(&mut buffer) {
            Ok(read) if read > 4 => {
                packets += 1;
                bytes += read as u64;
                largest = largest.max(read - 4);
            }
            _ => {}
        }
    }
    println!("read {packets} packets, {bytes} bytes, largest {largest}");
    drop(session);
    println!("closed");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {}

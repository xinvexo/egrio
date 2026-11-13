use super::*;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;

fn flow(protocol: FlowProtocol, local: SocketAddr, remote: SocketAddr) -> FlowKey {
    FlowKey {
        protocol,
        source_ip: local.ip(),
        source_port: local.port(),
        destination_ip: remote.ip(),
        destination_port: remote.port(),
    }
}
fn own<'a>(report: &'a ScanReport, fd: i32) -> &'a FlowCandidate {
    report.candidates.iter().find(|candidate| candidate.pid == std::process::id() && candidate.fd == fd as u32)
        .unwrap_or_else(|| panic!("own socket not found (complete={}, pids={}, fds={}, denied={}, races={}, errors={}, limited={}, timeout={})",
            report.complete,report.pids_scanned,report.fds_scanned,report.permission_denied,report.raced,
            report.syscall_errors,report.limited,report.timed_out))
}
#[test]
fn bridge_layout_matches_compiled_sdk_shim() {
    assert_eq!(
        unsafe { ffi::egrio_macos_flow_candidate_size() },
        std::mem::size_of::<ffi::RawCandidate>()
    );
}
#[test]
fn own_tcp_and_connected_udp_batch_has_exact_endpoints_and_stable_process_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_server, _) = listener.accept().unwrap();
    let udp_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.connect(udp_peer.local_addr().unwrap()).unwrap();
    let requests = [
        flow(
            FlowProtocol::Tcp,
            client.local_addr().unwrap(),
            client.peer_addr().unwrap(),
        ),
        flow(
            FlowProtocol::Udp,
            udp.local_addr().unwrap(),
            udp.peer_addr().unwrap(),
        ),
    ];
    let cancelled = AtomicBool::new(false);
    let report = scan(
        Source::Sockets,
        &requests,
        Duration::from_millis(100),
        &cancelled,
    );
    for (fd, local, remote) in [
        (
            client.as_raw_fd(),
            client.local_addr().unwrap(),
            client.peer_addr().unwrap(),
        ),
        (
            udp.as_raw_fd(),
            udp.local_addr().unwrap(),
            udp.peer_addr().unwrap(),
        ),
    ] {
        let candidate = own(&report, fd);
        assert_eq!(candidate.local_endpoint, local);
        assert_eq!(candidate.remote_endpoint, Some(remote));
        assert!(candidate.start_sec > 0);
        assert!(candidate.start_usec < 1_000_000);
        assert_ne!(candidate.socket_id, 0);
        assert_eq!(
            candidate.executable.canonicalize().unwrap(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
    }
    assert_eq!(
        own(&report, client.as_raw_fd()).start_sec,
        own(&report, udp.as_raw_fd()).start_sec
    );
    assert_eq!(
        own(&report, client.as_raw_fd()).start_usec,
        own(&report, udp.as_raw_fd()).start_usec
    );
    eprintln!("libproc local TCP/UDP batch: elapsed_us={}, pids={}, fds={}, complete={}, denied={}, races={}",
        report.elapsed.as_micros(),report.pids_scanned,report.fds_scanned,report.complete,report.permission_denied,report.raced);
}
#[test]
fn duplicate_fd_and_udp_reuse_flags_remain_visible_instead_of_selecting_a_pid() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let duplicate = udp.try_clone().unwrap();
    let enabled: libc::c_int = 1;
    for option in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    udp.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::from_ref(&enabled).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            },
            0
        );
    }
    let request = flow(
        FlowProtocol::Udp,
        udp.local_addr().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
    );
    let report = scan(
        Source::Sockets,
        &[request],
        Duration::from_millis(100),
        &AtomicBool::new(false),
    );
    let first = own(&report, udp.as_raw_fd());
    let second = own(&report, duplicate.as_raw_fd());
    assert_eq!(first.socket_id, second.socket_id);
    assert_eq!(first.socket_generation, second.socket_generation);
    assert!(first.shared && second.shared);
    assert!(first.reuse_port && first.reuse_addr);
    assert_eq!(first.remote_endpoint, None);
}
#[test]
fn own_ipv6_endpoints_are_decoded_from_the_sdk_ipv6_union() {
    let peer = UdpSocket::bind("[::1]:0").unwrap();
    let socket = UdpSocket::bind("[::1]:0").unwrap();
    socket.connect(peer.local_addr().unwrap()).unwrap();
    let request = flow(
        FlowProtocol::Udp,
        socket.local_addr().unwrap(),
        socket.peer_addr().unwrap(),
    );
    let report = scan(
        Source::Sockets,
        &[request],
        Duration::from_millis(100),
        &AtomicBool::new(false),
    );
    let candidate = own(&report, socket.as_raw_fd());
    assert_eq!(candidate.local_endpoint, socket.local_addr().unwrap());
    assert_eq!(candidate.remote_endpoint, Some(socket.peer_addr().unwrap()));
}
#[test]
fn cancellation_and_zero_budget_do_not_start_an_unbounded_snapshot() {
    let request = flow(
        FlowProtocol::Udp,
        "127.0.0.1:12345".parse().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
    );
    for source in [Source::Sockets, Source::UserlandFlows] {
        let cancelled = AtomicBool::new(true);
        let report = scan(
            source,
            std::slice::from_ref(&request),
            Duration::from_millis(100),
            &cancelled,
        );
        assert!(report.cancelled && !report.complete);
        assert_eq!((report.fds_scanned, report.userland_flows), (0, 0));
        cancelled.store(false, Ordering::Release);
        let report = scan(
            source,
            std::slice::from_ref(&request),
            Duration::ZERO,
            &cancelled,
        );
        assert!(report.timed_out && !report.complete);
        assert_eq!((report.fds_scanned, report.userland_flows), (0, 0));
        assert!(report.candidates.is_empty());
    }
}

#[test]
fn c_loop_checks_opaque_cancellation_callback_between_proc_syscalls() {
    use std::ffi::c_void;
    use std::mem::MaybeUninit;
    use std::sync::atomic::AtomicUsize;
    unsafe extern "C" fn cancel_after_two_checks(context: *mut c_void) -> i32 {
        let calls = unsafe { &*context.cast::<AtomicUsize>() };
        i32::from(calls.fetch_add(1, Ordering::AcqRel) >= 2)
    }
    let calls = AtomicUsize::new(0);
    let query = ffi::RawQuery {
        protocol: 17,
        local_port: 12345,
        reserved: 0,
    };
    let mut row = MaybeUninit::<ffi::RawCandidate>::uninit();
    let mut report = ffi::RawReport::default();
    unsafe {
        ffi::egrio_macos_scan_sockets(
            &query,
            1,
            100_000_000,
            row.as_mut_ptr(),
            1,
            &mut report,
            Some(cancel_after_two_checks),
            (&calls as *const AtomicUsize).cast_mut().cast(),
        );
    }
    assert!(report.flags & ffi::CANCELLED != 0);
    assert_eq!(report.candidate_count, 0);
    assert!(calls.load(Ordering::Acquire) >= 3);
}

use super::*;
use std::mem::MaybeUninit;

fn u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

// Sanitized shape of the native, eight-byte aligned xinpgen/xgen_n stream.
// The endpoint/owner offsets are the private exported wire prefixes recorded
// beside userland_flow_scan.c, independent of Rust's bridge structures.
fn snapshot(protocol: u32, v6: bool) -> Vec<u8> {
    let mut bytes = vec![0; 24];
    u32_at(&mut bytes, 0, 24);
    for kind in [16, 1, 2, 4, 8, 32] {
        if kind == 32 && protocol == 17 {
            continue;
        }
        let offset = bytes.len();
        let length = if matches!(kind, 1 | 16) { 104 } else { 8 };
        bytes.resize(offset + length, 0);
        u32_at(&mut bytes, offset, length as u32);
        u32_at(&mut bytes, offset + 4, kind);
        if kind == 1 {
            u32_at(&mut bytes, offset + 36, protocol);
            u32_at(&mut bytes, offset + 68, 1003);
            u32_at(&mut bytes, offset + 72, 993);
        } else if kind == 16 {
            bytes[offset + 16..offset + 18].copy_from_slice(&443_u16.to_be_bytes());
            bytes[offset + 18..offset + 20].copy_from_slice(&54123_u16.to_be_bytes());
            bytes[offset + 44] = if v6 { 2 } else { 1 };
            if v6 {
                bytes[offset + 48..offset + 64].copy_from_slice(
                    &"fd11:5ca1:ab1e:1::c612:2d8c"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                bytes[offset + 64..offset + 80].copy_from_slice(
                    &"fd00:6572:6769:6f00::2"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
            } else {
                bytes[offset + 60..offset + 64].copy_from_slice(&[198, 18, 55, 239]);
                bytes[offset + 76..offset + 80].copy_from_slice(&[10, 255, 255, 1]);
            }
        }
    }
    let end = bytes.len();
    bytes.resize(end + 24, 0);
    u32_at(&mut bytes, end, 24);
    bytes
}

fn parse(
    bytes: &[u8],
    protocol: u32,
    capacity: usize,
) -> (ffi::RawReport, Vec<ffi::RawUserlandFlow>) {
    let query = ffi::RawQuery {
        protocol,
        local_port: 54123,
        reserved: 0,
    };
    let mut rows = Vec::<MaybeUninit<ffi::RawUserlandFlow>>::with_capacity(capacity);
    let mut count = 0;
    let mut report = ffi::RawReport::default();
    unsafe {
        ffi::egrio_parse_userland_snapshot(
            bytes.as_ptr(),
            bytes.len(),
            protocol,
            &query,
            1,
            rows.as_mut_ptr().cast(),
            capacity as u32,
            &mut count,
            &mut report,
            u64::MAX,
            None,
            std::ptr::null_mut(),
        );
        assert!(count as usize <= capacity);
        rows.set_len(count as usize);
    }
    let rows = rows
        .into_iter()
        .map(|row| unsafe { row.assume_init() })
        .collect();
    (report, rows)
}

#[test]
fn userland_tcp_and_udp_preserve_both_endpoint_families_and_delegation() {
    for protocol in [6, 17] {
        for v6 in [false, true] {
            let (report, rows) = parse(&snapshot(protocol, v6), protocol, 2);
            assert_eq!(report.flags, 0);
            assert_eq!(rows.len(), 1);
            assert_eq!((rows[0].owner_pid, rows[0].effective_pid), (1003, 993));
            assert_eq!((rows[0].local.port, rows[0].remote.port), (54123, 443));
            assert_eq!(rows[0].local.family, if v6 { 6 } else { 4 });
            if v6 {
                assert_eq!(
                    std::net::Ipv6Addr::from(rows[0].local.address),
                    "fd00:6572:6769:6f00::2"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                );
            } else {
                assert_eq!(&rows[0].local.address[..4], &[10, 255, 255, 1]);
                assert_eq!(&rows[0].remote.address[..4], &[198, 18, 55, 239]);
            }
        }
    }
}

#[test]
fn ordinary_bsd_sockets_are_not_published_as_userland_flows() {
    let mut bytes = snapshot(6, false);
    u32_at(&mut bytes, 24 + 104 + 40, 2); // xsocket family AF_INET
    let (report, rows) = parse(&bytes, 6, 1);
    assert_eq!(report.flags, 0);
    assert!(rows.is_empty());
}

#[test]
fn malformed_lengths_duplicate_tags_and_missing_trailers_are_rejected() {
    let good = snapshot(6, false);
    let mut corruptions = vec![
        Vec::new(),
        good[..20].to_vec(),
        good[..good.len() - 1].to_vec(),
    ];
    for (offset, value) in [(0, 8), (24, 7), (24, u32::MAX), (24 + 104 + 4, 16)] {
        let mut bad = good.clone();
        u32_at(&mut bad, offset, value);
        corruptions.push(bad);
    }
    for bytes in corruptions {
        let (report, _) = parse(&bytes, 6, 2);
        assert_ne!(report.flags & ffi::SYSCALL_ERROR, 0);
    }
}

#[test]
fn candidate_capacity_is_a_hard_bound() {
    let mut bytes = snapshot(6, false);
    let group = bytes[24..bytes.len() - 24].to_vec();
    bytes.splice(bytes.len() - 24..bytes.len() - 24, group);
    let (report, rows) = parse(&bytes, 6, 1);
    assert_eq!(rows.len(), 1);
    assert_ne!(report.flags & ffi::LIMIT_CANDIDATES, 0);
}

#[test]
fn live_kernel_snapshot_parses_and_never_publishes_ordinary_sockets() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_server, _) = listener.accept().unwrap();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.connect(peer.local_addr().unwrap()).unwrap();
    let flow = |protocol, local: std::net::SocketAddr, remote: std::net::SocketAddr| FlowKey {
        protocol,
        source_ip: local.ip(),
        source_port: local.port(),
        destination_ip: remote.ip(),
        destination_port: remote.port(),
    };
    let requests = [
        flow(
            FlowProtocol::Tcp,
            tcp.local_addr().unwrap(),
            tcp.peer_addr().unwrap(),
        ),
        flow(
            FlowProtocol::Udp,
            udp.local_addr().unwrap(),
            udp.peer_addr().unwrap(),
        ),
    ];
    // Both PCB snapshots of the running kernel must keep the private framing
    // this decoder expects; this process's own BSD rows are never userland.
    let report = scan(
        Source::UserlandFlows,
        &requests,
        std::time::Duration::from_millis(100),
        &std::sync::atomic::AtomicBool::new(false),
    );
    assert!(report.complete, "{report:?}");
    for request in &requests {
        assert!(!report.candidates.iter().any(|candidate| {
            candidate.local_endpoint.port() == request.source_port
                && candidate.remote_endpoint.map(|remote| remote.port())
                    == Some(request.destination_port)
        }));
    }
}

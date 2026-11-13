use super::*;

pub(super) fn flow(udp: bool) -> FlowKey {
    FlowKey {
        protocol: if udp {
            FlowProtocol::Udp
        } else {
            FlowProtocol::Tcp
        },
        source_ip: "10.255.255.1".parse().unwrap(),
        source_port: 54123,
        destination_ip: "198.18.55.239".parse().unwrap(),
        destination_port: 443,
    }
}
pub(super) fn candidate(flow: &FlowKey, pid: u32) -> FlowCandidate {
    FlowCandidate {
        pid,
        owner_pid: pid,
        userland: false,
        start_sec: 10,
        start_usec: 20,
        fd: 7,
        socket_id: 9,
        socket_generation: 11,
        protocol: flow.protocol,
        local_endpoint: SocketAddr::new(flow.source_ip, flow.source_port),
        remote_endpoint: Some(SocketAddr::new(flow.destination_ip, flow.destination_port)),
        executable: format!("/Applications/Test{pid}.app/Contents/MacOS/Test{pid}").into(),
        reuse_port: false,
        reuse_addr: false,
        shared: false,
        dual_stack: false,
    }
}
/// A userland flow held by `pid + 10` on behalf of its delegate `pid`.
fn delegated(flow: &FlowKey, pid: u32) -> FlowCandidate {
    FlowCandidate {
        owner_pid: pid + 10,
        userland: true,
        fd: 0,
        socket_id: 0,
        socket_generation: 0,
        ..candidate(flow, pid)
    }
}
fn complete(candidates: Vec<FlowCandidate>) -> ScanReport {
    ScanReport {
        candidates,
        complete: true,
        ..Default::default()
    }
}
fn owner_name(key: &FlowKey, candidates: &[FlowCandidate]) -> Option<String> {
    resolve(key, candidates).and_then(|process| process.name)
}
fn names(attribution: &Attribution) -> Vec<Option<&str>> {
    attribution
        .owners
        .iter()
        .map(|owner| owner.as_ref().and_then(|process| process.name.as_deref()))
        .collect()
}
/// Two flows on different source ports: the first held by a socket, the
/// second only reachable through the userland-flow snapshot.
fn socket_and_userland_flows() -> [FlowKey; 2] {
    let mut userland = flow(false);
    userland.source_port += 1;
    [flow(false), userland]
}

#[test]
fn userland_flows_answer_only_flows_that_no_socket_owns() {
    let flows = socket_and_userland_flows();
    let mut sources = Vec::new();
    let attribution = attribute(&flows, |source, requests| {
        sources.push(source);
        match source {
            Source::Sockets => complete(vec![candidate(&flows[0], 42)]),
            Source::UserlandFlows => {
                assert_eq!(requests, &flows[1..]);
                complete(vec![delegated(&flows[1], 993)])
            }
        }
    });
    assert_eq!(sources, [Source::Sockets, Source::UserlandFlows]);
    assert_eq!(names(&attribution), [Some("Test42"), Some("Test993")]);
    assert!(attribution.incomplete.is_none());
}
#[test]
fn socket_owned_batches_never_read_the_userland_snapshot() {
    let flows = [flow(false), flow(true)];
    let attribution = attribute(&flows, |source, _| {
        assert_eq!(source, Source::Sockets);
        complete(flows.iter().map(|flow| candidate(flow, 42)).collect())
    });
    assert_eq!(names(&attribution), [Some("Test42"), Some("Test42")]);
}
#[test]
fn incomplete_sockets_leave_the_batch_unknown_without_reading_userland_flows() {
    let flows = socket_and_userland_flows();
    let attribution = attribute(&flows, |source, _| {
        assert_eq!(source, Source::Sockets);
        ScanReport {
            candidates: vec![candidate(&flows[0], 42)],
            raced: 1,
            ..Default::default()
        }
    });
    assert_eq!(names(&attribution), [None, None]);
    assert!(matches!(attribution.incomplete, Some((Source::Sockets, _))));
}
#[test]
fn an_unusable_userland_snapshot_keeps_socket_owners_and_publishes_none_of_its_rows() {
    let flows = socket_and_userland_flows();
    let attribution = attribute(&flows, |source, _| match source {
        Source::Sockets => complete(vec![candidate(&flows[0], 42)]),
        Source::UserlandFlows => ScanReport {
            candidates: vec![delegated(&flows[1], 993)],
            timed_out: true,
            ..Default::default()
        },
    });
    assert_eq!(names(&attribution), [Some("Test42"), None]);
    assert!(matches!(
        attribution.incomplete,
        Some((Source::UserlandFlows, _))
    ));
}
#[test]
fn network_framework_uses_the_kernel_delegate_and_keeps_different_owners_ambiguous() {
    for udp in [false, true] {
        let key = flow(udp);
        let delegated = delegated(&key, 993);
        let process = resolve(&key, std::slice::from_ref(&delegated)).unwrap();
        assert_eq!(process.name.as_deref(), Some("Test993"));
        assert_eq!(
            process.path.as_deref(),
            Some("/Applications/Test993.app/Contents/MacOS/Test993")
        );
        let mut other_owner = delegated.clone();
        other_owner.owner_pid += 1;
        assert!(resolve(&key, &[delegated, other_owner]).is_none());
    }
}
#[test]
fn exact_original_fake_address_selects_only_its_socket_for_both_families() {
    for udp in [false, true] {
        let mut key = flow(udp);
        for v6 in [false, true] {
            if v6 {
                key.source_ip = "fd00:23::2".parse().unwrap();
                key.destination_ip = "fd11:5ca1:ab1e:1::c612:2d8c".parse().unwrap();
            }
            let exact = candidate(&key, 42);
            let mut wrong = candidate(&key, 43);
            wrong.remote_endpoint = Some(
                if v6 { "[::1]:443" } else { "127.0.0.1:443" }
                    .parse()
                    .unwrap(),
            );
            let result = resolve(&key, &[wrong, exact]).unwrap();
            assert_eq!(result.name.as_deref(), Some("Test42"));
            assert_eq!(
                result.path.as_deref(),
                Some("/Applications/Test42.app/Contents/MacOS/Test42")
            );
        }
    }
}
#[test]
fn unconnected_udp_can_match_a_unique_non_reused_local_bind_but_tcp_cannot() {
    for udp in [false, true] {
        let key = flow(udp);
        let mut socket = candidate(&key, 42);
        socket.remote_endpoint = None;
        socket.local_endpoint.set_ip("0.0.0.0".parse().unwrap());
        assert_eq!(resolve(&key, &[socket]).is_some(), udp);
    }
}
#[test]
fn ambiguity_shared_descriptors_and_reusable_udp_binds_remain_unknown() {
    let key = flow(true);
    let one = candidate(&key, 42);
    assert!(resolve(&key, &[one.clone(), candidate(&key, 43)]).is_none());
    for flag in 0..4 {
        let mut unsafe_owner = one.clone();
        match flag {
            0 => unsafe_owner.shared = true,
            1 => unsafe_owner.reuse_port = true,
            2 => unsafe_owner.reuse_addr = true,
            _ => unsafe_owner.dual_stack = true,
        }
        assert!(resolve(&key, &[unsafe_owner]).is_none());
    }
    let mut reused_pid = one.clone();
    reused_pid.start_usec += 1;
    assert!(resolve(&key, &[one.clone(), reused_pid]).is_none());
    let mut duplicate = one.clone();
    duplicate.fd += 1;
    assert_eq!(
        owner_name(&key, &[one, duplicate]).as_deref(),
        Some("Test42")
    );
}
#[test]
fn wrong_tuple_or_relative_executable_never_produces_an_identity() {
    let key = flow(false);
    let mut wrong_port = candidate(&key, 42);
    wrong_port.local_endpoint.set_port(1);
    assert!(resolve(&key, &[wrong_port]).is_none());
    let mut relative = candidate(&key, 42);
    relative.executable = "relative-executable".into();
    assert!(resolve(&key, &[relative]).is_none());
}
#[test]
fn scanner_answers_every_requested_flow_in_order() {
    // Unowned test tuples stay unknown; the batch never misaligns owners.
    let scanner = MacosFlowScanner::default();
    let flows = [flow(false), flow(true)];
    let results = scanner.scan(&flows, Duration::from_millis(10), &AtomicBool::new(false));
    assert_eq!(results.len(), flows.len());
}

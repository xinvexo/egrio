use super::*;
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

const IF_TYPE_TUNNEL_FOR_TEST: u32 = 131;

#[test]
fn active_capture_accepts_only_service_created_wintun_adapters() {
    assert!(validate_windows_wintun_active_adapter_ownership(true, "Egrio Wintun").is_ok());
}

#[test]
fn active_capture_rejects_pre_existing_wintun_adapters_before_mutation() {
    let error = validate_windows_wintun_active_adapter_ownership(false, "Shared Wintun")
        .expect_err("a pre-existing adapter must not be adopted");

    assert!(error.contains("Shared Wintun"));
    assert!(error.contains("pre-existing"));
    assert!(error.contains("IPv4/IPv6 address, metric, and MTU baseline"));
}

#[test]
fn wrapper_native_open_failure_sentinel_requires_confirmation() {
    assert_eq!(
        classify_wintun_wrapper_open_error(&wintun::Error::String(
            WINTUN_WRAPPER_NATIVE_OPEN_FAILED.into()
        )),
        WintunWrapperOpenErrorKind::NativeOpenFailed
    );
}

#[test]
fn wrapper_metadata_and_unknown_failures_do_not_trigger_reopen() {
    assert_eq!(
        classify_wintun_wrapper_open_error(&wintun::Error::Io(std::io::Error::from_raw_os_error(
            ERROR_ACCESS_DENIED as i32,
        ))),
        WintunWrapperOpenErrorKind::Uncertain
    );
    assert_eq!(
        classify_wintun_wrapper_open_error(&wintun::Error::String(
            "unexpected wrapper failure".into()
        )),
        WintunWrapperOpenErrorKind::Uncertain
    );
}

#[test]
fn adapter_open_not_found_is_the_only_absent_classification() {
    assert_eq!(
        classify_wintun_adapter_open_error(ERROR_NOT_FOUND),
        WintunAdapterOpenErrorKind::NotFound
    );
    assert_eq!(
        classify_wintun_adapter_open_error(ERROR_ACCESS_DENIED),
        WintunAdapterOpenErrorKind::Failed
    );
}

#[test]
fn adapter_open_errors_other_than_not_found_fail_closed() {
    assert_eq!(
        classify_wintun_adapter_open_error(ERROR_SUCCESS),
        WintunAdapterOpenErrorKind::Failed
    );
}

#[test]
fn cleanup_error_suffix_is_empty_without_cleanup_errors() {
    assert_eq!(cleanup_error_suffix(&[], &[]), "");
}

#[test]
fn cleanup_error_suffix_includes_route_and_dns_failures() {
    assert_eq!(
        cleanup_error_suffix(
            &["route delete failed".to_string()],
            &["dns clear failed".to_string()]
        ),
        "; cleanup errors: route: route delete failed; dns: dns clear failed"
    );
}

#[test]
fn ipv4_prefix_length_rejects_non_contiguous_netmask() {
    assert_eq!(
        ipv4_prefix_length_from_netmask(Ipv4Addr::new(255, 255, 255, 252)),
        Ok(30)
    );

    let error = ipv4_prefix_length_from_netmask(Ipv4Addr::new(255, 0, 255, 0))
        .expect_err("non-contiguous netmask should fail");

    assert!(error.contains("non-contiguous"));
}

#[test]
fn wintun_address_conflict_points_to_configuration() {
    let addresses = vec![
        WindowsIpv4InterfaceAddress {
            interface_index: 49,
            address: Ipv4Addr::new(10, 255, 255, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 252),
        },
        WindowsIpv4InterfaceAddress {
            interface_index: 18,
            address: Ipv4Addr::new(198, 18, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 252),
        },
    ];

    assert!(configured_wintun_address_conflict_message(
        49,
        Ipv4Addr::new(10, 255, 255, 1),
        &addresses,
    )
    .is_none());
    let message =
        configured_wintun_address_conflict_message(49, Ipv4Addr::new(198, 18, 0, 1), &addresses)
            .expect("other interface owns the address");

    assert!(message.contains("EGRIO_WINTUN_ADDRESS"));
    assert!(message.contains("interface 18"));
}

#[test]
fn windows_dns_name_server_string_is_comma_separated_and_null_terminated() {
    let encoded = windows_dns_name_server_string(&[
        IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
    ]);

    assert_eq!(encoded.last().copied(), Some(0));
    assert_eq!(
        String::from_utf16(&encoded[..encoded.len() - 1]).unwrap(),
        "10.255.255.1,192.168.1.1"
    );

    assert_eq!(windows_dns_name_server_string(&[]), vec![0]);
}

#[test]
fn adapter_dns_server_chain_preserves_both_address_families() {
    let mut ipv4 = unsafe { sockaddr_inet_ipv4(Ipv4Addr::new(10, 255, 255, 2)).Ipv4 };
    let mut ipv6 = unsafe { sockaddr_inet_ipv6("fd11:5ca1:ab1e::2".parse().unwrap()).Ipv6 };
    let mut placeholder =
        unsafe { sockaddr_inet_ipv6(WINDOWS_EMPTY_IPV6_DNS_PLACEHOLDERS[0]).Ipv6 };
    let mut ipv6_entry = IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
        Address: SOCKET_ADDRESS {
            lpSockaddr: (&mut ipv6 as *mut SOCKADDR_IN6)
                .cast::<windows_sys::Win32::Networking::WinSock::SOCKADDR>(),
            iSockaddrLength: mem::size_of::<SOCKADDR_IN6>() as i32,
        },
        ..Default::default()
    };
    let mut placeholder_entry = IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
        Next: &mut ipv6_entry,
        Address: SOCKET_ADDRESS {
            lpSockaddr: (&mut placeholder as *mut SOCKADDR_IN6)
                .cast::<windows_sys::Win32::Networking::WinSock::SOCKADDR>(),
            iSockaddrLength: mem::size_of::<SOCKADDR_IN6>() as i32,
        },
        ..Default::default()
    };
    let mut ipv4_entry = IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
        Next: &mut placeholder_entry,
        Address: SOCKET_ADDRESS {
            lpSockaddr: (&mut ipv4 as *mut SOCKADDR_IN)
                .cast::<windows_sys::Win32::Networking::WinSock::SOCKADDR>(),
            iSockaddrLength: mem::size_of::<SOCKADDR_IN>() as i32,
        },
        ..Default::default()
    };

    assert_eq!(
        dns_server_addresses(&mut ipv4_entry),
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2)),
            IpAddr::V6("fd11:5ca1:ab1e::2".parse().unwrap()),
        ]
    );
}

#[test]
fn dns_family_updates_always_replace_both_address_families() {
    let updates = windows_dns_family_updates(&[
        IpAddr::V6("fd11:5ca1:ab1e::2".parse().unwrap()),
        IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2)),
    ]);

    assert_eq!(updates[0].0, WindowsDnsAddressFamily::Ipv4);
    assert_eq!(
        updates[0].1,
        vec![IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2))]
    );
    assert_eq!(updates[1].0, WindowsDnsAddressFamily::Ipv6);
    assert_eq!(
        updates[1].1,
        vec![IpAddr::V6("fd11:5ca1:ab1e::2".parse().unwrap())]
    );

    let clear_updates = windows_dns_family_updates(&[]);
    assert!(clear_updates[0].1.is_empty());
    assert!(clear_updates[1].1.is_empty());
}

#[test]
fn dns_family_flags_select_ipv6_explicitly() {
    assert_eq!(
        windows_dns_settings_flags(WindowsDnsAddressFamily::Ipv4),
        u64::from(DNS_SETTING_NAMESERVER)
    );
    assert_eq!(
        windows_dns_settings_flags(WindowsDnsAddressFamily::Ipv6),
        u64::from(DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6)
    );
}

#[test]
fn ipv6_prefix_matches_covers_default_split_and_specifics() {
    let target: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();

    assert!(ipv6_prefix_matches(target, "::".parse().unwrap(), 0));
    assert!(ipv6_prefix_matches(
        target,
        "2001:db8::".parse().unwrap(),
        32
    ));
    assert!(!ipv6_prefix_matches(target, "8000::".parse().unwrap(), 1));
    assert!(!ipv6_prefix_matches(target, "::".parse().unwrap(), 129));
}

#[test]
fn best_physical_route_ignores_virtual_default_routes() {
    let routes = vec![
        WindowsIpv4RouteTableEntry {
            destination: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::new(198, 18, 0, 2),
            interface_index: 18,
            metric: 0,
            raw_row: None,
        },
        WindowsIpv4RouteTableEntry {
            destination: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: 4,
            metric: 30,
            raw_row: None,
        },
    ];
    let interfaces = vec![
        interface_metadata(18, "other-vpn", "Other VPN Tunnel", IF_TYPE_TUNNEL_FOR_TEST),
        interface_metadata(4, "WLAN", "Wireless Network Adapter", IF_TYPE_IEEE80211),
    ];

    let route =
        select_best_physical_route_for_ipv4(Ipv4Addr::new(1, 1, 1, 1), &routes, &interfaces, None)
            .expect("physical route should win");

    assert_eq!(route.gateway, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(route.interface_index, 4);
}

#[test]
fn best_physical_route_selects_hyper_v_vethernet_on_structure_not_name() {
    // Regression: on a Hyper-V host the real uplink is a "vEthernet" adapter —
    // an up ethernet interface with a hardware address whose description carries
    // "Virtual". Egress selection must accept it on structure and never reject
    // it for the name, which is what left the host with "no usable physical
    // route" before the snapshot redesign.
    let routes = vec![WindowsIpv4RouteTableEntry {
        destination: Ipv4Addr::UNSPECIFIED,
        netmask: Ipv4Addr::UNSPECIFIED,
        gateway: Ipv4Addr::new(172, 26, 0, 1),
        interface_index: 22,
        metric: 5,
        raw_row: None,
    }];
    let interfaces = vec![interface_metadata(
        22,
        "vEthernet (Default Switch)",
        "Hyper-V Virtual Ethernet Adapter",
        IF_TYPE_ETHERNET_CSMACD,
    )];

    let route =
        select_best_physical_route_for_ipv4(Ipv4Addr::new(1, 1, 1, 1), &routes, &interfaces, None)
            .expect("Hyper-V vEthernet is a real physical egress");

    assert_eq!(route.interface_index, 22);
    assert_eq!(route.gateway, Ipv4Addr::new(172, 26, 0, 1));
}

#[test]
fn excluded_wintun_loses_to_the_physical_default_even_with_a_longer_prefix() {
    // The loop the old per-dial design fell into: once the tunnel installs its
    // `/1` capture route it is longer-prefix than the physical `/0` default, so
    // an unfiltered longest-prefix match resolves the tunnel itself. Excluding
    // our own Wintun by index must make the physical uplink win regardless of
    // prefix length — this is the deterministic loop protection that lets the
    // underlying be recomputed at any time, even after the hijack.
    let routes = vec![
        WindowsIpv4RouteTableEntry {
            // Our own Wintun capture route: 0.0.0.0/1, longer-prefix than /0.
            destination: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::new(128, 0, 0, 0),
            gateway: Ipv4Addr::UNSPECIFIED,
            interface_index: 42,
            metric: 0,
            raw_row: None,
        },
        WindowsIpv4RouteTableEntry {
            // The physical uplink's default route.
            destination: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: 4,
            metric: 30,
            raw_row: None,
        },
    ];
    let interfaces = vec![
        // Wintun reports as a real ethernet NIC with a hardware address, so the
        // structural filter alone cannot reject it — only the index exclusion.
        interface_metadata(
            42,
            "Egrio-TUN",
            "Wintun Userspace Tunnel",
            IF_TYPE_ETHERNET_CSMACD,
        ),
        interface_metadata(4, "WLAN", "Wireless Network Adapter", IF_TYPE_IEEE80211),
    ];

    // Without exclusion the longer-prefix Wintun route wins — the loop.
    let looped =
        select_best_physical_route_for_ipv4(Ipv4Addr::new(1, 1, 1, 1), &routes, &interfaces, None)
            .expect("some route matches");
    assert_eq!(
        looped.interface_index, 42,
        "unfiltered match resolves the tunnel"
    );

    // Excluding our own Wintun by index falls through to the physical default.
    let route = select_best_physical_route_for_ipv4(
        Ipv4Addr::new(1, 1, 1, 1),
        &routes,
        &interfaces,
        Some(42),
    )
    .expect("physical default wins once the tunnel is excluded");
    assert_eq!(route.interface_index, 4);
    assert_eq!(route.gateway, Ipv4Addr::new(192, 168, 1, 1));
}

#[test]
fn best_physical_route_uses_effective_route_and_interface_metric() {
    let routes = vec![
        WindowsIpv4RouteTableEntry {
            destination: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::new(192, 168, 2, 1),
            interface_index: 5,
            metric: 1,
            raw_row: None,
        },
        WindowsIpv4RouteTableEntry {
            destination: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: 4,
            metric: 10,
            raw_row: None,
        },
    ];
    let interfaces = vec![
        interface_metadata_with_metric(5, "Ethernet", "USB Ethernet", IF_TYPE_ETHERNET_CSMACD, 200),
        interface_metadata_with_metric(4, "WLAN", "Wireless Network Adapter", IF_TYPE_IEEE80211, 1),
    ];

    let route =
        select_best_physical_route_for_ipv4(Ipv4Addr::new(8, 8, 4, 4), &routes, &interfaces, None)
            .expect("lower effective metric should win");

    assert_eq!(route.gateway, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(route.interface_index, 4);
}

#[test]
fn best_physical_route_returns_none_without_physical_interface() {
    let routes = vec![WindowsIpv4RouteTableEntry {
        destination: Ipv4Addr::UNSPECIFIED,
        netmask: Ipv4Addr::UNSPECIFIED,
        gateway: Ipv4Addr::new(198, 18, 0, 2),
        interface_index: 18,
        metric: 0,
        raw_row: None,
    }];
    let interfaces = vec![interface_metadata(
        18,
        "other-vpn",
        "Other VPN Tunnel",
        IF_TYPE_TUNNEL_FOR_TEST,
    )];

    assert!(select_best_physical_route_for_ipv4(
        Ipv4Addr::new(1, 1, 1, 1),
        &routes,
        &interfaces,
        None
    )
    .is_none());
}

#[test]
fn route_ownership_requires_protocol_and_manual_origin() {
    let route = WindowsWintunRoute {
        destination: Ipv4Addr::UNSPECIFIED,
        netmask: Ipv4Addr::new(192, 0, 0, 0),
        gateway: Ipv4Addr::UNSPECIFIED,
        interface_index: 49,
        metric: 1,
    };
    let owned = windows_ipv4_route_table_entry_from_row(ip_forward_row(
        route.destination,
        2,
        route.gateway,
        route.interface_index,
        route.metric,
    ))
    .unwrap();
    assert!(windows_route_table_entry_matches_wintun_route(
        &owned, &route
    ));

    let mut wrong_protocol = owned.clone();
    wrong_protocol.raw_row.as_mut().unwrap().Protocol = MIB_IPPROTO_NETMGMT + 1;
    assert!(!windows_route_table_entry_matches_wintun_route(
        &wrong_protocol,
        &route
    ));

    let mut wrong_origin = owned.clone();
    wrong_origin.raw_row.as_mut().unwrap().Origin = NlroManual + 1;
    assert!(!windows_route_table_entry_matches_wintun_route(
        &wrong_origin,
        &route
    ));

    let without_raw_row = WindowsIpv4RouteTableEntry {
        raw_row: None,
        ..owned
    };
    assert!(!windows_route_table_entry_matches_wintun_route(
        &without_raw_row,
        &route
    ));
}

#[test]
fn ipv6_route_ownership_requires_protocol_and_manual_origin() {
    let route = WindowsWintunRoute6 {
        destination: Ipv6Addr::UNSPECIFIED,
        prefix_length: 1,
        gateway: Ipv6Addr::UNSPECIFIED,
        interface_index: 49,
        metric: 1,
    };
    let owned =
        windows_ipv6_route_table_entry_from_row(ip_forward_row_from_wintun_route6(&route)).unwrap();
    assert!(windows_ipv6_route_table_entry_matches_wintun_route(
        &owned, &route
    ));

    let mut wrong_protocol = owned.clone();
    wrong_protocol.raw_row.as_mut().unwrap().Protocol = MIB_IPPROTO_NETMGMT + 1;
    assert!(!windows_ipv6_route_table_entry_matches_wintun_route(
        &wrong_protocol,
        &route
    ));

    let mut wrong_origin = owned.clone();
    wrong_origin.raw_row.as_mut().unwrap().Origin = NlroManual + 1;
    assert!(!windows_ipv6_route_table_entry_matches_wintun_route(
        &wrong_origin,
        &route
    ));

    let without_raw_row = WindowsIpv6RouteTableEntry {
        raw_row: None,
        ..owned
    };
    assert!(!windows_ipv6_route_table_entry_matches_wintun_route(
        &without_raw_row,
        &route
    ));
}

#[test]
fn ip_forward_row_preserves_wintun_route_shape() {
    let route = WindowsWintunRoute {
        destination: Ipv4Addr::new(203, 0, 113, 0),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(192, 168, 1, 1),
        interface_index: 12,
        metric: 7,
    };

    let row = ip_forward_row_from_wintun_route(&route).unwrap();
    let entry = windows_ipv4_route_table_entry_from_row(row).unwrap();

    assert_eq!(entry.destination, route.destination);
    assert_eq!(entry.netmask, route.netmask);
    assert_eq!(entry.gateway, route.gateway);
    assert_eq!(entry.interface_index, route.interface_index);
    assert_eq!(entry.metric, route.metric);
    assert_eq!(row.DestinationPrefix.PrefixLength, 24);
    assert_eq!(row.SitePrefixLength, 24);
    assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);
    assert_eq!(row.Origin, NlroManual);
}

#[test]
fn observed_capture_route_keys_round_trip_installed_routes_and_skip_noise() {
    let adapter_index = 12;
    let other_index = 99;

    // Egrio-owned IPv4 capture routes, built exactly as the installer would
    // (NETMGMT protocol, adapter interface) and turned into route-table entries.
    let installed_v4 = windows_wintun_ipv4_capture_routes(adapter_index, 1, &[]).unwrap();
    let mut v4: Vec<WindowsIpv4RouteTableEntry> = installed_v4
        .iter()
        .map(|route| {
            windows_ipv4_route_table_entry_from_row(
                ip_forward_row_from_wintun_route(route).unwrap(),
            )
            .unwrap()
        })
        .collect();
    // Noise (1): the same NETMGMT routes on a different interface — not ours.
    v4.extend(
        windows_wintun_ipv4_capture_routes(other_index, 1, &[])
            .unwrap()
            .iter()
            .map(|route| {
                windows_ipv4_route_table_entry_from_row(
                    ip_forward_row_from_wintun_route(route).unwrap(),
                )
                .unwrap()
            }),
    );
    // Noise (2): an on-link route on the Egrio interface with a non-NETMGMT
    // protocol — the kind Windows auto-creates, not installed by Egrio.
    let mut auto_route = windows_ipv4_route_table_entry_from_row(
        ip_forward_row_from_wintun_route(&WindowsWintunRoute {
            destination: Ipv4Addr::new(10, 255, 255, 0),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(0, 0, 0, 0),
            interface_index: adapter_index,
            metric: 1,
        })
        .unwrap(),
    )
    .unwrap();
    auto_route.raw_row.as_mut().unwrap().Protocol = MIB_IPPROTO_NETMGMT + 1;
    v4.push(auto_route);

    // Egrio-owned IPv6 capture routes plus the same two classes of noise.
    let installed_v6 = windows_wintun_ipv6_capture_routes(adapter_index, 1, &[]).unwrap();
    let mut v6: Vec<WindowsIpv6RouteTableEntry> = installed_v6
        .iter()
        .map(|route| {
            windows_ipv6_route_table_entry_from_row(ip_forward_row_from_wintun_route6(route))
                .unwrap()
        })
        .collect();
    let mut other_interface = installed_v6[0].clone();
    other_interface.interface_index = other_index;
    v6.push(
        windows_ipv6_route_table_entry_from_row(ip_forward_row_from_wintun_route6(
            &other_interface,
        ))
        .unwrap(),
    );
    let mut wrong_protocol = windows_ipv6_route_table_entry_from_row(ip_forward_row6(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        10,
        Ipv6Addr::UNSPECIFIED,
        adapter_index,
        1,
    ))
    .unwrap();
    wrong_protocol.raw_row.as_mut().unwrap().Protocol = MIB_IPPROTO_NETMGMT + 1;
    v6.push(wrong_protocol);
    let mut wrong_origin = windows_ipv6_route_table_entry_from_row(ip_forward_row6(
        Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        8,
        Ipv6Addr::UNSPECIFIED,
        adapter_index,
        1,
    ))
    .unwrap();
    wrong_origin.raw_row.as_mut().unwrap().Origin = NlroManual + 1;
    v6.push(wrong_origin);

    let observed = egrio_owned_capture_route_keys(adapter_index, &v4, &v6);

    // The observed keys are exactly the installed capture routes' canonical keys —
    // the same formatter the desired-state builder uses — with all noise dropped.
    let mut derived: Vec<String> = installed_v4
        .iter()
        .map(WindowsWintunRoute::cidr_key)
        .chain(installed_v6.iter().map(WindowsWintunRoute6::cidr_key))
        .collect();
    derived.sort();
    assert_eq!(observed, derived);

    let mut expected = vec![
        "0.0.0.0/2".to_string(),
        "64.0.0.0/2".to_string(),
        "128.0.0.0/2".to_string(),
        "192.0.0.0/2".to_string(),
        "::/1".to_string(),
        "8000::/1".to_string(),
    ];
    expected.sort();
    assert_eq!(observed, expected);
}

fn interface_metadata(
    interface_index: u32,
    alias: &str,
    description: &str,
    if_type: u32,
) -> WindowsInterfaceMetadata {
    WindowsInterfaceMetadata {
        interface_index,
        alias: alias.into(),
        description: description.into(),
        if_type,
        oper_status: IfOperStatusUp,
        physical_address_length: 6,
        ipv4_metric: 1,
        automatic_metric: false,
    }
}

fn interface_metadata_with_metric(
    interface_index: u32,
    alias: &str,
    description: &str,
    if_type: u32,
    ipv4_metric: u32,
) -> WindowsInterfaceMetadata {
    WindowsInterfaceMetadata {
        ipv4_metric,
        ..interface_metadata(interface_index, alias, description, if_type)
    }
}

#[test]
fn resolve_wintun_dll_path_prefers_the_explicit_config_path() {
    let config = WindowsWintunConfig {
        dll_path: Some(r"C:\custom\path\wintun.dll".into()),
        ..WindowsWintunConfig::default()
    };

    assert_eq!(
        resolve_wintun_dll_path(&config),
        PathBuf::from(r"C:\custom\path\wintun.dll")
    );
}

#[test]
fn wintun_dll_beside_current_exe_is_an_absolute_wintun_dll() {
    let path = wintun_dll_beside_current_exe().expect("current exe path resolves in tests");

    assert!(path.is_absolute());
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("wintun.dll")
    );
}

#[test]
fn resolve_wintun_dll_path_falls_back_to_the_bare_name_without_a_bundled_dll() {
    // No explicit path: the resolver prefers a wintun.dll shipped beside the
    // executable, else the bare name so Windows' standard DLL search still
    // applies. The test binary has no bundled copy beside it, so the bare-name
    // fallback holds (guarded in case one is ever staged there).
    let config = WindowsWintunConfig {
        dll_path: None,
        ..WindowsWintunConfig::default()
    };

    let resolved = resolve_wintun_dll_path(&config);
    match wintun_dll_beside_current_exe() {
        Some(beside) if beside.is_file() => assert_eq!(resolved, beside),
        _ => assert_eq!(resolved, PathBuf::from("wintun.dll")),
    }
}

#[test]
fn the_reader_nudge_is_an_ipv4_header_the_stack_discards() {
    let header = DISCARDED_IPV4_HEADER;
    assert_eq!(header[0], 0x45, "IPv4 with a 20-byte header");
    assert_eq!(u16::from_be_bytes([header[2], header[3]]), 20);
    // A valid header sums to 0xffff in one's complement, checksum included.
    let mut sum: u32 = header
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    assert_ne!(sum, 0xffff, "the checksum must be wrong");
}

//! The tunnel adapter's addresses and interface settings, IPv4 and IPv6.

use super::*;

pub(super) fn configure_windows_wintun_ipv4_address(
    adapter_index: u32,
    config: &WindowsWintunConfig,
) -> Result<(), String> {
    configured_wintun_address_conflict(adapter_index, config)?;
    upsert_windows_unicast_ipv4_address(
        adapter_index,
        config.adapter_address,
        config.adapter_netmask,
    )
}

fn configured_wintun_address_conflict(
    adapter_index: u32,
    config: &WindowsWintunConfig,
) -> Result<(), String> {
    if let Some(message) = configured_wintun_address_conflict_message(
        adapter_index,
        config.adapter_address,
        &windows_ipv4_interface_addresses()?,
    ) {
        return Err(message);
    }

    Ok(())
}

pub(super) fn configured_wintun_address_conflict_message(
    adapter_index: u32,
    address: Ipv4Addr,
    addresses: &[WindowsIpv4InterfaceAddress],
) -> Option<String> {
    let owner = addresses.iter().find(|candidate| {
        candidate.address == address && candidate.interface_index != adapter_index
    })?;
    Some(format!(
        "configured Wintun IPv4 address {address} is already assigned to Windows interface {}; set EGRIO_WINTUN_ADDRESS, EGRIO_WINTUN_NETMASK, and optionally EGRIO_WINTUN_DNS to an unused TUN subnet",
        owner.interface_index
    ))
}

pub(super) fn configure_windows_wintun_ipv4_interface(
    interface_index: u32,
    metric: u32,
    mtu: u32,
) -> Result<(), String> {
    let mut row = initialized_ip_interface_row(interface_index);
    let error = unsafe { GetIpInterfaceEntry(&mut row) };
    win32_success_or_error(
        error,
        format!("failed to inspect Wintun IPv4 interface on interface {interface_index}"),
    )?;

    if !row.UseAutomaticMetric && row.Metric == metric && row.NlMtu == mtu {
        return Ok(());
    }

    row.UseAutomaticMetric = false;
    row.Metric = metric;
    // The IP-layer MTU governs the MSS a captured client advertises and the
    // path MTU it computes. `wintun::Adapter::set_mtu` only sets the adapter
    // (NDIS) MTU, which does NOT propagate to `NlMtu` — left unset it stays at
    // Wintun's 0xFFFF default, so clients advertise a ~65495 MSS and the
    // sustained inbound-inject path stalls. Set the IP-interface MTU so
    // the TCP stack uses the capture device's configured packet size.
    row.NlMtu = mtu;
    // Windows may return a SitePrefixLength that SetIpInterfaceEntry rejects
    // when the row is written back. Reset it before calling the setter.
    row.SitePrefixLength = 0;
    let error = unsafe { SetIpInterfaceEntry(&mut row) };
    win32_success_or_error(
        error,
        format!(
            "failed to set Wintun IPv4 interface metric {metric}/mtu {mtu} on interface {interface_index}"
        ),
    )
}

pub(super) fn initialized_ip_interface_row(interface_index: u32) -> MIB_IPINTERFACE_ROW {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe {
        InitializeIpInterfaceEntry(&mut row);
    }
    row.Family = AF_INET;
    row.InterfaceIndex = interface_index;
    row
}

fn upsert_windows_unicast_ipv4_address(
    interface_index: u32,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Result<(), String> {
    let prefix_length = ipv4_prefix_length_from_netmask(netmask)?;
    if let Some(mut row) = get_windows_unicast_ipv4_address(interface_index, address)? {
        if row.OnLinkPrefixLength == prefix_length
            && row.PrefixOrigin == IpPrefixOriginManual
            && row.SuffixOrigin == IpSuffixOriginManual
        {
            return Ok(());
        }
        configure_unicast_address_row(&mut row, prefix_length);
        let error = unsafe { SetUnicastIpAddressEntry(&row) };
        return win32_success_or_error(
            error,
            format!("failed to update Wintun IPv4 address {address}/{prefix_length}"),
        );
    }

    let mut row = initialized_unicast_ipv4_address_row(interface_index, address, prefix_length);
    let error = unsafe { CreateUnicastIpAddressEntry(&row) };
    match error {
        ERROR_SUCCESS => Ok(()),
        ERROR_ALREADY_EXISTS | ERROR_OBJECT_ALREADY_EXISTS => {
            if get_windows_unicast_ipv4_address(interface_index, address)?.is_some() {
                row = initialized_unicast_ipv4_address_row(interface_index, address, prefix_length);
                let error = unsafe { SetUnicastIpAddressEntry(&row) };
                win32_success_or_error(
                    error,
                    format!("failed to reconcile existing Wintun IPv4 address {address}/{prefix_length}"),
                )
            } else {
                Err(format!(
                    "configured Wintun IPv4 address {address} already exists on another Windows interface; set EGRIO_WINTUN_ADDRESS to an unused TUN subnet"
                ))
            }
        }
        error => win32_success_or_error(
            error,
            format!("failed to create Wintun IPv4 address {address}/{prefix_length}"),
        ),
    }
}

fn get_windows_unicast_ipv4_address(
    interface_index: u32,
    address: Ipv4Addr,
) -> Result<Option<MIB_UNICASTIPADDRESS_ROW>, String> {
    let mut row = initialized_unicast_ipv4_address_row(interface_index, address, 32);
    let error = unsafe { GetUnicastIpAddressEntry(&mut row) };
    match error {
        ERROR_SUCCESS => Ok(Some(row)),
        ERROR_NOT_FOUND => Ok(None),
        error => Err(format!(
            "failed to inspect Wintun IPv4 address {address} on interface {interface_index}: {}",
            std::io::Error::from_raw_os_error(error as i32)
        )),
    }
}

fn initialized_unicast_ipv4_address_row(
    interface_index: u32,
    address: Ipv4Addr,
    prefix_length: u8,
) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe {
        InitializeUnicastIpAddressEntry(&mut row);
    }
    row.InterfaceIndex = interface_index;
    row.Address = sockaddr_inet_ipv4(address);
    configure_unicast_address_row(&mut row, prefix_length);
    row
}

fn configure_unicast_address_row(row: &mut MIB_UNICASTIPADDRESS_ROW, prefix_length: u8) {
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.OnLinkPrefixLength = prefix_length;
    row.SkipAsSource = false;
    row.DadState = IpDadStatePreferred;
}

pub(super) fn sockaddr_inet_ipv4(address: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: ipv4_to_windows_addr(address),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

pub(super) fn sockaddr_inet_to_ipv4(address: SOCKADDR_INET) -> Option<Ipv4Addr> {
    let family = unsafe { address.si_family };
    if family != AF_INET {
        return None;
    }
    Some(windows_addr_to_ipv4(unsafe {
        address.Ipv4.sin_addr.S_un.S_addr
    }))
}

pub(super) fn ipv4_netmask_from_prefix_length(prefix_length: u8) -> Option<Ipv4Addr> {
    if prefix_length > 32 {
        return None;
    }
    let bits = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_length))
    };
    Some(Ipv4Addr::from(bits))
}

pub(super) fn win32_success_or_error(error: u32, action: impl Into<String>) -> Result<(), String> {
    if error == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "{}: {}",
            action.into(),
            std::io::Error::from_raw_os_error(error as i32)
        ))
    }
}

/// A `SOCKADDR_INET` holding an IPv6 address (family AF_INET6), the v6 analogue
/// of [`sockaddr_inet_ipv4`]. Field layout verified against windows-sys 0.61.
pub(super) fn sockaddr_inet_ipv6(address: Ipv6Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv6: SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: address.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        },
    }
}

pub(super) fn configure_windows_wintun_ipv6_address(
    interface_index: u32,
    address: Ipv6Addr,
    prefix_length: u8,
) -> Result<(), String> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe {
        InitializeUnicastIpAddressEntry(&mut row);
    }
    row.InterfaceIndex = interface_index;
    row.Address = sockaddr_inet_ipv6(address);
    configure_unicast_address_row(&mut row, prefix_length);
    let error = unsafe { CreateUnicastIpAddressEntry(&row) };
    match error {
        ERROR_SUCCESS | ERROR_ALREADY_EXISTS | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        error => win32_success_or_error(
            error,
            format!("failed to set Wintun IPv6 address {address}/{prefix_length}"),
        ),
    }
}

pub(super) fn configure_windows_wintun_ipv6_interface(
    interface_index: u32,
    metric: u32,
    mtu: u32,
) -> Result<(), String> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe {
        InitializeIpInterfaceEntry(&mut row);
    }
    row.Family = AF_INET6;
    row.InterfaceIndex = interface_index;
    let error = unsafe { GetIpInterfaceEntry(&mut row) };
    win32_success_or_error(
        error,
        format!("failed to inspect Wintun IPv6 interface on interface {interface_index}"),
    )?;

    row.UseAutomaticMetric = false;
    row.Metric = metric;
    // See the IPv4 setter: set the IP-layer MTU so the client negotiates a sane
    // MSS instead of Wintun's 0xFFFF default.
    row.NlMtu = mtu;
    // The tunnel is authoritative for its addresses: disable IPv6 router
    // discovery (no RA/SLAAC autoconfig on the tun) and duplicate address
    // detection (nothing else owns the ULA).
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    row.DadTransmits = 0;
    // See the IPv4 metric setter: Windows rejects a written-back SitePrefixLength.
    row.SitePrefixLength = 0;
    let error = unsafe { SetIpInterfaceEntry(&mut row) };
    win32_success_or_error(
        error,
        format!("failed to set Wintun IPv6 interface settings on interface {interface_index}"),
    )
}

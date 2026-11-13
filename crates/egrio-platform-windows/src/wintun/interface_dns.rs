//! The DNS servers of the tunnel adapter, and of any interface by its
//! index.

use super::*;

/// Observes the interface DNS servers Egrio set on the Wintun adapter. The
/// Wintun adapter is entirely Egrio-owned, so any interface DNS on it
/// is ours; a non-empty result is the reconciler's observed DNS resource for the
/// adapter, and the servers let a caller detect drift from the configured
/// virtual resolver. Read-only. Empty when the adapter is absent — Windows drops
/// an interface's DNS settings together with the interface.
pub fn windows_wintun_observe_capture_dns_servers(
    config: &WindowsWintunConfig,
) -> Result<Vec<IpAddr>, String> {
    let wintun = load_wintun(config)?;
    let adapter = match open_wintun_adapter_if_present(&wintun, &config.adapter_name)? {
        Some(adapter) => adapter,
        None => return Ok(Vec::new()),
    };
    // `read_…` keys the interface by the canonical GUID it resolves from this
    // index (byte-order-safe — the Wintun crate's `get_guid()` does not
    // round-trip through `GUID::from_u128`).
    let interface_index = adapter
        .get_adapter_index()
        .map_err(|error| error.to_string())?;
    read_interface_dns_servers(interface_index)
}

pub fn apply_windows_runtime_dns(
    config: &WindowsWintunConfig,
    settings: &egrio_runtime::DnsSettings,
) -> Result<Vec<IpAddr>, String> {
    if !settings.search_domains.is_empty() {
        return Err("Windows runtime DNS search domains are not implemented".into());
    }
    if settings.servers.is_empty() {
        return Err("Windows runtime DNS requires at least one server".into());
    }
    let interface_index = windows_wintun_adapter_index(config)?;
    let mut configured = set_windows_wintun_dns_servers(interface_index, &settings.servers)?;
    configured.sort();
    configured.dedup();
    let mut observed = windows_wintun_observe_capture_dns_servers(config)?;
    observed.sort();
    observed.dedup();
    if observed != configured {
        return Err(format!(
            "Windows runtime DNS observation did not match the applied servers: configured={configured:?}, observed={observed:?}"
        ));
    }
    Ok(observed)
}

pub fn restore_windows_runtime_dns(
    config: &WindowsWintunConfig,
    baseline_servers: &[IpAddr],
) -> Result<Vec<IpAddr>, String> {
    let mut expected = baseline_servers.to_vec();
    expected.sort();
    expected.dedup();
    // Adapter gone (desktop crash) → its interface DNS went with it; the
    // baseline is what remains, so report it restored.
    let Some(interface_index) = windows_wintun_adapter_index_if_present(config)? else {
        return Ok(expected);
    };
    set_windows_wintun_dns_servers(interface_index, &expected)?;
    let mut observed = windows_wintun_observe_capture_dns_servers(config)?;
    observed.sort();
    observed.dedup();
    if observed != expected {
        return Err(format!(
            "Windows runtime DNS did not restore to the checkpoint baseline: expected={expected:?}, observed={observed:?}"
        ));
    }
    Ok(observed)
}

/// Resolves an interface's canonical GUID from its index via the IP Helper
/// `ConvertInterfaceIndexToLuid` → `ConvertInterfaceLuidToGuid` chain — the
/// byte-order-safe identity `SetInterfaceDnsSettings` expects.
fn interface_guid_from_index(interface_index: u32) -> Result<GUID, String> {
    let mut luid = NET_LUID_LH { Value: 0 };
    let status = unsafe { ConvertInterfaceIndexToLuid(interface_index, &mut luid) };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "failed to resolve interface LUID for index {interface_index}: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    let mut guid = GUID::from_u128(0);
    let status = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "failed to resolve interface GUID for index {interface_index}: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    Ok(guid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsDnsAddressFamily {
    Ipv4,
    Ipv6,
}

pub(super) const WINDOWS_EMPTY_IPV6_DNS_PLACEHOLDERS: [Ipv6Addr; 3] = [
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1),
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2),
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3),
];

pub(super) fn windows_dns_family_updates(
    dns_servers: &[IpAddr],
) -> [(WindowsDnsAddressFamily, Vec<IpAddr>); 2] {
    [
        (
            WindowsDnsAddressFamily::Ipv4,
            dns_servers
                .iter()
                .copied()
                .filter(IpAddr::is_ipv4)
                .collect(),
        ),
        (
            WindowsDnsAddressFamily::Ipv6,
            dns_servers
                .iter()
                .copied()
                .filter(IpAddr::is_ipv6)
                .collect(),
        ),
    ]
}

pub(super) fn windows_dns_settings_flags(family: WindowsDnsAddressFamily) -> u64 {
    let flags = match family {
        WindowsDnsAddressFamily::Ipv4 => DNS_SETTING_NAMESERVER,
        WindowsDnsAddressFamily::Ipv6 => DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6,
    };
    u64::from(flags)
}

/// Configures both Wintun DNS address families through VERSION1 and returns the
/// complete applied list. Empty family lists are still sent so applying or
/// restoring one family cannot leave stale NameServer state in the other.
fn set_windows_wintun_dns_servers(
    interface_index: u32,
    dns_servers: &[IpAddr],
) -> Result<Vec<IpAddr>, String> {
    let interface_guid = interface_guid_from_index(interface_index)?;
    let mut configured = Vec::new();
    let mut errors = Vec::new();
    for (family, family_servers) in windows_dns_family_updates(dns_servers) {
        match set_windows_wintun_dns_servers_for_family(interface_guid, family, &family_servers) {
            Ok(()) => configured.extend(family_servers),
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(configured)
    } else {
        Err(errors.join("; "))
    }
}

fn set_windows_wintun_dns_servers_for_family(
    interface_guid: GUID,
    family: WindowsDnsAddressFamily,
    dns_servers: &[IpAddr],
) -> Result<(), String> {
    let mut name_servers = windows_dns_name_server_string(dns_servers);
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: windows_dns_settings_flags(family),
        NameServer: name_servers.as_mut_ptr(),
        Domain: ptr::null_mut(),
        SearchList: ptr::null_mut(),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: ptr::null_mut(),
    };
    let error = unsafe { SetInterfaceDnsSettings(interface_guid, &settings) };
    let family_name = match family {
        WindowsDnsAddressFamily::Ipv4 => "IPv4",
        WindowsDnsAddressFamily::Ipv6 => "IPv6",
    };
    win32_success_or_error(
        error,
        format!("failed to configure Wintun {family_name} DNS servers"),
    )
}

pub(super) fn windows_dns_name_server_string(dns_servers: &[IpAddr]) -> Vec<u16> {
    dns_servers
        .iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// Reads one interface's complete IPv4/IPv6 DNS server chain through
/// `GetAdaptersAddresses` and `FirstDnsServerAddress`. Windows can expose the
/// legacy `fec0:...` trio when IPv6 DNS is empty; those placeholders are
/// omitted, so the Wintun observation compares cleanly with the transaction
/// and the physical uplink yields only real resolvers.
pub(crate) fn read_interface_dns_servers(interface_index: u32) -> Result<Vec<IpAddr>, String> {
    let mut size = 0u32;
    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
    let error = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            ptr::null(),
            ptr::null_mut(),
            &mut size,
        )
    };
    if error != ERROR_BUFFER_OVERFLOW {
        return Err(format!(
            "failed to size Windows adapter DNS observation: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }
    for _ in 0..3 {
        let words = (size as usize).div_ceil(mem::size_of::<usize>());
        let mut buffer = vec![0usize; words.max(1)];
        let error = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if error == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if error != ERROR_SUCCESS {
            return Err(format!(
                "failed to read Windows adapter DNS servers: {}",
                std::io::Error::from_raw_os_error(error as i32)
            ));
        }
        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            let current = unsafe { &*adapter };
            let ipv4_index = unsafe { current.Anonymous1.Anonymous.IfIndex };
            if ipv4_index == interface_index || current.Ipv6IfIndex == interface_index {
                let mut servers = dns_server_addresses(current.FirstDnsServerAddress);
                servers.sort();
                servers.dedup();
                return Ok(servers);
            }
            adapter = current.Next;
        }
        return Ok(Vec::new());
    }
    Err("Windows adapter list changed repeatedly during DNS observation".into())
}

pub(super) fn dns_server_addresses(
    mut current: *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    while !current.is_null() {
        let entry = unsafe { &*current };
        if let Some(address) = socket_address_ip(entry.Address) {
            if !matches!(
                address,
                IpAddr::V6(address) if WINDOWS_EMPTY_IPV6_DNS_PLACEHOLDERS.contains(&address)
            ) {
                servers.push(address);
            }
        }
        current = entry.Next;
    }
    servers
}

fn socket_address_ip(address: SOCKET_ADDRESS) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() {
        return None;
    }
    let family = unsafe { (*address.lpSockaddr).sa_family };
    if family == AF_INET {
        let address = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN>() };
        return Some(IpAddr::V4(windows_addr_to_ipv4(unsafe {
            address.sin_addr.S_un.S_addr
        })));
    }
    if family == AF_INET6 {
        let address = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN6>() };
        return Some(IpAddr::V6(Ipv6Addr::from(unsafe {
            address.sin6_addr.u.Byte
        })));
    }
    None
}

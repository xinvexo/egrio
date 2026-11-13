//! The physical uplink: the host's route tables, its interfaces' metadata
//! and addresses, and which interface carries traffic that leaves the
//! machine.

use super::*;

/// The physical interface index that currently reaches one destination: the
/// longest-prefix, lowest-effective-metric route over an up interface with a
/// hardware address and a real NIC type. `exclude_ifindex` drops our own Wintun
/// from the candidates by index, which is what makes the result correct even
/// after the tunnel has installed its `/1` capture routes — the deterministic
/// loop protection [`network_state::WindowsNetworkState`] relies on to recompute
/// the underlying uplink live. Reads the live route table on each call.
pub(crate) fn physical_egress_interface_index(
    target: IpAddr,
    exclude_ifindex: Option<u32>,
) -> Result<u32, String> {
    match target {
        IpAddr::V4(v4) => {
            let routes = windows_ipv4_route_table()?;
            let interfaces = windows_interface_metadata_for_routes(&routes)?;
            select_best_physical_route_for_ipv4(v4, &routes, &interfaces, exclude_ifindex)
                .map(|route| route.interface_index)
                .ok_or_else(|| {
                    format!(
                        "no usable physical Windows egress route found for {v4} (need an up interface with a hardware address)"
                    )
                })
        }
        IpAddr::V6(v6) => select_physical_egress_interface_index_v6(v6, exclude_ifindex),
    }
}

fn select_physical_egress_interface_index_v6(
    target: Ipv6Addr,
    exclude_ifindex: Option<u32>,
) -> Result<u32, String> {
    let routes = windows_ipv6_route_table()?;
    let mut metadata_cache: BTreeMap<u32, Option<(WindowsInterfaceMetadata, u32)>> =
        BTreeMap::new();
    let mut candidates = Vec::new();
    for route in &routes {
        if !ipv6_prefix_matches(target, route.destination, route.prefix_length) {
            continue;
        }
        // Same deterministic loop protection as the IPv4 selector: never pick
        // our own Wintun, so the underlying stays recomputable post-hijack.
        if exclude_ifindex == Some(route.interface_index) {
            continue;
        }
        let entry = metadata_cache
            .entry(route.interface_index)
            .or_insert_with(|| ipv6_candidate_interface(route.interface_index));
        let Some((metadata, interface_metric)) = entry else {
            continue;
        };
        if !usable_physical_egress_interface(metadata) {
            continue;
        }
        candidates.push((
            route.prefix_length,
            route.metric.saturating_add(*interface_metric),
            route.interface_index,
        ));
    }
    candidates.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    candidates.first().map(|candidate| candidate.2).ok_or_else(|| {
        format!(
            "no usable physical Windows IPv6 egress route found for {target} (need an up interface with a hardware address)"
        )
    })
}

/// Interface metadata plus the AF_INET6 interface metric for one v6 route
/// candidate; `None` when either read fails (the interface is skipped, not
/// fatal — other candidates may still serve the dial).
fn ipv6_candidate_interface(interface_index: u32) -> Option<(WindowsInterfaceMetadata, u32)> {
    let metadata = windows_if_row2_metadata(interface_index).ok()?;
    let metric = windows_ipv6_interface_metric(interface_index).ok()?;
    Some((metadata, metric))
}

const ERROR_INSUFFICIENT_BUFFER_CODE: u32 = 122;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WindowsIpv4Route {
    target: Ipv4Addr,
    pub(super) gateway: Ipv4Addr,
    pub(super) interface_index: u32,
}

#[derive(Clone)]
pub(super) struct WindowsIpv4RouteTableEntry {
    pub(super) destination: Ipv4Addr,
    pub(super) netmask: Ipv4Addr,
    pub(super) gateway: Ipv4Addr,
    pub(super) interface_index: u32,
    pub(super) metric: u32,
    pub(super) raw_row: Option<MIB_IPFORWARD_ROW2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WindowsInterfaceMetadata {
    pub(super) interface_index: u32,
    pub(super) alias: String,
    pub(super) description: String,
    pub(super) if_type: u32,
    pub(super) oper_status: i32,
    pub(super) physical_address_length: u32,
    pub(super) ipv4_metric: u32,
    pub(super) automatic_metric: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WindowsIpv4InterfaceAddress {
    pub(super) interface_index: u32,
    pub(super) address: Ipv4Addr,
    pub(super) netmask: Ipv4Addr,
}

pub(super) fn select_best_physical_route_for_ipv4(
    target: Ipv4Addr,
    routes: &[WindowsIpv4RouteTableEntry],
    interfaces: &[WindowsInterfaceMetadata],
    exclude_ifindex: Option<u32>,
) -> Option<WindowsIpv4Route> {
    let interfaces = interfaces
        .iter()
        .map(|interface| (interface.interface_index, interface))
        .collect::<BTreeMap<_, _>>();
    let mut candidates = Vec::new();

    for route in routes {
        if !ipv4_route_matches(target, route) {
            continue;
        }
        // Exclude our own Wintun by its current interface index: this is the
        // deterministic loop protection. Once the tunnel installs its `/1`
        // capture routes they are longer-prefix than the physical `/0`, so
        // without this skip a recompute would resolve our own tunnel. Excluding
        // it by index means the underlying can be recomputed at any time — even
        // after the hijack — and never selects the tunnel, which is what lets a
        // network-change monitor follow a Wi-Fi→Ethernet switch live.
        if exclude_ifindex == Some(route.interface_index) {
            continue;
        }
        let Some(interface) = interfaces.get(&route.interface_index) else {
            continue;
        };
        if !usable_physical_egress_interface(interface) {
            continue;
        }
        let Ok(prefix_length) = ipv4_prefix_length_from_netmask(route.netmask) else {
            continue;
        };
        candidates.push((prefix_length, route));
    }

    candidates.sort_by(|(left_prefix, left), (right_prefix, right)| {
        let left_interface = interfaces
            .get(&left.interface_index)
            .expect("candidate route interface metadata exists");
        let right_interface = interfaces
            .get(&right.interface_index)
            .expect("candidate route interface metadata exists");
        let left_metric = effective_route_metric(left, left_interface);
        let right_metric = effective_route_metric(right, right_interface);
        right_prefix
            .cmp(left_prefix)
            .then_with(|| left_metric.cmp(&right_metric))
            .then_with(|| left.interface_index.cmp(&right.interface_index))
            .then_with(|| left.gateway.cmp(&right.gateway))
    });

    candidates.first().map(|(_, route)| WindowsIpv4Route {
        target,
        gateway: route.gateway,
        interface_index: route.interface_index,
    })
}

fn ipv4_route_matches(target: Ipv4Addr, route: &WindowsIpv4RouteTableEntry) -> bool {
    same_ipv4_subnet(target, route.destination, route.netmask)
}

fn effective_route_metric(
    route: &WindowsIpv4RouteTableEntry,
    interface: &WindowsInterfaceMetadata,
) -> u32 {
    route.metric.saturating_add(interface.ipv4_metric)
}

/// Whether an interface can carry Egrio egress: it is up, has a hardware
/// address, and presents a real NIC type (ethernet/Wi-Fi/WWAN). Judged purely
/// on structure, never on adapter name — a Hyper-V vEthernet adapter is a
/// legitimate physical uplink even though "Virtual" is in its description, and
/// a real TUN/tunnel interface is excluded by its NIC type, not by matching
/// strings. Snapshotting the egress before the tunnel installs its routes is
/// what keeps our own Wintun out of the result, so no name/index exclusion is
/// needed here.
fn usable_physical_egress_interface(interface: &WindowsInterfaceMetadata) -> bool {
    interface.oper_status == IfOperStatusUp
        && interface.physical_address_length > 0
        && physical_egress_interface_type(interface.if_type)
}

/// The non-link-local addresses of the usable physical interfaces (see
/// [`usable_physical_egress_interface`]), each with its interface index; `None`
/// when the address table cannot be read. `GetUnicastIpAddressTable`
/// (netioapi.h) lists every unicast address of every interface.
pub(crate) fn physical_interface_addresses() -> Option<Vec<(u32, IpAddr)>> {
    let mut table = ptr::null_mut::<MIB_UNICASTIPADDRESS_TABLE>();
    if unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) } != ERROR_SUCCESS
        || table.is_null()
    {
        return None;
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut physical = BTreeMap::new();
    let mut addresses = Vec::new();
    for row in rows {
        let address = sockaddr_inet_to_ipv4(row.Address)
            .map(IpAddr::V4)
            .or_else(|| sockaddr_inet_to_ipv6(row.Address).map(IpAddr::V6));
        let Some(address) = address else {
            continue;
        };
        let link_local = match address {
            IpAddr::V4(address) => address.is_link_local(),
            IpAddr::V6(address) => address.is_unicast_link_local(),
        };
        if link_local || address.is_loopback() {
            continue;
        }
        let usable = *physical.entry(row.InterfaceIndex).or_insert_with(|| {
            windows_if_row2_metadata(row.InterfaceIndex)
                .is_ok_and(|interface| usable_physical_egress_interface(&interface))
        });
        if usable {
            addresses.push((row.InterfaceIndex, address));
        }
    }
    unsafe { FreeMibTable(table.cast::<c_void>()) };
    addresses.sort_unstable();
    addresses.dedup();
    Some(addresses)
}

fn physical_egress_interface_type(if_type: u32) -> bool {
    matches!(
        if_type,
        IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211 | IF_TYPE_WWANPP | IF_TYPE_WWANPP2
    )
}

pub(super) fn windows_ipv4_route_table() -> Result<Vec<WindowsIpv4RouteTableEntry>, String> {
    let mut table = ptr::null_mut::<MIB_IPFORWARD_TABLE2>();
    let error = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if error != ERROR_SUCCESS {
        return Err(format!(
            "failed to read Windows IPv4 route table: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }

    if table.is_null() {
        return Ok(Vec::new());
    }

    let routes = unsafe {
        let entry_count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), entry_count);
        rows.iter()
            .filter_map(|row| windows_ipv4_route_table_entry_from_row(*row))
            .collect()
    };
    unsafe {
        FreeMibTable(table.cast::<c_void>());
    }
    Ok(routes)
}

pub(super) fn windows_ipv4_route_table_entry_from_row(
    row: MIB_IPFORWARD_ROW2,
) -> Option<WindowsIpv4RouteTableEntry> {
    let destination = sockaddr_inet_to_ipv4(row.DestinationPrefix.Prefix)?;
    let netmask = ipv4_netmask_from_prefix_length(row.DestinationPrefix.PrefixLength)?;
    let gateway = sockaddr_inet_to_ipv4(row.NextHop)?;
    Some(WindowsIpv4RouteTableEntry {
        destination,
        netmask,
        gateway,
        interface_index: row.InterfaceIndex,
        metric: row.Metric,
        raw_row: Some(row),
    })
}

#[derive(Clone)]
pub(super) struct WindowsIpv6RouteTableEntry {
    pub(super) destination: Ipv6Addr,
    pub(super) prefix_length: u8,
    pub(super) gateway: Ipv6Addr,
    pub(super) interface_index: u32,
    pub(super) metric: u32,
    pub(super) raw_row: Option<MIB_IPFORWARD_ROW2>,
}

pub(super) fn windows_ipv6_route_table() -> Result<Vec<WindowsIpv6RouteTableEntry>, String> {
    let mut table = ptr::null_mut::<MIB_IPFORWARD_TABLE2>();
    let error = unsafe { GetIpForwardTable2(AF_INET6, &mut table) };
    if error != ERROR_SUCCESS {
        return Err(format!(
            "failed to read Windows IPv6 route table: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }

    if table.is_null() {
        return Ok(Vec::new());
    }

    let routes = unsafe {
        let entry_count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), entry_count);
        rows.iter()
            .filter_map(|row| windows_ipv6_route_table_entry_from_row(*row))
            .collect()
    };
    unsafe {
        FreeMibTable(table.cast::<c_void>());
    }
    Ok(routes)
}

pub(super) fn windows_ipv6_route_table_entry_from_row(
    row: MIB_IPFORWARD_ROW2,
) -> Option<WindowsIpv6RouteTableEntry> {
    let destination = sockaddr_inet_to_ipv6(row.DestinationPrefix.Prefix)?;
    let gateway = sockaddr_inet_to_ipv6(row.NextHop)?;
    Some(WindowsIpv6RouteTableEntry {
        destination,
        prefix_length: row.DestinationPrefix.PrefixLength,
        gateway,
        interface_index: row.InterfaceIndex,
        metric: row.Metric,
        raw_row: Some(row),
    })
}

fn sockaddr_inet_to_ipv6(address: SOCKADDR_INET) -> Option<Ipv6Addr> {
    let family = unsafe { address.si_family };
    if family != AF_INET6 {
        return None;
    }
    Some(Ipv6Addr::from(unsafe { address.Ipv6.sin6_addr.u.Byte }))
}

pub(super) fn ipv6_prefix_matches(
    target: Ipv6Addr,
    destination: Ipv6Addr,
    prefix_length: u8,
) -> bool {
    if prefix_length > 128 {
        return false;
    }
    let mask = if prefix_length == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_length))
    };
    (u128::from_be_bytes(target.octets()) & mask)
        == (u128::from_be_bytes(destination.octets()) & mask)
}

fn windows_ipv6_interface_metric(interface_index: u32) -> Result<u32, String> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe {
        InitializeIpInterfaceEntry(&mut row);
    }
    row.Family = AF_INET6;
    row.InterfaceIndex = interface_index;
    let error = unsafe { GetIpInterfaceEntry(&mut row) };
    win32_success_or_error(
        error,
        format!("failed to read Windows IPv6 interface metric for {interface_index}"),
    )?;
    Ok(row.Metric)
}

fn windows_interface_metadata_for_routes(
    routes: &[WindowsIpv4RouteTableEntry],
) -> Result<Vec<WindowsInterfaceMetadata>, String> {
    routes
        .iter()
        .map(|route| route.interface_index)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(windows_interface_metadata)
        .collect()
}

/// Interface identity/type/status from `GetIfEntry2` alone, without any
/// per-family IP interface row; the v6 candidate path uses this so a
/// v6-only interface is not rejected for lacking an IPv4 row.
fn windows_if_row2_metadata(interface_index: u32) -> Result<WindowsInterfaceMetadata, String> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: interface_index,
        ..MIB_IF_ROW2::default()
    };
    let error = unsafe { GetIfEntry2(&mut row) };
    if error != ERROR_SUCCESS {
        return Err(format!(
            "failed to read Windows interface {interface_index}: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }

    Ok(WindowsInterfaceMetadata {
        interface_index,
        alias: wide_null_string(&row.Alias),
        description: wide_null_string(&row.Description),
        if_type: row.Type,
        oper_status: row.OperStatus,
        physical_address_length: row.PhysicalAddressLength,
        ipv4_metric: 0,
        automatic_metric: false,
    })
}

fn windows_interface_metadata(interface_index: u32) -> Result<WindowsInterfaceMetadata, String> {
    let mut metadata = windows_if_row2_metadata(interface_index)?;
    let ip_interface = windows_ipv4_interface_row(interface_index)?;
    metadata.ipv4_metric = ip_interface.Metric;
    metadata.automatic_metric = ip_interface.UseAutomaticMetric;
    Ok(metadata)
}

fn windows_ipv4_interface_row(interface_index: u32) -> Result<MIB_IPINTERFACE_ROW, String> {
    let mut row = initialized_ip_interface_row(interface_index);
    let error = unsafe { GetIpInterfaceEntry(&mut row) };
    if error != ERROR_SUCCESS {
        return Err(format!(
            "failed to read Windows IPv4 interface metric for {interface_index}: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }
    Ok(row)
}

fn wide_null_string(value: &[u16]) -> String {
    let len = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..len])
}

pub(super) fn windows_ipv4_interface_addresses() -> Result<Vec<WindowsIpv4InterfaceAddress>, String>
{
    let mut size = 0u32;
    let error = unsafe { GetIpAddrTable(ptr::null_mut(), &mut size, 0) };
    if error != 0 && error != ERROR_INSUFFICIENT_BUFFER_CODE {
        return Err(format!(
            "failed to size Windows IPv4 interface table: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }
    if size == 0 {
        size = mem::size_of::<MIB_IPADDRTABLE>() as u32;
    }

    loop {
        let word_count = (size as usize).div_ceil(mem::size_of::<usize>());
        let mut buffer = vec![0usize; word_count];
        let table = buffer.as_mut_ptr() as *mut MIB_IPADDRTABLE;
        let error = unsafe { GetIpAddrTable(table, &mut size, 0) };
        if error == ERROR_INSUFFICIENT_BUFFER_CODE {
            continue;
        }
        if error != 0 {
            return Err(format!(
                "failed to read Windows IPv4 interface table: {}",
                std::io::Error::from_raw_os_error(error as i32)
            ));
        }

        let entry_count = unsafe { (*table).dwNumEntries as usize };
        let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), entry_count) };
        return Ok(rows
            .iter()
            .map(|row| WindowsIpv4InterfaceAddress {
                interface_index: row.dwIndex,
                address: windows_addr_to_ipv4(row.dwAddr),
                netmask: windows_addr_to_ipv4(row.dwMask),
            })
            .collect());
    }
}

pub(super) fn ipv4_prefix_length_from_netmask(netmask: Ipv4Addr) -> Result<u8, String> {
    let bits = u32::from(netmask);
    let prefix_length = bits.count_ones();
    let expected = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    };
    if bits != expected {
        return Err(format!("invalid non-contiguous IPv4 netmask {netmask}"));
    }

    u8::try_from(prefix_length)
        .map_err(|_| format!("invalid IPv4 netmask prefix length {prefix_length}"))
}

fn same_ipv4_subnet(left: Ipv4Addr, right: Ipv4Addr, netmask: Ipv4Addr) -> bool {
    u32::from(left) & u32::from(netmask) == u32::from(right) & u32::from(netmask)
}

pub(super) fn ipv4_to_windows_addr(address: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(address.octets())
}

pub(super) fn windows_addr_to_ipv4(address: u32) -> Ipv4Addr {
    Ipv4Addr::from(address.to_ne_bytes())
}

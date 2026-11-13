//! The capture routes on the tunnel adapter: what Egrio owns in the host's
//! route tables, and bringing that to what a session's settings ask for.

use super::*;

/// Observes the Egrio-owned capture routes currently in the host route table.
/// Enumerates the IPv4 and IPv6 route tables and keeps the routes
/// that both point at the Egrio Wintun adapter and carry the
/// `MIB_IPPROTO_NETMGMT`/`NlroManual` ownership stamp Egrio writes on every
/// capture route it installs; the keys are the reconciler's observed route
/// resource set, formatted as canonical CIDRs so they diff exactly against the
/// desired set built from the capture-route structs.
///
/// Read-only — opens the adapter to resolve its interface index but installs
/// nothing. When the adapter is absent the result is empty: Windows drops an
/// interface's routes together with the interface, so no Egrio route outlives it.
pub fn windows_wintun_observe_capture_route_keys(
    config: &WindowsWintunConfig,
) -> Result<Vec<String>, String> {
    let wintun = load_wintun(config)?;
    let adapter_index = match open_wintun_adapter_if_present(&wintun, &config.adapter_name)? {
        Some(adapter) => adapter
            .get_adapter_index()
            .map_err(|error| error.to_string())?,
        None => return Ok(Vec::new()),
    };

    let v4 = windows_ipv4_route_table()?;
    let v6 = windows_ipv6_route_table()?;
    Ok(egrio_owned_capture_route_keys(adapter_index, &v4, &v6))
}

pub fn windows_wintun_adapter_index(config: &WindowsWintunConfig) -> Result<u32, String> {
    let wintun = load_wintun(config)?;
    let adapter = open_wintun_adapter_if_present(&wintun, &config.adapter_name)?
        .ok_or_else(|| format!("Wintun adapter '{}' is not prepared", config.adapter_name))?;
    adapter
        .get_adapter_index()
        .map_err(|error| error.to_string())
}

/// The adapter index when the Wintun adapter is present, `None` when it is
/// absent. Interface-scoped route and DNS state die with the adapter, so a
/// restore after a desktop crash — which closed the packet session and its
/// adapter — treats "adapter absent" as "already restored" instead of a
/// hard open failure. The capture-gated egress binder reads the same
/// distinction: absent means "nothing to loop into", not a fault.
pub(crate) fn windows_wintun_adapter_index_if_present(
    config: &WindowsWintunConfig,
) -> Result<Option<u32>, String> {
    let wintun = load_wintun(config)?;
    match open_wintun_adapter_if_present(&wintun, &config.adapter_name)? {
        Some(adapter) => adapter
            .get_adapter_index()
            .map(Some)
            .map_err(|error| error.to_string()),
        None => Ok(None),
    }
}

/// Installs the capture routes: the IPv4 `/2` quarters and, when IPv6
/// tunnels, the IPv6 `/1` halves, each split around the excluded prefixes so
/// that excluded destinations keep the routes the system had.
pub fn apply_windows_runtime_routes(
    config: &WindowsWintunConfig,
    settings: &egrio_runtime::RouteSettings,
) -> Result<Vec<String>, String> {
    if !settings.default_route {
        return Ok(windows_wintun_observe_capture_route_keys(config)?);
    }
    let interface_index = windows_wintun_adapter_index(config)?;
    let excluded = &settings.excluded_prefixes;
    let routes =
        windows_wintun_ipv4_capture_routes(interface_index, config.route_metric, excluded)?;
    let routes6 = if resolve_windows_ipv6_mode(config).tunnels_v6() {
        windows_wintun_ipv6_capture_routes(interface_index, config.route_metric, excluded)?
    } else {
        Vec::new()
    };
    reconcile_capture_routes(interface_index, &routes, &routes6)?;
    let observed = windows_wintun_observe_capture_route_keys(config)?;
    let missing = routes
        .iter()
        .map(WindowsWintunRoute::cidr_key)
        .chain(routes6.iter().map(WindowsWintunRoute6::cidr_key))
        .filter(|key| observed.binary_search(key).is_err())
        .count();
    if missing > 0 {
        return Err(format!(
            "{missing} Wintun capture routes are missing from the route table after install"
        ));
    }
    Ok(observed)
}

pub fn restore_windows_runtime_routes(
    config: &WindowsWintunConfig,
    baseline_keys: &[String],
) -> Result<Vec<String>, String> {
    let mut baseline_sorted = baseline_keys.to_vec();
    baseline_sorted.sort();
    baseline_sorted.dedup();
    // Adapter gone (desktop crash) → its capture routes went with it; the
    // baseline is what remains, so report it restored.
    let Some(interface_index) = windows_wintun_adapter_index_if_present(config)? else {
        return Ok(baseline_sorted);
    };
    let baseline = baseline_keys.iter().cloned().collect::<BTreeSet<_>>();
    // The baseline is whatever capture routes the adapter had before the
    // change: none for a start, the previous split for an in-place update.
    let mut routes = Vec::new();
    let mut routes6 = Vec::new();
    for key in &baseline {
        let prefix = key
            .parse::<egrio_runtime::IpPrefix>()
            .map_err(|error| format!("route checkpoint holds an invalid key: {error}"))?;
        match prefix.address {
            IpAddr::V4(destination) => routes.push(WindowsWintunRoute {
                destination,
                netmask: Ipv4Addr::from(
                    u32::MAX
                        .checked_shl(32 - u32::from(prefix.prefix_len))
                        .unwrap_or(0),
                ),
                gateway: Ipv4Addr::UNSPECIFIED,
                interface_index,
                metric: config.route_metric,
            }),
            IpAddr::V6(destination) => routes6.push(WindowsWintunRoute6 {
                destination,
                prefix_length: prefix.prefix_len,
                gateway: Ipv6Addr::UNSPECIFIED,
                interface_index,
                metric: config.route_metric,
            }),
        }
    }
    reconcile_capture_routes(interface_index, &routes, &routes6)?;
    let observed = windows_wintun_observe_capture_route_keys(config)?;
    if observed.iter().cloned().collect::<BTreeSet<_>>() != baseline {
        return Err("Windows runtime routes did not restore to the checkpoint baseline".into());
    }
    Ok(observed)
}

/// Brings the adapter's Egrio-owned routes to exactly `routes` and
/// `routes6`: adds the missing ones first, so a destination that stays
/// captured is never left without a route, then removes the rest. An
/// in-place update therefore never routes a still-captured destination past
/// the TUN.
fn reconcile_capture_routes(
    adapter_index: u32,
    routes: &[WindowsWintunRoute],
    routes6: &[WindowsWintunRoute6],
) -> Result<(), String> {
    let present = egrio_owned_capture_route_keys(
        adapter_index,
        &windows_ipv4_route_table()?,
        &windows_ipv6_route_table()?,
    )
    .into_iter()
    .collect::<BTreeSet<_>>();
    let missing = routes
        .iter()
        .filter(|route| !present.contains(&route.cidr_key()))
        .cloned()
        .collect::<Vec<_>>();
    let missing6 = routes6
        .iter()
        .filter(|route| !present.contains(&route.cidr_key()))
        .cloned()
        .collect::<Vec<_>>();
    let added = add_routes(&missing)?;
    if let Err(error) = add_routes6(&missing6) {
        let cleanup = remove_routes(&added);
        return Err(format!(
            "{error}{}",
            cleanup_error_suffix(&cleanup.errors, &[])
        ));
    }
    let keep = routes
        .iter()
        .map(WindowsWintunRoute::cidr_key)
        .chain(routes6.iter().map(WindowsWintunRoute6::cidr_key))
        .collect::<BTreeSet<_>>();
    let errors = remove_owned_routes_except(adapter_index, &keep);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Deletes the Egrio-owned routes on the adapter whose keys are not in
/// `keep`, reading each family's route table once.
fn remove_owned_routes_except(adapter_index: u32, keep: &BTreeSet<String>) -> Vec<String> {
    let mut errors = Vec::new();
    let delete = |row: &MIB_IPFORWARD_ROW2, key: &str| {
        let error = unsafe { DeleteIpForwardEntry2(row) };
        (error != ERROR_SUCCESS && error != ERROR_NOT_FOUND).then(|| {
            format!(
                "failed to delete Wintun route {key}: {}",
                std::io::Error::from_raw_os_error(error as i32)
            )
        })
    };
    match windows_ipv4_route_table() {
        Ok(table) => {
            for entry in table.iter().filter(|entry| {
                entry.interface_index == adapter_index
                    && windows_ipv4_route_entry_is_egrio_owned(entry)
            }) {
                let (Ok(prefix_length), Some(row)) = (
                    ipv4_prefix_length_from_netmask(entry.netmask),
                    entry.raw_row.as_ref(),
                ) else {
                    continue;
                };
                let key =
                    windows_wintun_route_cidr_key(IpAddr::V4(entry.destination), prefix_length);
                if !keep.contains(&key) {
                    errors.extend(delete(row, &key));
                }
            }
        }
        Err(error) => errors.push(error),
    }
    match windows_ipv6_route_table() {
        Ok(table) => {
            for entry in table.iter().filter(|entry| {
                entry.interface_index == adapter_index
                    && windows_ipv6_route_entry_is_egrio_owned(entry)
            }) {
                let Some(row) = entry.raw_row.as_ref() else {
                    continue;
                };
                let key = windows_wintun_route_cidr_key(
                    IpAddr::V6(entry.destination),
                    entry.prefix_length,
                );
                if !keep.contains(&key) {
                    errors.extend(delete(row, &key));
                }
            }
        }
        Err(error) => errors.push(error),
    }
    errors
}

/// The pure ownership filter behind [`windows_wintun_observe_capture_route_keys`]:
/// a route is Egrio-owned iff it points at the Egrio adapter and Egrio installed
/// it (`MIB_IPPROTO_NETMGMT`/`NlroManual`), which excludes the on-link,
/// multicast, and broadcast routes Windows auto-creates on the same interface
/// with other ownership stamps. Keys are deduplicated and sorted so the
/// observed set is order-stable.
pub(super) fn egrio_owned_capture_route_keys(
    adapter_index: u32,
    v4: &[WindowsIpv4RouteTableEntry],
    v6: &[WindowsIpv6RouteTableEntry],
) -> Vec<String> {
    let mut keys = Vec::new();
    for entry in v4 {
        if entry.interface_index != adapter_index {
            continue;
        }
        if !windows_ipv4_route_entry_is_egrio_owned(entry) {
            continue;
        }
        let Ok(prefix_length) = ipv4_prefix_length_from_netmask(entry.netmask) else {
            continue;
        };
        keys.push(windows_wintun_route_cidr_key(
            IpAddr::V4(entry.destination),
            prefix_length,
        ));
    }
    for entry in v6 {
        if entry.interface_index != adapter_index || !windows_ipv6_route_entry_is_egrio_owned(entry)
        {
            continue;
        }
        keys.push(windows_wintun_route_cidr_key(
            IpAddr::V6(entry.destination),
            entry.prefix_length,
        ));
    }
    keys.sort();
    keys.dedup();
    keys
}

fn add_routes(routes: &[WindowsWintunRoute]) -> Result<Vec<WindowsWintunRoute>, String> {
    let mut added = Vec::new();
    for route in routes {
        if let Err(error) = create_windows_wintun_route(route) {
            let cleanup = remove_routes(&added);
            let cleanup_message = cleanup_error_suffix(&cleanup.errors, &[]);
            return Err(format!(
                "failed to add Wintun route {}: {error}{cleanup_message}",
                format_route(route)
            ));
        }
        added.push(route.clone());
    }
    Ok(added)
}

fn remove_routes(routes: &[WindowsWintunRoute]) -> WindowsWintunRouteRestoreReport {
    let mut report = WindowsWintunRouteRestoreReport::default();
    for route in routes {
        match delete_windows_wintun_route(route) {
            Ok(deleted) => {
                if deleted {
                    report.routes_removed.push(route.clone());
                }
            }
            Err(error) => report.errors.push(error),
        }
    }
    report
}

fn create_windows_wintun_route(route: &WindowsWintunRoute) -> Result<(), String> {
    let row = ip_forward_row_from_wintun_route(route)?;
    let error = unsafe { CreateIpForwardEntry2(&row) };
    match error {
        ERROR_SUCCESS | ERROR_ALREADY_EXISTS | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        error => Err(format!(
            "{}",
            std::io::Error::from_raw_os_error(error as i32)
        )),
    }
}

fn delete_windows_wintun_route(route: &WindowsWintunRoute) -> Result<bool, String> {
    let route_table = windows_ipv4_route_table()?;
    let matching_entries = route_table
        .iter()
        .filter(|entry| windows_route_table_entry_matches_wintun_route(entry, route))
        .collect::<Vec<_>>();
    if matching_entries.is_empty() {
        return Ok(false);
    }

    let mut deleted = false;
    for entry in &matching_entries {
        let row = ip_forward_row_from_route_table_entry(entry)?;
        let error = unsafe { DeleteIpForwardEntry2(&row) };
        match error {
            ERROR_SUCCESS => deleted = true,
            ERROR_NOT_FOUND => {}
            error => {
                return Err(format!(
                    "failed to delete Wintun route {}: {}",
                    format_route(route),
                    std::io::Error::from_raw_os_error(error as i32)
                ));
            }
        }
    }
    if windows_ipv4_route_table()?
        .iter()
        .any(|entry| windows_route_table_entry_matches_wintun_route(entry, route))
    {
        return Err(format!(
            "failed to delete Wintun route {}; route is still present after native delete",
            format_route(route)
        ));
    }
    Ok(deleted || !matching_entries.is_empty())
}

pub(super) fn windows_route_table_entry_matches_wintun_route(
    entry: &WindowsIpv4RouteTableEntry,
    route: &WindowsWintunRoute,
) -> bool {
    windows_ipv4_route_entry_is_egrio_owned(entry)
        && entry.destination == route.destination
        && entry.netmask == route.netmask
        && route_table_gateway_matches_wintun_route(entry.gateway, route.gateway)
        && entry.interface_index == route.interface_index
}

fn route_table_gateway_matches_wintun_route(
    route_table_gateway: Ipv4Addr,
    configured_gateway: Ipv4Addr,
) -> bool {
    configured_gateway.is_unspecified() || route_table_gateway == configured_gateway
}

fn windows_ipv4_route_entry_is_egrio_owned(entry: &WindowsIpv4RouteTableEntry) -> bool {
    entry
        .raw_row
        .as_ref()
        .is_some_and(|row| row.Protocol == MIB_IPPROTO_NETMGMT && row.Origin == NlroManual)
}

fn windows_ipv6_route_entry_is_egrio_owned(entry: &WindowsIpv6RouteTableEntry) -> bool {
    entry
        .raw_row
        .as_ref()
        .is_some_and(|row| row.Protocol == MIB_IPPROTO_NETMGMT && row.Origin == NlroManual)
}

pub(super) fn ip_forward_row_from_wintun_route(
    route: &WindowsWintunRoute,
) -> Result<MIB_IPFORWARD_ROW2, String> {
    let prefix_length = ipv4_prefix_length_from_netmask(route.netmask)?;
    Ok(ip_forward_row(
        route.destination,
        prefix_length,
        route.gateway,
        route.interface_index,
        route.metric,
    ))
}

fn ip_forward_row_from_route_table_entry(
    entry: &WindowsIpv4RouteTableEntry,
) -> Result<MIB_IPFORWARD_ROW2, String> {
    if let Some(row) = entry.raw_row {
        return Ok(row);
    }

    let prefix_length = ipv4_prefix_length_from_netmask(entry.netmask)?;
    Ok(ip_forward_row(
        entry.destination,
        prefix_length,
        entry.gateway,
        entry.interface_index,
        entry.metric,
    ))
}

pub(super) fn ip_forward_row(
    destination: Ipv4Addr,
    prefix_length: u8,
    gateway: Ipv4Addr,
    interface_index: u32,
    metric: u32,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }
    row.InterfaceIndex = interface_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_inet_ipv4(destination),
        PrefixLength: prefix_length,
    };
    row.NextHop = sockaddr_inet_ipv4(gateway);
    row.SitePrefixLength = prefix_length;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Immortal = true;
    row.Origin = NlroManual;
    row
}

pub(super) fn ip_forward_row6(
    destination: Ipv6Addr,
    prefix_length: u8,
    gateway: Ipv6Addr,
    interface_index: u32,
    metric: u32,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }
    row.InterfaceIndex = interface_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_inet_ipv6(destination),
        PrefixLength: prefix_length,
    };
    row.NextHop = sockaddr_inet_ipv6(gateway);
    row.SitePrefixLength = prefix_length;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Immortal = true;
    row.Origin = NlroManual;
    row
}

pub(super) fn ip_forward_row_from_wintun_route6(route: &WindowsWintunRoute6) -> MIB_IPFORWARD_ROW2 {
    ip_forward_row6(
        route.destination,
        route.prefix_length,
        route.gateway,
        route.interface_index,
        route.metric,
    )
}

fn create_windows_wintun_route6(route: &WindowsWintunRoute6) -> Result<(), String> {
    let row = ip_forward_row_from_wintun_route6(route);
    let error = unsafe { CreateIpForwardEntry2(&row) };
    match error {
        ERROR_SUCCESS | ERROR_ALREADY_EXISTS | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        error => Err(format!(
            "{}",
            std::io::Error::from_raw_os_error(error as i32)
        )),
    }
}

fn delete_windows_wintun_route6(route: &WindowsWintunRoute6) -> Result<bool, String> {
    let route_table = windows_ipv6_route_table()?;
    let matching_entries = route_table
        .iter()
        .filter(|entry| windows_ipv6_route_table_entry_matches_wintun_route(entry, route))
        .collect::<Vec<_>>();
    if matching_entries.is_empty() {
        return Ok(false);
    }

    let mut deleted = false;
    for entry in &matching_entries {
        let row = entry.raw_row.ok_or_else(|| {
            format!(
                "refusing to delete Wintun IPv6 route {}/{} without its native route row",
                route.destination, route.prefix_length
            )
        })?;
        let error = unsafe { DeleteIpForwardEntry2(&row) };
        match error {
            ERROR_SUCCESS => deleted = true,
            ERROR_NOT_FOUND => {}
            error => {
                return Err(format!(
                    "failed to delete Wintun IPv6 route {}/{}: {}",
                    route.destination,
                    route.prefix_length,
                    std::io::Error::from_raw_os_error(error as i32)
                ));
            }
        }
    }
    if windows_ipv6_route_table()?
        .iter()
        .any(|entry| windows_ipv6_route_table_entry_matches_wintun_route(entry, route))
    {
        return Err(format!(
            "failed to delete Wintun IPv6 route {}/{}; route is still present after native delete",
            route.destination, route.prefix_length
        ));
    }
    Ok(deleted || !matching_entries.is_empty())
}

pub(super) fn windows_ipv6_route_table_entry_matches_wintun_route(
    entry: &WindowsIpv6RouteTableEntry,
    route: &WindowsWintunRoute6,
) -> bool {
    windows_ipv6_route_entry_is_egrio_owned(entry)
        && entry.destination == route.destination
        && entry.prefix_length == route.prefix_length
        && (route.gateway.is_unspecified() || entry.gateway == route.gateway)
        && entry.interface_index == route.interface_index
}

fn add_routes6(routes: &[WindowsWintunRoute6]) -> Result<Vec<WindowsWintunRoute6>, String> {
    let mut added = Vec::new();
    for route in routes {
        if let Err(error) = create_windows_wintun_route6(route) {
            let cleanup = remove_routes6(&added);
            let cleanup_message = cleanup_error_suffix(&cleanup.errors, &[]);
            return Err(format!(
                "failed to add Wintun IPv6 route {}/{}: {error}{cleanup_message}",
                route.destination, route.prefix_length
            ));
        }
        added.push(route.clone());
    }
    Ok(added)
}

fn remove_routes6(routes: &[WindowsWintunRoute6]) -> WindowsWintunRouteRestoreReport {
    let mut report = WindowsWintunRouteRestoreReport::default();
    for route in routes {
        match delete_windows_wintun_route6(route) {
            Ok(_) => {}
            Err(error) => report.errors.push(error),
        }
    }
    report
}

pub(super) fn cleanup_error_suffix(route_errors: &[String], dns_errors: &[String]) -> String {
    let mut errors = Vec::new();
    errors.extend(route_errors.iter().map(|error| format!("route: {error}")));
    errors.extend(dns_errors.iter().map(|error| format!("dns: {error}")));

    if errors.is_empty() {
        String::new()
    } else {
        format!("; cleanup errors: {}", errors.join("; "))
    }
}

fn format_route(route: &WindowsWintunRoute) -> String {
    format!(
        "{} mask {} gateway {} if {} metric {}",
        route.destination, route.netmask, route.gateway, route.interface_index, route.metric
    )
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use egrio_runtime::{family_capture_prefixes, IpPrefix};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsWintunRoute {
    pub destination: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub interface_index: u32,
    pub metric: u32,
}

/// IPv6 capture route. Kept separate from the IPv4
/// [`WindowsWintunRoute`] rather than generalized to `IpAddr`; the two families
/// meet only at the family-neutral IP Helper row (`MIB_IPFORWARD_ROW2`). A `::`
/// gateway means an on-link route on the Wintun interface, exactly like a
/// `0.0.0.0` gateway does for IPv4.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsWintunRoute6 {
    pub destination: Ipv6Addr,
    pub prefix_length: u8,
    pub gateway: Ipv6Addr,
    pub interface_index: u32,
    pub metric: u32,
}

/// The canonical CIDR key (`destination/prefix-length`) identifying a capture
/// route in the reconciler's desired and observed resource sets.
/// The desired keys come from the capture-route structs below via [`WindowsWintunRoute::cidr_key`]
/// / [`WindowsWintunRoute6::cidr_key`], and the observed keys come from the IP
/// Helper route table; both format through here so the reconciler diff is exact.
pub fn windows_wintun_route_cidr_key(destination: IpAddr, prefix_length: u8) -> String {
    format!("{destination}/{prefix_length}")
}

impl WindowsWintunRoute {
    /// This capture route's canonical CIDR key. A capture route's netmask is
    /// always contiguous, so its set-bit count is the prefix length.
    pub fn cidr_key(&self) -> String {
        let prefix_length = u32::from(self.netmask).count_ones() as u8;
        windows_wintun_route_cidr_key(IpAddr::V4(self.destination), prefix_length)
    }
}

impl WindowsWintunRoute6 {
    /// This capture route's canonical CIDR key.
    pub fn cidr_key(&self) -> String {
        windows_wintun_route_cidr_key(IpAddr::V6(self.destination), self.prefix_length)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsWintunRouteRestoreReport {
    pub adapter_name: String,
    pub adapter_found: bool,
    pub adapter_index: Option<u32>,
    pub routes_removed: Vec<WindowsWintunRoute>,
    pub errors: Vec<String>,
}

/// The four `/2` quarters of the IPv4 space minus `excluded`, pointed at the
/// Wintun interface. Each `/2` is more specific than the OS `/0` default, and
/// any more specific on-link or LAN route still wins over it.
pub fn windows_wintun_ipv4_capture_routes(
    interface_index: u32,
    metric: u32,
    excluded: &[IpPrefix],
) -> Result<Vec<WindowsWintunRoute>, String> {
    let roots = [0, 64, 128, 192].map(|first| IpPrefix {
        address: IpAddr::V4(Ipv4Addr::new(first, 0, 0, 0)),
        prefix_len: 2,
    });
    Ok(family_capture_prefixes(&roots, excluded)?
        .into_iter()
        .map(|prefix| WindowsWintunRoute {
            destination: match prefix.address {
                IpAddr::V4(address) => address,
                IpAddr::V6(_) => unreachable!("IPv4 capture prefixes stay IPv4"),
            },
            netmask: Ipv4Addr::from(
                u32::MAX
                    .checked_shl(32 - u32::from(prefix.prefix_len))
                    .unwrap_or(0),
            ),
            gateway: Ipv4Addr::new(0, 0, 0, 0),
            interface_index,
            metric,
        })
        .collect())
}

/// Split-default IPv6 capture prefix length. Two `/1` routes (`::/1` and
/// `8000::/1`) cover the whole IPv6 space and win over the OS `::/0` default,
/// while any more-specific on-link route (link-local `fe80::/10`, a LAN prefix)
/// stays more specific and keeps egressing the physical adapter — the IPv6
/// analogue of the IPv4 `/2` capture split.
pub const WINDOWS_WINTUN_IPV6_CAPTURE_PREFIX_LENGTH: u8 = 1;

/// The `::/1` + `8000::/1` capture routes minus `excluded`, pointed at the
/// Wintun interface, so the rest of global IPv6 is pulled into the tunnel
/// (mirrors [`windows_wintun_ipv4_capture_routes`]).
pub fn windows_wintun_ipv6_capture_routes(
    interface_index: u32,
    metric: u32,
    excluded: &[IpPrefix],
) -> Result<Vec<WindowsWintunRoute6>, String> {
    let roots = [
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
    ]
    .map(|address| IpPrefix {
        address: IpAddr::V6(address),
        prefix_len: WINDOWS_WINTUN_IPV6_CAPTURE_PREFIX_LENGTH,
    });
    Ok(family_capture_prefixes(&roots, excluded)?
        .into_iter()
        .map(|prefix| WindowsWintunRoute6 {
            destination: match prefix.address {
                IpAddr::V6(address) => address,
                IpAddr::V4(_) => unreachable!("IPv6 capture prefixes stay IPv6"),
            },
            prefix_length: prefix.prefix_len,
            gateway: Ipv6Addr::UNSPECIFIED,
            interface_index,
            metric,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_capture_routes_are_reversible_for_adapter_index() {
        let routes = windows_wintun_ipv4_capture_routes(42, 3, &[]).unwrap();

        assert_eq!(routes.len(), 4);
        assert_eq!(routes[0].destination, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(routes[0].netmask, Ipv4Addr::new(192, 0, 0, 0));
        assert_eq!(routes[1].destination, Ipv4Addr::new(64, 0, 0, 0));
        assert_eq!(routes[1].netmask, Ipv4Addr::new(192, 0, 0, 0));
        assert_eq!(routes[2].destination, Ipv4Addr::new(128, 0, 0, 0));
        assert_eq!(routes[2].netmask, Ipv4Addr::new(192, 0, 0, 0));
        assert_eq!(routes[3].destination, Ipv4Addr::new(192, 0, 0, 0));
        assert_eq!(routes[3].netmask, Ipv4Addr::new(192, 0, 0, 0));
        assert!(routes.iter().all(|route| {
            route.gateway == Ipv4Addr::new(0, 0, 0, 0)
                && route.interface_index == 42
                && route.metric == 3
        }));
    }

    #[test]
    fn ipv6_capture_routes_split_the_default_over_the_wintun_interface() {
        let routes = windows_wintun_ipv6_capture_routes(42, 3, &[]).unwrap();

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, Ipv6Addr::UNSPECIFIED);
        assert_eq!(
            routes[1].destination,
            Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)
        );
        assert!(routes.iter().all(|route| {
            route.prefix_length == 1
                && route.gateway == Ipv6Addr::UNSPECIFIED
                && route.interface_index == 42
                && route.metric == 3
        }));
    }

    #[test]
    fn capture_routes_have_canonical_cidr_keys() {
        // The IPv4 capture split is four /2 routes; the IPv6 split is two /1
        // routes. These keys are the reconciler's desired route resource set and
        // must match what the route observer recovers from the IP Helper table.
        let v4 = windows_wintun_ipv4_capture_routes(42, 1, &[])
            .unwrap()
            .iter()
            .map(WindowsWintunRoute::cidr_key)
            .collect::<Vec<_>>();
        assert_eq!(
            v4,
            ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"]
        );

        let v6 = windows_wintun_ipv6_capture_routes(42, 1, &[])
            .unwrap()
            .iter()
            .map(WindowsWintunRoute6::cidr_key)
            .collect::<Vec<_>>();
        assert_eq!(v6, ["::/1", "8000::/1"]);
    }

    fn prefix(text: &str) -> IpPrefix {
        text.parse().unwrap()
    }

    #[test]
    fn an_exclusion_splits_its_quarter_and_leaves_the_rest_whole() {
        let routes = windows_wintun_ipv4_capture_routes(42, 1, &[prefix("100.64.0.0/10")])
            .unwrap()
            .iter()
            .map(WindowsWintunRoute::cidr_key)
            .collect::<Vec<_>>();
        assert_eq!(
            routes,
            [
                "0.0.0.0/2",
                "64.0.0.0/3",
                "96.0.0.0/6",
                "100.0.0.0/10",
                "100.128.0.0/9",
                "101.0.0.0/8",
                "102.0.0.0/7",
                "104.0.0.0/5",
                "112.0.0.0/4",
                "128.0.0.0/2",
                "192.0.0.0/2",
            ]
        );
    }

    #[test]
    fn ipv6_splits_alike() {
        let v6 = windows_wintun_ipv6_capture_routes(
            7,
            1,
            &[prefix("fd7a:115c:a1e0::/48"), prefix("10.0.0.0/8")],
        )
        .unwrap();
        assert_eq!(v6.len(), 1 + 47);
        assert!(v6.iter().all(|route| route.interface_index == 7));
    }

    #[test]
    fn too_many_routes_are_refused() {
        let hosts = (0..64)
            .map(|index| prefix(&format!("2001:db8:{index:x}::1/128")))
            .collect::<Vec<_>>();
        assert!(windows_wintun_ipv6_capture_routes(7, 1, &hosts).is_err());
    }
}

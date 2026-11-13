//! The routes into the tunnel, added and removed through a routing socket
//! (`route_socket.rs`) the way route(8) would. Each family's address space
//! but its first /8 goes into the utun as interface routes (1.0.0.0/8,
//! 2.0.0.0/7 ... 128.0.0.0/1; 100::/8 ... 8000::/1): more specific than the
//! physical default routes, which stay the primary service's with its
//! multicast, broadcast and on-link routes, and less specific than any other.
//! A route at the all-zero address would break the Core's egress: XNU takes
//! the most specific route covering 0.0.0.0 (or ::) for the default
//! (bsd/net/route.c `node_lookup_default`, `SA_DEFAULT` ignores the mask), so
//! with 0.0.0.0/1 in the utun a socket bound to the physical interface
//! (`IP_BOUND_IF`) finds no route at all. 0.0.0.0/8 is "this network" and
//! ::/8 holds the unspecified, loopback and other reserved addresses, none of
//! them a destination to relay.
//!
//! An excluded prefix is cut out of these routes (`capture_prefixes`): the
//! route that holds it is halved down to it, so an excluded destination
//! matches no route into the utun and keeps the route the system has, the
//! physical default, an on-link network or another tunnel's route, and
//! follows it as the network changes. A route of its own through the physical
//! router would be more specific than another tunnel's wider route over it
//! (an overlay VPN's 100.64.0.0/10) and take that tunnel's traffic to the router.
//! When the exclusions change, the new routes go in before the stale ones go,
//! so a captured destination always has a route into the utun.
//!
//! The Core's fake-IP pool and its IPv6 projection are rejected on each
//! physical interface with an address of their family, by routes scoped to it
//! (`route_socket.rs`): a socket bound to a physical interface that got a fake
//! IP from the system's resolver (the tunnel's) then fails its connect at once
//! instead of waiting for a peer that is not there, as the firewall makes it
//! on Windows and Linux, and a program bound to a physical
//! interface can turn to another way of resolving. Unbound sockets keep the
//! utun's route to the pool. The session follows the interfaces and their
//! addresses (`session.rs`); a route whose interface gets another address
//! keeps failing connects at once. A
//! reject route that cannot be added leaves that interface's connects to time
//! out and does not fail the tunnel.
//!
//! A route the session added survives the service process, so every route
//! is recorded in a state file under /var/run (emptied at boot) before it is
//! added and dropped from it after it is removed; the service removes what a
//! previous process left there before it changes anything.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use egrio_runtime::{family_capture_prefixes, IpPrefix};
use serde::{Deserialize, Serialize};

use super::route_socket::{self, Kind, PhysicalInterface};

const STATE_FILE: &str = "/var/run/egrio-tun-routes.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Route {
    destination: IpPrefix,
    interface: String,
    /// Rejected for sockets bound to `interface`, rather than routed into
    /// it; recorded only when set.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    reject: bool,
}

impl Route {
    fn kind(&self) -> Kind {
        if self.reject {
            Kind::RejectScoped
        } else {
            Kind::Interface
        }
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let how = if self.reject { "rejected on" } else { "via" };
        write!(formatter, "{} {how} {}", self.destination, self.interface)
    }
}

#[derive(Debug)]
pub(super) struct TunnelRoutes {
    interface: String,
    prefixes: Vec<IpPrefix>,
    fake_ip_prefixes: Vec<IpPrefix>,
    installed: Vec<Route>,
}

impl TunnelRoutes {
    /// The routes into the utun `interface`, less the excluded `prefixes`,
    /// with `fake_ip_prefixes` rejected on the physical interfaces.
    pub(super) fn new(
        interface: &str,
        prefixes: Vec<IpPrefix>,
        fake_ip_prefixes: Vec<IpPrefix>,
    ) -> Self {
        Self {
            interface: interface.into(),
            prefixes,
            fake_ip_prefixes,
            installed: Vec::new(),
        }
    }

    /// Replaces the excluded prefixes.
    pub(super) fn set_prefixes(&mut self, prefixes: Vec<IpPrefix>) -> Result<(), String> {
        self.prefixes = prefixes;
        self.reconcile()
    }

    /// Makes the routing table hold exactly the routes into the utun less the
    /// exclusions and the fake-IP pool's rejection on the physical interfaces
    /// up now: the missing ones first, then without the stale ones.
    pub(super) fn reconcile(&mut self) -> Result<(), String> {
        let mut wanted = captured(&self.interface, &self.prefixes)?;
        wanted.extend(rejected(&self.fake_ip_prefixes));
        let mut failures = Vec::new();
        for route in &wanted {
            if self.installed.contains(route) {
                continue;
            }
            self.installed.push(route.clone());
            record(&self.installed);
            if let Err(error) = add(route) {
                self.installed.retain(|installed| installed != route);
                record(&self.installed);
                if route.reject {
                    log::warn!("macOS TUN {error}");
                } else {
                    failures.push(error);
                }
            }
        }
        let stale: Vec<Route> = self
            .installed
            .iter()
            .filter(|route| !wanted.contains(route))
            .cloned()
            .collect();
        for route in stale {
            remove(&route);
            self.installed.retain(|installed| *installed != route);
            record(&self.installed);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    /// Removes every route this session added, the latest first.
    pub(super) fn clear(&mut self) {
        for route in std::mem::take(&mut self.installed).iter().rev() {
            remove(route);
        }
        record(&self.installed);
    }
}

impl Drop for TunnelRoutes {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Removes the routes a previous service process recorded and did not
/// remove.
pub(super) fn remove_leftovers() {
    let Ok(text) = std::fs::read_to_string(STATE_FILE) else {
        return;
    };
    if let Ok(routes) = serde_json::from_str::<Vec<Route>>(&text) {
        for route in &routes {
            remove(route);
        }
    }
    let _ = std::fs::remove_file(STATE_FILE);
}

/// Each family's address space but its first /8 less `excluded`, into the
/// utun `interface`: before exclusions, the prefix of length 8 - i starts at
/// the value 1 << i in the first byte.
fn captured(interface: &str, excluded: &[IpPrefix]) -> Result<Vec<Route>, String> {
    let ipv4 = (0..8u8)
        .map(|bit| IpPrefix {
            address: IpAddr::V4(Ipv4Addr::new(1 << bit, 0, 0, 0)),
            prefix_len: 8 - bit,
        })
        .collect::<Vec<_>>();
    let ipv6 = (0..8u8)
        .map(|bit| IpPrefix {
            address: IpAddr::V6(Ipv6Addr::new(
                u16::from(1u8 << bit) << 8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )),
            prefix_len: 8 - bit,
        })
        .collect::<Vec<_>>();
    let mut routes = Vec::new();
    for roots in [ipv4, ipv6] {
        routes.extend(
            family_capture_prefixes(&roots, excluded)?
                .into_iter()
                .map(|destination| Route {
                    destination,
                    interface: interface.into(),
                    reject: false,
                }),
        );
    }
    Ok(routes)
}

/// `fake_ip_prefixes` rejected on the physical interfaces up now; none when
/// the interfaces cannot be listed.
fn rejected(fake_ip_prefixes: &[IpPrefix]) -> Vec<Route> {
    if fake_ip_prefixes.is_empty() {
        return Vec::new();
    }
    match route_socket::physical_interfaces() {
        Ok(interfaces) => reject_routes(&interfaces, fake_ip_prefixes),
        Err(error) => {
            log::warn!("macOS TUN cannot list the physical interfaces: {error}");
            Vec::new()
        }
    }
}

/// Each of `prefixes` rejected on each of `interfaces` with an address of its
/// family.
fn reject_routes(interfaces: &[PhysicalInterface], prefixes: &[IpPrefix]) -> Vec<Route> {
    interfaces
        .iter()
        .flat_map(|interface| {
            prefixes
                .iter()
                .filter(|prefix| interface.carries(prefix))
                .map(|destination| Route {
                    destination: *destination,
                    interface: interface.name.clone(),
                    reject: true,
                })
        })
        .collect()
}

fn add(route: &Route) -> Result<(), String> {
    route_socket::add(route.destination, &route.interface, route.kind())
        .map_err(|error| format!("add the route {route}: {error}"))
}

/// A route that is gone already is what removal wants.
fn remove(route: &Route) {
    let _ = route_socket::delete(route.destination, &route.interface, route.kind());
}

fn record(installed: &[Route]) {
    let path = Path::new(STATE_FILE);
    if installed.is_empty() {
        let _ = std::fs::remove_file(path);
        return;
    }
    if let Ok(text) = serde_json::to_string(installed) {
        let _ = std::fs::write(path, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> IpPrefix {
        text.parse().unwrap()
    }

    fn keys(routes: &[Route]) -> Vec<String> {
        routes.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn all_but_the_first_slash_8_goes_into_the_utun() {
        let expected: Vec<String> = [
            "1.0.0.0/8",
            "2.0.0.0/7",
            "4.0.0.0/6",
            "8.0.0.0/5",
            "16.0.0.0/4",
            "32.0.0.0/3",
            "64.0.0.0/2",
            "128.0.0.0/1",
            "100::/8",
            "200::/7",
            "400::/6",
            "800::/5",
            "1000::/4",
            "2000::/3",
            "4000::/2",
            "8000::/1",
        ]
        .iter()
        .map(|prefix| format!("{prefix} via utun4"))
        .collect();
        assert_eq!(keys(&captured("utun4", &[]).unwrap()), expected);
    }

    /// Excluding a tailnet leaves it to the other tunnel's wider route: no
    /// route into the utun covers it, and none goes through a router.
    #[test]
    fn an_exclusion_is_a_hole_in_the_routes_into_the_utun() {
        let excluded = [prefix("100.64.1.0/24"), prefix("100.100.0.0/16")];
        let routes = captured("utun4", &excluded).unwrap();
        assert!(routes.iter().all(|route| route.interface == "utun4"));
        for probe in ["100.64.1.20", "100.100.100.100"] {
            let address = probe.parse().unwrap();
            assert!(
                routes
                    .iter()
                    .all(|route| !route.destination.contains(address)),
                "{probe} stays out of the utun"
            );
        }
        for probe in [
            "100.64.0.1",
            "100.64.2.1",
            "64.0.0.1",
            "127.0.0.1",
            "1.1.1.1",
        ] {
            let address = probe.parse().unwrap();
            assert_eq!(
                routes
                    .iter()
                    .filter(|route| route.destination.contains(address))
                    .count(),
                1,
                "{probe} goes into the utun once"
            );
        }
        let untouched = captured("utun4", &[]).unwrap();
        for root in untouched
            .iter()
            .filter(|route| route.destination != prefix("64.0.0.0/2"))
        {
            assert!(routes.contains(root), "{root} is not split");
        }
    }

    #[test]
    fn the_fake_ip_pool_is_rejected_on_each_physical_interface_of_its_family() {
        assert!(rejected(&[]).is_empty());
        let pool = [
            prefix("198.18.0.0/16"),
            prefix("fd11:5ca1:ab1e:1::c612:0/112"),
        ];
        let interface = |name: &str, ipv4, ipv6| PhysicalInterface {
            name: name.into(),
            ipv4,
            ipv6,
        };
        let routes = reject_routes(
            &[
                interface("en0", true, true),
                interface("en1", true, false),
                interface("en2", false, true),
            ],
            &pool,
        );
        let listed = routes
            .iter()
            .map(|route| {
                assert_eq!(route.kind(), Kind::RejectScoped);
                route.to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            listed,
            [
                "198.18.0.0/16 rejected on en0",
                "fd11:5ca1:ab1e:1::c612:0/112 rejected on en0",
                "198.18.0.0/16 rejected on en1",
                "fd11:5ca1:ab1e:1::c612:0/112 rejected on en2",
            ]
        );
    }

    #[test]
    fn only_a_reject_route_records_its_flag() {
        let routes = [
            Route {
                destination: prefix("128.0.0.0/1"),
                interface: "utun4".into(),
                reject: false,
            },
            Route {
                destination: prefix("198.18.0.0/16"),
                interface: "en0".into(),
                reject: true,
            },
        ];
        let text = serde_json::to_string(&routes).unwrap();
        assert_eq!(text.matches("reject").count(), 1, "{text}");
        let read: Vec<Route> = serde_json::from_str(&text).unwrap();
        assert_eq!(read, routes);
        assert_eq!(read[0].kind(), Kind::Interface);
    }

    #[test]
    fn an_exclusion_set_that_splits_too_far_is_refused() {
        let hosts = (0..64)
            .map(|index| prefix(&format!("2001:db8:{index:x}::1/128")))
            .collect::<Vec<_>>();
        assert!(captured("utun4", &hosts).is_err());
    }
}

//! Follows the host's physical network for the Core: which interface each
//! family's default route leaves through, and the addresses of the interfaces
//! that carry a default route. An rtnetlink socket subscribed to the link,
//! address and route multicast groups (rtnetlink(7), netlink(7)) is the change
//! signal; the routes come from the main table (`ip -j route show table main
//! default`, which the Core's marked egress follows) and the addresses from
//! getifaddrs(3). The TUN's own default route lives in its private table, so
//! the TUN never counts as an uplink.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use egrio_core::EgressNetwork;

/// The physical network now; `None` when the routes or addresses cannot be
/// read, so the Core keeps the network it has instead of taking an empty one
/// for every address lost.
pub(crate) fn observe_network() -> Option<EgressNetwork> {
    let ipv4 = default_routes("-4")?;
    let ipv6 = default_routes("-6")?;
    let uplink = |routes: &[DefaultRoute]| {
        routes
            .iter()
            .min_by_key(|route| route.metric)
            .map(|route| route.interface)
    };
    let mut carriers: Vec<u32> = ipv4
        .iter()
        .chain(&ipv6)
        .map(|route| route.interface)
        .collect();
    carriers.sort_unstable();
    carriers.dedup();
    Some(EgressNetwork {
        ipv4_uplink: uplink(&ipv4),
        ipv6_uplink: uplink(&ipv6),
        addresses: interface_addresses(&carriers)?,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct DefaultRoute {
    interface: u32,
    metric: u64,
}

fn default_routes(family: &str) -> Option<Vec<DefaultRoute>> {
    let routes = crate::command::json(crate::command::OsCommand::new(
        "ip",
        ["-j", family, "route", "show", "table", "main", "default"],
    ))
    .ok()?;
    Some(parse_default_routes(&routes, interface_index))
}

/// The unicast default routes of `ip -j route` output; `unreachable`,
/// `blackhole` and `prohibit` routes carry no traffic.
fn parse_default_routes(
    routes: &[serde_json::Value],
    index_of: impl Fn(&str) -> Option<u32>,
) -> Vec<DefaultRoute> {
    routes
        .iter()
        .filter(|route| route["type"].as_str().is_none_or(|kind| kind == "unicast"))
        .filter_map(|route| {
            Some(DefaultRoute {
                interface: index_of(route["dev"].as_str()?)?,
                metric: crate::command::number(&route["metric"]).unwrap_or(0),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn interface_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}
#[cfg(not(target_os = "linux"))]
fn interface_index(_: &str) -> Option<u32> {
    None
}

/// The non-link-local addresses of `interfaces` that are up with a carrier.
#[cfg(target_os = "linux")]
fn interface_addresses(interfaces: &[u32]) -> Option<Vec<(u32, IpAddr)>> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut addresses = Vec::new();
    let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        let running = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_uint;
        if entry.ifa_addr.is_null() || entry.ifa_flags & running != running {
            continue;
        }
        let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
        if !interfaces.contains(&index) {
            continue;
        }
        let address = match i32::from(unsafe { (*entry.ifa_addr).sa_family }) {
            libc::AF_INET => {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        let link_local = match address {
            IpAddr::V4(address) => address.is_link_local(),
            IpAddr::V6(address) => address.is_unicast_link_local(),
        };
        if !link_local {
            addresses.push((index, address));
        }
    }
    unsafe { libc::freeifaddrs(list) };
    addresses.sort_unstable();
    addresses.dedup();
    Some(addresses)
}
#[cfg(not(target_os = "linux"))]
fn interface_addresses(_: &[u32]) -> Option<Vec<(u32, IpAddr)>> {
    None
}

/// Runs `on_change` on a background thread after each burst of link, address
/// or route changes, until dropped.
#[derive(Debug)]
pub(crate) struct NetworkWatch {
    stopped: Arc<AtomicBool>,
    /// An eventfd the thread waits on beside the netlink socket; dropping the
    /// watch writes it, so the thread sleeps without a timeout until a change
    /// or the drop.
    #[cfg(target_os = "linux")]
    stop: Arc<std::os::fd::OwnedFd>,
}

impl NetworkWatch {
    #[cfg(target_os = "linux")]
    pub(crate) fn start(on_change: impl Fn() + Send + 'static) -> Result<Self, String> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(format!(
                "open an rtnetlink socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        let netlink = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        address.nl_groups = (libc::RTMGRP_LINK
            | libc::RTMGRP_IPV4_IFADDR
            | libc::RTMGRP_IPV6_IFADDR
            | libc::RTMGRP_IPV4_ROUTE
            | libc::RTMGRP_IPV6_ROUTE) as u32;
        if unsafe {
            libc::bind(
                netlink.as_raw_fd(),
                std::ptr::from_ref(&address).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(format!(
                "subscribe to rtnetlink changes: {}",
                std::io::Error::last_os_error()
            ));
        }
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if raw < 0 {
            return Err(format!("eventfd: {}", std::io::Error::last_os_error()));
        }
        let stop = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let stopped = Arc::new(AtomicBool::new(false));
        let (thread_stop, thread_stopped) = (Arc::clone(&stop), Arc::clone(&stopped));
        std::thread::Builder::new()
            .name("egrio-network-watch".into())
            .spawn(move || {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    let mut ready = [
                        libc::pollfd {
                            fd: netlink.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: thread_stop.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                    ];
                    if unsafe { libc::poll(ready.as_mut_ptr(), 2, -1) } < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        break;
                    }
                    if ready[1].revents != 0 || thread_stopped.load(Ordering::Acquire) {
                        break;
                    }
                    if ready[0].revents == 0 {
                        continue;
                    }
                    // One switch is a burst of link, address and route
                    // messages; let it finish, then take everything queued as
                    // one change. An overrun (ENOBUFS) is a change as well.
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    loop {
                        let read = unsafe {
                            libc::recv(
                                netlink.as_raw_fd(),
                                buffer.as_mut_ptr().cast(),
                                buffer.len(),
                                0,
                            )
                        };
                        let overrun = read < 0
                            && std::io::Error::last_os_error().raw_os_error()
                                == Some(libc::ENOBUFS);
                        if read <= 0 && !overrun {
                            break;
                        }
                    }
                    if thread_stopped.load(Ordering::Acquire) {
                        break;
                    }
                    on_change();
                }
            })
            .map_err(|error| format!("start the network watch: {error}"))?;
        Ok(Self { stopped, stop })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn start(_on_change: impl Fn() + Send + 'static) -> Result<Self, String> {
        Err("rtnetlink exists only on Linux".into())
    }
}

impl Drop for NetworkWatch {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let one = 1u64.to_ne_bytes();
            unsafe { libc::write(self.stop.as_raw_fd(), one.as_ptr().cast(), one.len()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_uplinks_are_the_unicast_default_routes_by_metric() {
        let routes: Vec<serde_json::Value> = serde_json::from_str(
            r#"[
                {"dst":"default","gateway":"192.0.2.1","dev":"wlan0","protocol":"dhcp","metric":600,"flags":[]},
                {"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","metric":100,"flags":[]},
                {"type":"unreachable","dst":"default","dev":"lo","metric":4278198272,"flags":[]},
                {"dst":"default","dev":"gone","flags":[]}
            ]"#,
        )
        .unwrap();
        let index = |name: &str| match name {
            "eth0" => Some(2),
            "wlan0" => Some(3),
            "lo" => Some(1),
            _ => None,
        };

        assert_eq!(
            parse_default_routes(&routes, index),
            vec![
                DefaultRoute {
                    interface: 3,
                    metric: 600
                },
                DefaultRoute {
                    interface: 2,
                    metric: 100
                },
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_watch_subscribes_without_privileges_and_a_drop_ends_it() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let watch = NetworkWatch::start(move || {
            let _ = sender.send(());
        })
        .expect("rtnetlink subscriptions need no privileges");
        drop(watch);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(receiver.try_recv().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_machines_uplinks_carry_their_addresses() {
        let network = observe_network().expect("the routes and addresses are readable");
        for uplink in [network.ipv4_uplink, network.ipv6_uplink]
            .into_iter()
            .flatten()
        {
            assert!(network
                .addresses
                .iter()
                .any(|(interface, _)| *interface == uplink));
        }
    }
}

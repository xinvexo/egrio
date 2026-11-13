//! What a change of the host's physical network strands.
//!
//! A platform guard observes the network (links, addresses, which interface
//! new dials bind to) and publishes an [`EgressNetwork`] whenever it changes.
//! Nothing in TCP notices on its own that the address a connection uses is
//! gone: a relay that only receives has nothing to retransmit, so it waits
//! until the client gives up. A socket bound to an interface that lost its
//! last address of the socket's family is just as dead. [`NetworkChange`]
//! names both, and the Core ends those connections so their clients
//! reconnect over the network that is there now. Everything else keeps
//! running: a connection on Wi-Fi survives an Ethernet cable plugged in.
//! A carrier that can move its connection to a new socket (QUIC) follows the
//! uplink instead, stranded or not.

use std::collections::HashSet;
use std::net::IpAddr;

use super::EgressBinding;

/// The physical network as a platform guard last observed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressNetwork {
    /// The interface new IPv4 dials bind to, if the guard binds them.
    pub ipv4_uplink: Option<u32>,
    /// The interface new IPv6 dials bind to, if the guard binds them.
    pub ipv6_uplink: Option<u32>,
    /// The addresses of the physical interfaces, each with its interface
    /// index.
    pub addresses: Vec<(u32, IpAddr)>,
}

/// What one network change took away, relative to the network before it.
/// Interfaces a platform does not report never strand anything.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct NetworkChange {
    /// Addresses no interface has any more.
    removed: HashSet<IpAddr>,
    /// Interfaces left without an address of a family they had, as
    /// (interface index, is IPv6).
    emptied: HashSet<(u32, bool)>,
    /// The interfaces new IPv4 and IPv6 dials bind to now.
    uplinks: (Option<u32>, Option<u32>),
}

impl NetworkChange {
    pub(crate) fn between(previous: &EgressNetwork, current: &EgressNetwork) -> Self {
        let kept: HashSet<IpAddr> = current.addresses.iter().map(|(_, ip)| *ip).collect();
        let families = |network: &EgressNetwork| -> HashSet<(u32, bool)> {
            network
                .addresses
                .iter()
                .map(|(index, ip)| (*index, ip.is_ipv6()))
                .collect()
        };
        let still = families(current);
        Self {
            removed: previous
                .addresses
                .iter()
                .map(|(_, ip)| *ip)
                .filter(|ip| !kept.contains(ip))
                .collect(),
            emptied: families(previous)
                .into_iter()
                .filter(|family| !still.contains(family))
                .collect(),
            uplinks: (current.ipv4_uplink, current.ipv6_uplink),
        }
    }

    /// Whether a socket with this egress can no longer carry traffic: its
    /// local address is gone, or the interface it is bound to has no address
    /// of its family left. An unbound socket without a fixed local address
    /// (unconnected UDP) follows the routes and is never stranded.
    pub(crate) fn strands(&self, binding: &EgressBinding) -> bool {
        let Some(local) = binding.local_address else {
            return false;
        };
        (!local.is_unspecified() && self.removed.contains(&local))
            || binding
                .interface_index
                .is_some_and(|index| self.emptied.contains(&(index, local.is_ipv6())))
    }

    /// Whether a socket bound to an interface is off the interface new dials
    /// of its family bind to now. A connection stays where it is; a carrier
    /// that can move moves.
    pub(crate) fn moves(&self, binding: &EgressBinding) -> bool {
        let (Some(index), Some(local)) = (binding.interface_index, binding.local_address) else {
            return false;
        };
        let uplink = if local.is_ipv6() {
            self.uplinks.1
        } else {
            self.uplinks.0
        };
        uplink.is_some_and(|uplink| uplink != index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(addresses: &[(u32, &str)]) -> EgressNetwork {
        EgressNetwork {
            ipv4_uplink: addresses.first().map(|(index, _)| *index),
            ipv6_uplink: None,
            addresses: addresses
                .iter()
                .map(|(index, ip)| (*index, ip.parse().unwrap()))
                .collect(),
        }
    }

    fn egress(interface: Option<u32>, local: &str) -> EgressBinding {
        EgressBinding {
            interface_index: interface,
            local_address: Some(local.parse().unwrap()),
        }
    }

    #[test]
    fn a_lost_link_strands_its_connections_and_bound_sockets() {
        let before = network(&[(2, "192.0.2.10"), (3, "198.51.100.20")]);
        let after = network(&[(3, "198.51.100.20")]);
        let change = NetworkChange::between(&before, &after);

        assert!(change.strands(&egress(Some(2), "192.0.2.10")));
        assert!(change.strands(&egress(None, "192.0.2.10")));
        assert!(change.strands(&egress(Some(2), "0.0.0.0")));
        assert!(!change.strands(&egress(Some(3), "198.51.100.20")));
        assert!(!change.strands(&egress(Some(3), "0.0.0.0")));
        assert!(!change.strands(&egress(None, "0.0.0.0")));
    }

    #[test]
    fn a_new_link_or_an_uplink_move_strands_nothing_and_moves_what_is_off_it() {
        let wifi = network(&[(3, "198.51.100.20")]);
        let wired_first = network(&[(2, "192.0.2.10"), (3, "198.51.100.20")]);
        let change = NetworkChange::between(&wifi, &wired_first);
        assert!(!change.strands(&egress(Some(3), "198.51.100.20")));
        assert!(!change.strands(&egress(Some(3), "0.0.0.0")));
        assert!(change.moves(&egress(Some(3), "198.51.100.20")));
        assert!(change.moves(&egress(Some(3), "0.0.0.0")));
        assert!(!change.moves(&egress(Some(2), "192.0.2.10")));

        let mut wifi_first = wired_first.clone();
        wifi_first.ipv4_uplink = Some(3);
        let change = NetworkChange::between(&wired_first, &wifi_first);
        assert!(!change.strands(&egress(Some(2), "192.0.2.10")));
        assert!(change.moves(&egress(Some(2), "192.0.2.10")));
        assert!(!change.moves(&egress(Some(3), "0.0.0.0")));
        // Unbound sockets follow the routes; a family without an uplink, or a
        // binding without an address, has nowhere to move.
        assert!(!change.moves(&egress(None, "192.0.2.10")));
        assert!(!change.moves(&egress(Some(2), "::")));
        assert!(!change.moves(&EgressBinding::bound(2)));
    }

    #[test]
    fn a_new_address_on_the_same_link_strands_only_what_used_the_old_one() {
        let before = network(&[(3, "198.51.100.20"), (3, "2001:db8::20")]);
        let after = network(&[(3, "10.0.0.5"), (3, "2001:db8::20")]);
        let change = NetworkChange::between(&before, &after);

        assert!(change.strands(&egress(Some(3), "198.51.100.20")));
        assert!(!change.strands(&egress(Some(3), "0.0.0.0")));
        assert!(!change.strands(&egress(Some(3), "2001:db8::20")));
        assert!(!change.strands(&egress(Some(3), "::")));
    }

    #[test]
    fn a_link_losing_one_family_strands_that_family_only() {
        let before = network(&[(2, "192.0.2.10"), (2, "2001:db8::10")]);
        let after = network(&[(2, "192.0.2.10")]);
        let change = NetworkChange::between(&before, &after);

        assert!(change.strands(&egress(Some(2), "::")));
        assert!(change.strands(&egress(None, "2001:db8::10")));
        assert!(!change.strands(&egress(Some(2), "0.0.0.0")));
        assert!(!change.strands(&EgressBinding::bound(2)));
    }
}

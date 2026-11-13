use crate::network_state::{require_owned_link, TunCheckpoint};

/// Installs the kill switch, or replaces it in place without a moment
/// without the table.
pub(crate) fn apply(checkpoint: &TunCheckpoint) -> Result<(), String> {
    require_owned_link(checkpoint)?;
    crate::nft::replace(
        &checkpoint.config.nft_table(),
        &checkpoint.ownership,
        &nft_script(checkpoint),
    )
}
pub(crate) fn observe(checkpoint: &TunCheckpoint) -> Result<bool, String> {
    crate::nft::owned(&checkpoint.config.nft_table(), &checkpoint.ownership)
}
pub(crate) fn restore(checkpoint: &TunCheckpoint) -> Result<(), String> {
    if checkpoint.applied {
        // Rolling back an in-place update: the baseline's kill switch.
        return apply(checkpoint);
    }
    crate::nft::remove(&checkpoint.config.nft_table(), &checkpoint.ownership)
}
/// The link types of physical uplinks, whose DNS is a leak: `ARPHRD_ETHER`
/// (Ethernet and Wi-Fi) and `ARPHRD_PPP` (linux/if_arp.h), nft's `ether` and
/// `ppp` interface types. Another VPN's TUN device is `ARPHRD_NONE`: the DNS
/// it carries goes to that VPN's resolver, not to the local network.
const UPLINK_LINK_TYPES: [u16; 2] = [1, 512];

/// Whether `link` is a physical uplink by its kernel link type
/// (`/sys/class/net/<link>/type`, Documentation/ABI/testing/sysfs-class-net).
pub(crate) fn is_uplink(link: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{link}/type"))
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .is_some_and(|link_type| UPLINK_LINK_TYPES.contains(&link_type))
}

/// Leak protection while the TUN runs: what goes through the TUN, Egrio's
/// own marked egress and loopback pass; DNS leaving by a physical uplink,
/// fake IPs outside the TUN and, when the TUN carries no IPv6, IPv6 are
/// rejected. Everything else passes: what other software sends outside the
/// TUN on purpose (another VPN's own connections and its DNS, a socket bound
/// to an interface). The table goes with the session, so a stopped or
/// crashed Egrio leaves the network as it is without Egrio.
pub(crate) fn nft_script(checkpoint: &TunCheckpoint) -> String {
    let config = &checkpoint.config;
    let mut rules = format!(
        "oifname \"lo\" accept\nmeta mark {} accept\noifname \"{}\" accept\n",
        config.mark(),
        config.interface_name
    );
    if config.capture_dns {
        rules.push_str(
            "meta oiftype { ether, ppp } meta l4proto { tcp, udp } th dport { 53, 853 } reject\n",
        );
    }
    let prefixes = |prefixes: &[egrio_runtime::IpPrefix], v4: bool| {
        prefixes
            .iter()
            .filter(|prefix| prefix.address.is_ipv4() == v4)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };
    // A fake IP means something only to the Core: outside the TUN the
    // connect fails at once instead of waiting for a peer that is not there.
    for (family, v4) in [("ip", true), ("ip6", false)] {
        let fake = prefixes(&checkpoint.fake_ip_prefixes, v4);
        if !fake.is_empty() {
            rules.push_str(&format!(
                "{family} daddr {{ {} }} reject\n",
                fake.join(", ")
            ));
        }
    }
    if checkpoint.ipv4_only {
        // No IPv6 enters the TUN, so none leaves outside it but the link's
        // own (DHCPv6, neighbour discovery), the LAN scopes and the excluded
        // destinations.
        rules.push_str("udp sport 546 udp dport 547 accept\nicmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n");
        if config.allow_lan {
            rules.push_str("ip6 daddr { fc00::/7, fe80::/10, ff00::/8 } accept\n");
        }
        let excluded = prefixes(&checkpoint.excluded_prefixes, false);
        if !excluded.is_empty() {
            rules.push_str(&format!("ip6 daddr {{ {} }} accept\n", excluded.join(", ")));
        }
        rules.push_str("meta nfproto ipv6 reject\n");
    }
    format!("add table inet {} {{ comment \"{}\"; }}\nadd chain inet {} output {{ type filter hook output priority -150; policy accept; }}\n{}",config.nft_table(),checkpoint.ownership,config.nft_table(),rules.lines().map(|line|format!("add rule inet {} output {line}\n",config.nft_table())).collect::<String>())
}

//! The TUN link's resolver in systemd-resolved: the virtual resolver as its
//! DNS server, the default route, and routing domains that send it every name.
//!
//! resolved sends a name to the links whose routing domain matches it with the
//! most labels; `~.` matches every name only weakly, so a name under another
//! link's routing domain (a DHCP search domain, a VPN's route-only domain) goes
//! to that link alone (systemd-resolved.service(8), "Protocols and Routing").
//! While the tunnel runs, the leak rules reject DNS on the physical uplinks, a
//! lookup there fails, resolved's stub leaves the query unanswered, and glibc,
//! which tries the search domains after a name lacks the type asked for (AAAA
//! while IPv6 is off), waits out its timeouts: ten seconds. The TUN link
//! therefore carries the uplinks' routing domains too, and follows them while
//! applied: resolved then asks both links and returns the first successful
//! answer, the virtual resolver's. Another VPN's domains stay its own: its DNS
//! passes, and its resolver answers the names only it knows.

use std::sync::Mutex;

use crate::{
    command::{run, OsCommand},
    config::LINUX_TUN_VIRTUAL_DNS,
    network_state::{links, require_owned_link, TunCheckpoint},
    resolver_watch::ResolverWatch,
};

/// Per applied TUN link, the watch that keeps its routing domains in step.
static FOLLOWERS: Mutex<Vec<(String, ResolverWatch)>> = Mutex::new(Vec::new());

pub(crate) fn apply(checkpoint: &TunCheckpoint) -> Result<(), String> {
    require_owned_link(checkpoint)?;
    let listing = run(&OsCommand::new("resolvectl", ["domain"]))?;
    for command in dns_commands(checkpoint, &listing) {
        run(&command)?;
    }
    if !observe(checkpoint)? {
        return Err("Linux TUN DNS observation did not match".into());
    }
    follow(&checkpoint.config.interface_name);
    Ok(())
}

/// Re-reads the other links' routing domains whenever resolved's state
/// changes. Best effort: without the watch the domains stay as applied.
fn follow(name: &str) {
    let link = name.to_owned();
    let watch = ResolverWatch::start(move || {
        if let Err(error) = follow_domains(&link) {
            log::warn!("Linux TUN routing domains not updated: {error}");
        }
    });
    let mut followers = FOLLOWERS.lock().expect("Linux TUN DNS followers");
    followers.retain(|(followed, _)| followed != name);
    match watch {
        Ok(watch) => followers.push((name.to_owned(), watch)),
        Err(error) => log::warn!("Linux TUN routing domains will not follow the network: {error}"),
    }
}

fn unfollow(name: &str) {
    FOLLOWERS
        .lock()
        .expect("Linux TUN DNS followers")
        .retain(|(followed, _)| followed != name);
}

/// Sets the TUN link's routing domains again when the other links' changed.
fn follow_domains(name: &str) -> Result<(), String> {
    let listing = run(&OsCommand::new("resolvectl", ["domain"]))?;
    let wanted = tun_domains(name, &listing, crate::firewall::is_uplink);
    if link_domains(name, &listing).as_deref() == Some(&wanted[..]) {
        return Ok(());
    }
    run(&domain_command(name, &wanted)).map(|_| ())
}
pub(crate) fn observe(checkpoint: &TunCheckpoint) -> Result<bool, String> {
    require_owned_link(checkpoint)?;
    let dns = run(&OsCommand::new(
        "resolvectl",
        ["dns", &checkpoint.config.interface_name],
    ))?;
    let domain = run(&OsCommand::new(
        "resolvectl",
        ["domain", &checkpoint.config.interface_name],
    ))?;
    Ok(lists_virtual_dns(&dns) && domain.split_whitespace().any(|value| value == "~."))
}
pub(crate) fn restore(checkpoint: &TunCheckpoint) -> Result<(), String> {
    unfollow(&checkpoint.config.interface_name);
    if !links()?
        .iter()
        .any(|link| link["ifname"] == checkpoint.config.interface_name)
    {
        return Ok(());
    }
    require_owned_link(checkpoint)?;
    run(&OsCommand::new(
        "resolvectl",
        ["revert", &checkpoint.config.interface_name],
    ))?;
    let dns = run(&OsCommand::new(
        "resolvectl",
        ["dns", &checkpoint.config.interface_name],
    ))?;
    let domain = run(&OsCommand::new(
        "resolvectl",
        ["domain", &checkpoint.config.interface_name],
    ))?;
    if lists_virtual_dns(&dns) || domain.split_whitespace().any(|value| value == "~.") {
        return Err("Linux TUN DNS cleanup could not be verified".into());
    }
    Ok(())
}
fn lists_virtual_dns(resolvectl_output: &str) -> bool {
    let virtual_dns = LINUX_TUN_VIRTUAL_DNS.to_string();
    resolvectl_output
        .split_whitespace()
        .any(|value| value == virtual_dns)
}
fn dns_commands(checkpoint: &TunCheckpoint, listing: &str) -> Vec<OsCommand> {
    let name = &checkpoint.config.interface_name;
    vec![
        OsCommand::new(
            "resolvectl",
            ["dns", name, &LINUX_TUN_VIRTUAL_DNS.to_string()],
        ),
        domain_command(
            name,
            &tun_domains(name, listing, crate::firewall::is_uplink),
        ),
        OsCommand::new("resolvectl", ["default-route", name, "yes"]),
    ]
}

fn domain_command(name: &str, domains: &[String]) -> OsCommand {
    OsCommand::new(
        "resolvectl",
        ["domain", name]
            .into_iter()
            .chain(domains.iter().map(String::as_str)),
    )
}

/// The TUN link's routing domains: `~.`, then, route-only, every routing
/// domain of the global settings and of the physical uplinks (`uplink`) in
/// `resolvectl domain`'s listing.
fn tun_domains(name: &str, listing: &str, uplink: impl Fn(&str) -> bool) -> Vec<String> {
    let mut domains = vec!["~.".to_owned()];
    for line in listing.lines() {
        let Some((scope, values)) = line.split_once(':') else {
            continue;
        };
        if scope_link(scope).is_some_and(|link| link == name || !uplink(link)) {
            continue;
        }
        for domain in values.split_whitespace() {
            let domain = domain.trim_start_matches('~').trim_end_matches('.');
            if domain.is_empty() {
                continue;
            }
            let route = format!("~{domain}");
            if !domains.contains(&route) {
                domains.push(route);
            }
        }
    }
    domains
}

/// The routing domains `listing` shows for link `name`.
fn link_domains(name: &str, listing: &str) -> Option<Vec<String>> {
    listing.lines().find_map(|line| {
        let (scope, values) = line.split_once(':')?;
        (scope_link(scope) == Some(name))
            .then(|| values.split_whitespace().map(str::to_owned).collect())
    })
}

/// The interface a `resolvectl domain` line is for: `Link 2 (eth0)` is eth0.
fn scope_link(scope: &str) -> Option<&str> {
    scope
        .strip_prefix("Link ")?
        .split_once('(')?
        .1
        .strip_suffix(')')
}
/// Physical resolvers from systemd-resolved, excluding the TUN's own.
pub(crate) fn linux_physical_dns_servers() -> Result<Vec<std::net::SocketAddr>, String> {
    let text = run(&OsCommand::new("resolvectl", ["dns"]))?;
    let mut servers = Vec::new();
    for value in text.split_whitespace() {
        if let Ok(ip) = value.trim_end_matches(',').parse::<std::net::IpAddr>() {
            if !ip.is_loopback()
                && !ip.is_unspecified()
                && ip != std::net::IpAddr::V4(LINUX_TUN_VIRTUAL_DNS)
                && !servers.contains(&std::net::SocketAddr::new(ip, 53))
            {
                servers.push(std::net::SocketAddr::new(ip, 53));
            }
        }
    }
    if servers.is_empty() {
        return Err(
            "Linux TUN needs physical DNS servers from systemd-resolved before capture starts"
                .into(),
        );
    }
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "Global: corp.example\n\
        Link 2 (eth0): lan.example ~vpn.example\n\
        Link 3 (wg0): ~. ~tailnet.example\n\
        Link 120 (egrio0): ~. ~old.example\n";

    #[test]
    fn the_tun_link_carries_the_uplinks_routing_domains_and_leaves_other_vpns_theirs() {
        assert_eq!(
            tun_domains("egrio0", LISTING, |link| link == "eth0"),
            ["~.", "~corp.example", "~lan.example", "~vpn.example"]
        );
    }

    #[test]
    fn the_listing_names_each_links_domains() {
        assert_eq!(
            link_domains("egrio0", LISTING),
            Some(vec!["~.".to_owned(), "~old.example".to_owned()])
        );
        assert_eq!(link_domains("eth1", LISTING), None);
        assert_eq!(scope_link("Link 120 (egrio0)"), Some("egrio0"));
        assert_eq!(scope_link("Global"), None);
    }
}

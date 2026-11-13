use crate::{
    command::{json, number, run, OsCommand},
    config::LINUX_TUN_VIRTUAL_DNS,
    network_state::{links, require_owned_link, TunCheckpoint},
    LinuxTunConfig,
};
use egrio_runtime::IpPrefix;
use serde_json::Value;
use std::collections::BTreeSet;

/// Installs the routing, or updates the exclusions of routing already in
/// place: an in-place update only adds and deletes `throw` routes.
pub(crate) fn apply(checkpoint: &TunCheckpoint) -> Result<(), String> {
    require_owned_link(checkpoint)?;
    if checkpoint.install_default_route {
        // Before the capture rule, so no reply to an inbound connection is
        // ever captured.
        crate::nft::replace(
            &checkpoint.config.nft_reply_table(),
            &checkpoint.ownership,
            &reply_mark_script(checkpoint),
        )?;
    }
    if !base_present(checkpoint)? {
        for command in route_commands(checkpoint) {
            run(&command)?;
        }
    }
    reconcile_throw_routes(checkpoint)?;
    if !observe(checkpoint)? {
        return Err("Linux TUN routing observation did not match".into());
    }
    Ok(())
}
pub(crate) fn observe(checkpoint: &TunCheckpoint) -> Result<bool, String> {
    Ok(base_present(checkpoint)?
        && throw_routes_match(checkpoint)?
        && (!checkpoint.install_default_route
            || crate::nft::owned(&checkpoint.config.nft_reply_table(), &checkpoint.ownership)?))
}
/// Replies to connections that came in from outside keep the main table's
/// routes. Conntrack marks each new connection that arrives on another
/// interface for a local address, and the replies of a marked connection
/// carry Egrio's egress mark: the capture rule skips them, and the kill
/// switch lets them through. Replies sent from this host take the mark in a
/// route chain, which routes them again; replies forwarded from the target
/// of a port forward take it as they arrive. A mark other software set, on
/// the connection or the packet, stays.
pub(crate) fn reply_mark_script(checkpoint: &TunCheckpoint) -> String {
    let config = &checkpoint.config;
    let table = config.nft_reply_table();
    let tun = &config.interface_name;
    let mark = config.mark();
    [
        format!("add table inet {table} {{ comment \"{}\"; }}", checkpoint.ownership),
        format!("add chain inet {table} inbound {{ type filter hook prerouting priority -150; policy accept; }}"),
        format!("add rule inet {table} inbound iifname != {{ \"lo\", \"{tun}\" }} fib daddr type local ct state new ct mark 0 ct mark set {mark}"),
        format!("add rule inet {table} inbound ct direction reply ct mark {mark} meta mark 0 meta mark set {mark}"),
        // Ahead of the kill switch's output chain at -150.
        format!("add chain inet {table} replies {{ type route hook output priority -151; policy accept; }}"),
        format!("add rule inet {table} replies ct direction reply ct mark {mark} meta mark 0 meta mark set {mark}"),
    ]
    .map(|line| line + "\n")
    .concat()
}
/// An excluded prefix is a `throw` route in Egrio's table: a lookup that
/// hits it leaves the table and continues with the next rule, so the
/// destination keeps the main table's routes and never reaches the TUN.
fn throw_route_command(
    config: &LinuxTunConfig,
    family: &str,
    action: &str,
    prefix: &str,
) -> OsCommand {
    OsCommand::new(
        "ip",
        [
            family,
            "route",
            action,
            "throw",
            prefix,
            "table",
            &config.routing_table.to_string(),
        ],
    )
}
/// Whether an `ip -j` route entry is a `throw` route. With `-N` iproute2
/// prints the route type as its number, `RTN_THROW` = 9 in the kernel's
/// `include/uapi/linux/rtnetlink.h`.
fn is_throw_route(route: &Value) -> bool {
    route["type"] == "throw" || route["type"] == "9"
}
fn family_flag(prefix: &IpPrefix) -> &'static str {
    if prefix.address.is_ipv4() {
        "-4"
    } else {
        "-6"
    }
}
/// The excluded prefixes of `family` the checkpoint asks for.
fn wanted_throw_routes(checkpoint: &TunCheckpoint, family: &str) -> BTreeSet<IpPrefix> {
    if !checkpoint.install_default_route || !checkpoint.families().contains(&family) {
        return BTreeSet::new();
    }
    checkpoint
        .excluded_prefixes
        .iter()
        .filter(|prefix| family_flag(prefix) == family)
        .copied()
        .collect()
}
/// The `throw` routes in Egrio's table. iproute2 prints a host prefix as
/// the bare address, which parses as that host.
fn present_throw_routes(
    config: &LinuxTunConfig,
    family: &str,
) -> Result<BTreeSet<IpPrefix>, String> {
    table_routes(config, family)?
        .iter()
        .filter(|route| is_throw_route(route))
        .map(|route| {
            route["dst"]
                .as_str()
                .ok_or_else(|| "Linux TUN throw route has no destination".to_string())?
                .parse::<IpPrefix>()
        })
        .collect()
}
fn throw_routes_match(checkpoint: &TunCheckpoint) -> Result<bool, String> {
    for family in ["-4", "-6"] {
        if present_throw_routes(&checkpoint.config, family)?
            != wanted_throw_routes(checkpoint, family)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn reconcile_throw_routes(checkpoint: &TunCheckpoint) -> Result<(), String> {
    let config = &checkpoint.config;
    for family in ["-4", "-6"] {
        let wanted = wanted_throw_routes(checkpoint, family);
        let present = present_throw_routes(config, family)?;
        for prefix in wanted.difference(&present) {
            run(&throw_route_command(
                config,
                family,
                "add",
                &prefix.to_string(),
            ))?;
        }
        for prefix in present.difference(&wanted) {
            run(&throw_route_command(
                config,
                family,
                "del",
                &prefix.to_string(),
            ))?;
        }
    }
    Ok(())
}
fn base_present(checkpoint: &TunCheckpoint) -> Result<bool, String> {
    let config = &checkpoint.config;
    require_owned_link(checkpoint)?;
    if config.capture_dns {
        let dns = dns_host_routes()?;
        if dns.len() != 1
            || dns[0]["dev"] != config.interface_name
            || dns[0].get("gateway").is_some()
        {
            return Ok(false);
        }
    }
    if checkpoint.install_default_route {
        for &family in checkpoint.families() {
            let expected = if config.allow_lan { 2 } else { 1 };
            let rules = priority_rules(config, family)?;
            if rules.len() != expected
                || !rules.iter().any(|rule| {
                    number(&rule["priority"]) == Some(config.rule_priority.into())
                        && capture_rule_owned(rule, config)
                })
                || (config.allow_lan
                    && !rules.iter().any(|rule| {
                        number(&rule["priority"]) == Some((config.rule_priority - 1).into())
                            && lan_rule_owned(rule)
                    }))
            {
                return Ok(false);
            }
            if !table_routes(config, family)?
                .iter()
                .any(|route| route["dst"] == "default" && route["dev"] == config.interface_name)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
pub(crate) fn restore(checkpoint: &TunCheckpoint) -> Result<(), String> {
    let config = &checkpoint.config;
    if checkpoint.applied {
        // Rolling back an in-place update: the routing stays, the
        // exclusions return to the baseline.
        require_owned_link(checkpoint)?;
        reconcile_throw_routes(checkpoint)?;
        if !observe(checkpoint)? {
            return Err("Linux TUN routing did not return to its baseline".into());
        }
        return Ok(());
    }
    if links()?
        .iter()
        .any(|link| link["ifname"] == config.interface_name)
    {
        require_owned_link(checkpoint)?;
    }
    if config.capture_dns {
        for route in dns_host_routes()? {
            if route["dev"] != config.interface_name || route.get("gateway").is_some() {
                return Err("Linux TUN DNS host route changed owner".into());
            }
            run(&dns_host_route_command(config, "del"))?;
        }
        if !dns_host_routes()?.is_empty() {
            return Err("Linux TUN DNS host route cleanup could not be verified".into());
        }
    }
    if !checkpoint.install_default_route {
        return Ok(());
    }
    for family in ["-4", "-6"] {
        for command in rule_removal_commands(config, family, &priority_rules(config, family)?)? {
            run(&command)?;
        }
        for route in table_routes(config, family)? {
            if is_throw_route(&route) {
                let dst = route["dst"]
                    .as_str()
                    .ok_or("Linux TUN throw route has no destination")?;
                run(&throw_route_command(config, family, "del", dst))?;
                continue;
            }
            if route["dst"] != "default"
                || route["dev"] != config.interface_name
                || route.get("gateway").is_some()
            {
                return Err("Linux TUN routing table contains a foreign route".into());
            }
            run(&OsCommand::new(
                "ip",
                [
                    family,
                    "route",
                    "del",
                    "table",
                    &config.routing_table.to_string(),
                    "default",
                    "dev",
                    &config.interface_name,
                ],
            ))?;
        }
        if !table_routes(config, family)?.is_empty() || !priority_rules(config, family)?.is_empty()
        {
            return Err("Linux TUN route/rule cleanup could not be verified".into());
        }
    }
    // After the capture rule is gone, so no reply is captured in between.
    crate::nft::remove(&config.nft_reply_table(), &checkpoint.ownership)
}
/// Removes the observed rules in the reverse of their installation: the
/// capture rule before the LAN bypass. Alone, the capture rule would send LAN
/// traffic into the TUN, where the Core resets connections it never carried.
fn rule_removal_commands(
    config: &LinuxTunConfig,
    family: &str,
    rules: &[Value],
) -> Result<Vec<OsCommand>, String> {
    let mut capture = Vec::new();
    let mut lan = Vec::new();
    for rule in rules {
        let priority = number(&rule["priority"]).ok_or("Linux TUN rule priority missing")?;
        if priority == u64::from(config.rule_priority) {
            if !capture_rule_owned(rule, config) {
                return Err("Linux TUN rule changed owner; refusing to delete it".into());
            }
            capture.push(capture_rule(config, family, "del"));
        } else {
            if !lan_rule_owned(rule) {
                return Err("Linux TUN LAN-bypass rule changed owner".into());
            }
            lan.push(lan_rule(config, family, "del"));
        }
    }
    capture.extend(lan);
    Ok(capture)
}
fn rules(family: &str) -> Result<Vec<Value>, String> {
    json(OsCommand::new("ip", ["-j", "-N", family, "rule", "show"]))
}
fn routes(family: &str) -> Result<Vec<Value>, String> {
    json(OsCommand::new(
        "ip",
        ["-j", "-N", family, "route", "show", "table", "all"],
    ))
}
pub(crate) fn table_routes(config: &LinuxTunConfig, family: &str) -> Result<Vec<Value>, String> {
    Ok(routes(family)?
        .into_iter()
        .filter(|route| number(&route["table"]) == Some(config.routing_table.into()))
        .collect())
}
pub(crate) fn priority_rules(config: &LinuxTunConfig, family: &str) -> Result<Vec<Value>, String> {
    Ok(rules(family)?
        .into_iter()
        .filter(|rule| {
            number(&rule["priority"]).is_some_and(|n| {
                n == u64::from(config.rule_priority)
                    || (config.allow_lan && n + 1 == u64::from(config.rule_priority))
            })
        })
        .collect())
}
pub(crate) fn dns_host_routes() -> Result<Vec<Value>, String> {
    Ok(routes("-4")?
        .into_iter()
        .filter(|route| {
            route["dst"].as_str().is_some_and(|dst| {
                dst.strip_suffix("/32").unwrap_or(dst) == LINUX_TUN_VIRTUAL_DNS.to_string()
            }) && (route.get("table").is_none()
                || route["table"] == "main"
                || number(&route["table"]) == Some(254))
        })
        .collect())
}
fn dns_host_route_command(config: &LinuxTunConfig, action: &str) -> OsCommand {
    OsCommand::new(
        "ip",
        [
            "-4",
            "route",
            action,
            &format!("{LINUX_TUN_VIRTUAL_DNS}/32"),
            "dev",
            &config.interface_name,
        ],
    )
}

fn numeric_or_hex(value: &Value) -> Option<u64> {
    number(value).or_else(|| {
        value
            .as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .and_then(|s| u64::from_str_radix(s, 16).ok())
    })
}
fn rule_mark_matches(rule: &Value, mark: u32) -> bool {
    numeric_or_hex(&rule["fwmark"]) == Some(mark.into())
        && rule
            .get("fwmask")
            .is_none_or(|value| numeric_or_hex(value) == Some(u32::MAX.into()))
}
fn basic_rule_selectors(rule: &Value) -> bool {
    rule["src"] == "all"
        && [
            "dst",
            "iif",
            "oif",
            "uid_start",
            "uid_end",
            "ipproto",
            "sport",
            "dport",
            "tos",
            "l3mdev",
            "goto",
            "action",
        ]
        .iter()
        .all(|key| rule.get(*key).is_none())
}
fn capture_rule_owned(rule: &Value, config: &LinuxTunConfig) -> bool {
    number(&rule["table"]) == Some(config.routing_table.into())
        && rule_mark_matches(rule, 0)
        && rule.get("not").is_none()
        && basic_rule_selectors(rule)
}
fn lan_rule_owned(rule: &Value) -> bool {
    (rule["table"] == "main" || number(&rule["table"]) == Some(254))
        && number(&rule["suppress_prefixlen"]) == Some(0)
        && rule.get("not").is_none()
        && rule.get("fwmark").is_none()
        && basic_rule_selectors(rule)
}
/// Captures only unmarked traffic. A mark is a routing decision privileged
/// software already made: Egrio's egress carries `config.fwmark`, and a
/// full-tunnel VPN such as wg-quick marks its encrypted packets. Capturing
/// those would send them around the TUN and the VPN without end; left to
/// their own routes, the kill-switch keeps them off the physical interface.
fn capture_rule(config: &LinuxTunConfig, family: &str, action: &str) -> OsCommand {
    OsCommand::new(
        "ip",
        [
            family,
            "rule",
            action,
            "priority",
            &config.rule_priority.to_string(),
            "fwmark",
            "0/0xffffffff",
            "lookup",
            &config.routing_table.to_string(),
        ],
    )
}
fn lan_rule(config: &LinuxTunConfig, family: &str, action: &str) -> OsCommand {
    OsCommand::new(
        "ip",
        [
            family,
            "rule",
            action,
            "priority",
            &(config.rule_priority - 1).to_string(),
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
        ],
    )
}
pub(crate) fn route_commands(checkpoint: &TunCheckpoint) -> Vec<OsCommand> {
    let config = &checkpoint.config;
    let name = &config.interface_name;
    let mut commands = Vec::new();
    if config.capture_dns {
        commands.push(dns_host_route_command(config, "add"));
    }
    if checkpoint.install_default_route {
        for &family in checkpoint.families() {
            commands.push(OsCommand::new(
                "ip",
                [
                    family,
                    "route",
                    "add",
                    "table",
                    &config.routing_table.to_string(),
                    "default",
                    "dev",
                    name,
                ],
            ));
            if config.allow_lan {
                commands.push(lan_rule(config, family, "add"));
            }
            commands.push(capture_rule(config, family, "add"));
        }
    }
    commands
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_host_route_exists_without_default_capture() {
        let checkpoint = TunCheckpoint {
            config: LinuxTunConfig::default(),
            install_default_route: false,
            ownership: format!("egrio:{}", "a".repeat(32)),
            fake_ip_prefixes: Vec::new(),
            excluded_prefixes: Vec::new(),
            applied: false,
            ipv4_only: false,
        };
        let commands = route_commands(&checkpoint);
        assert_eq!(commands.len(), 1);
        assert!(commands[0]
            .args
            .iter()
            .any(|arg| *arg == format!("{LINUX_TUN_VIRTUAL_DNS}/32")));
    }
    #[test]
    fn iproute_json_ownership_uses_vendor_field_shapes() {
        let config = LinuxTunConfig::default();
        // `fwmark 0/0xffffffff` prints without its full mask.
        let rule = serde_json::json!({"priority":20220,"src":"all","fwmark":"0","table":"20220"});
        assert!(capture_rule_owned(&rule, &config));
        let mut masked = rule.clone();
        masked["fwmask"] = serde_json::json!("0xff");
        assert!(!capture_rule_owned(&masked, &config));
        let mut inverted = rule.clone();
        inverted["not"] = serde_json::Value::Null;
        assert!(!capture_rule_owned(&inverted, &config));
        let mut marked = rule;
        marked["fwmark"] = serde_json::json!("0xe671");
        assert!(!capture_rule_owned(&marked, &config));
        assert!(lan_rule_owned(
            &serde_json::json!({"priority":20219,"src":"all","table":"254","suppress_prefixlen":0})
        ));
    }
    #[test]
    fn the_capture_rule_goes_before_its_lan_bypass() {
        let config = LinuxTunConfig::default();
        // `ip rule show` lists the bypass first, by priority.
        let observed = [
            serde_json::json!({"priority":20219,"src":"all","table":"main","suppress_prefixlen":0}),
            serde_json::json!({"priority":20220,"src":"all","fwmark":"0","table":"20220"}),
        ];
        let commands = rule_removal_commands(&config, "-4", &observed).unwrap();
        let priorities: Vec<_> = commands
            .iter()
            .map(|command| {
                let at = command
                    .args
                    .iter()
                    .position(|arg| arg == "priority")
                    .unwrap();
                command.args[at + 1].clone()
            })
            .collect();
        assert_eq!(priorities, ["20220", "20219"]);
        assert!(commands
            .iter()
            .all(|command| command.args.iter().any(|arg| arg == "del")));

        let foreign = [serde_json::json!({"priority":20219,"src":"all","table":"main"})];
        assert!(rule_removal_commands(&config, "-4", &foreign).is_err());
    }
    #[test]
    fn replies_to_inbound_connections_take_the_egress_mark_before_the_kill_switch() {
        let ownership = format!("egrio:{}", "a".repeat(32));
        let checkpoint = TunCheckpoint {
            config: LinuxTunConfig::default(),
            install_default_route: true,
            ownership: ownership.clone(),
            fake_ip_prefixes: Vec::new(),
            excluded_prefixes: Vec::new(),
            applied: false,
            ipv4_only: false,
        };
        let script = reply_mark_script(&checkpoint);
        let lines = script.lines().collect::<Vec<_>>();
        assert_eq!(
            lines[0],
            format!("add table inet egrio_egrio0_replies {{ comment \"{ownership}\"; }}")
        );
        assert!(lines[1]
            .ends_with("inbound { type filter hook prerouting priority -150; policy accept; }"));
        assert!(lines[2].ends_with(
            "inbound iifname != { \"lo\", \"egrio0\" } fib daddr type local ct state new ct mark 0 ct mark set 0xe671"
        ));
        assert!(lines[3].ends_with(
            "inbound ct direction reply ct mark 0xe671 meta mark 0 meta mark set 0xe671"
        ));
        // A route chain reroutes what it marks, ahead of the kill switch at -150.
        assert!(
            lines[4].ends_with("replies { type route hook output priority -151; policy accept; }")
        );
        assert!(lines[5].ends_with(
            "replies ct direction reply ct mark 0xe671 meta mark 0 meta mark set 0xe671"
        ));
        assert_eq!(lines.len(), 6);
    }
    #[test]
    fn exclusions_are_throw_routes_of_their_family_in_egrios_table() {
        let checkpoint = TunCheckpoint {
            config: LinuxTunConfig::default(),
            install_default_route: true,
            ownership: format!("egrio:{}", "a".repeat(32)),
            fake_ip_prefixes: Vec::new(),
            excluded_prefixes: vec![
                "100.64.0.0/10".parse().unwrap(),
                "203.0.113.7/32".parse().unwrap(),
                "fd7a:115c:a1e0::/48".parse().unwrap(),
            ],
            applied: false,
            ipv4_only: false,
        };
        let v4 = wanted_throw_routes(&checkpoint, "-4");
        let v6 = wanted_throw_routes(&checkpoint, "-6");
        assert_eq!(v4.len(), 2);
        assert_eq!(
            v6.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["fd7a:115c:a1e0::/48"]
        );
        let command = throw_route_command(&checkpoint.config, "-6", "add", "fd7a:115c:a1e0::/48");
        assert_eq!(
            command.args,
            [
                "-6",
                "route",
                "add",
                "throw",
                "fd7a:115c:a1e0::/48",
                "table",
                "20220"
            ]
        );
        // Without the default route there is nothing to keep out of.
        let unrouted = TunCheckpoint {
            install_default_route: false,
            ..checkpoint
        };
        assert!(wanted_throw_routes(&unrouted, "-4").is_empty());
        // An IPv4-only TUN routes no IPv6, so it has nothing to keep out.
        let ipv4_only = TunCheckpoint {
            ipv4_only: true,
            ..unrouted.clone()
        };
        let ipv4_only = TunCheckpoint {
            install_default_route: true,
            ..ipv4_only
        };
        assert!(wanted_throw_routes(&ipv4_only, "-6").is_empty());
        assert_eq!(wanted_throw_routes(&ipv4_only, "-4").len(), 2);
        // `ip -j -N` prints a throw route's type as its number.
        assert!(is_throw_route(
            &serde_json::json!({"type":"9","dst":"198.51.100.7","table":"20220"})
        ));
        assert!(!is_throw_route(
            &serde_json::json!({"dst":"default","dev":"egrio0","table":"20220"})
        ));
        // iproute2 prints a host prefix as the bare address.
        assert_eq!(
            "203.0.113.7".parse::<IpPrefix>().unwrap(),
            "203.0.113.7/32".parse::<IpPrefix>().unwrap()
        );
    }
}

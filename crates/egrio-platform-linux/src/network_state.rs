//! Linux TUN OS ownership. Kernel TUN and policy routing are separate from
//! Core packet processing. Only session-created resources may be removed.
use crate::command::{json, number, program_available, run, OsCommand};
use crate::config::{
    LINUX_TUN_IPV4, LINUX_TUN_IPV4_PREFIX, LINUX_TUN_IPV6, LINUX_TUN_IPV6_PREFIX,
    LINUX_TUN_TX_QUEUE_LEN, LINUX_TUN_VIRTUAL_DNS,
};
use crate::routes::{dns_host_routes, priority_rules, table_routes};
use crate::session::Control;
use crate::{LinuxTunConfig, LinuxTunDevice};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, sync::Arc};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinuxTunPreflight {
    pub supported_os: bool,
    pub ready: bool,
    pub has_net_admin: bool,
    pub running_as_root: bool,
    pub tun_device_available: bool,
    pub blockers: Vec<String>,
}

pub fn linux_tun_preflight(config: &LinuxTunConfig) -> LinuxTunPreflight {
    let mut blockers = Vec::new();
    if let Err(error) = config.validate() {
        blockers.push(error);
    }
    let supported_os = cfg!(target_os = "linux");
    let has_net_admin = supported_os
        && std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|text| {
                text.lines().find_map(|line| {
                    line.strip_prefix("CapEff:\t")
                        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                })
            })
            .is_some_and(|mask| mask & (1 << 12) != 0);
    // CAP_NET_ADMIN is bit 12 in linux/uapi/linux/capability.h. Root in a
    // restricted namespace/container may lack it and is not sufficient.
    #[cfg(target_os = "linux")]
    let running_as_root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(target_os = "linux"))]
    let running_as_root = false;
    let tun_device_available = supported_os
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .is_ok();
    if !supported_os {
        blockers.push("Linux TUN is only available on Linux".into());
    } else {
        if !running_as_root {
            blockers.push("Linux TUN command runner requires a root host; a file capability on Egrio alone does not give ip/nft child processes privileges".into());
        }
        if !has_net_admin {
            blockers.push("Linux TUN requires effective CAP_NET_ADMIN for TUNSETIFF, routes, nftables and SO_MARK".into());
        }
        if !tun_device_available {
            blockers.push("/dev/net/tun is unavailable or inaccessible".into());
        }
        for program in [
            Some("ip"),
            config.kill_switch.then_some("nft"),
            config.capture_dns.then_some("resolvectl"),
        ]
        .into_iter()
        .flatten()
        {
            if !program_available(program) {
                blockers.push(format!("required Linux TUN command {program} is missing"));
            }
        }
        if config.capture_dns
            && program_available("resolvectl")
            && run(&OsCommand::new("resolvectl", ["--no-pager", "status"])).is_err()
        {
            blockers.push("Linux TUN DNS capture requires a running systemd-resolved".into());
        }
    }
    LinuxTunPreflight {
        supported_os,
        ready: blockers.is_empty(),
        has_net_admin,
        running_as_root,
        tun_device_available,
        blockers,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TunCheckpoint {
    pub config: LinuxTunConfig,
    pub install_default_route: bool,
    pub ownership: String,
    /// Destinations the Route and Firewall controls keep outside the tunnel.
    #[serde(default)]
    pub excluded_prefixes: Vec<egrio_runtime::IpPrefix>,
    /// The Core's fake-IP pool and its IPv6 projection, which the Firewall
    /// control rejects outside the tunnel.
    #[serde(default)]
    pub fake_ip_prefixes: Vec<egrio_runtime::IpPrefix>,
    /// Set on a control checkpoint prepared while the control was already
    /// applied: restoring it brings these settings back instead of removing
    /// the control, which is how an in-place update rolls back.
    #[serde(default)]
    pub applied: bool,
    /// The kernel keeps IPv6 off on new interfaces, so the TUN carries IPv4
    /// only: no IPv6 address, rules or routes. The firewall then rejects IPv6
    /// that would leave outside the TUN.
    #[serde(default)]
    pub ipv4_only: bool,
}

impl TunCheckpoint {
    /// The `ip` address families the TUN's addresses and routing cover.
    pub(crate) fn families(&self) -> &'static [&'static str] {
        if self.ipv4_only {
            &["-4"]
        } else {
            &["-4", "-6"]
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.config.validate()?;
        if self.ownership.len() != 38
            || !self.ownership.starts_with("egrio:")
            || !self.ownership[6..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid Linux TUN ownership token".into());
        }
        Ok(())
    }
}

pub(crate) trait Backend: Send + Sync + fmt::Debug {
    fn prepare(&self, checkpoint: &TunCheckpoint) -> Result<(), String>;
    /// Opens the TUN with `queues` queues, at least one.
    fn open(
        &self,
        checkpoint: &TunCheckpoint,
        queues: usize,
    ) -> Result<Vec<Box<dyn egrio_core::PacketDevice>>, String>;
    /// Creates the TUN for another user's process: a persistent device owned
    /// by `uid`, configured and verified exactly as `open` configures its
    /// own. Returns the interface index.
    fn open_for_user(&self, checkpoint: &TunCheckpoint, uid: u32) -> Result<u32, String>;
    fn observe(&self, checkpoint: &TunCheckpoint) -> Result<bool, String>;
    fn restore(&self, checkpoint: &TunCheckpoint) -> Result<(), String>;
    fn apply_control(&self, control: Control, checkpoint: &TunCheckpoint) -> Result<(), String>;
    fn observe_control(&self, control: Control, checkpoint: &TunCheckpoint)
        -> Result<bool, String>;
    fn restore_control(&self, control: Control, checkpoint: &TunCheckpoint) -> Result<(), String>;
    /// The physical resolvers, read before the DNS capability applies.
    fn physical_dns_servers(&self) -> Result<Vec<std::net::SocketAddr>, String>;
    /// Whether an interface created now would carry IPv6.
    fn new_interfaces_carry_ipv6(&self) -> bool;
}
#[derive(Debug)]
pub(crate) struct NativeBackend;

impl NativeBackend {
    /// Configures a just-created user TUN as `open` configures its own and
    /// returns its interface index.
    fn configure_user_tun(&self, checkpoint: &TunCheckpoint) -> Result<u32, String> {
        for command in apply_commands(checkpoint) {
            run(&command)?;
        }
        if !self.observe(checkpoint)? {
            return Err(
                "Linux TUN post-apply observation did not match requested resources".into(),
            );
        }
        links()?
            .into_iter()
            .find(|link| link["ifname"] == checkpoint.config.interface_name)
            .and_then(|link| number(&link["ifindex"]))
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| "Linux TUN interface index is unavailable".into())
    }
}
/// The machine-level resources `config` names that already exist: the TUN
/// interface, its rule priority and routing table, the virtual DNS host route
/// and Egrio's nftables tables. Opening TUN requires that none exists, and the
/// helper is only removed while none does, because only a running helper can
/// restore them from the desktop's checkpoint.
pub fn linux_tun_occupied_resources(config: &LinuxTunConfig) -> Result<Vec<String>, String> {
    let mut occupied = Vec::new();
    if links()?
        .iter()
        .any(|link| link["ifname"] == config.interface_name)
    {
        occupied.push(format!("interface {}", config.interface_name));
    }
    for (family, name) in [("-4", "IPv4"), ("-6", "IPv6")] {
        if !priority_rules(config, family)?.is_empty() {
            occupied.push(format!("{name} rule priority {}", config.rule_priority));
        }
        if !table_routes(config, family)?.is_empty() {
            occupied.push(format!("{name} routing table {}", config.routing_table));
        }
    }
    if config.capture_dns && !dns_host_routes()?.is_empty() {
        occupied.push(format!("DNS host route {LINUX_TUN_VIRTUAL_DNS}"));
    }
    for table in [config.nft_table(), config.nft_reply_table()] {
        if crate::nft::has_table(&table)? {
            occupied.push(format!("nftables table inet {table}"));
        }
    }
    Ok(occupied)
}

pub(crate) fn links() -> Result<Vec<Value>, String> {
    json(OsCommand::new("ip", ["-j", "-N", "-d", "link", "show"]))
}

impl Backend for NativeBackend {
    fn physical_dns_servers(&self) -> Result<Vec<std::net::SocketAddr>, String> {
        crate::dns::linux_physical_dns_servers()
    }

    /// A new interface copies `net.ipv6.conf.default`
    /// (Documentation/networking/ip-sysctl.rst, `conf/default/*`), and with
    /// `disable_ipv6` set the kernel refuses its IPv6 addresses and routes.
    fn new_interfaces_carry_ipv6(&self) -> bool {
        ipv6_enabled_in("default")
    }

    fn prepare(&self, checkpoint: &TunCheckpoint) -> Result<(), String> {
        checkpoint.validate()?;
        let preflight = linux_tun_preflight(&checkpoint.config);
        if !preflight.ready {
            return Err(preflight.blockers.join("; "));
        }
        let occupied = linux_tun_occupied_resources(&checkpoint.config)?;
        if !occupied.is_empty() {
            return Err(format!(
                "Linux TUN resources already exist, refusing to attach or replace them: {}",
                occupied.join(", ")
            ));
        }
        Ok(())
    }
    fn open(
        &self,
        checkpoint: &TunCheckpoint,
        queues: usize,
    ) -> Result<Vec<Box<dyn egrio_core::PacketDevice>>, String> {
        // Repeat conflict detection immediately before mutation. TUN_EXCL and
        // `add` (never replace/flush) retain the kernel's collision checks.
        self.prepare(checkpoint)?;
        let devices = LinuxTunDevice::open(&checkpoint.config.interface_name, queues)?;
        for command in apply_commands(checkpoint) {
            run(&command)?;
        }
        if !self.observe(checkpoint)? {
            return Err(
                "Linux TUN post-apply observation did not match requested resources".into(),
            );
        }
        Ok(devices
            .into_iter()
            .map(|device| Box::new(device) as Box<dyn egrio_core::PacketDevice>)
            .collect())
    }
    fn open_for_user(&self, checkpoint: &TunCheckpoint, uid: u32) -> Result<u32, String> {
        self.prepare(checkpoint)?;
        let name = &checkpoint.config.interface_name;
        LinuxTunDevice::create_for_user(name, uid)?;
        // The device outlives this process's descriptor, so a failed
        // configuration deletes it here, as closing `open`'s descriptor
        // would: restore only deletes a device carrying the ownership alias.
        self.configure_user_tun(checkpoint).inspect_err(|_| {
            let _ = run(&OsCommand::new("ip", ["link", "delete", "dev", name]));
        })
    }
    fn observe(&self, checkpoint: &TunCheckpoint) -> Result<bool, String> {
        let config = &checkpoint.config;
        let link = links()?
            .into_iter()
            .find(|link| link["ifname"] == config.interface_name);
        let Some(link) = link else { return Ok(false) };
        if link["ifalias"] != checkpoint.ownership
            || link["linkinfo"]["info_kind"] != "tun"
            || number(&link["mtu"]) != Some(config.mtu.into())
        {
            return Err("Linux TUN interface ownership, kind or MTU changed".into());
        }
        if !link["flags"]
            .as_array()
            .is_some_and(|flags| flags.iter().any(|flag| flag == "UP"))
        {
            return Ok(false);
        }
        let addresses = json(OsCommand::new(
            "ip",
            ["-j", "address", "show", "dev", &config.interface_name],
        ))?;
        let entries = addresses
            .first()
            .and_then(|address| address["addr_info"].as_array())
            .ok_or("Linux TUN address observation missing")?;
        let has_address = |address: String, prefix: u8| {
            entries.iter().any(|entry| {
                entry["local"] == address.as_str()
                    && number(&entry["prefixlen"]) == Some(prefix.into())
            })
        };
        if !has_address(LINUX_TUN_IPV4.to_string(), LINUX_TUN_IPV4_PREFIX)
            || (!checkpoint.ipv4_only
                && !has_address(LINUX_TUN_IPV6.to_string(), LINUX_TUN_IPV6_PREFIX))
        {
            return Ok(false);
        }

        Ok(true)
    }
    fn restore(&self, checkpoint: &TunCheckpoint) -> Result<(), String> {
        checkpoint.validate()?;
        if !cfg!(target_os = "linux") {
            return Err("Linux TUN restore is only available on Linux".into());
        }
        let config = &checkpoint.config;
        if links()?
            .iter()
            .any(|link| link["ifname"] == config.interface_name)
        {
            require_owned_link(checkpoint)?;
            run(&OsCommand::new(
                "ip",
                ["link", "delete", "dev", &config.interface_name],
            ))?;
        }
        if links()?
            .iter()
            .any(|link| link["ifname"] == config.interface_name)
        {
            return Err("Linux TUN interface removal could not be verified".into());
        }
        Ok(())
    }
    fn apply_control(&self, control: Control, checkpoint: &TunCheckpoint) -> Result<(), String> {
        match control {
            Control::Route => crate::routes::apply(checkpoint),
            Control::Dns => crate::dns::apply(checkpoint),
            Control::Firewall => crate::firewall::apply(checkpoint),
        }
    }
    fn observe_control(
        &self,
        control: Control,
        checkpoint: &TunCheckpoint,
    ) -> Result<bool, String> {
        match control {
            Control::Route => crate::routes::observe(checkpoint),
            Control::Dns => crate::dns::observe(checkpoint),
            Control::Firewall => crate::firewall::observe(checkpoint),
        }
    }
    fn restore_control(&self, control: Control, checkpoint: &TunCheckpoint) -> Result<(), String> {
        match control {
            Control::Route => crate::routes::restore(checkpoint),
            Control::Dns => crate::dns::restore(checkpoint),
            Control::Firewall => crate::firewall::restore(checkpoint),
        }
    }
}

pub(crate) fn apply_commands(checkpoint: &TunCheckpoint) -> Vec<OsCommand> {
    let config = &checkpoint.config;
    let name = &config.interface_name;
    let mut commands = vec![
        OsCommand::new(
            "ip",
            ["link", "set", "dev", name, "alias", &checkpoint.ownership],
        ),
        OsCommand::new(
            "ip",
            [
                "address",
                "add",
                &format!("{LINUX_TUN_IPV4}/{LINUX_TUN_IPV4_PREFIX}"),
                "dev",
                name,
            ],
        ),
    ];
    if !checkpoint.ipv4_only {
        commands.push(OsCommand::new(
            "ip",
            [
                "-6",
                "address",
                "add",
                &format!("{LINUX_TUN_IPV6}/{LINUX_TUN_IPV6_PREFIX}"),
                "dev",
                name,
                "nodad",
            ],
        ));
    }
    commands.push(OsCommand::new(
        "ip",
        [
            "link",
            "set",
            "dev",
            name,
            "mtu",
            &config.mtu.to_string(),
            "txqueuelen",
            &LINUX_TUN_TX_QUEUE_LEN.to_string(),
            "up",
        ],
    ));
    commands
}

pub(crate) fn require_owned_link(checkpoint: &TunCheckpoint) -> Result<(), String> {
    let link = links()?
        .into_iter()
        .find(|link| link["ifname"] == checkpoint.config.interface_name)
        .ok_or("Linux TUN interface is absent")?;
    if link["ifalias"] != checkpoint.ownership || link["linkinfo"]["info_kind"] != "tun" {
        return Err("Linux TUN interface ownership changed".into());
    }
    Ok(())
}

pub(crate) fn native_backend() -> Arc<dyn Backend> {
    Arc::new(NativeBackend)
}

/// Whether the IPv6 configuration `conf` (`default` or an interface name)
/// has IPv6 on. A kernel without IPv6 has no such file.
fn ipv6_enabled_in(conf: &str) -> bool {
    std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{conf}/disable_ipv6"))
        .is_ok_and(|value| value.trim() == "0")
}

/// Whether the interface `name` carries IPv6, so Core egress may resolve and
/// dial IPv6 while it captures.
pub fn linux_interface_carries_ipv6(name: &str) -> bool {
    ipv6_enabled_in(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_uses_tun_policy_routes_and_a_table_that_rejects_only_leaks() {
        let checkpoint = TunCheckpoint {
            config: LinuxTunConfig::default(),
            install_default_route: true,
            ownership: format!("egrio:{}", "a".repeat(32)),
            fake_ip_prefixes: Vec::new(),
            excluded_prefixes: Vec::new(),
            applied: false,
            ipv4_only: false,
        };
        checkpoint.validate().unwrap();
        let commands = crate::routes::route_commands(&checkpoint);
        // One capture rule per family, for unmarked traffic only.
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.args.iter().any(|arg| arg == "0/0xffffffff"))
                .count(),
            2
        );
        assert!(!commands
            .iter()
            .any(|command| command.args.iter().any(|arg| arg == "not")));
        let script = crate::firewall::nft_script(&checkpoint);
        assert!(script.contains("meta mark 0xe671 accept"));
        assert!(script.contains(
            "meta oiftype { ether, ppp } meta l4proto { tcp, udp } th dport { 53, 853 } reject"
        ));
        // What leaves outside the TUN on purpose passes: no rule rejects all.
        assert!(!script.lines().any(|line| line.ends_with(" output reject")));
        assert!(!commands.iter().any(|command| command
            .args
            .iter()
            .any(|arg| arg == "replace" || arg == "flush")));
        assert!(commands
            .iter()
            .all(|command| !format!("{command:?}").contains("tproxy")));
    }

    #[test]
    fn the_link_comes_up_with_room_for_bursts_of_packets() {
        let checkpoint = TunCheckpoint {
            config: LinuxTunConfig::default(),
            install_default_route: true,
            ownership: format!("egrio:{}", "a".repeat(32)),
            fake_ip_prefixes: Vec::new(),
            excluded_prefixes: Vec::new(),
            applied: false,
            ipv4_only: false,
        };
        let commands = apply_commands(&checkpoint);
        let up = commands.last().expect("the link is brought up last");
        let queue = up
            .args
            .iter()
            .position(|arg| arg == "txqueuelen")
            .expect("the queue length is set");
        assert_eq!(up.args[queue + 1], LINUX_TUN_TX_QUEUE_LEN.to_string());
        assert_eq!(up.args.last().map(String::as_str), Some("up"));
    }

    #[test]
    fn an_ipv4_only_tun_gets_no_ipv6_address_rules_or_routes() {
        let checkpoint = TunCheckpoint {
            config: LinuxTunConfig::default(),
            install_default_route: true,
            ownership: format!("egrio:{}", "a".repeat(32)),
            fake_ip_prefixes: Vec::new(),
            excluded_prefixes: vec!["fd7a:115c:a1e0::/48".parse().unwrap()],
            applied: false,
            ipv4_only: true,
        };
        let commands = apply_commands(&checkpoint)
            .into_iter()
            .chain(crate::routes::route_commands(&checkpoint))
            .collect::<Vec<_>>();
        assert!(!commands
            .iter()
            .any(|command| command.args.first().is_some_and(|arg| arg == "-6")));
        assert!(commands
            .iter()
            .any(|command| command.args.iter().any(|arg| arg == "0/0xffffffff")));
        // IPv6 the TUN does not carry is rejected but for the excluded.
        let script = crate::firewall::nft_script(&checkpoint);
        let excluded = script
            .find("ip6 daddr { fd7a:115c:a1e0::/48 } accept")
            .unwrap();
        let reject = script.find("output meta nfproto ipv6 reject").unwrap();
        assert!(excluded < reject);
    }

    #[test]
    fn fake_ips_are_rejected_outside_the_tun_after_the_dns_reject() {
        let checkpoint = TunCheckpoint {
            config: LinuxTunConfig::default(),
            install_default_route: true,
            ownership: format!("egrio:{}", "a".repeat(32)),
            fake_ip_prefixes: vec![
                "198.18.0.0/16".parse().unwrap(),
                "fd11:5ca1:ab1e:1::c612:0/112".parse().unwrap(),
            ],
            excluded_prefixes: vec![
                "100.64.0.0/10".parse().unwrap(),
                "fd7a:115c:a1e0::/48".parse().unwrap(),
            ],
            applied: false,
            ipv4_only: false,
        };
        let script = crate::firewall::nft_script(&checkpoint);
        let tun = script.find("oifname \"egrio0\" accept").unwrap();
        let dns = script
            .find(
                "meta oiftype { ether, ppp } meta l4proto { tcp, udp } th dport { 53, 853 } reject",
            )
            .unwrap();
        let v4 = script.find("ip daddr { 198.18.0.0/16 } reject").unwrap();
        let v6 = script
            .find("ip6 daddr { fd11:5ca1:ab1e:1::c612:0/112 } reject")
            .unwrap();
        assert!(tun < dns && dns < v4 && v4 < v6);
        // Excluded destinations already leave outside the TUN; with IPv6
        // tunneled nothing rejects them.
        assert!(!script.contains("100.64.0.0/10"));
        assert!(!script.contains("fd7a:115c:a1e0::/48"));
    }
}

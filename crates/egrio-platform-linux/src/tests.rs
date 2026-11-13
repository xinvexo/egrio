use crate::network_state::{Backend, TunCheckpoint};
use crate::session::Control;
use crate::{LinuxTun, LinuxTunConfig};
use egrio_runtime::{
    CapabilityKind, DnsControl, DnsSettings, FirewallControl, FirewallSettings, PacketCapture,
    PacketCaptureSettings, PacketCaptureSource, RouteControl, RouteSettings,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct FakeBackend {
    active: AtomicBool,
    fail_restore: AtomicBool,
    fail_open: AtomicBool,
    lacks_ipv6: AtomicBool,
    events: Mutex<Vec<String>>,
}

#[derive(Debug)]
struct Device;

impl egrio_core::PacketDevice for Device {
    fn name(&self) -> &str {
        "linux-test"
    }
    fn try_recv(&mut self) -> Result<Option<egrio_core::ReceivedPacket>, String> {
        Ok(None)
    }
    fn try_send(&mut self, _: &[u8]) -> Result<egrio_core::PacketSend, String> {
        Ok(egrio_core::PacketSend::Sent)
    }
    fn ready(&mut self, _: egrio_core::PacketInterest) -> egrio_core::PacketReady<'_> {
        Box::pin(std::future::pending())
    }
}

fn label(control: Control) -> &'static str {
    match control {
        Control::Route => "route",
        Control::Dns => "dns",
        Control::Firewall => "firewall",
    }
}

impl FakeBackend {
    fn record(&self, event: String) {
        self.events.lock().unwrap().push(event);
    }
}

impl Backend for FakeBackend {
    fn physical_dns_servers(&self) -> Result<Vec<std::net::SocketAddr>, String> {
        Ok(vec!["192.0.2.53:53".parse().unwrap()])
    }

    fn new_interfaces_carry_ipv6(&self) -> bool {
        !self.lacks_ipv6.load(Ordering::SeqCst)
    }

    fn prepare(&self, _: &TunCheckpoint) -> Result<(), String> {
        if self.active.load(Ordering::SeqCst) {
            Err("occupied".into())
        } else {
            Ok(())
        }
    }
    fn open(
        &self,
        _: &TunCheckpoint,
        queues: usize,
    ) -> Result<Vec<Box<dyn egrio_core::PacketDevice>>, String> {
        self.record(format!("packet-open-{queues}"));
        self.active.store(true, Ordering::SeqCst);
        if self.fail_open.load(Ordering::SeqCst) {
            Err("partial apply".into())
        } else {
            Ok((0..queues)
                .map(|_| Box::new(Device) as Box<dyn egrio_core::PacketDevice>)
                .collect())
        }
    }
    fn open_for_user(&self, _: &TunCheckpoint, uid: u32) -> Result<u32, String> {
        self.record(format!("packet-open-for-{uid}"));
        self.active.store(true, Ordering::SeqCst);
        if self.fail_open.load(Ordering::SeqCst) {
            Err("partial apply".into())
        } else {
            Ok(42)
        }
    }
    fn observe(&self, _: &TunCheckpoint) -> Result<bool, String> {
        Ok(self.active.load(Ordering::SeqCst))
    }
    fn restore(&self, _: &TunCheckpoint) -> Result<(), String> {
        if self.fail_restore.load(Ordering::SeqCst) {
            return Err("cleanup interrupted".into());
        }
        self.record("packet-restore".into());
        self.active.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn apply_control(&self, control: Control, checkpoint: &TunCheckpoint) -> Result<(), String> {
        assert_eq!(checkpoint.install_default_route, control == Control::Route);
        self.record(format!("{}-apply", label(control)));
        Ok(())
    }
    fn observe_control(&self, _: Control, _: &TunCheckpoint) -> Result<bool, String> {
        Ok(true)
    }
    fn restore_control(&self, control: Control, checkpoint: &TunCheckpoint) -> Result<(), String> {
        assert_eq!(checkpoint.install_default_route, control == Control::Route);
        self.record(format!("{}-restore", label(control)));
        Ok(())
    }
}

fn tun(config: LinuxTunConfig) -> (LinuxTun, Arc<FakeBackend>) {
    let backend = Arc::new(FakeBackend::default());
    (LinuxTun::with_backend(config, backend.clone()), backend)
}

/// The default configuration's MTU, which a capture request must match.
fn default_mtu() -> u32 {
    LinuxTunConfig::default().mtu
}

fn packet(mtu: u32) -> PacketCaptureSettings {
    PacketCaptureSettings {
        source: PacketCaptureSource::Tun,
        mtu,
        install_default_route: false,
        install_dns: false,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    }
}

fn dns() -> DnsSettings {
    DnsSettings {
        servers: Vec::new(),
        search_domains: Vec::new(),
    }
}

fn route() -> RouteSettings {
    RouteSettings {
        default_route: true,
        excluded_prefixes: Vec::new(),
    }
}

#[tokio::test]
async fn a_kernel_without_ipv6_on_new_interfaces_prepares_an_ipv4_only_tun() {
    let (tun, backend) = tun(LinuxTunConfig::default());
    backend.lacks_ipv6.store(true, Ordering::SeqCst);
    let checkpoint = tun.capture.prepare(&packet(default_mtu())).await.unwrap();
    assert_eq!(checkpoint.payload["ipv4_only"], true);
    let (tun, _) = self::tun(LinuxTunConfig::default());
    let checkpoint = tun.capture.prepare(&packet(default_mtu())).await.unwrap();
    assert_eq!(checkpoint.payload["ipv4_only"], false);
}

#[test]
fn the_core_capture_config_carries_the_tun_mtu() {
    assert_eq!(crate::linux_tun_core_capture_config().mtu, default_mtu());
    assert_eq!(default_mtu(), 65535, "the tun driver's largest MTU");
}

#[tokio::test]
async fn capability_checkpoints_share_owner_and_preserve_route_intent_on_restore() {
    let (tun, backend) = tun(LinuxTunConfig::default());
    let packet = packet(default_mtu());
    let firewall = FirewallSettings {
        kill_switch: true,
        allow_lan: true,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    };
    let packet_checkpoint = tun.capture.prepare(&packet).await.unwrap();
    let firewall_checkpoint = tun.firewall.prepare(&firewall).await.unwrap();
    let route_checkpoint = tun.route.prepare(&route()).await.unwrap();
    let dns_checkpoint = tun.dns.prepare(&dns()).await.unwrap();
    for checkpoint in [&firewall_checkpoint, &route_checkpoint, &dns_checkpoint] {
        assert_eq!(
            checkpoint.payload["ownership"],
            packet_checkpoint.payload["ownership"]
        );
    }
    assert_eq!(packet_checkpoint.payload["install_default_route"], false);
    assert_eq!(route_checkpoint.payload["install_default_route"], true);
    let opened = tun.capture.open(&packet, 2).await.unwrap();
    tun.firewall.apply(&firewall).await.unwrap();
    tun.route.apply(&route()).await.unwrap();
    tun.dns.apply(&dns()).await.unwrap();
    assert!(tun.route.observe().await.unwrap().active);
    // The route intent cannot change in place.
    let unrouted = RouteSettings {
        default_route: false,
        excluded_prefixes: Vec::new(),
    };
    assert!(tun.route.prepare(&unrouted).await.is_err());
    tun.dns.restore(&dns_checkpoint).await.unwrap();
    tun.route.restore(&route_checkpoint).await.unwrap();
    tun.firewall.restore(&firewall_checkpoint).await.unwrap();
    assert!(!tun.route.observe().await.unwrap().active);
    drop(opened);
    tun.capture.restore(&packet_checkpoint).await.unwrap();
    assert_eq!(
        *backend.events.lock().unwrap(),
        vec![
            "packet-open-2",
            "firewall-apply",
            "route-apply",
            "dns-apply",
            "dns-restore",
            "route-restore",
            "firewall-restore",
            "packet-restore"
        ]
    );
}

#[tokio::test]
async fn exclusions_update_in_place_and_roll_back_to_the_applied_baseline() {
    let (tun, backend) = tun(LinuxTunConfig::default());
    let packet = packet(default_mtu());
    let excluded = |prefixes: &[&str]| -> Vec<egrio_runtime::IpPrefix> {
        prefixes
            .iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect()
    };
    let rule_mode = RouteSettings {
        default_route: true,
        excluded_prefixes: excluded(&["100.64.0.0/10"]),
    };
    let global_mode = route();
    tun.capture.prepare(&packet).await.unwrap();
    let start = tun.route.prepare(&rule_mode).await.unwrap();
    let opened = tun.capture.open(&packet, 2).await.unwrap();
    tun.route.apply(&rule_mode).await.unwrap();

    // Re-preparing an applied control records what is applied as the baseline.
    let baseline = tun.route.prepare(&global_mode).await.unwrap();
    assert_eq!(baseline.payload["applied"], true);
    assert_eq!(baseline.payload["excluded_prefixes"][0]["prefix_len"], 10);
    tun.route.apply(&global_mode).await.unwrap();
    // Restoring that baseline brings the exclusion back and keeps routing.
    tun.route.restore(&baseline).await.unwrap();
    assert!(tun.route.observe().await.unwrap().active);
    let again = tun.route.prepare(&global_mode).await.unwrap();
    assert_eq!(again.payload["excluded_prefixes"][0]["prefix_len"], 10);
    // The start checkpoint removes routing altogether.
    assert_eq!(start.payload["applied"], false);
    tun.route.restore(&start).await.unwrap();
    assert!(!tun.route.observe().await.unwrap().active);
    drop(opened);
    assert_eq!(
        backend
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.starts_with("route-"))
            .cloned()
            .collect::<Vec<_>>(),
        [
            "route-apply",
            "route-apply",
            "route-restore",
            "route-restore"
        ]
    );
}

#[tokio::test]
async fn dns_requires_route_to_own_the_virtual_resolver_route() {
    let (tun, _) = tun(LinuxTunConfig::default());
    tun.capture.prepare(&packet(default_mtu())).await.unwrap();
    assert!(tun.dns.prepare(&dns()).await.is_err());
    tun.route.prepare(&route()).await.unwrap();
    tun.dns.prepare(&dns()).await.unwrap();
    let foreign = DnsSettings {
        servers: vec!["1.1.1.1".parse().unwrap()],
        search_domains: Vec::new(),
    };
    assert!(tun.dns.prepare(&foreign).await.is_err());
}

#[tokio::test]
async fn partial_open_and_failed_restore_retain_ownership_until_retry() {
    let (tun, backend) = tun(LinuxTunConfig::default());
    let settings = packet(default_mtu());
    let checkpoint = tun.capture.prepare(&settings).await.unwrap();
    backend.fail_open.store(true, Ordering::SeqCst);
    assert!(tun.capture.open(&settings, 1).await.is_err());
    assert!(tun.capture.prepare(&settings).await.is_err());
    backend.fail_restore.store(true, Ordering::SeqCst);
    assert!(tun.capture.restore(&checkpoint).await.is_err());
    assert!(tun.capture.observe().await.unwrap().active);
    backend.fail_restore.store(false, Ordering::SeqCst);
    tun.capture.restore(&checkpoint).await.unwrap();
    assert!(!tun.capture.observe().await.unwrap().active);
    assert!(tun.capture.prepare(&settings).await.is_ok());
}

#[tokio::test]
async fn rejects_mtu_drift_before_preparing_or_opening_the_device() {
    let (tun, backend) = tun(LinuxTunConfig {
        mtu: 1420,
        ..LinuxTunConfig::default()
    });
    assert!(tun.capture.prepare(&packet(default_mtu())).await.is_err());
    let checkpoint = tun.capture.prepare(&packet(1420)).await.unwrap();
    assert_eq!(checkpoint.payload["config"]["mtu"], 1420);
    assert!(tun.capture.open(&packet(default_mtu()), 1).await.is_err());
    assert!(backend.events.lock().unwrap().is_empty());
    assert!(!backend.active.load(Ordering::SeqCst));
}

#[tokio::test]
async fn rejects_wrong_source_and_mismatched_checkpoint_before_backend() {
    let (tun, _) = tun(LinuxTunConfig::default());
    assert!(tun
        .capture
        .prepare(&PacketCaptureSettings {
            source: PacketCaptureSource::PacketTunnel,
            ..packet(default_mtu())
        })
        .await
        .is_err());
    let mut checkpoint = tun.capture.prepare(&packet(default_mtu())).await.unwrap();
    checkpoint.schema_version = 99;
    assert_eq!(
        tun.capture
            .restore(&checkpoint)
            .await
            .unwrap_err()
            .capability,
        CapabilityKind::PacketCapture
    );
    assert_eq!(
        tun.dns.restore(&checkpoint).await.unwrap_err().capability,
        CapabilityKind::Dns
    );
    assert_eq!(
        tun.firewall
            .restore(&checkpoint)
            .await
            .unwrap_err()
            .capability,
        CapabilityKind::Firewall
    );
    assert_eq!(
        tun.route.restore(&checkpoint).await.unwrap_err().capability,
        CapabilityKind::Route
    );
}

#[tokio::test]
async fn egress_overlay_follows_the_open_tun() {
    let (tun, _) = tun(LinuxTunConfig::default());
    let guard = tun.egress_socket_guard();
    let settings = packet(default_mtu());
    assert!(guard.capture_overlay().is_none());
    let checkpoint = tun.capture.prepare(&settings).await.unwrap();
    let open = tun.capture.open(&settings, 4).await.unwrap();
    assert_eq!(open.queues.len(), 4);
    let overlay = guard
        .capture_overlay()
        .expect("an open TUN reports its resolvers");
    assert_eq!(
        overlay.dns_servers,
        vec!["192.0.2.53:53".parse::<std::net::SocketAddr>().unwrap()]
    );
    tun.capture.restore(&checkpoint).await.unwrap();
    assert!(guard.capture_overlay().is_none());
}

#[tokio::test]
async fn a_user_tun_reports_its_interface_and_leaves_local_egress_alone() {
    let (tun, backend) = tun(LinuxTunConfig::default());
    let guard = tun.egress_socket_guard();
    let settings = packet(default_mtu());
    let checkpoint = tun.capture.prepare(&settings).await.unwrap();
    let opened = tun.capture.open_for_user(&settings, 1000).await.unwrap();
    assert_eq!(
        opened,
        crate::LinuxUserTun {
            interface_name: "egrio0".into(),
            interface_index: 42,
            mtu: default_mtu(),
            physical_dns_servers: vec!["192.0.2.53:53".parse().unwrap()],
        }
    );
    // The resolvers go to the user's process; this one's egress is untouched.
    assert!(guard.capture_overlay().is_none());
    assert!(tun.capture.prepare(&settings).await.is_err());
    tun.capture.restore(&checkpoint).await.unwrap();
    assert!(tun.capture.prepare(&settings).await.is_ok());
    assert_eq!(
        *backend.events.lock().unwrap(),
        vec!["packet-open-for-1000", "packet-restore"]
    );
}

#[tokio::test]
async fn restores_refuse_checkpoints_naming_foreign_kernel_objects() {
    let (tun, backend) = tun(LinuxTunConfig::default());
    let checkpoint = tun.capture.prepare(&packet(default_mtu())).await.unwrap();
    for (field, value) in [
        ("interface_name", serde_json::json!("wg0")),
        ("fwmark", serde_json::json!(51820)),
        ("routing_table", serde_json::json!(51820)),
        ("rule_priority", serde_json::json!(32765)),
    ] {
        let mut foreign = checkpoint.clone();
        foreign.payload["config"][field] = value;
        assert!(tun.capture.restore(&foreign).await.is_err(), "{field}");
        let mut route = foreign.clone();
        route.lease_key = egrio_runtime::PlatformLeaseKey::default_route();
        assert!(tun.route.restore(&route).await.is_err(), "{field}");
    }
    assert!(backend.events.lock().unwrap().is_empty());
}

#[test]
fn fake_pool_cannot_allocate_the_declared_tun_addresses() {
    let (tun, _) = tun(LinuxTunConfig::default());
    let reserved = tun.capture.reserved_addresses();
    let mut dns = egrio_core::RuntimeProfile::new("linux-fake-ip").dns;
    dns.enabled = true;
    dns.enhanced_mode = egrio_core::dns::config::DnsMode::FakeIp;
    egrio_core::validate_fake_ip_capture_addresses(&dns, reserved.clone()).unwrap();
    dns.fake_ip_range = "10.255.0.0/16".parse().unwrap();
    assert!(
        egrio_core::validate_fake_ip_capture_addresses(&dns, reserved)
            .unwrap_err()
            .contains("10.255.255.1")
    );
}

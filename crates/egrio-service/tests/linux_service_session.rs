#![cfg(target_os = "linux")]
//! End-to-end check of the Linux service host on a disposable VM.
//!
//! It changes the machine's network for a few seconds: a TUN with policy
//! routes, resolved link DNS and nftables leak protection, so it is ignored
//! by default. Run it as a non-root user the
//! running helper serves (listed by `egrio-service install-linux-service
//! --allow-uid <uid>` as root); it ends with everything restored.
//!
//! ```text
//! cargo test -p egrio-service --test linux_service_session -- --ignored --nocapture
//! ```

use std::io;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egrio_core::PacketDevice;
use egrio_platform_linux::{LinuxTunDevice, LINUX_MARK_SOCKET, LINUX_SERVICE_SOCKET};
use egrio_runtime::{
    CapabilityCheckpoint, CapabilityKind, DnsSettings, FirewallSettings, PacketCaptureSettings,
    PacketCaptureSource, RouteSettings, RuntimeId,
};
use egrio_service::client::ControlClient;
use egrio_service::linux::MarkClient;
use egrio_service::unix::UnixSocketTransport;
use egrio_service::{ControlRequest, ControlResponse, PacketChannel};

/// Outside the LAN, so only the TUN or the physical route can carry it; a
/// public resolver that answers on both its HTTPS and DNS ports.
const PROBE: Ipv4Addr = Ipv4Addr::new(223, 5, 5, 5);
const PROBE_PORT: u16 = 443;
/// DNS outside the TUN is what leak protection rejects.
const DNS_PORT: u16 = 53;

async fn connect() -> ControlClient {
    ControlClient::connect(
        Arc::new(UnixSocketTransport::new(LINUX_SERVICE_SOCKET)),
        RuntimeId::new(),
        "linux-service-session-check",
    )
    .await
    .expect("an allowed user opens a session")
}

async fn request(client: &ControlClient, request: ControlRequest) -> ControlResponse {
    match client.request(request).await.expect("the service answers") {
        ControlResponse::Error { code, message } => panic!("{code:?}: {message}"),
        response => response,
    }
}

async fn prepare(
    client: &ControlClient,
    capability: CapabilityKind,
    settings: impl serde::Serialize,
) -> CapabilityCheckpoint {
    let settings = serde_json::to_value(settings).unwrap();
    match request(
        client,
        ControlRequest::Prepare {
            capability,
            settings,
        },
    )
    .await
    {
        ControlResponse::Checkpoint(checkpoint) => checkpoint,
        response => panic!("unexpected prepare response {response:?}"),
    }
}

async fn apply(
    client: &ControlClient,
    capability: CapabilityKind,
    settings: impl serde::Serialize,
) {
    let settings = serde_json::to_value(settings).unwrap();
    let response = request(
        client,
        ControlRequest::Apply {
            capability,
            settings,
        },
    )
    .await;
    assert!(
        matches!(response, ControlResponse::Operation(report) if report.verified),
        "{capability:?} apply"
    );
}

async fn restore(client: &ControlClient, checkpoint: &CapabilityCheckpoint) {
    let response = request(
        client,
        ControlRequest::Restore {
            checkpoint: checkpoint.clone(),
        },
    )
    .await;
    assert!(matches!(response, ControlResponse::Operation(_)));
}

fn packet_settings() -> PacketCaptureSettings {
    PacketCaptureSettings {
        source: PacketCaptureSource::Tun,
        mtu: egrio_platform_linux::LinuxTunConfig::default().mtu,
        install_default_route: false,
        install_dns: false,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    }
}

fn route_settings() -> RouteSettings {
    RouteSettings {
        default_route: true,
        excluded_prefixes: Vec::new(),
    }
}

fn dns_settings() -> DnsSettings {
    DnsSettings {
        servers: Vec::new(),
        search_domains: Vec::new(),
    }
}

fn firewall_settings() -> FirewallSettings {
    FirewallSettings {
        kill_switch: true,
        allow_lan: true,
        excluded_prefixes: Vec::new(),
        fake_ip_prefixes: Vec::new(),
    }
}

/// A blocking TCP connect to the probe's HTTPS port, optionally marked by
/// the service first; `Ok` means the SYN left the machine and was answered.
fn connect_probe(marked: bool) -> io::Result<()> {
    connect_probe_port(marked, PROBE_PORT)
}

fn connect_probe_port(marked: bool, port: u16) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    if marked {
        MarkClient::new(LINUX_MARK_SOCKET).mark(socket.as_fd())?;
    }
    let timeout = libc::timeval {
        tv_sec: 3,
        tv_usec: 0,
    };
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(PROBE).to_be(),
        },
        sin_zero: [0; 8],
    };
    let connected = unsafe {
        // A blocking connect gives up after SO_SNDTIMEO (socket(7)).
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::connect(
            socket.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if connected == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn link_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", name])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn capture_rules() -> String {
    let output = Command::new("ip")
        .args(["rule", "show", "priority", "20220"])
        .output()
        .expect("ip rule");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Waits for the first IPv4 packet the TUN carries to the probe, on
/// whichever queue the kernel picks for its flow.
fn probe_packet_on(queues: &mut [LinuxTunDevice]) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let mut idle = true;
        for queue in queues.iter_mut() {
            match queue.try_recv().expect("read the attached TUN") {
                Some(packet)
                    if packet.bytes[0] >> 4 == 4 && packet.bytes[16..20] == PROBE.octets() =>
                {
                    return true
                }
                Some(_) => idle = false,
                None => {}
            }
        }
        if idle {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "changes the machine's network; run on a VM against a running service"]
async fn a_session_runs_tun_mode_and_an_abandoned_one_leaves_the_network_as_it_was() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as the allowed desktop user, not root"
    );
    assert!(!link_exists("egrio0"), "a TUN is already up");

    // A session prepares, opens and applies TUN mode.
    let client = connect().await;
    let capture = prepare(&client, CapabilityKind::PacketCapture, packet_settings()).await;
    let route = prepare(&client, CapabilityKind::Route, route_settings()).await;
    let dns = prepare(&client, CapabilityKind::Dns, dns_settings()).await;
    let firewall = prepare(&client, CapabilityKind::Firewall, firewall_settings()).await;
    let channel = match request(
        &client,
        ControlRequest::OpenPacketCapture {
            settings: packet_settings(),
        },
    )
    .await
    {
        ControlResponse::PacketChannel(PacketChannel::OwnedTun(channel)) => channel,
        response => panic!("unexpected open response {response:?}"),
    };
    assert_eq!(
        (channel.interface_name.as_str(), channel.mtu),
        (
            "egrio0",
            egrio_platform_linux::LinuxTunConfig::default().mtu
        )
    );
    assert!(!channel.physical_dns_servers.is_empty());
    let mut queues = LinuxTunDevice::attach(&channel.interface_name, 4)
        .expect("the TUN's owner attaches its queues without CAP_NET_ADMIN");
    assert_eq!(queues.len(), 4);
    apply(&client, CapabilityKind::Firewall, firewall_settings()).await;
    apply(&client, CapabilityKind::Route, route_settings()).await;
    apply(&client, CapabilityKind::Dns, dns_settings()).await;
    assert!(capture_rules().contains("lookup 20220"));

    // Unmarked traffic enters the TUN; a socket the service marked leaves
    // through the physical route.
    let unmarked = std::thread::spawn(|| connect_probe(false));
    assert!(probe_packet_on(&mut queues), "unmarked SYN reaches the TUN");
    connect_probe(true).expect("a marked socket bypasses the TUN");
    assert!(unmarked.join().unwrap().is_err());

    // The desktop disappears without restoring anything: the service
    // removes all of it, leak protection included.
    drop(queues);
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(5);
    while link_exists("egrio0") && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!link_exists("egrio0"), "the ended session's TUN is deleted");
    assert!(!capture_rules().contains("lookup 20220"));
    connect_probe(false).expect("the network works as it does without Egrio");
    connect_probe_port(false, DNS_PORT).expect("no DNS reject is left behind");

    // A later session restores the abandoned session's checkpoints, which
    // find nothing left.
    let client = connect().await;
    for checkpoint in [&firewall, &dns, &route, &capture] {
        restore(&client, checkpoint).await;
    }
    connect_probe(false).expect("the network still works after the restore");
    client.close().await.unwrap();
}

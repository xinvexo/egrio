//! The server-assembly host: a deployment's role is
//! composition, not a mode. This module composes `egrio-core` into the
//! *server* role — inbound acceptors plus DIRECT/upstream outbounds — the
//! mirror of the capture facade in this same crate composing the core into
//! the *capture* role.
//!
//! It is ungated and core-only: it links no platform-capture adapter, so the
//! `egrio-server` binary (`--no-default-features --features server`) carries
//! none. The inbounds the core exposes compose here: the plaintext SOCKS5/HTTP
//! acceptor, the Shadowsocks server inbound (`ServerConfig::shadowsocks`), the
//! Trojan inbound (`ServerConfig::trojan`) and the Hysteria2 QUIC/H3 inbound
//! (`ServerConfig::hysteria2`) — each encrypted one authenticating against a pre-shared
//! user table and surfacing its auth-failure count on the manager. The `server`
//! cargo feature enables the core `server` feature that terminates the
//! Hysteria2 TLS (certificate loading); per-user accounting is the next cut.
//!
//! The open-proxy safety floor is built into the
//! server egress here, not exposed as a config knob: a public inbound over
//! DIRECT must never be able to pivot into the host's own loopback or LAN.

use std::net::SocketAddr;

use egrio_core::{
    CoreInbound, CoreSessionManager, CoreSessionStartConfig,
    Hysteria2Inbound as CoreHysteria2Inbound, NativeCoreEgressConfig, NativeCoreState,
    RuntimeProfile,
};
use serde::Deserialize;

/// One server deployment: where to listen and what to route. The profile is
/// the same `RuntimeProfile` the core compiles everywhere — the server role
/// is expressed by composing inbound acceptors with DIRECT/upstream
/// outbounds, not by a distinct schema.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address the inbound listener binds. A public bind is the whole point of
    /// a server, so the safety floor below is not optional.
    pub listen_addr: SocketAddr,
    /// Optional DNS listener bind; the core always starts one, defaulting to
    /// an ephemeral loopback port when unset.
    #[serde(default)]
    pub dns_listen_addr: Option<SocketAddr>,
    /// Global IPv6 switch (Clash `ipv6` semantics), off by default.
    #[serde(default)]
    pub ipv6_enabled: bool,
    /// Optional Shadowsocks server inbound. When set,
    /// the listener terminates Shadowsocks — authenticating each connection
    /// against `users` — instead of the mixed plaintext SOCKS5/HTTP acceptor.
    /// A public Shadowsocks port is the common server shape; the same
    /// open-proxy safety floor still arms the egress underneath it.
    #[serde(default)]
    pub shadowsocks: Option<ShadowsocksInbound>,
    /// Optional Hysteria2 QUIC/H3 server inbound. When
    /// set, the manager runs a Hysteria2 QUIC endpoint alongside the main
    /// listener, terminating TLS with the supplied PEM material and
    /// authenticating each connection against `users`. Independent of
    /// `shadowsocks` — a deployment may run either, both, or neither. Requires
    /// the `server` build to actually stand up; the same open-proxy safety
    /// floor still arms the egress underneath it.
    #[serde(default)]
    pub hysteria2: Option<Hysteria2Inbound>,
    /// Optional Trojan-over-TLS server inbound. When
    /// set, the main listener terminates Trojan — authenticating each connection
    /// against `users` by their `hex(SHA224(password))` hash — instead of the
    /// mixed plaintext or Shadowsocks acceptor. Mutually exclusive with
    /// `shadowsocks` (both occupy the one stream listener; Trojan wins if both
    /// are set); independent of `hysteria2`, which rides its own QUIC endpoint.
    /// Requires the `server` build to stand up; the same open-proxy safety floor
    /// arms the egress underneath it.
    #[serde(default)]
    pub trojan: Option<TrojanInbound>,
    /// The compiled routing/outbound profile this server serves.
    pub profile: RuntimeProfile,
}

/// A Shadowsocks inbound's pre-shared credentials: the AEAD cipher every user
/// keys against and the `(name, password)` users the acceptor authenticates.
/// Mirrors the core `CoreInbound::Shadowsocks` selector one layer down.
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksInbound {
    /// Clash cipher name, e.g. `aes-256-gcm` or `chacha20-ietf-poly1305`.
    pub cipher: String,
    /// The users the server pre-shares; at least one is required.
    pub users: Vec<ShadowsocksUserCredential>,
}

/// One pre-shared Shadowsocks user: a label for the session ledger and the
/// password its master key derives from.
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksUserCredential {
    pub name: String,
    pub password: String,
}

/// A Hysteria2 inbound's bind address, TLS material, and pre-shared users. The
/// certificate chain and private key are inline PEM (the operator supplies
/// them out of band); the core certificate subsystem parses them. Mirrors the
/// core [`CoreHysteria2Inbound`] one layer down.
#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2Inbound {
    /// Address the Hysteria2 QUIC endpoint binds.
    pub listen_addr: SocketAddr,
    /// PEM-encoded certificate chain the endpoint presents.
    pub cert_pem: String,
    /// PEM-encoded private key for the certificate.
    pub key_pem: String,
    /// The users the server pre-shares; at least one is required.
    pub users: Vec<Hysteria2UserCredential>,
}

/// One pre-shared Hysteria2 user: a label for the session ledger and the auth
/// string the client presents in the `Hysteria-Auth` HTTP/3 header.
#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2UserCredential {
    pub name: String,
    pub auth: String,
}

/// A Trojan inbound's TLS material and pre-shared users. The certificate chain
/// and private key are inline PEM (the operator supplies them out of band); the
/// core certificate subsystem parses them. It terminates on the main listener,
/// so unlike [`Hysteria2Inbound`] it carries no bind address of its own.
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanInbound {
    /// PEM-encoded certificate chain the inbound presents.
    pub cert_pem: String,
    /// PEM-encoded private key for the certificate.
    pub key_pem: String,
    /// The users the server pre-shares; at least one is required.
    pub users: Vec<TrojanUserCredential>,
}

/// One pre-shared Trojan user: a label for the session ledger and the password
/// whose `hex(SHA224(password))` hash the acceptor authenticates.
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanUserCredential {
    pub name: String,
    pub password: String,
}

/// Builds the server egress with the open-proxy safety floor armed. Always
/// refuses private/loopback destinations —
/// it is built into the server assembly, never a user knob.
pub fn server_egress(config: &ServerConfig) -> NativeCoreEgressConfig {
    NativeCoreEgressConfig {
        ipv6_enabled: config.ipv6_enabled,
        refuse_private_destinations: true,
        ..NativeCoreEgressConfig::default()
    }
}

/// Maps the server's inbound selection onto the core [`CoreInbound`]: a Trojan
/// inbound when its TLS material is configured, else a Shadowsocks inbound when
/// its credentials are, else the mixed plaintext inbound.
pub fn server_inbound(config: &ServerConfig) -> CoreInbound {
    // Trojan and Shadowsocks both terminate on the one stream listener, so a
    // deployment composes at most one; Trojan takes precedence when both are set.
    if let Some(trojan) = &config.trojan {
        return CoreInbound::Trojan {
            cert_pem: trojan.cert_pem.clone().into_bytes(),
            key_pem: trojan.key_pem.clone().into_bytes(),
            users: trojan
                .users
                .iter()
                .map(|user| (user.name.clone(), user.password.clone()))
                .collect(),
        };
    }
    match &config.shadowsocks {
        Some(inbound) => CoreInbound::Shadowsocks {
            cipher: inbound.cipher.clone(),
            users: inbound
                .users
                .iter()
                .map(|user| (user.name.clone(), user.password.clone()))
                .collect(),
        },
        None => CoreInbound::Mixed,
    }
}

/// Maps the server's optional Hysteria2 inbound onto the core
/// [`CoreHysteria2Inbound`]: inline PEM into the byte buffers the certificate
/// subsystem parses, and the pre-shared users into `(name, auth)` pairs.
pub fn server_hysteria2(config: &ServerConfig) -> Option<CoreHysteria2Inbound> {
    config
        .hysteria2
        .as_ref()
        .map(|inbound| CoreHysteria2Inbound {
            listen_addr: inbound.listen_addr,
            cert_pem: inbound.cert_pem.clone().into_bytes(),
            key_pem: inbound.key_pem.clone().into_bytes(),
            users: inbound
                .users
                .iter()
                .map(|user| (user.name.clone(), user.auth.clone()))
                .collect(),
        })
}

/// The core start config this server composition produces: the configured
/// profile and inbound(s), over the safety-floored server egress. The one place
/// a `ServerConfig` becomes a `CoreSessionStartConfig`, so [`start`] and its
/// tests compose the listener the same way.
pub fn server_start_config(config: &ServerConfig) -> CoreSessionStartConfig {
    CoreSessionStartConfig {
        profile: config.profile.clone(),
        egress: server_egress(config),
        socket_guard: None,
        listen_addr: Some(config.listen_addr),
        dns_listen_addr: config.dns_listen_addr,
        inbound: server_inbound(config),
        hysteria2: server_hysteria2(config),
    }
}

/// Starts the server listener over the composed core and returns the running
/// manager. The caller drives shutdown (`stop`) and can poll
/// [`CoreSessionManager::inbound_auth_failures`] to alarm on credential
/// probing against its encrypted inbound.
pub async fn start(config: ServerConfig) -> Result<CoreSessionManager, String> {
    let manager = CoreSessionManager::default();
    manager
        .start_with_config(server_start_config(&config))
        .await?;
    Ok(manager)
}

/// Loads a JSON [`ServerConfig`] from `path`.
pub fn load_config(path: &str) -> Result<ServerConfig, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("failed to read {path}: {error}"))?;
    serde_json::from_str(&text).map_err(|error| format!("failed to parse {path}: {error}"))
}

/// Loads the config, starts the server, and blocks until Ctrl-C, then stops
/// the listener. The binary entry point.
pub async fn run(config_path: &str) -> Result<(), String> {
    crate::start_memory_reclaim();
    let config = load_config(config_path)?;
    let requested = config.listen_addr;
    let manager = start(config).await?;
    let bound = manager
        .status()
        .listen_addr
        .unwrap_or_else(|| requested.to_string());
    eprintln!("egrio-server: listening on {bound}");
    tokio::signal::ctrl_c()
        .await
        .map_err(|error| format!("failed to wait for shutdown signal: {error}"))?;
    manager.stop();
    while manager.status().state == NativeCoreState::Stopping {
        tokio::task::yield_now().await;
    }
    let final_status = manager.status();
    if final_status.state != NativeCoreState::Stopped {
        return Err(final_status
            .last_error
            .unwrap_or_else(|| format!("server stopped in state {:?}", final_status.state)));
    }
    eprintln!("egrio-server: stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use egrio_core::{RouteRule, RuleKind, RuntimeProfile};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    use super::*;

    fn match_direct_profile() -> RuntimeProfile {
        let mut profile = RuntimeProfile::new("server-test");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into();
        profile
    }

    fn config_on_loopback(profile: RuntimeProfile) -> ServerConfig {
        ServerConfig {
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            dns_listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            ipv6_enabled: false,
            shadowsocks: None,
            hysteria2: None,
            trojan: None,
            profile,
        }
    }

    const SS_CIPHER: &str = "aes-256-gcm";
    const SS_USER: &str = "alice";
    const SS_PASSWORD: &str = "s3cr3t-preshared-key";

    /// A loopback server config that terminates a single-user Shadowsocks
    /// inbound over the same MATCH → DIRECT profile.
    fn shadowsocks_config_on_loopback() -> ServerConfig {
        ServerConfig {
            shadowsocks: Some(ShadowsocksInbound {
                cipher: SS_CIPHER.into(),
                users: vec![ShadowsocksUserCredential {
                    name: SS_USER.into(),
                    password: SS_PASSWORD.into(),
                }],
            }),
            ..config_on_loopback(match_direct_profile())
        }
    }

    /// A loopback TCP echo the relayed CONNECT lands on; returns its address.
    async fn spawn_loopback_echo() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo target");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = vec![0_u8; 4096];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => {
                                if stream.write_all(&buffer[..read]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    /// A loopback UDP echo the relayed datagram lands on; returns its addr. Used
    /// by the UDP-relay gates: Shadowsocks (no server feature) and, under the
    /// server feature, Hysteria2 and Trojan.
    async fn spawn_loopback_udp_echo() -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind udp echo");
        let addr = socket.local_addr().expect("udp echo addr");
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 2048];
            while let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
                if socket.send_to(&buffer[..read], peer).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    fn listen_addr_of(manager: &CoreSessionManager) -> SocketAddr {
        manager
            .status()
            .listen_addr
            .expect("listen addr")
            .parse()
            .expect("valid listen addr")
    }

    /// The composed server always arms the open-proxy safety floor, whatever
    /// the config says.
    #[test]
    fn server_egress_always_refuses_private_destinations() {
        let egress = server_egress(&config_on_loopback(match_direct_profile()));
        assert!(egress.refuse_private_destinations);
    }

    /// End to end through the server: a SOCKS5 client completes the handshake
    /// (the plaintext acceptor + listener are live) but a CONNECT to a
    /// loopback target is refused by the safety floor built into the server
    /// egress — the open-proxy pivot the floor exists to stop.
    #[tokio::test]
    async fn server_refuses_socks5_connect_to_a_loopback_target() {
        let manager = start(config_on_loopback(match_direct_profile()))
            .await
            .expect("server starts");
        let proxy_addr: SocketAddr = manager
            .status()
            .listen_addr
            .expect("listen addr")
            .parse()
            .expect("valid listen addr");

        let reply = socks5_connect_reply(proxy_addr, "127.0.0.1", 9)
            .await
            .expect("socks5 exchange completes");
        // 0x00 = success; anything else = refused. The floor makes the DIRECT
        // dial to loopback fail, surfaced as a SOCKS5 connection failure.
        assert_ne!(reply, 0x00, "loopback CONNECT must be refused by the floor");

        manager.stop();
    }

    /// End to end through a `ServerConfig`-composed Shadowsocks inbound: a
    /// client dialing with the in-tree connector authenticates, and its
    /// CONNECT relays a payload byte-exact to a DIRECT target. The composition
    /// is the real `server_start_config` mapping; only the open-proxy floor is
    /// disarmed so the relay can reach a hermetic loopback echo (the floor's
    /// refusal has its own test above), leaving the Shadowsocks inbound wiring
    /// as what this exercises.
    #[tokio::test]
    async fn server_shadowsocks_inbound_authenticates_and_relays_a_connect() {
        let echo_addr = spawn_loopback_echo().await;

        let mut start_config = server_start_config(&shadowsocks_config_on_loopback());
        start_config.egress.refuse_private_destinations = false;
        let manager = CoreSessionManager::default();
        manager
            .start_with_config(start_config)
            .await
            .expect("shadowsocks server starts");
        let server_addr = listen_addr_of(&manager);

        let payload = b"through-the-shadowsocks-server-inbound";
        let echoed = egrio_core::self_test::run_shadowsocks_connect_client(
            server_addr,
            SS_CIPHER,
            SS_PASSWORD,
            echo_addr,
            payload,
        )
        .await
        .expect("shadowsocks CONNECT relays");
        assert_eq!(echoed, payload, "payload survived the shadowsocks relay");
        assert_eq!(
            manager.inbound_auth_failures(),
            Some(0),
            "a good handshake never fails auth"
        );

        manager.stop();
    }

    /// End to end through the Shadowsocks UDP server face: the in-tree client
    /// half seals a datagram to `target`, the direct-drive UDP server trial-
    /// decrypts it, relays it to a DIRECT loopback echo, and seals the echo back.
    /// The open-proxy floor is disarmed so the relay reaches the hermetic echo
    /// (the floor has its own test above).
    #[tokio::test]
    async fn server_shadowsocks_inbound_relays_udp() {
        let udp_echo = spawn_loopback_udp_echo().await;

        let mut start_config = server_start_config(&shadowsocks_config_on_loopback());
        start_config.egress.refuse_private_destinations = false;
        let manager = CoreSessionManager::default();
        manager
            .start_with_config(start_config)
            .await
            .expect("shadowsocks server starts");
        let server_addr = listen_addr_of(&manager);

        let payload = b"shadowsocks-server-udp-round-trip";
        let echoed = egrio_core::self_test::run_shadowsocks_udp_client(
            server_addr,
            SS_CIPHER,
            SS_PASSWORD,
            udp_echo,
            payload,
        )
        .await
        .expect("shadowsocks UDP relays");
        assert_eq!(
            echoed, payload,
            "UDP datagram round-tripped the shadowsocks UDP server"
        );

        manager.stop();
    }

    #[tokio::test]
    async fn server_ss2022_inbound_relays_tcp_and_udp_for_each_method() {
        let tcp_echo = spawn_loopback_echo().await;
        let udp_echo = spawn_loopback_udp_echo().await;
        for (cipher, key) in [
            ("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA=="),
            (
                "2022-blake3-aes-256-gcm",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
            (
                "2022-blake3-chacha20-poly1305",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
        ] {
            let mut config = shadowsocks_config_on_loopback();
            let inbound = config.shadowsocks.as_mut().unwrap();
            inbound.cipher = cipher.into();
            inbound.users[0].password = key.into();
            let mut start_config = server_start_config(&config);
            start_config.egress.refuse_private_destinations = false;
            let manager = CoreSessionManager::default();
            manager.start_with_config(start_config).await.unwrap();
            let addr = listen_addr_of(&manager);
            let payload = b"ss2022-through-daemon-server";
            let tcp = egrio_core::self_test::run_shadowsocks_connect_client(
                addr, cipher, key, tcp_echo, payload,
            )
            .await
            .unwrap();
            let udp = egrio_core::self_test::run_shadowsocks_udp_client(
                addr, cipher, key, udp_echo, payload,
            )
            .await
            .unwrap();
            assert_eq!(tcp, payload);
            assert_eq!(udp, payload);
            assert_eq!(manager.inbound_auth_failures(), Some(0));
            manager.stop();
        }
    }

    /// Live per-user accounting reflects an authenticated user's UDP flow: after
    /// a Shadowsocks UDP round-trip for `alice`, the manager's per-user surface
    /// shows her flow with the relayed bytes. UDP flows persist (unlike a closed
    /// TCP relay), so the live fold still sees them after the exchange.
    #[tokio::test]
    async fn server_reports_per_user_traffic() {
        let udp_echo = spawn_loopback_udp_echo().await;

        let mut start_config = server_start_config(&shadowsocks_config_on_loopback());
        start_config.egress.refuse_private_destinations = false;
        let manager = CoreSessionManager::default();
        manager
            .start_with_config(start_config)
            .await
            .expect("shadowsocks server starts");
        let server_addr = listen_addr_of(&manager);

        let payload = b"per-user-accounting-probe";
        egrio_core::self_test::run_shadowsocks_udp_client(
            server_addr,
            SS_CIPHER,
            SS_PASSWORD,
            udp_echo,
            payload,
        )
        .await
        .expect("shadowsocks UDP relays");

        let traffic = manager.per_user_traffic();
        let alice = traffic
            .iter()
            .find(|row| row.user == SS_USER)
            .unwrap_or_else(|| panic!("alice has a per-user row: {traffic:?}"));
        assert_eq!(alice.udp_flows, 1);
        assert!(
            alice.upload_bytes >= payload.len() as u64,
            "upload accounted: {alice:?}"
        );
        assert!(
            alice.download_bytes >= payload.len() as u64,
            "download accounted: {alice:?}"
        );

        manager.stop();
    }

    /// A wrong-key client bumps the auth-failure count the manager surfaces,
    /// so a host can alarm on credential probing. Goes
    /// through the real `start` (floor armed): auth fails before any dial, so
    /// the floor never enters the picture.
    #[tokio::test]
    async fn server_shadowsocks_inbound_counts_a_wrong_key_client() {
        let echo_addr = spawn_loopback_echo().await;
        let manager = start(shadowsocks_config_on_loopback())
            .await
            .expect("shadowsocks server starts");
        let server_addr = listen_addr_of(&manager);
        assert_eq!(
            manager.inbound_auth_failures(),
            Some(0),
            "the fresh inbound has seen no auth failures"
        );

        // The dial writes an unauthenticatable request; the server reads a
        // bounded salt + length record, fails every user key, and counts it.
        // The client's own result is irrelevant — the server drops it.
        let _ = egrio_core::self_test::run_shadowsocks_connect_client(
            server_addr,
            SS_CIPHER,
            "not-the-preshared-key",
            echo_addr,
            b"payload-that-never-arrives",
        )
        .await;

        let mut failures = None;
        for _ in 0..250 {
            failures = manager.inbound_auth_failures();
            if failures.unwrap_or(0) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(failures, Some(1), "the wrong-key request was counted once");

        manager.stop();
    }

    /// Minimal SOCKS5 no-auth CONNECT: returns the reply status byte.
    async fn socks5_connect_reply(proxy: SocketAddr, host: &str, port: u16) -> Result<u8, String> {
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(proxy))
            .await
            .map_err(|_| "connect timeout".to_string())?
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|error| error.to_string())?;
        let mut method = [0_u8; 2];
        stream
            .read_exact(&mut method)
            .await
            .map_err(|error| error.to_string())?;
        if method != [0x05, 0x00] {
            return Err(format!("no-auth negotiation failed: {method:?}"));
        }
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        stream
            .write_all(&request)
            .await
            .map_err(|error| error.to_string())?;
        let mut reply = [0_u8; 10];
        timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
            .await
            .map_err(|_| "reply timeout".to_string())?
            .map_err(|error| error.to_string())?;
        Ok(reply[1])
    }

    /// The Hysteria2 server inbound needs the core
    /// `server` feature to terminate TLS, so its gate is gated the same way.
    #[cfg(feature = "server")]
    mod hysteria2_gate {
        use super::*;

        const HY2_USER: &str = "alice";
        const HY2_AUTH: &str = "s3cr3t-hysteria2-auth";
        const HY2_SNI: &str = "localhost";

        /// A throwaway self-signed cert + key (PEM, SAN `localhost`) — the
        /// material an operator hands the certificate subsystem.
        fn self_signed_pem() -> (String, String) {
            let key_pair = rcgen::KeyPair::generate().expect("keypair");
            let cert = rcgen::CertificateParams::new(vec![HY2_SNI.into()])
                .expect("params")
                .self_signed(&key_pair)
                .expect("self-signed cert");
            (cert.pem(), key_pair.serialize_pem())
        }

        /// A loopback server config carrying a single-user Hysteria2 inbound on
        /// an ephemeral port, over the same MATCH → DIRECT profile.
        fn hysteria2_config_on_loopback() -> ServerConfig {
            let (cert_pem, key_pem) = self_signed_pem();
            ServerConfig {
                hysteria2: Some(Hysteria2Inbound {
                    listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                    cert_pem,
                    key_pem,
                    users: vec![Hysteria2UserCredential {
                        name: HY2_USER.into(),
                        auth: HY2_AUTH.into(),
                    }],
                }),
                ..config_on_loopback(match_direct_profile())
            }
        }

        /// End to end through a `ServerConfig`-composed Hysteria2 inbound: a
        /// client dialing with the in-tree connector authenticates over HTTP/3,
        /// its CONNECT relays a payload byte-exact to a DIRECT target, and a UDP
        /// datagram round-trips the connection's datagram face. The composition
        /// is the real `server_start_config` mapping; only the open-proxy floor
        /// is disarmed so the relay can reach hermetic loopback echoes (the
        /// floor has its own test), leaving the Hysteria2 inbound wiring — a
        /// live QUIC listener the manager stands up from `ServerConfig`, its
        /// bound address and auth-failure counter on the control surface — as
        /// what this exercises.
        #[tokio::test]
        async fn server_hysteria2_inbound_authenticates_and_relays_tcp_and_udp() {
            let tcp_echo = spawn_loopback_echo().await;
            let udp_echo = spawn_loopback_udp_echo().await;

            let mut start_config = server_start_config(&hysteria2_config_on_loopback());
            start_config.egress.refuse_private_destinations = false;
            let manager = CoreSessionManager::default();
            manager
                .start_with_config(start_config)
                .await
                .expect("hysteria2 server starts");
            let server_addr: SocketAddr = manager
                .hysteria2_listen_addr()
                .expect("hysteria2 listen addr")
                .parse()
                .expect("valid hysteria2 listen addr");

            let tcp_payload = b"through-the-hysteria2-server-inbound";
            let echoed = egrio_core::self_test::run_hysteria2_connect_client(
                server_addr,
                HY2_AUTH,
                HY2_SNI,
                tcp_echo,
                tcp_payload,
            )
            .await
            .expect("hysteria2 TCP relays");
            assert_eq!(
                echoed, tcp_payload,
                "TCP payload survived the hysteria2 relay"
            );

            let udp_payload = b"hysteria2-server-udp-round-trip";
            let echoed_udp = egrio_core::self_test::run_hysteria2_udp_client(
                server_addr,
                HY2_AUTH,
                HY2_SNI,
                udp_echo,
                udp_payload,
            )
            .await
            .expect("hysteria2 UDP relays");
            assert_eq!(
                echoed_udp, udp_payload,
                "UDP datagram round-tripped the hysteria2 datagram face"
            );

            assert_eq!(
                manager.hysteria2_auth_failures(),
                Some(0),
                "a good handshake never fails auth"
            );

            manager.stop();
        }
    }

    /// The Trojan server inbound needs the core `server`
    /// feature to terminate TLS, so its gate is gated the same way.
    #[cfg(feature = "server")]
    mod trojan_gate {
        use super::*;

        const TROJAN_USER: &str = "alice";
        const TROJAN_PASSWORD: &str = "s3cr3t-trojan-password";
        const TROJAN_SNI: &str = "localhost";

        /// A throwaway self-signed cert + key (PEM, SAN `localhost`) — the
        /// material an operator hands the certificate subsystem.
        fn self_signed_pem() -> (String, String) {
            let key_pair = rcgen::KeyPair::generate().expect("keypair");
            let cert = rcgen::CertificateParams::new(vec![TROJAN_SNI.into()])
                .expect("params")
                .self_signed(&key_pair)
                .expect("self-signed cert");
            (cert.pem(), key_pair.serialize_pem())
        }

        /// A loopback server config terminating a single-user Trojan inbound on
        /// the main listener, over the same MATCH → DIRECT profile.
        fn trojan_config_on_loopback() -> ServerConfig {
            let (cert_pem, key_pem) = self_signed_pem();
            ServerConfig {
                trojan: Some(TrojanInbound {
                    cert_pem,
                    key_pem,
                    users: vec![TrojanUserCredential {
                        name: TROJAN_USER.into(),
                        password: TROJAN_PASSWORD.into(),
                    }],
                }),
                ..config_on_loopback(match_direct_profile())
            }
        }

        /// End to end through a `ServerConfig`-composed Trojan inbound: a client
        /// dialing with the in-tree connector authenticates over TLS, and its
        /// CONNECT relays a payload byte-exact to a DIRECT target. The
        /// composition is the real `server_start_config` mapping; only the
        /// open-proxy floor is disarmed so the relay can reach a hermetic
        /// loopback echo (the floor's refusal has its own test above), leaving
        /// the Trojan inbound wiring as what this exercises.
        #[tokio::test]
        async fn server_trojan_inbound_authenticates_and_relays_a_connect() {
            let echo_addr = spawn_loopback_echo().await;

            let mut start_config = server_start_config(&trojan_config_on_loopback());
            start_config.egress.refuse_private_destinations = false;
            let manager = CoreSessionManager::default();
            manager
                .start_with_config(start_config)
                .await
                .expect("trojan server starts");
            let server_addr = listen_addr_of(&manager);

            let payload = b"through-the-trojan-server-inbound";
            let echoed = egrio_core::self_test::run_trojan_connect_client(
                server_addr,
                TROJAN_PASSWORD,
                TROJAN_SNI,
                echo_addr,
                payload,
            )
            .await
            .expect("trojan CONNECT relays");
            assert_eq!(echoed, payload, "payload survived the trojan relay");
            assert_eq!(
                manager.inbound_auth_failures(),
                Some(0),
                "a good handshake never fails auth"
            );

            manager.stop();
        }

        /// A wrong-password client bumps the auth-failure count the manager
        /// surfaces. Goes through the real `start` (floor
        /// armed): auth fails before any dial, so the floor never enters.
        #[tokio::test]
        async fn server_trojan_inbound_counts_a_wrong_password_client() {
            let echo_addr = spawn_loopback_echo().await;
            let manager = start(trojan_config_on_loopback())
                .await
                .expect("trojan server starts");
            let server_addr = listen_addr_of(&manager);
            assert_eq!(
                manager.inbound_auth_failures(),
                Some(0),
                "the fresh inbound has seen no auth failures"
            );

            // The dial completes TLS and writes an unauthenticatable preamble;
            // the server reads a bounded 56-byte hash, misses every user, and
            // counts it. The client's own result is irrelevant — the server
            // drops it.
            let _ = egrio_core::self_test::run_trojan_connect_client(
                server_addr,
                "not-the-preshared-password",
                TROJAN_SNI,
                echo_addr,
                b"payload-that-never-arrives",
            )
            .await;

            let mut failures = None;
            for _ in 0..250 {
                failures = manager.inbound_auth_failures();
                if failures.unwrap_or(0) >= 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(
                failures,
                Some(1),
                "the wrong-password request was counted once"
            );

            manager.stop();
        }

        /// End to end through the Trojan datagram face: a hand-rolled UDP client
        /// authenticates over TLS, opens the associate, and one datagram
        /// round-trips to a DIRECT loopback echo — the Trojan peer of the
        /// Hysteria2 UDP gate. The open-proxy floor is disarmed so the relay
        /// reaches the hermetic echo (the floor has its own test above).
        #[tokio::test]
        async fn server_trojan_inbound_relays_udp() {
            let udp_echo = spawn_loopback_udp_echo().await;

            let mut start_config = server_start_config(&trojan_config_on_loopback());
            start_config.egress.refuse_private_destinations = false;
            let manager = CoreSessionManager::default();
            manager
                .start_with_config(start_config)
                .await
                .expect("trojan server starts");
            let server_addr = listen_addr_of(&manager);

            let payload = b"trojan-server-udp-round-trip";
            let echoed = egrio_core::self_test::run_trojan_udp_client(
                server_addr,
                TROJAN_PASSWORD,
                TROJAN_SNI,
                udp_echo,
                payload,
            )
            .await
            .expect("trojan UDP relays");
            assert_eq!(
                echoed, payload,
                "UDP datagram round-tripped the trojan datagram face"
            );

            manager.stop();
        }
    }
}

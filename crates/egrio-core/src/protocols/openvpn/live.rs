//! A manual check against a real OpenVPN server: runs the control channel to
//! the pushed configuration and reports what was negotiated, never a key or
//! a credential.
//!
//! ```text
//! EGRIO_OPENVPN_CONFIG=client.ovpn EGRIO_OPENVPN_AUTH=auth.txt \
//!   cargo test -p egrio-core --lib openvpn::live -- --ignored --nocapture
//! ```
//!
//! `auth.txt` holds the username and the password on two lines.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::config::{parse, Transport};
use super::control::{tls_config, Control, Event};
use super::exchange::Credentials;

enum Link {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl Link {
    async fn send(&mut self, packet: &[u8]) {
        match self {
            Self::Udp(socket) => {
                socket.send(packet).await.expect("send");
            }
            Self::Tcp(stream) => {
                let mut framed = (packet.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(packet);
                stream.write_all(&framed).await.expect("send");
            }
        }
    }

    async fn recv(&mut self) -> Vec<u8> {
        match self {
            Self::Udp(socket) => {
                let mut buffer = vec![0_u8; 65536];
                let read = socket.recv(&mut buffer).await.expect("recv");
                buffer.truncate(read);
                buffer
            }
            Self::Tcp(stream) => {
                let Ok(length) = stream.read_u16().await else {
                    println!("the server closed the connection");
                    std::future::pending::<()>().await;
                    unreachable!();
                };
                let length = length as usize;
                let mut buffer = vec![0_u8; length];
                stream.read_exact(&mut buffer).await.expect("packet");
                buffer
            }
        }
    }
}

#[tokio::test]
#[ignore = "needs a real OpenVPN server: EGRIO_OPENVPN_CONFIG and EGRIO_OPENVPN_AUTH"]
async fn handshake_with_a_real_server() {
    let config_path = std::env::var("EGRIO_OPENVPN_CONFIG").expect("EGRIO_OPENVPN_CONFIG");
    let config = parse(&std::fs::read_to_string(config_path).expect("config")).expect("parses");
    let credentials = std::env::var("EGRIO_OPENVPN_AUTH").ok().map(|path| {
        let text = std::fs::read_to_string(path).expect("auth file");
        let mut lines = text.lines();
        Credentials {
            username: lines.next().unwrap_or_default().to_owned(),
            password: lines.next().unwrap_or_default().to_owned(),
        }
    });
    let remote = &config.remotes[0];
    println!("remote transport {:?}", remote.transport);
    let address = tokio::net::lookup_host((remote.host.as_str(), remote.port))
        .await
        .expect("resolve")
        .next()
        .expect("an address");
    let mut link = match remote.transport {
        Transport::Udp => {
            let socket = UdpSocket::bind("0.0.0.0:0").await.expect("bind");
            socket.connect(address).await.expect("connect");
            Link::Udp(socket)
        }
        Transport::Tcp => Link::Tcp(TcpStream::connect(address).await.expect("connect")),
    };
    let tls = tls_config(&config).expect("TLS config");
    let started = Instant::now();
    let mut control = Control::new(
        &config,
        tls,
        credentials,
        remote.transport == Transport::Tcp,
        started,
    );
    let outcome = loop {
        let now = Instant::now();
        for packet in control.transmit(now) {
            println!(
                "{:>6?} sent op {} len {}",
                started.elapsed(),
                super::wire::opcode(packet[0]),
                packet.len()
            );
            link.send(&packet).await;
        }
        if let Some(event) = control.event() {
            break event;
        }
        let wait = control
            .next_deadline()
            .map_or(Duration::from_secs(1), |deadline| {
                deadline.saturating_duration_since(now)
            });
        tokio::select! {
            packet = link.recv() => {
                let opcode = super::wire::opcode(packet[0]);
                println!("{:>6?} received op {opcode} len {}", started.elapsed(), packet.len());
                if opcode == super::wire::P_DATA_V2 || opcode == super::wire::P_DATA_V1 {
                    continue;
                }
                control.receive(&packet, Instant::now());
            }
            () = tokio::time::sleep(wait) => {}
        }
        if let Some(event) = control.event() {
            break event;
        }
    };
    match outcome {
        Event::Up(pushed, mut keys) => {
            println!(
                "up after {:?}: ip {:?} ipv6 {:?} routes {:?} dns {:?} peer-id {:?} cipher {:?} \
                 ekm {} cc-exit {} ping {:?}/{:?} mtu {:?} redirect {} token {}; data key id {}",
                started.elapsed(),
                pushed.ipv4,
                pushed.ipv6,
                pushed.routes,
                pushed.dns,
                pushed.peer_id,
                pushed.cipher,
                pushed.tls_ekm,
                pushed.cc_exit,
                pushed.ping,
                pushed.ping_restart,
                pushed.mtu,
                pushed.redirect_gateway,
                pushed.auth_token.is_some(),
                keys.key_id(),
            );
            // An ICMP echo to the server's end of the tunnel proves the data
            // channel's keys, nonces and associated data.
            if let (Some(local), Ok(gateway)) = (
                pushed.ipv4,
                std::env::var("EGRIO_OPENVPN_PING")
                    .unwrap_or_else(|_| "10.9.0.1".into())
                    .parse::<std::net::Ipv4Addr>(),
            ) {
                let echo = icmp_echo(local, gateway, 0x4567, 1);
                let packet = keys.seal(pushed.peer_id, &echo).expect("seal");
                link.send(&packet).await;
                let sent = Instant::now();
                let reply = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let packet = link.recv().await;
                        match keys.open(&packet) {
                            Some(super::data::Payload::Ip(ip)) => break ip,
                            Some(other) => println!("data channel: {other:?}"),
                            None => println!(
                                "not data for this key: op {}",
                                super::wire::opcode(packet[0])
                            ),
                        }
                    }
                })
                .await;
                match reply {
                    Ok(ip) => println!(
                        "echo reply after {:?}: {} bytes, protocol {}, from {}.{}.{}.{}, type {}",
                        sent.elapsed(),
                        ip.len(),
                        ip[9],
                        ip[12],
                        ip[13],
                        ip[14],
                        ip[15],
                        ip[20]
                    ),
                    Err(_) => println!("no echo reply in 5 s"),
                }
            }
            control.exit();
            for packet in control.transmit(Instant::now()) {
                link.send(&packet).await;
            }
        }
        Event::Rekeyed(_) => println!("rekeyed before up?"),
        Event::Ended(ending) => println!("ended after {:?}: {ending}", started.elapsed()),
    }
}

/// An IPv4 ICMP echo request.
fn icmp_echo(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    id: u16,
    sequence: u16,
) -> Vec<u8> {
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for pair in bytes.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
    let mut icmp = vec![8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&sequence.to_be_bytes());
    icmp.extend_from_slice(b"egrio openvpn echo");
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0, 0, 64, 1, 0, 0]);
    ip.extend_from_slice(&source.octets());
    ip.extend_from_slice(&destination.octets());
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// The node end to end: a profile's OpenVPN node opens its session, then a
/// TCP connection and a UDP exchange to hosts behind the VPN go through the
/// Core's TCP engine and the tunnel.
///
/// ```text
/// EGRIO_OPENVPN_CONFIG=client.ovpn EGRIO_OPENVPN_AUTH=auth.txt EGRIO_OPENVPN_HTTP=192.168.1.1:80 \
///   EGRIO_OPENVPN_DNS=192.168.1.1:53 cargo test -p egrio-core --lib openvpn::live -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a real OpenVPN server: EGRIO_OPENVPN_CONFIG, EGRIO_OPENVPN_AUTH, EGRIO_OPENVPN_HTTP"]
async fn the_node_reaches_hosts_behind_the_vpn() {
    use crate::target::ConnectTarget;

    let config = std::env::var("EGRIO_OPENVPN_CONFIG").unwrap();
    let auth = std::fs::read_to_string(std::env::var("EGRIO_OPENVPN_AUTH").unwrap()).unwrap();
    let mut lines = auth.lines();
    let options = serde_json::json!({
        "config": config,
        "username": lines.next().unwrap_or_default(),
        "password": lines.next().unwrap_or_default(),
    });
    let node = crate::profile::ProxyNode {
        id: "vpn".into(),
        name: "vpn".into(),
        protocol: crate::profile::ProxyProtocol::OpenVpn,
        server: None,
        port: None,
        options,
    };
    assert_eq!(
        crate::runtime::proxy_support_issue(&crate::profile::RuntimeProfile::new("live"), &node),
        None
    );
    let mut profile = crate::profile::RuntimeProfile::new("live");
    profile.proxies = vec![node];
    let runtime = crate::runtime::NativeCoreRuntime::compile(&profile);

    let target = ConnectTarget {
        host: "192.0.2.1".into(),
        port: 9,
    };
    if let Ok(http) = std::env::var("EGRIO_OPENVPN_HTTP") {
        let http: std::net::SocketAddr = http.parse().unwrap();
        let target = ConnectTarget {
            host: http.ip().to_string(),
            port: http.port(),
        };
        let started = Instant::now();
        let (mut stream, _) =
            crate::runtime::open_outbound_connection(&runtime, &target, "vpn", b"")
                .await
                .expect("a connection through the tunnel");
        println!("connected after {:?} (session included)", started.elapsed());
        let asked = Instant::now();
        stream
            .write_all(format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", http.ip()).as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await;
        let status = String::from_utf8_lossy(&response);
        println!(
            "answered after {:?}: {:?}",
            asked.elapsed(),
            status.lines().next().unwrap_or_default()
        );
        let again = Instant::now();
        let (_second, _) = crate::runtime::open_outbound_connection(&runtime, &target, "vpn", b"")
            .await
            .expect("a second connection on the same session");
        println!("second connection after {:?}", again.elapsed());
    }

    // A name the pushed DNS server knows, then a large download from it.
    if let Ok(name) = std::env::var("EGRIO_OPENVPN_NAME") {
        let (host, port) = name.rsplit_once(':').unwrap();
        let target = ConnectTarget {
            host: host.into(),
            port: port.parse().unwrap(),
        };
        let started = Instant::now();
        let (mut stream, _) =
            crate::runtime::open_outbound_connection(&runtime, &target, "vpn", b"")
                .await
                .expect("the name resolves through the tunnel's DNS");
        println!("{name} connected after {:?}", started.elapsed());
        // Without its leading slash: Git Bash rewrites `/x` arguments as paths.
        let path = format!(
            "/{}",
            std::env::var("EGRIO_OPENVPN_PATH").unwrap_or_default()
        );
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let fetched = Instant::now();
        let mut buffer = vec![0_u8; 256 * 1024];
        let mut total = 0_usize;
        loop {
            match tokio::time::timeout(Duration::from_secs(20), stream.read(&mut buffer)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(read)) => total += read,
                Ok(Err(error)) => {
                    println!("read failed: {error}");
                    break;
                }
            }
        }
        let seconds = fetched.elapsed().as_secs_f64();
        println!(
            "fetched {total} bytes in {seconds:.2} s: {:.1} MB/s",
            total as f64 / seconds / 1e6
        );
    }

    if let Ok(dns) = std::env::var("EGRIO_OPENVPN_DNS") {
        let dns: std::net::SocketAddr = dns.parse().unwrap();
        let connector = runtime
            .resolve_outbound("vpn", &target)
            .expect("the node")
            .connector;
        let transport = connector
            .connect_datagram(runtime.egress(), &target)
            .await
            .expect("an association");
        let request =
            crate::dns::wire::query("example.com", hickory_proto::rr::RecordType::A).unwrap();
        let server = ConnectTarget {
            host: dns.ip().to_string(),
            port: dns.port(),
        };
        let sent = Instant::now();
        transport
            .sender
            .send(&server, &crate::dns::wire::encode(&request).unwrap())
            .await
            .unwrap();
        let mut receiver = transport.receiver;
        match tokio::time::timeout(Duration::from_secs(5), receiver.recv()).await {
            Ok(Ok(Some((from, payload)))) => {
                let answer = crate::dns::wire::decode(&payload).unwrap();
                println!(
                    "DNS from {}:{} after {:?}: {:?} with {} answers",
                    from.host,
                    from.port,
                    sent.elapsed(),
                    answer.response_code(),
                    answer.answers().len()
                );
            }
            other => println!(
                "no DNS answer: {:?}",
                other.map(|result| result.map(|_| ()))
            ),
        }
    }
}

/// A TCP connection and a UDP association opened before a key
/// renegotiation keep working after it (`EGRIO_OPENVPN_HOLD` seconds later;
/// run it against a server with a shorter `reneg-sec`).
#[tokio::test]
#[ignore = "needs a real OpenVPN server: EGRIO_OPENVPN_CONFIG, EGRIO_OPENVPN_AUTH, EGRIO_OPENVPN_HTTP, EGRIO_OPENVPN_ECHO, EGRIO_OPENVPN_HOLD"]
async fn connections_outlive_a_renegotiation() {
    use crate::target::ConnectTarget;

    let config = std::env::var("EGRIO_OPENVPN_CONFIG").unwrap();
    let auth = std::fs::read_to_string(std::env::var("EGRIO_OPENVPN_AUTH").unwrap()).unwrap();
    let mut lines = auth.lines();
    let mut profile = crate::profile::RuntimeProfile::new("live");
    profile.proxies = vec![crate::profile::ProxyNode {
        id: "vpn".into(),
        name: "vpn".into(),
        protocol: crate::profile::ProxyProtocol::OpenVpn,
        server: None,
        port: None,
        options: serde_json::json!({
            "config": config,
            "username": lines.next().unwrap_or_default(),
            "password": lines.next().unwrap_or_default(),
        }),
    }];
    let runtime = crate::runtime::NativeCoreRuntime::compile(&profile);
    let http: std::net::SocketAddr = std::env::var("EGRIO_OPENVPN_HTTP")
        .unwrap()
        .parse()
        .unwrap();
    let echo: std::net::SocketAddr = std::env::var("EGRIO_OPENVPN_ECHO")
        .unwrap()
        .parse()
        .unwrap();
    let hold: u64 = std::env::var("EGRIO_OPENVPN_HOLD")
        .unwrap()
        .parse()
        .unwrap();
    let target = |address: std::net::SocketAddr| ConnectTarget {
        host: address.ip().to_string(),
        port: address.port(),
    };
    let (mut stream, _) =
        crate::runtime::open_outbound_connection(&runtime, &target(http), "vpn", b"")
            .await
            .expect("a connection");
    let connector = runtime
        .resolve_outbound("vpn", &target(echo))
        .unwrap()
        .connector;
    let transport = connector
        .connect_datagram(runtime.egress(), &target(echo))
        .await
        .expect("an association");
    let mut receiver = transport.receiver;
    for round in ["before", "after"] {
        transport
            .sender
            .send(&target(echo), round.as_bytes())
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), receiver.recv()).await;
        println!(
            "UDP echo {round}: {:?}",
            reply
                .map(|reply| reply.map(|answer| answer
                    .map(|(_, payload)| String::from_utf8_lossy(&payload).into_owned())))
        );
        if round == "before" {
            println!("holding {hold} s");
            tokio::time::sleep(Duration::from_secs(hold)).await;
        }
    }
    stream
        .write_all(format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", http.ip()).as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await;
    println!(
        "TCP opened before, answered after: {:?}",
        String::from_utf8_lossy(&response)
            .lines()
            .next()
            .unwrap_or_default()
    );
    // Dropping the node ends the session; the server hears EXIT at once.
    drop(runtime);
    tokio::time::sleep(Duration::from_millis(500)).await;
}

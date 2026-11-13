//! One-shot functional probe for the SOCKS5 UDP outbound. The request
//! enters Core as a captured IPv4/UDP packet through an in-memory TUN, the
//! production capture data plane. NTP mode is the real-link validation path
//! because it cannot be replaced by the Core DNS engine or a host fake-IP
//! resolver.
//!
//! Usage:
//!   udp_socks5_probe <proxy-host> <proxy-port> ntp <server-ip> [port]
//!   udp_socks5_probe <proxy-host> <proxy-port> dns <server-ip> <domain> [port]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use egrio_core::{CoreRuntime, ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};

#[path = "support/udp_tun.rs"]
mod udp_tun;

#[derive(Debug)]
enum Probe {
    Ntp {
        server: String,
        port: u16,
    },
    Dns {
        server: String,
        port: u16,
        domain: String,
    },
}

impl Probe {
    fn parse(args: &[String]) -> Result<Self, String> {
        match args.get(2).map(String::as_str) {
            Some("ntp") if (4..=5).contains(&args.len()) => Ok(Self::Ntp {
                server: args[3].clone(),
                port: args
                    .get(4)
                    .map(|value| value.parse::<u16>().map_err(|error| error.to_string()))
                    .transpose()?
                    .unwrap_or(123),
            }),
            Some("dns") if (5..=6).contains(&args.len()) => Ok(Self::Dns {
                server: args[3].clone(),
                domain: args[4].clone(),
                port: args
                    .get(5)
                    .map(|value| value.parse::<u16>().map_err(|error| error.to_string()))
                    .transpose()?
                    .unwrap_or(53),
            }),
            _ => Err(
                "usage: udp_socks5_probe <proxy-host> <proxy-port> ntp <server-ip> [port]\n       udp_socks5_probe <proxy-host> <proxy-port> dns <server-ip> <domain> [port]"
                    .into(),
            ),
        }
    }

    fn target(&self) -> Result<SocketAddrV4, String> {
        match self {
            Self::Ntp { server, port } | Self::Dns { server, port, .. } => server
                .parse::<Ipv4Addr>()
                .map(|ip| SocketAddrV4::new(ip, *port))
                .map_err(|error| format!("server must be an IPv4 address: {error}")),
        }
    }

    fn payload(&self) -> Vec<u8> {
        match self {
            Self::Ntp { .. } => {
                let mut request = vec![0_u8; 48];
                request[0] = 0x1b;
                request
            }
            Self::Dns { domain, .. } => dns_a_query(domain),
        }
    }

    fn describe_response(&self, response: &[u8]) -> Result<Vec<String>, String> {
        match self {
            Self::Ntp { .. } => {
                if response.len() < 48 || response[0] & 0x07 != 4 {
                    return Err(format!(
                        "unexpected NTP response: {} bytes, first={:?}",
                        response.len(),
                        response.first()
                    ));
                }
                Ok(vec![format!("NTP server reply, stratum {}", response[1])])
            }
            Self::Dns { domain, .. } => {
                let answers = parse_dns_a_answers(response)?;
                let mut lines = vec![format!("DNS answer for {domain}")];
                lines.extend(answers.into_iter().map(|answer| format!("A {answer}")));
                Ok(lines)
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let probe = Probe::parse(&args).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let proxy_host = &args[0];
    let proxy_port: u16 = args[1].parse().expect("proxy port");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        match run(proxy_host, proxy_port, probe).await {
            Ok(()) => {}
            Err(error) => {
                eprintln!("probe failed: {error}");
                std::process::exit(1);
            }
        }
    });
}

async fn run(proxy_host: &str, proxy_port: u16, probe: Probe) -> Result<(), String> {
    let target = probe.target()?;
    let core = CoreRuntime::from_profile(socks5_profile(proxy_host, proxy_port));
    let (writer, mut reader, pump) = udp_tun::start(core.device());
    let payload = probe.payload();
    let source = SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 1), 40000);

    // Retry over one session: the reader delivers whichever attempt's answer
    // arrives first.
    let mut result = Err("no UDP response after 5 attempts".to_string());
    for attempt in 1..=5 {
        writer.send(source, target, &payload).await;
        let Some(response) = reader.recv(Duration::from_secs(5)).await else {
            eprintln!("attempt {attempt}: no response before the deadline, retrying");
            continue;
        };
        result = probe.describe_response(&response.payload).map(|details| {
            println!(
                "received UDP response from {} through socks5://{proxy_host}:{proxy_port} ({} bytes)",
                response.source,
                response.payload.len(),
            );
            for detail in details {
                println!("  {detail}");
            }
        });
        break;
    }

    let pump_report = pump.stop().await;
    core.shutdown();
    result?;
    pump_report?;
    let audit = core.state_audit();
    if audit.udp_sessions != 0 || audit.udp_session_sockets != 0 {
        return Err(format!(
            "UDP flow did not close cleanly: sessions={}, sockets={}",
            audit.udp_sessions, audit.udp_session_sockets
        ));
    }
    println!("  audit clean after closing the UDP flow");
    Ok(())
}

fn socks5_profile(proxy_host: &str, proxy_port: u16) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("udp-socks5-probe");
    profile.proxies = vec![ProxyNode {
        id: "host-socks".into(),
        name: "HostSocks".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some(proxy_host.to_string()),
        port: Some(proxy_port),
        options: serde_json::Value::Null,
    }];
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "HostSocks",
        no_resolve: false,
    }]
    .into();
    profile
}

fn dns_a_query(domain: &str) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, // id
        0x01, 0x00, // RD
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
    query
}

/// Minimal DNS answer walk: skips the question, then collects A rdata.
fn parse_dns_a_answers(message: &[u8]) -> Result<Vec<String>, String> {
    if message.len() < 12 || message[0] != 0x12 || message[1] != 0x34 {
        return Err(format!(
            "unexpected DNS response head: {:?}",
            &message[..message.len().min(12)]
        ));
    }
    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut at = 12;
    for _ in 0..qdcount {
        at = skip_dns_name(message, at)? + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        at = skip_dns_name(message, at)?;
        let record_type = u16::from_be_bytes([message[at], message[at + 1]]);
        let rdlength = u16::from_be_bytes([message[at + 8], message[at + 9]]) as usize;
        let rdata = &message[at + 10..at + 10 + rdlength];
        if record_type == 1 && rdlength == 4 {
            answers.push(format!(
                "{}.{}.{}.{}",
                rdata[0], rdata[1], rdata[2], rdata[3]
            ));
        }
        at += 10 + rdlength;
    }
    Ok(answers)
}

fn skip_dns_name(message: &[u8], mut at: usize) -> Result<usize, String> {
    loop {
        let length = *message.get(at).ok_or("truncated DNS name")?;
        if length & 0xc0 == 0xc0 {
            return Ok(at + 2);
        }
        if length == 0 {
            return Ok(at + 1);
        }
        at += 1 + length as usize;
    }
}

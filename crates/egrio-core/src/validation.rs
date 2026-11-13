use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks5ValidationProxyConfig {
    pub listen_addr: String,
    pub udp_upstream: Option<SocketAddr>,
    pub udp_only: bool,
}

impl Default for Socks5ValidationProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:19080".into(),
            udp_upstream: None,
            udp_only: false,
        }
    }
}

pub fn parse_socks5_validation_proxy_args(
    args: &[String],
) -> Result<Socks5ValidationProxyConfig, String> {
    let mut config = Socks5ValidationProxyConfig::default();
    let mut index = 0;
    if let Some(value) = args.first().filter(|value| !value.starts_with("--")) {
        config.listen_addr = value.clone();
        index = 1;
    }
    while index < args.len() {
        match args[index].as_str() {
            "--udp-upstream" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--udp-upstream requires host:port".to_string())?;
                config.udp_upstream = Some(
                    value
                        .parse()
                        .map_err(|error| format!("invalid --udp-upstream '{value}': {error}"))?,
                );
            }
            "--udp-only" => config.udp_only = true,
            value => {
                return Err(format!(
                    "unknown SOCKS5 validation proxy argument '{value}'; usage: socks5-validation-proxy [listen-host:port] [--udp-upstream ip:port] [--udp-only]"
                ));
            }
        }
        index += 1;
    }
    Ok(config)
}

pub async fn run_socks5_validation_proxy(
    config: Socks5ValidationProxyConfig,
) -> Result<(), String> {
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|error| error.to_string())?;
    println!(
        "SOCKS5 validation proxy listening on {}",
        listener.local_addr().map_err(|error| error.to_string())?
    );
    if let Some(upstream) = config.udp_upstream {
        println!("SOCKS5 validation UDP upstream override: {upstream}");
    }
    loop {
        let (client, _) = listener.accept().await.map_err(|error| error.to_string())?;
        let udp_upstream = config.udp_upstream;
        tokio::spawn(async move {
            if let Err(error) = serve_client(client, udp_upstream, config.udp_only).await {
                eprintln!("SOCKS5 validation client failed: {error}");
            }
        });
    }
}

#[derive(Clone, Debug)]
enum Target {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl Target {
    async fn resolve(&self) -> Result<SocketAddr, String> {
        match self {
            Self::Socket(address) => Ok(*address),
            Self::Domain(host, port) => lookup_host((host.as_str(), *port))
                .await
                .map_err(|error| error.to_string())?
                .next()
                .ok_or_else(|| format!("SOCKS5 target '{host}:{port}' did not resolve")),
        }
    }
}

async fn serve_client(
    mut client: TcpStream,
    udp_upstream: Option<SocketAddr>,
    udp_only: bool,
) -> Result<(), String> {
    let mut greeting = [0_u8; 2];
    client
        .read_exact(&mut greeting)
        .await
        .map_err(|error| error.to_string())?;
    if greeting[0] != 0x05 {
        return Err(format!("unexpected SOCKS version {}", greeting[0]));
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|error| error.to_string())?;
    if !methods.contains(&0x00) {
        client
            .write_all(&[0x05, 0xff])
            .await
            .map_err(|error| error.to_string())?;
        return Err("client did not offer SOCKS5 no-auth".into());
    }
    client
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|error| error.to_string())?;

    let mut head = [0_u8; 4];
    client
        .read_exact(&mut head)
        .await
        .map_err(|error| error.to_string())?;
    if head[0] != 0x05 || head[2] != 0x00 {
        return Err(format!("invalid SOCKS5 request head {head:?}"));
    }
    let target = read_target(&mut client, head[3]).await?;
    match head[1] {
        0x01 if !udp_only => serve_connect(client, target).await,
        0x01 => {
            write_reply(&mut client, 0x07, 0).await?;
            Err("SOCKS5 CONNECT is disabled for this validation proxy".into())
        }
        0x03 => serve_udp_associate(client, udp_upstream).await,
        command => {
            write_reply(&mut client, 0x07, 0).await?;
            Err(format!("unsupported SOCKS5 command {command}"))
        }
    }
}

async fn serve_connect(mut client: TcpStream, target: Target) -> Result<(), String> {
    let mut upstream = TcpStream::connect(target.resolve().await?)
        .await
        .map_err(|error| error.to_string())?;
    write_reply(&mut client, 0x00, 0).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn serve_udp_associate(
    mut control: TcpStream,
    udp_upstream: Option<SocketAddr>,
) -> Result<(), String> {
    let relay = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| error.to_string())?;
    let relay_port = relay
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    write_reply(&mut control, 0x00, relay_port).await?;

    let mut control_eof = [0_u8; 1];
    let mut datagram = vec![0_u8; u16::MAX as usize];
    loop {
        tokio::select! {
            result = control.read(&mut control_eof) => {
                result.map_err(|error| error.to_string())?;
                return Ok(());
            }
            received = relay.recv_from(&mut datagram) => {
                let (read, client) = received.map_err(|error| error.to_string())?;
                let (payload_at, target) = parse_udp_target(&datagram[..read])?;
                let target = match udp_upstream {
                    Some(address) => address,
                    None => target.resolve().await?,
                };
                let bind_addr = match target.ip() {
                    IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                    IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                };
                let upstream = UdpSocket::bind(bind_addr)
                    .await
                    .map_err(|error| error.to_string())?;
                upstream
                    .send_to(&datagram[payload_at..read], target)
                    .await
                    .map_err(|error| error.to_string())?;
                let mut response = vec![0_u8; u16::MAX as usize];
                let (response_len, _) = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    upstream.recv_from(&mut response),
                )
                .await
                .map_err(|_| "SOCKS5 UDP upstream response timed out".to_string())?
                .map_err(|error| error.to_string())?;
                let wire = udp_response_wire(&datagram[..payload_at], &response[..response_len]);
                relay
                    .send_to(&wire, client)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

async fn read_target(client: &mut TcpStream, address_type: u8) -> Result<Target, String> {
    let target = match address_type {
        0x01 => {
            let mut octets = [0_u8; 4];
            client
                .read_exact(&mut octets)
                .await
                .map_err(|error| error.to_string())?;
            Target::Socket(SocketAddr::from((
                Ipv4Addr::from(octets),
                read_port(client).await?,
            )))
        }
        0x03 => {
            let length = client.read_u8().await.map_err(|error| error.to_string())? as usize;
            let mut domain = vec![0_u8; length];
            client
                .read_exact(&mut domain)
                .await
                .map_err(|error| error.to_string())?;
            Target::Domain(
                String::from_utf8(domain).map_err(|error| error.to_string())?,
                read_port(client).await?,
            )
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            client
                .read_exact(&mut octets)
                .await
                .map_err(|error| error.to_string())?;
            Target::Socket(SocketAddr::from((
                Ipv6Addr::from(octets),
                read_port(client).await?,
            )))
        }
        value => return Err(format!("unsupported SOCKS5 address type {value}")),
    };
    Ok(target)
}

async fn read_port(client: &mut TcpStream) -> Result<u16, String> {
    let mut port = [0_u8; 2];
    client
        .read_exact(&mut port)
        .await
        .map_err(|error| error.to_string())?;
    Ok(u16::from_be_bytes(port))
}

fn parse_udp_target(datagram: &[u8]) -> Result<(usize, Target), String> {
    if datagram.len() < 4 || datagram[..2] != [0, 0] || datagram[2] != 0 {
        return Err("invalid SOCKS5 UDP request header".into());
    }
    match datagram[3] {
        0x01 if datagram.len() >= 10 => Ok((
            10,
            Target::Socket(SocketAddr::from((
                Ipv4Addr::new(datagram[4], datagram[5], datagram[6], datagram[7]),
                u16::from_be_bytes([datagram[8], datagram[9]]),
            ))),
        )),
        0x03 if datagram.len() >= 7 => {
            let length = datagram[4] as usize;
            let payload_at = 5 + length + 2;
            if datagram.len() < payload_at {
                return Err("truncated SOCKS5 UDP domain target".into());
            }
            Ok((
                payload_at,
                Target::Domain(
                    String::from_utf8(datagram[5..5 + length].to_vec())
                        .map_err(|error| error.to_string())?,
                    u16::from_be_bytes([datagram[payload_at - 2], datagram[payload_at - 1]]),
                ),
            ))
        }
        0x04 if datagram.len() >= 22 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&datagram[4..20]);
            Ok((
                22,
                Target::Socket(SocketAddr::from((
                    Ipv6Addr::from(octets),
                    u16::from_be_bytes([datagram[20], datagram[21]]),
                ))),
            ))
        }
        value => Err(format!(
            "unsupported or truncated SOCKS5 UDP address type {value}"
        )),
    }
}

fn udp_response_wire(header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut wire = header.to_vec();
    wire.extend_from_slice(payload);
    wire
}

async fn write_reply(client: &mut TcpStream, reply: u8, port: u16) -> Result<(), String> {
    let mut response = vec![0x05, reply, 0x00, 0x01, 0, 0, 0, 0];
    response.extend_from_slice(&port.to_be_bytes());
    client
        .write_all(&response)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_socks5_validation_proxy_args, udp_response_wire, Socks5ValidationProxyConfig,
    };
    use std::net::SocketAddr;

    #[test]
    fn parses_listen_and_udp_override() {
        let args = [
            "192.0.2.10:19080".to_string(),
            "--udp-upstream".to_string(),
            "198.51.100.123:123".to_string(),
        ];
        assert_eq!(
            parse_socks5_validation_proxy_args(&args).unwrap(),
            Socks5ValidationProxyConfig {
                listen_addr: "192.0.2.10:19080".into(),
                udp_upstream: Some("198.51.100.123:123".parse::<SocketAddr>().unwrap()),
                udp_only: false,
            }
        );
    }

    #[test]
    fn parses_udp_only_mode() {
        let args = ["--udp-only".to_string()];
        assert!(parse_socks5_validation_proxy_args(&args).unwrap().udp_only);
    }

    #[test]
    fn defaults_without_arguments() {
        assert_eq!(
            parse_socks5_validation_proxy_args(&[]).unwrap(),
            Socks5ValidationProxyConfig::default()
        );
    }

    #[test]
    fn preserves_requested_udp_header_when_wrapping_response() {
        assert_eq!(
            udp_response_wire(&[0, 0, 0, 1, 203, 0, 113, 10, 0, 123], &[1, 2, 3]),
            vec![0, 0, 0, 1, 203, 0, 113, 10, 0, 123, 1, 2, 3]
        );
    }
}

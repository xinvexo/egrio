use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

struct IpLiteral<'a> {
    address: IpAddr,
    zone: Option<&'a str>,
}

/// Zone qualifiers are local IPv6 metadata, never part of a DNS name. Keep
/// their presence even before validating or resolving the zone itself.
fn parse_ip_literal(host: &str) -> Option<IpLiteral<'_>> {
    if let Ok(address) = host.parse() {
        return Some(IpLiteral {
            address,
            zone: None,
        });
    }
    let (address, zone) = host.split_once('%')?;
    Some(IpLiteral {
        address: IpAddr::V6(address.parse().ok()?),
        zone: Some(zone),
    })
}

/// Parses numeric IP authorities without dropping an IPv6 interface scope.
pub(crate) fn literal_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    let literal = parse_ip_literal(host)?;
    match (literal.address, literal.zone) {
        (IpAddr::V6(ip), Some(scope)) => Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            0,
            scope.parse().ok()?,
        ))),
        (ip, None) => Some(SocketAddr::new(ip, port)),
        _ => None,
    }
}

/// `host:port`, with an IPv6 literal (scoped or not) in brackets.
pub(crate) fn authority(host: &str, port: u16) -> String {
    if matches!(
        parse_ip_literal(host),
        Some(IpLiteral {
            address: IpAddr::V6(_),
            ..
        })
    ) {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ConnectTarget {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl ConnectTarget {
    pub(crate) fn ip(&self) -> Option<IpAddr> {
        parse_ip_literal(&self.host).map(|literal| literal.address)
    }

    pub(crate) fn has_ipv6_scope(&self) -> bool {
        parse_ip_literal(&self.host).is_some_and(|literal| literal.zone.is_some())
    }

    pub(crate) fn host_for_route(&self) -> Option<String> {
        self.ip().is_none().then(|| self.host.clone())
    }

    pub(crate) fn authority(&self) -> String {
        authority(&self.host, self.port)
    }

    /// Encodes the target as a SOCKS address (`[type][addr][port]`): the
    /// address vocabulary Shadowsocks and Trojan share on the wire, written
    /// once. A literal IP encodes as its family;
    /// a domain encodes verbatim so the proxy resolves it (no DNS leak).
    pub(crate) fn socks_address(&self) -> Result<Vec<u8>, String> {
        let literal = parse_ip_literal(&self.host);
        // RFC 4007 zones are node-local; SOCKS5/Trojan have no zone field.
        if literal
            .as_ref()
            .is_some_and(|literal| literal.zone.is_some())
        {
            return Err("scoped IPv6 targets cannot be encoded for a remote proxy".into());
        }
        let mut address = Vec::new();
        if let Some(IpLiteral { address: ip, .. }) = literal {
            match ip {
                IpAddr::V4(ip) => {
                    address.push(0x01);
                    address.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    address.push(0x04);
                    address.extend_from_slice(&ip.octets());
                }
            }
        } else {
            let host = self.host.as_bytes();
            if host.len() > u8::MAX as usize {
                return Err(format!("target host is too long: {}", self.host));
            }
            address.push(0x03);
            address.push(host.len() as u8);
            address.extend_from_slice(host);
        }
        address.extend_from_slice(&self.port.to_be_bytes());
        Ok(address)
    }
}

pub(crate) fn parse_connect_authority(authority: &str) -> Result<ConnectTarget, String> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok(ConnectTarget {
            host: match addr {
                SocketAddr::V6(v6) if v6.scope_id() != 0 || authority.contains('%') => {
                    format!("{}%{}", v6.ip(), v6.scope_id())
                }
                _ => addr.ip().to_string(),
            },
            port: addr.port(),
        });
    }

    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("CONNECT target is missing port: {authority}"))?;
    if host.is_empty() {
        return Err(format!("CONNECT target host is empty: {authority}"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|error| format!("invalid CONNECT target port '{port}': {error}"))?;

    Ok(ConnectTarget {
        host: host.trim_matches(['[', ']']).to_string(),
        port,
    })
}

/// Decodes a SOCKS address from the front of `packet`, returning the target
/// and how many bytes it consumed (so a caller can find the payload that
/// follows). The dual of [`ConnectTarget::socks_address`]; both the
/// Shadowsocks acceptor's request header and its UDP packets carry this.
pub(crate) fn parse_socks_address(packet: &[u8]) -> Result<(ConnectTarget, usize), String> {
    let Some((&address_type, rest)) = packet.split_first() else {
        return Err("SOCKS address packet is empty".into());
    };
    match address_type {
        0x01 => {
            if rest.len() < 6 {
                return Err(format!("invalid IPv4 SOCKS address length {}", rest.len()));
            }
            Ok((
                ConnectTarget {
                    host: IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])).to_string(),
                    port: u16::from_be_bytes([rest[4], rest[5]]),
                },
                1 + 4 + 2,
            ))
        }
        0x03 => {
            let Some((&length, rest)) = rest.split_first() else {
                return Err("domain SOCKS address is missing length".into());
            };
            let length = length as usize;
            if length == 0 {
                return Err("domain SOCKS address has zero length".into());
            }
            if rest.len() < length + 2 {
                return Err(format!(
                    "invalid domain SOCKS address length {}",
                    rest.len()
                ));
            }
            let host =
                String::from_utf8(rest[..length].to_vec()).map_err(|error| error.to_string())?;
            Ok((
                ConnectTarget {
                    host,
                    port: u16::from_be_bytes([rest[length], rest[length + 1]]),
                },
                1 + 1 + length + 2,
            ))
        }
        0x04 => {
            if rest.len() < 18 {
                return Err(format!("invalid IPv6 SOCKS address length {}", rest.len()));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&rest[..16]);
            Ok((
                ConnectTarget {
                    host: IpAddr::V6(Ipv6Addr::from(octets)).to_string(),
                    port: u16::from_be_bytes([rest[16], rest[17]]),
                },
                1 + 16 + 2,
            ))
        }
        unsupported => Err(format!("unsupported SOCKS address type {unsupported}")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn scoped_ipv6_remains_numeric_and_preserves_authority() {
        let target = super::ConnectTarget {
            host: "fe80::1234%7".into(),
            port: 4242,
        };
        assert!(target.ip().unwrap().is_ipv6());
        assert!(target.host_for_route().is_none());
        assert_eq!(target.authority(), "[fe80::1234%7]:4242");
        assert_eq!(
            super::literal_socket_addr(&target.host, target.port).unwrap(),
            "[fe80::1234%7]:4242"
                .parse::<std::net::SocketAddr>()
                .unwrap()
        );
    }

    #[test]
    fn named_ipv6_zone_remains_ip_metadata_not_a_domain() {
        let target = super::ConnectTarget {
            host: "fe80::1234%en0".into(),
            port: 4242,
        };
        assert_eq!(target.ip(), Some("fe80::1234".parse().unwrap()));
        assert!(target.host_for_route().is_none());
        assert!(target.has_ipv6_scope());
        assert_eq!(target.authority(), "[fe80::1234%en0]:4242");
        // Numeric socket construction is distinct from preserving zone metadata.
        assert!(super::literal_socket_addr(&target.host, target.port).is_none());
    }

    #[test]
    fn connect_authority_preserves_named_numeric_and_default_zones() {
        for zone in ["en0", "7", "0"] {
            let authority = format!("[fe80::1234%{zone}]:4242");
            let target = super::parse_connect_authority(&authority).unwrap();
            assert_eq!(target.host, format!("fe80::1234%{zone}"));
            assert_eq!(target.authority(), authority);
            assert!(target.has_ipv6_scope());
            assert!(target.host_for_route().is_none());
        }
    }

    #[test]
    fn remote_proxy_encoding_cannot_drop_or_reinterpret_an_ipv6_zone() {
        for host in [
            "fe80::1234%en0",
            "fe80::1234%7",
            "fe80::1234%0",
            "fe80::1234%",
        ] {
            let target = super::ConnectTarget {
                host: host.into(),
                port: 4242,
            };
            assert!(target.socks_address().unwrap_err().contains("scoped IPv6"));
            assert!(target.host_for_route().is_none());
        }
        let plain = super::ConnectTarget {
            host: "2001:db8::1".into(),
            port: 443,
        };
        assert!(!plain.has_ipv6_scope());
        assert_eq!(plain.socks_address().unwrap()[0], 0x04);
        let domain = super::ConnectTarget {
            host: "example.com".into(),
            port: 443,
        };
        assert!(!domain.has_ipv6_scope());
        assert_eq!(domain.socks_address().unwrap()[0], 0x03);
    }

    use super::*;

    #[test]
    fn parses_domain_connect_authority() {
        let target = parse_connect_authority("example.com:443").expect("valid target");

        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.ip(), None);
    }

    #[test]
    fn parses_ipv4_connect_authority() {
        let target = parse_connect_authority("127.0.0.1:8080").expect("valid target");

        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 8080);
        assert_eq!(target.ip(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_a_zero_length_domain_socks_address() {
        // ATYP=domain (0x03), length 0, then a port: an empty host must fail
        // here at parse time, not slip through as "" to fail later at
        // route/dial. Every protocol that shares this vocabulary (Shadowsocks,
        // Trojan) inherits the guard.
        let packet = [0x03, 0x00, 0x01, 0xbb];
        let error =
            parse_socks_address(&packet).expect_err("a zero-length domain must be rejected");
        assert!(error.contains("zero length"), "got: {error}");
    }
}

//! What client and server say inside the control channel's TLS session
//! (OpenVPN `ssl.c` `key_method_2_write`/`read`, `push.c`, the wire protocol
//! draft's "Key exchange message" and "Control channel messages"): first a
//! binary key exchange each way, then NUL-terminated text messages — the
//! push request and the server's pushed configuration among them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::config::DataCipher;

/// `IV_PROTO` bits this client announces (`ssl.h`): `P_DATA_V2`, a push
/// reply without waiting for the request, key derivation by TLS exporter,
/// `AUTH_PENDING` keywords, exit notification over the control channel and
/// `AUTH_FAILED,TEMP`.
const IV_PROTO: u32 = 1 << 1 | 1 << 2 | 1 << 3 | 1 << 4 | 1 << 7 | 1 << 8;

#[derive(Clone)]
pub(crate) struct Credentials {
    pub(crate) username: String,
    pub(crate) password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

fn write_string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

/// The client's peer info: what it implements, for the server to choose
/// from (cipher, peer ids, key derivation).
pub(super) fn peer_info(ciphers: &[DataCipher]) -> String {
    let platform = if cfg!(target_os = "windows") {
        "win"
    } else if cfg!(target_os = "macos") {
        "mac"
    } else {
        "linux"
    };
    let names: Vec<&str> = ciphers.iter().map(|cipher| cipher.name()).collect();
    let mut info = format!("IV_VER=2.6.0\nIV_PLAT={platform}\nIV_TCPNL=1\nIV_MTU=1600\n");
    if ciphers.contains(&DataCipher::Aes128Gcm) && ciphers.contains(&DataCipher::Aes256Gcm) {
        info.push_str("IV_NCP=2\n");
    }
    info.push_str(&format!(
        "IV_CIPHERS={}\nIV_PROTO={IV_PROTO}\nIV_GUI_VER=Egrio_{}\n",
        names.join(":"),
        env!("CARGO_PKG_VERSION")
    ));
    info
}

/// The client's key exchange (key method 2): the legacy key source the
/// TLS exporter has replaced (random, as the draft asks), the options
/// string, credentials and peer info.
pub(super) fn client_key_exchange(
    options: &str,
    credentials: Option<&Credentials>,
    peer_info: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&0_u32.to_be_bytes());
    out.push(2);
    out.extend_from_slice(&rand::random::<[u8; 48]>());
    out.extend_from_slice(&rand::random::<[u8; 64]>());
    write_string(&mut out, options);
    match credentials {
        Some(credentials) => {
            write_string(&mut out, &credentials.username);
            write_string(&mut out, &credentials.password);
        }
        None => out.extend_from_slice(&[0, 0, 0, 0]),
    }
    write_string(&mut out, peer_info);
    out
}

/// How long the server's key exchange at the front of `plaintext` is, once
/// it has all arrived; an error if it is not one.
pub(super) fn server_key_exchange_len(plaintext: &[u8]) -> Option<Result<usize, String>> {
    // u32 0, method, random1, random2, then options, username, password and
    // (from 2.4 on) peer info, each a u16 length and that many bytes.
    let fixed = 4 + 1 + 32 + 32;
    if plaintext.len() < fixed {
        return None;
    }
    if plaintext[..4] != [0; 4] || plaintext[4] & 0x0f != 2 {
        return Some(Err("the server's key exchange is not key method 2".into()));
    }
    let mut at = fixed;
    let string = |at: &mut usize| -> Option<()> {
        let length = u16::from_be_bytes(plaintext.get(*at..*at + 2)?.try_into().ok()?) as usize;
        if plaintext.len() < *at + 2 + length {
            return None;
        }
        *at += 2 + length;
        Some(())
    };
    for _ in 0..3 {
        string(&mut at)?;
    }
    // Peer info, when the length that follows fits what arrived.
    if let Some(length) = plaintext.get(at..at + 2) {
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;
        if plaintext.len() >= at + 2 + length {
            at += 2 + length;
        }
    }
    Some(Ok(at))
}

/// A text message from the server.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ServerMessage {
    /// Part of the pushed configuration; `more` when continuations follow.
    PushReply {
        options: Vec<String>,
        more: bool,
    },
    AuthFailed(String),
    /// Authentication waits on something else (a second factor): the
    /// handshake may take this long.
    AuthPending(Option<Duration>),
    /// End the session and connect again.
    Restart(String),
    /// End the session for good.
    Halt(String),
    /// The server is shutting down.
    Exit,
    Other,
}

impl ServerMessage {
    pub(super) fn parse(text: &str) -> Self {
        let (head, rest) = text.split_once(',').unwrap_or((text, ""));
        match head {
            "PUSH_REPLY" => {
                let mut more = false;
                let options = rest
                    .split(',')
                    .map(str::trim)
                    .filter(|option| !option.is_empty())
                    .filter(|option| match option.strip_prefix("push-continuation ") {
                        Some(value) => {
                            more = value.trim() == "2";
                            false
                        }
                        None => true,
                    })
                    .map(str::to_owned)
                    .collect();
                Self::PushReply { options, more }
            }
            "AUTH_FAILED" => Self::AuthFailed(rest.to_owned()),
            "AUTH_PENDING" => Self::AuthPending(
                rest.split(',')
                    .find_map(|flag| flag.trim().strip_prefix("timeout "))
                    .and_then(|seconds| seconds.trim().parse().ok())
                    .map(Duration::from_secs),
            ),
            "RESTART" => Self::Restart(rest.to_owned()),
            "HALT" => Self::Halt(rest.to_owned()),
            "EXIT" => Self::Exit,
            _ => Self::Other,
        }
    }
}

/// The server's pushed configuration this client uses (OpenVPN
/// `options.c`, the options a server may push).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Pushed {
    pub(crate) ipv4: Option<Ipv4Addr>,
    pub(crate) ipv6: Option<Ipv6Addr>,
    pub(crate) routes: Vec<(IpAddr, u8)>,
    pub(crate) dns: Vec<IpAddr>,
    pub(crate) peer_id: Option<u32>,
    /// The data cipher's name as pushed; `None` keeps the config's.
    pub(crate) cipher: Option<String>,
    pub(crate) tls_ekm: bool,
    pub(crate) cc_exit: bool,
    pub(crate) ping: Option<Duration>,
    pub(crate) ping_restart: Option<Duration>,
    pub(crate) mtu: Option<u16>,
    pub(crate) auth_token: Option<String>,
    pub(crate) redirect_gateway: bool,
}

fn netmask_bits(mask: &str) -> Option<u8> {
    let mask: Ipv4Addr = mask.parse().ok()?;
    Some(u32::from(mask).count_ones() as u8)
}

impl Pushed {
    pub(super) fn apply(&mut self, option: &str) {
        let words: Vec<&str> = option.split_whitespace().collect();
        let Some((&name, args)) = words.split_first() else {
            return;
        };
        let seconds = |value: Option<&&str>| {
            value
                .and_then(|value| value.parse().ok())
                .map(Duration::from_secs)
        };
        match name {
            "ifconfig" => self.ipv4 = args.first().and_then(|ip| ip.parse().ok()),
            "ifconfig-ipv6" => {
                self.ipv6 = args
                    .first()
                    .and_then(|address| address.split('/').next())
                    .and_then(|ip| ip.parse().ok());
            }
            "route" => {
                if let (Some(network), Some(bits)) = (
                    args.first().and_then(|ip| ip.parse::<Ipv4Addr>().ok()),
                    args.get(1).map_or(Some(32), |mask| netmask_bits(mask)),
                ) {
                    self.routes.push((IpAddr::V4(network), bits));
                }
            }
            "route-ipv6" => {
                if let Some((network, bits)) = args.first().and_then(|route| route.split_once('/'))
                {
                    if let (Ok(network), Ok(bits)) = (network.parse::<Ipv6Addr>(), bits.parse()) {
                        self.routes.push((IpAddr::V6(network), bits));
                    }
                }
            }
            "dhcp-option" => {
                if matches!(args.first(), Some(&"DNS") | Some(&"DNS6")) {
                    self.dns
                        .extend(args.get(1).and_then(|ip| ip.parse::<IpAddr>().ok()));
                }
            }
            // `dns server <n> address <ip>[:port] ...` (2.6's --dns).
            "dns" if args.get(2) == Some(&"address") => {
                for address in &args[3..] {
                    let address = address.trim_start_matches('[');
                    let ip = address.split(']').next().unwrap_or(address);
                    if let Ok(ip) = ip.parse::<IpAddr>() {
                        self.dns.push(ip);
                    } else if let Some(ip) = ip.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok())
                    {
                        self.dns.push(ip);
                    }
                }
            }
            "peer-id" => self.peer_id = args.first().and_then(|id| id.parse().ok()),
            "cipher" => self.cipher = args.first().map(|cipher| cipher.to_string()),
            "key-derivation" => self.tls_ekm |= args.first() == Some(&"tls-ekm"),
            "protocol-flags" => {
                for flag in args {
                    match *flag {
                        "tls-ekm" => self.tls_ekm = true,
                        "cc-exit" => self.cc_exit = true,
                        _ => {}
                    }
                }
            }
            "ping" => self.ping = seconds(args.first()),
            "ping-restart" => self.ping_restart = seconds(args.first()),
            "tun-mtu" => self.mtu = args.first().and_then(|mtu| mtu.parse().ok()),
            "auth-token" => self.auth_token = args.first().map(|token| token.to_string()),
            "redirect-gateway" => self.redirect_gateway = true,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_key_exchange_is_key_method_2_with_counted_strings() {
        let credentials = Credentials {
            username: "user".into(),
            password: "secret".into(),
        };
        let message = client_key_exchange("V4,dev-type tun", Some(&credentials), "IV_PROTO=2\n");
        assert_eq!(message[..5], [0, 0, 0, 0, 2]);
        let mut at = 5 + 48 + 64;
        let mut strings = Vec::new();
        while at < message.len() {
            let length = u16::from_be_bytes([message[at], message[at + 1]]) as usize;
            strings.push(&message[at + 2..at + 2 + length]);
            at += 2 + length;
        }
        assert_eq!(
            strings,
            [
                &b"V4,dev-type tun\0"[..],
                b"user\0",
                b"secret\0",
                b"IV_PROTO=2\n\0"
            ]
        );
        let anonymous = client_key_exchange("V4", None, "");
        assert_eq!(anonymous[5 + 112 + 5..5 + 112 + 9], [0, 0, 0, 0]);
    }

    #[test]
    fn the_server_key_exchange_is_measured_once_whole() {
        let mut message = vec![0, 0, 0, 0, 2];
        message.extend_from_slice(&[7; 64]);
        write_string(&mut message, "V4,dev-type tun");
        message.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(server_key_exchange_len(&message[..20]), None);
        let without_peer_info = message.len();
        assert_eq!(
            server_key_exchange_len(&message),
            Some(Ok(without_peer_info))
        );
        message.extend_from_slice(&[0, 0]);
        assert_eq!(server_key_exchange_len(&message), Some(Ok(message.len())));
        // A push reply right behind it is not taken for peer info.
        let whole = message.len();
        message.extend_from_slice(b"PUSH_REPLY,ping 10\0");
        assert_eq!(server_key_exchange_len(&message), Some(Ok(whole)));
        assert!(matches!(server_key_exchange_len(&[1; 80]), Some(Err(_))));
    }

    #[test]
    fn a_push_reply_reads_into_the_pushed_configuration() {
        let ServerMessage::PushReply { options, more } = ServerMessage::parse(
            "PUSH_REPLY,redirect-gateway def1 bypass-dhcp,dhcp-option DNS 10.8.0.1,\
             route 192.168.1.0 255.255.255.0,route-gateway 10.8.0.1,topology subnet,ping 10,\
             ping-restart 120,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,cipher AES-128-GCM,\
             protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500,push-continuation 2",
        ) else {
            panic!("a push reply");
        };
        assert!(more);
        let mut pushed = Pushed::default();
        for option in &options {
            pushed.apply(option);
        }
        assert_eq!(pushed.ipv4, Some(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(
            pushed.routes,
            [(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)]
        );
        assert_eq!(pushed.dns, [IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))]);
        assert_eq!(pushed.peer_id, Some(3));
        assert_eq!(pushed.cipher.as_deref(), Some("AES-128-GCM"));
        assert!(pushed.tls_ekm && pushed.cc_exit && pushed.redirect_gateway);
        assert_eq!(pushed.ping, Some(Duration::from_secs(10)));
        assert_eq!(pushed.ping_restart, Some(Duration::from_secs(120)));
        assert_eq!(pushed.mtu, Some(1500));
        assert_eq!(
            ServerMessage::parse("AUTH_FAILED"),
            ServerMessage::AuthFailed(String::new())
        );
        assert_eq!(
            ServerMessage::parse("AUTH_PENDING,timeout 180"),
            ServerMessage::AuthPending(Some(Duration::from_secs(180)))
        );
        assert_eq!(
            ServerMessage::parse("RESTART,server restarting"),
            ServerMessage::Restart("server restarting".into())
        );
    }

    #[test]
    fn the_peer_info_names_what_this_client_does() {
        let info = peer_info(&[DataCipher::Aes256Gcm, DataCipher::Aes128Gcm]);
        assert!(info.contains("IV_CIPHERS=AES-256-GCM:AES-128-GCM\n"));
        assert!(info.contains("IV_NCP=2\n"));
        assert!(info.contains(&format!("IV_PROTO={IV_PROTO}\n")));
        assert_eq!(IV_PROTO, 2 + 4 + 8 + 16 + 128 + 256);
    }
}

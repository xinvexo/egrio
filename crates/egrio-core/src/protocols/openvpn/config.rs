//! The `.ovpn` client configuration an OpenVPN node names (its `config`
//! option), read into what this client implements: TLS with the
//! inline CA, certificate and key, tls-crypt, AEAD data ciphers, and the
//! server's pushed configuration. Directives that only shape the host's own
//! interface, routes or scripts mean nothing here and are skipped; those
//! whose wire behavior this client lacks (compression, tls-auth, static-key
//! mode, TAP) make the node unusable with a reason, never a silently
//! different connection. Semantics follow OpenVPN 2.6's `options.c`.

use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use super::crypt::StaticKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

/// One `remote`: tried in order, unless `remote-random` shuffles them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Remote {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) transport: Transport,
}

/// `verify-x509-name`: what the server certificate's subject must say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum X509Name {
    /// `name`: the common name, exactly.
    CommonName(String),
    /// `name-prefix`: the common name begins with it.
    CommonNamePrefix(String),
}

/// The AEAD data channel ciphers this client speaks, by OpenVPN name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl DataCipher {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Some(Self::Aes128Gcm),
            "AES-256-GCM" => Some(Self::Aes256Gcm),
            "CHACHA20-POLY1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "CHACHA20-POLY1305",
        }
    }
}

/// OpenVPN 2.6's `data-ciphers` default.
const DEFAULT_CIPHERS: [DataCipher; 3] = [
    DataCipher::Aes256Gcm,
    DataCipher::Aes128Gcm,
    DataCipher::ChaCha20Poly1305,
];

pub(crate) struct ClientConfig {
    pub(crate) remotes: Vec<Remote>,
    pub(crate) remote_random: bool,
    pub(crate) ca: Vec<CertificateDer<'static>>,
    /// The client certificate, then any `extra-certs`.
    pub(crate) cert_chain: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
    pub(crate) tls_crypt: Option<StaticKey>,
    pub(crate) verify_name: Option<X509Name>,
    /// `remote-cert-tls server`: the server certificate carries key usage and
    /// the TLS Web Server Authentication extended key usage.
    pub(crate) remote_cert_tls_server: bool,
    /// Offered to the server in this order (`data-ciphers`).
    pub(crate) ciphers: Vec<DataCipher>,
    /// `cipher`: what a server that negotiates nothing is taken to use.
    pub(crate) fallback_cipher: Option<DataCipher>,
    /// `auth-user-pass`: the server wants a username and password.
    pub(crate) auth_user_pass: bool,
    pub(crate) reneg: Duration,
    pub(crate) hand_window: Duration,
    pub(crate) tls_timeout: Duration,
    pub(crate) ping: Option<Duration>,
    pub(crate) ping_restart: Option<Duration>,
    pub(crate) explicit_exit_notify: bool,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keys and certificates stay out of logs.
        formatter
            .debug_struct("ClientConfig")
            .field("remotes", &self.remotes)
            .field("tls_crypt", &self.tls_crypt.is_some())
            .field("verify_name", &self.verify_name)
            .field("ciphers", &self.ciphers)
            .finish_non_exhaustive()
    }
}

/// Directives whose wire behavior this client does not implement.
fn unsupported(directive: &str, args: &[String]) -> Option<String> {
    let reason = match directive {
        "comp-lzo" | "compress" => {
            "compression is not supported (it is unsafe and OpenVPN 2.6 disables it)"
        }
        "fragment" => "OpenVPN's own fragmentation is not supported",
        "tls-auth" => "tls-auth is not supported yet; tls-crypt is",
        "tls-crypt-v2" => "tls-crypt-v2 is not supported yet; tls-crypt is",
        "secret" => "static-key mode is not supported",
        "pkcs12" => "PKCS#12 bundles are not supported; inline <cert> and <key> are",
        "http-proxy" | "socks-proxy" => {
            "OpenVPN's own proxy settings are not supported; use dialer-proxy"
        }
        "connection" => "<connection> blocks are not supported",
        "ns-cert-type" => "ns-cert-type is obsolete; use remote-cert-tls server",
        "remote-cert-ku" | "remote-cert-eku" => {
            "remote-cert-ku and remote-cert-eku are not supported; remote-cert-tls server is"
        }
        "tls-server" | "server" | "mode" => "the configuration is not a client's",
        "dev" if args.first().is_some_and(|dev| dev.starts_with("tap")) => {
            "TAP (layer 2) tunnels are not supported"
        }
        "dev-type" if args.first().is_some_and(|dev| dev == "tap") => {
            "TAP (layer 2) tunnels are not supported"
        }
        _ => return None,
    };
    Some(format!("{directive}: {reason}"))
}

fn transport(proto: &str) -> Result<Transport, String> {
    match proto {
        "udp" | "udp4" | "udp6" => Ok(Transport::Udp),
        "tcp" | "tcp4" | "tcp6" | "tcp-client" | "tcp4-client" | "tcp6-client" => {
            Ok(Transport::Tcp)
        }
        other => Err(format!("proto {other} is not supported")),
    }
}

fn seconds(directive: &str, value: Option<&String>) -> Result<Duration, String> {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .ok_or_else(|| format!("{directive} needs a number of seconds"))
}

/// Splits a directive line into words, honoring double and single quotes.
fn words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    for ch in line.chars() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => word.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                started = true;
            }
            None if ch.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            None => {
                word.push(ch);
                started = true;
            }
        }
    }
    if started {
        words.push(word);
    }
    words
}

/// Reads a config. Every certificate and key must be inline in it, so the one
/// file is the node's whole configuration.
pub(crate) fn parse(text: &str) -> Result<ClientConfig, String> {
    let mut client = false;
    let mut pull = false;
    let mut tls_client = false;
    let mut default_transport = Transport::Udp;
    let mut default_port = 1194_u16;
    let mut remotes: Vec<(String, Option<u16>, Option<Transport>)> = Vec::new();
    let mut remote_random = false;
    let mut blocks: Vec<(String, String)> = Vec::new();
    let mut verify_name = None;
    let mut remote_cert_tls_server = false;
    let mut data_ciphers: Option<Vec<String>> = None;
    let mut fallback_cipher = None;
    let mut auth_user_pass = false;
    let mut reneg = Duration::from_secs(3600);
    let mut hand_window = Duration::from_secs(60);
    let mut tls_timeout = Duration::from_secs(2);
    let mut ping = None;
    let mut ping_restart = None;
    let mut explicit_exit_notify = false;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tag) = line
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
        {
            if tag.starts_with('/') {
                return Err(format!("unexpected <{tag}>"));
            }
            let close = format!("</{tag}>");
            let mut body = String::new();
            loop {
                let Some(line) = lines.next() else {
                    return Err(format!("<{tag}> is not closed"));
                };
                if line.trim() == close {
                    break;
                }
                body.push_str(line);
                body.push('\n');
            }
            blocks.push((tag.to_owned(), body));
            continue;
        }
        let words = words(line.strip_prefix("--").unwrap_or(line));
        let Some((directive, args)) = words.split_first() else {
            continue;
        };
        if let Some(reason) = unsupported(directive, args) {
            return Err(reason);
        }
        let first = args.first();
        match directive.as_str() {
            "client" => client = true,
            "pull" => pull = true,
            "tls-client" => tls_client = true,
            "proto" => {
                default_transport = transport(first.ok_or("proto needs a protocol")?)?;
            }
            "port" | "rport" => {
                default_port = first
                    .and_then(|port| port.parse().ok())
                    .ok_or_else(|| format!("{directive} needs a port"))?;
            }
            "remote" => {
                let host = first.ok_or("remote needs a host")?.clone();
                let port = args
                    .get(1)
                    .map(|port| {
                        port.parse::<u16>()
                            .map_err(|_| format!("bad remote port {port}"))
                    })
                    .transpose()?;
                let transport = args.get(2).map(|proto| transport(proto)).transpose()?;
                remotes.push((host, port, transport));
            }
            "remote-random" => remote_random = true,
            "ca" | "cert" | "key" | "extra-certs" | "tls-crypt"
                if first.is_some_and(|value| value != "[inline]") =>
            {
                return Err(format!(
                    "{directive} must be inline (<{directive}>) in a node's configuration"
                ));
            }
            "verify-x509-name" => {
                let name = first.ok_or("verify-x509-name needs a name")?.clone();
                verify_name = Some(match args.get(1).map(String::as_str) {
                    None | Some("name") => X509Name::CommonName(name),
                    Some("name-prefix") => X509Name::CommonNamePrefix(name),
                    Some(kind) => {
                        return Err(format!("verify-x509-name {kind} is not supported"));
                    }
                });
            }
            "remote-cert-tls" => match first.map(String::as_str) {
                Some("server") => remote_cert_tls_server = true,
                _ => return Err("remote-cert-tls must name server".into()),
            },
            "data-ciphers" | "ncp-ciphers" => {
                data_ciphers = Some(
                    first
                        .ok_or_else(|| format!("{directive} needs a cipher list"))?
                        .split(':')
                        .map(str::to_owned)
                        .collect(),
                );
            }
            "cipher" | "data-ciphers-fallback" => {
                let name = first.ok_or_else(|| format!("{directive} needs a cipher"))?;
                fallback_cipher = DataCipher::from_name(name);
            }
            "auth-user-pass" => auth_user_pass = true,
            "reneg-sec" => reneg = seconds(directive, first)?,
            "hand-window" => hand_window = seconds(directive, first)?,
            "tls-timeout" => tls_timeout = seconds(directive, first)?,
            "ping" => ping = Some(seconds(directive, first)?),
            "ping-restart" => ping_restart = Some(seconds(directive, first)?),
            "keepalive" => {
                ping = Some(seconds(directive, first)?);
                ping_restart = Some(seconds(directive, args.get(1))?);
            }
            "explicit-exit-notify" => explicit_exit_notify = true,
            _ => {}
        }
    }
    if !client && !(pull && tls_client) {
        return Err("the configuration is not a client's (no `client` directive)".into());
    }
    let block = |tag: &str| {
        blocks
            .iter()
            .filter(|(name, _)| name == tag)
            .map(|(_, body)| body.as_str())
            .collect::<Vec<_>>()
    };
    if let Some((tag, _)) = blocks.iter().find(|(tag, _)| {
        matches!(
            tag.as_str(),
            "tls-auth"
                | "tls-crypt-v2"
                | "secret"
                | "pkcs12"
                | "connection"
                | "http-proxy-user-pass"
        )
    }) {
        return Err(unsupported(tag, &[]).unwrap_or_else(|| format!("<{tag}> is not supported")));
    }
    let certificates = |tag: &str| -> Result<Vec<CertificateDer<'static>>, String> {
        block(tag)
            .into_iter()
            .flat_map(|body| CertificateDer::pem_slice_iter(body.as_bytes()))
            .collect::<Result<_, _>>()
            .map_err(|error| format!("<{tag}> is not a PEM certificate: {error}"))
    };
    let ca = certificates("ca")?;
    if ca.is_empty() {
        return Err("the configuration has no <ca>".into());
    }
    let mut cert_chain = certificates("cert")?;
    if cert_chain.is_empty() {
        return Err("the configuration has no client <cert>".into());
    }
    cert_chain.extend(certificates("extra-certs")?);
    let key = block("key")
        .first()
        .ok_or("the configuration has no client <key>")
        .and_then(|body| {
            if body.contains("ENCRYPTED") {
                return Err("an encrypted <key> is not supported");
            }
            PrivateKeyDer::from_pem_slice(body.as_bytes())
                .map_err(|_| "<key> is not a PEM private key")
        })?;
    let tls_crypt = block("tls-crypt")
        .first()
        .map(|body| StaticKey::parse(body))
        .transpose()?;
    let remotes = remotes
        .into_iter()
        .map(|(host, port, transport)| Remote {
            host,
            port: port.unwrap_or(default_port),
            transport: transport.unwrap_or(default_transport),
        })
        .collect::<Vec<_>>();
    if remotes.is_empty() {
        return Err("the configuration has no remote".into());
    }
    let ciphers: Vec<DataCipher> = match data_ciphers {
        Some(names) => names
            .iter()
            .filter_map(|name| DataCipher::from_name(name))
            .collect(),
        None => DEFAULT_CIPHERS.to_vec(),
    };
    if ciphers.is_empty() {
        return Err("data-ciphers names no AEAD cipher (AES-GCM or CHACHA20-POLY1305)".into());
    }
    Ok(ClientConfig {
        remotes,
        remote_random,
        ca,
        cert_chain,
        key,
        tls_crypt,
        verify_name,
        remote_cert_tls_server,
        ciphers,
        fallback_cipher,
        auth_user_pass,
        reneg,
        hand_window,
        tls_timeout,
        ping,
        ping_restart,
        explicit_exit_notify,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A config shaped like the ones OpenVPN's installers write, with
    /// throwaway credentials.
    pub(in crate::protocols::openvpn) fn sample(extra: &str) -> String {
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = rcgen::CertificateParams::new(vec!["client".into()])
            .expect("params")
            .self_signed(&key_pair)
            .expect("cert");
        let mut static_key = String::from("-----BEGIN OpenVPN Static key V1-----\n");
        for line in 0..16 {
            static_key.push_str(&format!("{:032x}\n", line));
        }
        static_key.push_str("-----END OpenVPN Static key V1-----\n");
        format!(
            "client\nproto udp\nremote 192.0.2.1 7005\nremote vpn.example 443 tcp\ndev tun\n\
             resolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\n\
             verify-x509-name server_abc name\nauth SHA256\nauth-user-pass\ncipher AES-128-GCM\n\
             tls-client\ntls-version-min 1.2\ntls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256\n\
             verb 3\nroute 192.168.88.0 255.255.255.0\n{extra}\
             <ca>\n{ca}</ca>\n<cert>\n{ca}</cert>\n<key>\n{key}</key>\n<tls-crypt>\n{static_key}</tls-crypt>\n",
            ca = cert.pem(),
            key = key_pair.serialize_pem(),
        )
    }

    #[test]
    fn an_installer_style_config_reads_whole() {
        let config = parse(&sample("")).expect("a client config");
        assert_eq!(
            config.remotes,
            [
                Remote {
                    host: "192.0.2.1".into(),
                    port: 7005,
                    transport: Transport::Udp
                },
                Remote {
                    host: "vpn.example".into(),
                    port: 443,
                    transport: Transport::Tcp
                },
            ]
        );
        assert_eq!(config.ca.len(), 1);
        assert_eq!(config.cert_chain.len(), 1);
        assert!(config.tls_crypt.is_some());
        assert_eq!(
            config.verify_name,
            Some(X509Name::CommonName("server_abc".into()))
        );
        assert!(config.remote_cert_tls_server);
        assert!(config.auth_user_pass);
        assert_eq!(config.ciphers, DEFAULT_CIPHERS);
        assert_eq!(config.fallback_cipher, Some(DataCipher::Aes128Gcm));
    }

    #[test]
    fn wire_options_it_lacks_fail_with_a_reason() {
        for (extra, named) in [
            ("comp-lzo\n", "compression"),
            ("compress lz4-v2\n", "compression"),
            ("tls-auth ta.key 1\n", "tls-auth"),
            ("dev tap\n", "TAP"),
            ("http-proxy 127.0.0.1 8080\n", "dialer-proxy"),
            ("ca ca.crt\n", "inline"),
            ("data-ciphers AES-256-CBC\n", "AEAD"),
        ] {
            let Err(reason) = parse(&sample(extra)) else {
                panic!("{extra} must not be ignored");
            };
            assert!(reason.contains(named), "{extra}: {reason}");
        }
        assert!(parse("remote 192.0.2.1\n").unwrap_err().contains("client"));
    }

    #[test]
    fn quoted_words_keep_their_spaces() {
        assert_eq!(
            words(r#"verify-x509-name "C=US, CN=server one" subject"#),
            ["verify-x509-name", "C=US, CN=server one", "subject"]
        );
    }
}

//! The control channel: one session with the server, keyed by the session
//! ids both sides chose, and its key states — the first one TLS session that
//! authenticates the client and fetches the pushed configuration, then one
//! per renegotiation (OpenVPN `ssl.c`). Each key state's TLS records ride
//! `P_CONTROL_V1` messages of its own reliability layer; the data channel
//! keys each one produces come from TLS's keying material exporter.
//!
//! Sans-IO: the tunnel hands packets in, takes packets out, and asks when it
//! must call again.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::ClientConnection;
use rustls_pki_types::ServerName;

use super::config::{ClientConfig, DataCipher};
use super::crypt::TlsCrypt;
use super::data::DataKeys;
use super::exchange::{
    client_key_exchange, peer_info, server_key_exchange_len, Credentials, Pushed, ServerMessage,
};
use super::reliable::Reliable;
use super::wire::{
    ControlPlain, Wrap, ACKS_ALONE, ACKS_WITH_MESSAGE, P_ACK_V1, P_CONTROL_HARD_RESET_CLIENT_V2,
    P_CONTROL_HARD_RESET_SERVER_V2, P_CONTROL_SOFT_RESET_V1, P_CONTROL_V1,
};

/// TLS bytes one `P_CONTROL_V1` message carries: control packets stay within
/// the 1250 bytes OpenVPN 2.6 accepts (`tls-mtu`) with tls-crypt, the acks
/// and the ids around them.
const TLS_PER_MESSAGE: usize = 1100;
/// How often a push request goes out until the reply comes
/// (`PUSH_REQUEST_INTERVAL`).
const PUSH_REQUEST_INTERVAL: Duration = Duration::from_secs(5);
/// The exporter label of the data channel keys (`EXPORT_KEY_DATA_LABEL`).
const DATA_KEYS_LABEL: &[u8] = b"EXPORTER-OpenVPN-datakeys";

/// What the session reports to the tunnel.
pub(super) enum Event {
    /// Authenticated, configured and keyed.
    Up(Pushed, DataKeys),
    /// A renegotiation's new data keys.
    Rekeyed(DataKeys),
    Ended(Ending),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ending {
    AuthFailed(String),
    Halt(String),
    Restart(String),
    Exit,
    Failed(String),
}

impl std::fmt::Display for Ending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthFailed(reason) if reason.is_empty() => {
                formatter.write_str("the server refused the credentials")
            }
            Self::AuthFailed(reason) => {
                write!(formatter, "the server refused the credentials: {reason}")
            }
            Self::Halt(reason) => write!(formatter, "the server halted the session: {reason}"),
            Self::Restart(reason) => {
                write!(formatter, "the server restarted the session: {reason}")
            }
            Self::Exit => formatter.write_str("the server closed the session"),
            Self::Failed(reason) => formatter.write_str(reason),
        }
    }
}

/// The TLS client every key state handshakes with: the config's client
/// certificate, its server check ([`super::verify`]), no SNI (OpenVPN sends
/// none) and no resumption (each key state is a full handshake).
pub(super) fn tls_config(config: &ClientConfig) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = super::verify::ServerVerifier::new(
        &config.ca,
        config.verify_name.clone(),
        config.remote_cert_tls_server,
        provider.clone(),
    )?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(config.cert_chain.clone(), config.key.clone_key())
        .map_err(|error| format!("the client certificate or key is unusable: {error}"))?;
    tls.enable_sni = false;
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(tls))
}

struct KeyState {
    key_id: u8,
    reliable: Reliable,
    tls: Option<ClientConnection>,
    sent_exchange: bool,
    got_exchange: bool,
    plaintext: Vec<u8>,
    /// When the key state must have produced its keys.
    deadline: Instant,
    keyed: bool,
}

impl KeyState {
    fn new(key_id: u8, reset: u8, now: Instant, timeout: Duration, window: Duration) -> Self {
        let mut reliable = Reliable::new(timeout);
        reliable.queue(reset, Vec::new());
        Self {
            key_id,
            reliable,
            tls: None,
            sent_exchange: false,
            got_exchange: false,
            plaintext: Vec::new(),
            deadline: now + window,
            keyed: false,
        }
    }
}

struct PushWait {
    next_request: Instant,
    pushed: Pushed,
}

pub(super) struct Control {
    tls_config: Arc<rustls::ClientConfig>,
    options: String,
    peer_info: String,
    credentials: Option<Credentials>,
    auth_token: Option<String>,
    ciphers: Vec<DataCipher>,
    fallback_cipher: Option<DataCipher>,
    cipher: Option<DataCipher>,
    session: [u8; 8],
    peer_session: Option<[u8; 8]>,
    wrap: Wrap,
    tls_timeout: Duration,
    hand_window: Duration,
    reneg: Duration,
    keys: Vec<KeyState>,
    next_key_id: u8,
    push: Option<PushWait>,
    up: bool,
    /// When the newest keys were made, for renegotiating on time.
    keyed_at: Option<Instant>,
    events: VecDeque<Event>,
    ended: bool,
}

impl Control {
    pub(super) fn new(
        config: &ClientConfig,
        tls_config: Arc<rustls::ClientConfig>,
        credentials: Option<Credentials>,
        tcp: bool,
        now: Instant,
    ) -> Self {
        let mut session: [u8; 8] = rand::random();
        if session == [0; 8] {
            session[0] = 1;
        }
        let fallback = config.fallback_cipher.unwrap_or(config.ciphers[0]);
        let options = format!(
            "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto {},cipher {},auth [null-digest],keysize {},key-method 2,tls-client",
            if tcp { "TCPv4_CLIENT" } else { "UDPv4" },
            fallback.name(),
            if fallback == DataCipher::Aes128Gcm { 128 } else { 256 },
        );
        let wrap = match &config.tls_crypt {
            Some(key) => Wrap::Crypt(TlsCrypt::client(key)),
            None => Wrap::None,
        };
        Self {
            tls_config,
            options,
            peer_info: peer_info(&config.ciphers),
            credentials,
            auth_token: None,
            ciphers: config.ciphers.clone(),
            fallback_cipher: config.fallback_cipher,
            cipher: None,
            session,
            peer_session: None,
            wrap,
            tls_timeout: config.tls_timeout,
            hand_window: config.hand_window,
            reneg: config.reneg,
            keys: vec![KeyState::new(
                0,
                P_CONTROL_HARD_RESET_CLIENT_V2,
                now,
                config.tls_timeout,
                config.hand_window,
            )],
            next_key_id: 1,
            push: None,
            up: false,
            keyed_at: None,
            events: VecDeque::new(),
            ended: false,
        }
    }

    pub(super) fn event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn end(&mut self, ending: Ending) {
        if !self.ended {
            self.ended = true;
            self.events.push_back(Event::Ended(ending));
        }
    }

    /// Takes one control packet from the server.
    pub(super) fn receive(&mut self, packet: &[u8], now: Instant) {
        if self.ended || packet.is_empty() {
            return;
        }
        let opcode = super::wire::opcode(packet[0]);
        let key_id = super::wire::key_id(packet[0]);
        let Some((sender, plain)) = self.wrap.open(packet) else {
            return;
        };
        match self.peer_session {
            Some(peer) if peer != sender => return,
            Some(_) => {}
            None if opcode == P_CONTROL_HARD_RESET_SERVER_V2 => self.peer_session = Some(sender),
            None => return,
        }
        if plain
            .acked_session
            .is_some_and(|acked| acked != self.session)
        {
            return;
        }
        let index = match self.keys.iter().position(|state| state.key_id == key_id) {
            Some(index) => index,
            // The server renegotiates.
            None if opcode == P_CONTROL_SOFT_RESET_V1 && key_id == self.next_key_id && self.up => {
                self.begin_key_state(now);
                self.keys.len() - 1
            }
            None => return,
        };
        self.keys[index].reliable.acknowledge(&plain.acks);
        let Some(message_id) = plain.message_id else {
            return;
        };
        let ready = self.keys[index]
            .reliable
            .receive(message_id, opcode, plain.payload);
        for (opcode, payload) in ready {
            self.deliver(index, opcode, &payload, now);
        }
    }

    /// Starts a key state for a renegotiation, ours or the server's.
    fn begin_key_state(&mut self, now: Instant) {
        let key_id = self.next_key_id;
        self.next_key_id = if key_id == 7 { 1 } else { key_id + 1 };
        self.keys.push(KeyState::new(
            key_id,
            P_CONTROL_SOFT_RESET_V1,
            now,
            self.tls_timeout,
            self.hand_window,
        ));
    }

    fn deliver(&mut self, index: usize, opcode: u8, payload: &[u8], now: Instant) {
        match opcode {
            P_CONTROL_HARD_RESET_SERVER_V2 | P_CONTROL_SOFT_RESET_V1 => {
                if self.keys[index].tls.is_none() {
                    let name = ServerName::try_from("openvpn").expect("a DNS name");
                    match ClientConnection::new(self.tls_config.clone(), name) {
                        Ok(tls) => self.keys[index].tls = Some(tls),
                        Err(error) => return self.end(Ending::Failed(error.to_string())),
                    }
                    self.flush_tls(index);
                }
            }
            P_CONTROL_V1 => {
                let Some(tls) = self.keys[index].tls.as_mut() else {
                    return;
                };
                let mut bytes = payload;
                while !bytes.is_empty() {
                    if tls.read_tls(&mut bytes).is_err() {
                        return self.end(Ending::Failed("TLS input overflowed".into()));
                    }
                    if let Err(error) = tls.process_new_packets() {
                        // The alert goes out before the session ends.
                        self.flush_tls(index);
                        return self.end(Ending::Failed(format!("TLS: {error}")));
                    }
                }
                self.after_tls(index, now);
            }
            _ => {}
        }
    }

    /// Moves TLS records into control messages.
    fn flush_tls(&mut self, index: usize) {
        let state = &mut self.keys[index];
        let Some(tls) = state.tls.as_mut() else {
            return;
        };
        let mut out = Vec::new();
        while tls.wants_write() {
            if tls.write_tls(&mut out).is_err() {
                break;
            }
        }
        for chunk in out.chunks(TLS_PER_MESSAGE) {
            state.reliable.queue(P_CONTROL_V1, chunk.to_vec());
        }
    }

    fn write_plaintext(&mut self, index: usize, message: &[u8]) {
        if let Some(tls) = self.keys[index].tls.as_mut() {
            let _ = tls.writer().write_all(message);
        }
        self.flush_tls(index);
    }

    fn after_tls(&mut self, index: usize, now: Instant) {
        let handshaking = self.keys[index]
            .tls
            .as_ref()
            .is_none_or(|tls| tls.is_handshaking());
        if !handshaking && !self.keys[index].sent_exchange {
            self.keys[index].sent_exchange = true;
            let credentials = match (&self.credentials, &self.auth_token) {
                (Some(credentials), Some(token)) => Some(Credentials {
                    username: credentials.username.clone(),
                    password: token.clone(),
                }),
                (credentials, _) => credentials.clone(),
            };
            let exchange =
                client_key_exchange(&self.options, credentials.as_ref(), &self.peer_info);
            self.write_plaintext(index, &exchange);
        }
        // Drain what TLS decrypted.
        let state = &mut self.keys[index];
        if let Some(tls) = state.tls.as_mut() {
            let mut buffer = [0_u8; 4096];
            loop {
                match tls.reader().read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => state.plaintext.extend_from_slice(&buffer[..read]),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        if !self.keys[index].got_exchange {
            match server_key_exchange_len(&self.keys[index].plaintext) {
                None => {}
                Some(Err(reason)) => return self.end(Ending::Failed(reason)),
                Some(Ok(length)) => {
                    self.keys[index].plaintext.drain(..length);
                    self.keys[index].got_exchange = true;
                    if self.keys[index].key_id == 0 {
                        self.push = Some(PushWait {
                            next_request: now,
                            pushed: Pushed::default(),
                        });
                    } else {
                        self.make_keys(index, now);
                    }
                }
            }
        }
        if self.keys[index].got_exchange {
            while let Some(end) = self.keys[index]
                .plaintext
                .iter()
                .position(|&byte| byte == 0)
            {
                let message: Vec<u8> = self.keys[index].plaintext.drain(..=end).collect();
                let text = String::from_utf8_lossy(&message[..end]).into_owned();
                self.message(&text, now);
                if self.ended {
                    return;
                }
            }
        }
        self.flush_tls(index);
    }

    fn message(&mut self, text: &str, now: Instant) {
        match ServerMessage::parse(text) {
            ServerMessage::PushReply { options, more } => {
                let Some(wait) = self.push.as_mut() else {
                    return;
                };
                for option in &options {
                    wait.pushed.apply(option);
                }
                if !more {
                    let pushed = self.push.take().expect("waiting for the push").pushed;
                    self.configure(pushed, now);
                }
            }
            ServerMessage::AuthFailed(reason) => self.end(Ending::AuthFailed(reason)),
            ServerMessage::AuthPending(timeout) => {
                let deadline = now + timeout.unwrap_or(Duration::from_secs(300));
                if let Some(state) = self.keys.iter_mut().find(|state| !state.keyed) {
                    state.deadline = state.deadline.max(deadline);
                }
            }
            ServerMessage::Restart(reason) => self.end(Ending::Restart(reason)),
            ServerMessage::Halt(reason) => self.end(Ending::Halt(reason)),
            ServerMessage::Exit => self.end(Ending::Exit),
            ServerMessage::Other => {}
        }
    }

    /// Applies the pushed configuration and keys the data channel.
    fn configure(&mut self, pushed: Pushed, now: Instant) {
        let cipher = match &pushed.cipher {
            Some(name) => match DataCipher::from_name(name) {
                Some(cipher) if self.ciphers.contains(&cipher) => cipher,
                _ => {
                    return self.end(Ending::Failed(format!(
                        "the server chose data cipher {name}, which this client does not offer"
                    )))
                }
            },
            None => match self.fallback_cipher {
                Some(cipher) => cipher,
                None => {
                    return self.end(Ending::Failed(
                        "the server negotiated no data cipher and the config names none".into(),
                    ))
                }
            },
        };
        if !pushed.tls_ekm {
            return self.end(Ending::Failed(
                "the server does not derive data keys with the TLS exporter (OpenVPN 2.6 or later does)"
                    .into(),
            ));
        }
        self.cipher = Some(cipher);
        if let Some(token) = &pushed.auth_token {
            self.auth_token = Some(token.clone());
        }
        let Some(keys) = self.export_keys(0) else {
            return self.end(Ending::Failed("TLS keying material export failed".into()));
        };
        self.keys[0].keyed = true;
        self.up = true;
        self.keyed_at = Some(now);
        self.events.push_back(Event::Up(pushed, keys));
    }

    fn export_keys(&self, index: usize) -> Option<DataKeys> {
        let state = &self.keys[index];
        let material = state
            .tls
            .as_ref()?
            .export_keying_material([0_u8; 256], DATA_KEYS_LABEL, None)
            .ok()?;
        Some(DataKeys::client(self.cipher?, &material, state.key_id))
    }

    /// A renegotiated key state's keys; older key states retire.
    fn make_keys(&mut self, index: usize, now: Instant) {
        let Some(keys) = self.export_keys(index) else {
            return self.end(Ending::Failed("TLS keying material export failed".into()));
        };
        self.keys[index].keyed = true;
        self.keyed_at = Some(now);
        self.events.push_back(Event::Rekeyed(keys));
    }

    /// Packets due now: messages and retransmissions, push requests, acks.
    pub(super) fn transmit(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if self.ended {
            return Vec::new();
        }
        if let Some(state) = self
            .keys
            .iter()
            .find(|state| !state.keyed && now >= state.deadline)
        {
            let reason = if state.key_id == 0 {
                "the handshake with the server timed out"
            } else {
                "a key renegotiation timed out"
            };
            self.end(Ending::Failed(reason.into()));
            return Vec::new();
        }
        if self
            .push
            .as_ref()
            .is_some_and(|wait| now >= wait.next_request)
        {
            if let Some(wait) = self.push.as_mut() {
                wait.next_request = now + PUSH_REQUEST_INTERVAL;
            }
            self.write_plaintext(0, b"PUSH_REQUEST\0");
        }
        let renegotiating = self.keys.iter().any(|state| !state.keyed);
        if self.up && !renegotiating && self.keyed_at.is_some_and(|keyed| now >= keyed + self.reneg)
        {
            self.begin_key_state(now);
        }
        // Key states a newer keyed one replaced leave once settled.
        if let Some(newest) = self.keys.iter().rposition(|state| state.keyed) {
            let mut position = 0;
            self.keys.retain(|state| {
                let keep = position >= newest || !state.reliable.settled();
                position += 1;
                keep
            });
        }
        let Some(peer) = self.peer_session else {
            // Only the first reset goes out before the server answers.
            return self.send_due(now, [0; 8]);
        };
        self.send_due(now, peer)
    }

    fn send_due(&mut self, now: Instant, peer: [u8; 8]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        for state in &mut self.keys {
            for (id, opcode, payload) in state.reliable.due(now) {
                let acks = state.reliable.take_acks(ACKS_WITH_MESSAGE);
                let plain = ControlPlain {
                    acked_session: (!acks.is_empty()).then_some(peer),
                    acks,
                    message_id: Some(id),
                    payload,
                };
                packets.push(self.wrap.seal(opcode, state.key_id, &self.session, &plain));
            }
            while state.reliable.has_acks() {
                let acks = state.reliable.take_acks(ACKS_ALONE);
                let plain = ControlPlain {
                    acks,
                    acked_session: Some(peer),
                    message_id: None,
                    payload: Vec::new(),
                };
                packets.push(
                    self.wrap
                        .seal(P_ACK_V1, state.key_id, &self.session, &plain),
                );
            }
        }
        packets
    }

    /// When [`Self::transmit`] next has something to do.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        if self.ended {
            return None;
        }
        let mut deadline = self
            .keys
            .iter()
            .filter_map(|state| {
                let retransmit = state.reliable.next_deadline();
                let keying = (!state.keyed).then_some(state.deadline);
                retransmit.into_iter().chain(keying).min()
            })
            .min();
        let push = self.push.as_ref().map(|wait| wait.next_request);
        let reneg = self
            .keyed_at
            .filter(|_| self.up)
            .map(|keyed| keyed + self.reneg);
        for candidate in [push, reneg].into_iter().flatten() {
            deadline = Some(deadline.map_or(candidate, |current| current.min(candidate)));
        }
        deadline
    }

    /// Tells the server the client is leaving (`EXIT`, when it accepts that
    /// over the control channel).
    pub(super) fn exit(&mut self) {
        if let Some(index) = self.keys.iter().rposition(|state| state.keyed) {
            self.write_plaintext(index, b"EXIT\0");
        }
    }
}

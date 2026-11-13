//! Fake DNS is an address translation layer, not evidence that an arbitrary
//! UDP reply came from the requested domain. A fake-IP identity binds the
//! target its name resolved to before it sends anything, and only replies
//! from that address come from its fake IP; every reply keeps its source
//! port, and unknown peers stay themselves.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwap;

use crate::outbound::PumpFrom;
use crate::target::ConnectTarget;

/// A target identity of one client 2-tuple: every real address the client
/// sends to, or one fake IP and the name it stands for. Each identity is
/// routed once, and identities routed to the same outbound share one
/// transport, so one mapping serves every remote (EIM).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum AssociationKey {
    Real,
    Virtual {
        client_host: String,
        logical_host: String,
    },
}

impl AssociationKey {
    pub(super) fn for_target(client: &ConnectTarget, logical: &ConnectTarget) -> Self {
        if client == logical {
            Self::Real
        } else {
            Self::Virtual {
                client_host: client.host.clone(),
                logical_host: logical.host.clone(),
            }
        }
    }
}

/// A fake-IP identity bound to the target its name resolved to: an address,
/// or the name itself when the proxy resolves it (strict global mode with
/// only the local resolver to ask).
#[derive(Debug)]
pub(super) struct Claim {
    client_host: String,
    client_ip: Option<IpAddr>,
    logical_host: String,
    wire: ConnectTarget,
    wire_ip: Option<IpAddr>,
    /// For a name the proxy resolves: the address its first reply came
    /// from, which later replies must come from too.
    resolved: OnceLock<IpAddr>,
}

impl Claim {
    /// `key`'s binding to `wire`; `None` for the real identity, which has
    /// nothing to translate.
    pub(super) fn new(key: &AssociationKey, wire: ConnectTarget) -> Option<Self> {
        let AssociationKey::Virtual {
            client_host,
            logical_host,
        } = key
        else {
            return None;
        };
        Some(Self {
            client_host: client_host.clone(),
            client_ip: client_host.parse().ok(),
            logical_host: logical_host.clone(),
            wire_ip: wire.ip(),
            wire,
            resolved: OnceLock::new(),
        })
    }

    /// The address the name resolved to; `None` for a name the proxy
    /// resolves.
    pub(super) fn wire_ip(&self) -> Option<IpAddr> {
        self.wire_ip
    }

    /// Where a datagram the client sent to `port` of the fake IP goes.
    pub(super) fn send_target(&self, port: u16) -> ConnectTarget {
        ConnectTarget {
            host: self.wire.host.clone(),
            port,
        }
    }

    /// The name the proxy resolves, as the `host:port` a datagram the client
    /// sent to `port` goes to; `None` for an address.
    pub(super) fn wire_name(&self, port: u16) -> Option<Arc<str>> {
        self.wire_ip
            .is_none()
            .then(|| crate::target::authority(&self.wire.host, port).into())
    }

    fn claims_ip(&self, remote: IpAddr) -> bool {
        match self.wire_ip {
            Some(wire) => wire == remote,
            // The proxy resolved the name: its first reply tells where it
            // went. Such a claim has a transport of its own.
            None => *self.resolved.get_or_init(|| remote) == remote,
        }
    }

    fn claims_name(&self, name: &str) -> bool {
        name.trim_end_matches('.')
            .eq_ignore_ascii_case(self.logical_host.trim_end_matches('.'))
    }
}

/// How one transport frames the replies it receives (EIF): a reply from an
/// address a fake-IP identity on it claims comes from that identity's fake
/// IP, and any other from its own address, a link-local real target's with
/// its scope restored. Claims never overlap: an identity whose name resolved
/// to an address another identity on the transport claims, and one whose
/// name the proxy resolves, each get a transport of their own. A real target
/// at a claimed address is answered from the fake IP.
#[derive(Debug)]
pub(super) struct ReplyTable {
    claims: ArcSwap<Vec<Arc<Claim>>>,
    /// Numeric IPv6 scope metadata is local; UDP source addresses omit it.
    scoped: Mutex<Vec<ConnectTarget>>,
}

impl Default for ReplyTable {
    fn default() -> Self {
        Self {
            claims: ArcSwap::from_pointee(Vec::new()),
            scoped: Mutex::default(),
        }
    }
}

impl ReplyTable {
    pub(super) fn with_claim(claim: Arc<Claim>) -> Self {
        let table = Self::default();
        table.add(claim);
        table
    }

    /// Whether an identity on this transport claims the replies from `ip`.
    pub(super) fn is_claimed(&self, ip: IpAddr) -> bool {
        self.claims
            .load()
            .iter()
            .any(|claim| claim.wire_ip == Some(ip))
    }

    /// Takes away `key`'s claim, for an identity that no longer sends where
    /// it did. A claim left behind keeps the address it claimed on this
    /// transport: the same name resolving there again cannot share the
    /// transport, so it opens a private one and the client's mapping stops
    /// being endpoint-independent.
    pub(super) fn remove(&self, key: &AssociationKey) {
        let AssociationKey::Virtual {
            client_host,
            logical_host,
        } = key
        else {
            return;
        };
        self.claims.rcu(|claims| {
            claims
                .iter()
                .filter(|claim| {
                    claim.client_host != *client_host || claim.logical_host != *logical_host
                })
                .cloned()
                .collect::<Vec<_>>()
        });
    }

    pub(super) fn add(&self, claim: Arc<Claim>) {
        self.claims.rcu(|claims| {
            let mut claims = Vec::clone(claims);
            claims.push(Arc::clone(&claim));
            claims
        });
    }

    pub(super) fn note_real_target(&self, target: &ConnectTarget) {
        if target.has_ipv6_scope() {
            let mut scoped = self.scoped.lock().expect("UDP scoped targets");
            if !scoped.contains(target) && scoped.len() < 64 {
                scoped.push(target.clone());
            }
        }
    }

    pub(super) fn source(&self, remote: ConnectTarget) -> ConnectTarget {
        let claims = self.claims.load();
        let claim = match remote.ip() {
            Some(ip) => claims.iter().find(|claim| claim.claims_ip(ip)),
            None => claims.iter().find(|claim| claim.claims_name(&remote.host)),
        };
        // Translation changes an address only. The peer's source port is never
        // inferred from the original destination (STUN and other protocols can
        // legitimately answer from another port).
        if let Some(claim) = claim {
            return ConnectTarget {
                host: claim.client_host.clone(),
                port: remote.port,
            };
        }
        let host = if remote.has_ipv6_scope() {
            None
        } else {
            let scoped = self.scoped.lock().expect("UDP scoped targets");
            let mut matches = scoped.iter().filter(|target| target.ip() == remote.ip());
            matches.next().and_then(|first| {
                matches
                    .all(|target| target.host == first.host)
                    .then(|| first.host.clone())
            })
        };
        ConnectTarget {
            host: host.unwrap_or(remote.host),
            port: remote.port,
        }
    }

    /// The source the packet pump frames a reply from, deciding as
    /// [`Self::source`] does; `None` for a name the client cannot be
    /// answered from.
    pub(super) fn pump_source(&self, from: PumpFrom) -> Option<SocketAddr> {
        match from {
            PumpFrom::Addr(remote) => {
                let claims = self.claims.load();
                let ip = claims
                    .iter()
                    .find(|claim| claim.claims_ip(remote.ip()))
                    .and_then(|claim| claim.client_ip)
                    .unwrap_or(remote.ip());
                Some(SocketAddr::new(ip, remote.port()))
            }
            PumpFrom::Name(remote) => {
                let source = self.source(remote);
                Some(SocketAddr::new(source.ip()?, source.port))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target(host: &str, port: u16) -> ConnectTarget {
        ConnectTarget {
            host: host.into(),
            port,
        }
    }
    fn claim(client: &str, logical: &str, wire: &str) -> Arc<Claim> {
        let key = AssociationKey::for_target(&target(client, 443), &target(logical, 443));
        Arc::new(Claim::new(&key, target(wire, 443)).unwrap())
    }
    fn from(addr: &str) -> PumpFrom {
        PumpFrom::Addr(addr.parse().unwrap())
    }
    fn at(addr: &str) -> Option<SocketAddr> {
        Some(addr.parse().unwrap())
    }

    #[test]
    fn the_real_identity_has_no_claim() {
        assert!(Claim::new(&AssociationKey::Real, target("203.0.113.7", 443)).is_none());
    }

    #[test]
    fn claims_translate_their_address_and_name_and_keep_the_reply_port() {
        let table = ReplyTable::with_claim(claim("198.18.0.1", "a.example", "203.0.113.7"));
        table.add(claim("198.18.0.2", "b.example", "203.0.113.8"));
        assert!(table.is_claimed("203.0.113.7".parse().unwrap()));
        assert!(!table.is_claimed("192.0.2.99".parse().unwrap()));
        assert_eq!(
            table.source(target("203.0.113.8", 8443)),
            target("198.18.0.2", 8443)
        );
        assert_eq!(
            table.source(target("203.0.113.7", 443)),
            target("198.18.0.1", 443)
        );
        assert_eq!(
            table.source(target("A.EXAMPLE.", 9999)),
            target("198.18.0.1", 9999)
        );
        // Unknown peers, real targets among them, stay themselves (EIF).
        assert_eq!(
            table.source(target("192.0.2.99", 5555)),
            target("192.0.2.99", 5555)
        );
        assert_eq!(
            table.source(target("c.example", 5555)),
            target("c.example", 5555)
        );
    }

    /// An identity that no longer sends where it did takes its claim with it,
    /// so the address is free for the next name that resolves there -- which
    /// can then share this transport instead of opening a private one.
    #[test]
    fn a_released_identity_takes_its_claim_with_it() {
        let table = ReplyTable::with_claim(claim("198.18.0.1", "a.example", "203.0.113.7"));
        table.add(claim("198.18.0.2", "b.example", "203.0.113.8"));
        let released =
            AssociationKey::for_target(&target("198.18.0.1", 443), &target("a.example", 443));

        table.remove(&released);

        assert!(!table.is_claimed("203.0.113.7".parse().unwrap()));
        assert!(
            table.is_claimed("203.0.113.8".parse().unwrap()),
            "an identity still sending keeps its claim"
        );
        assert_eq!(
            table.source(target("203.0.113.7", 443)).host,
            "203.0.113.7",
            "a reply from the freed address is nobody's fake IP now"
        );
    }

    #[test]
    fn a_claim_sends_to_its_address_at_the_port_the_client_chose() {
        let claim = claim("198.18.0.1", "a.example", "203.0.113.7");
        assert_eq!(claim.send_target(8443), target("203.0.113.7", 8443));
        assert_eq!(claim.wire_ip(), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(claim.wire_name(8443), None, "an address is not a name");
    }

    #[test]
    fn a_name_the_proxy_resolves_answers_from_its_first_reply_address() {
        let claim = claim("198.18.0.9", "a.example", "a.example");
        assert_eq!(claim.send_target(8443), target("a.example", 8443));
        assert_eq!(claim.wire_ip(), None);
        assert_eq!(claim.wire_name(8443).as_deref(), Some("a.example:8443"));
        let table = ReplyTable::with_claim(claim);
        assert_eq!(
            table.source(target("203.0.113.7", 443)),
            target("198.18.0.9", 443)
        );
        assert_eq!(
            table.source(target("203.0.113.7", 3478)),
            target("198.18.0.9", 3478)
        );
        // Another peer, such as a STUN server's alternate address, stays itself.
        assert_eq!(
            table.source(target("198.51.100.4", 3479)),
            target("198.51.100.4", 3479)
        );
        assert_eq!(
            table.source(target("a.example", 53)),
            target("198.18.0.9", 53)
        );
    }

    #[test]
    fn the_pump_frames_replies_as_the_actor_does() {
        let table = ReplyTable::default();
        assert_eq!(
            table.pump_source(from("203.0.113.7:443")),
            at("203.0.113.7:443")
        );
        table.add(claim("198.18.0.1", "a.example", "203.0.113.7"));
        assert_eq!(
            table.pump_source(from("203.0.113.7:3478")),
            at("198.18.0.1:3478")
        );
        assert_eq!(
            table.pump_source(from("192.0.2.99:443")),
            at("192.0.2.99:443")
        );

        let named = ReplyTable::with_claim(claim("198.18.0.9", "a.example", "a.example"));
        // The first reply tells where the name led; replies from there come
        // from the fake IP, other peers stay themselves.
        assert_eq!(
            named.pump_source(from("203.0.113.7:443")),
            at("198.18.0.9:443")
        );
        assert_eq!(
            named.pump_source(from("203.0.113.7:3478")),
            at("198.18.0.9:3478")
        );
        assert_eq!(
            named.pump_source(from("198.51.100.4:3479")),
            at("198.51.100.4:3479")
        );
        // A server answering by the name to which the request was addressed.
        assert_eq!(
            named.pump_source(PumpFrom::Name(target("A.Example.", 53))),
            at("198.18.0.9:53")
        );
        assert_eq!(
            named.pump_source(PumpFrom::Name(target("b.example", 53))),
            None
        );
    }

    #[test]
    fn real_targets_keep_endpoint_independent_reply_sources() {
        let table = ReplyTable::default();
        table.note_real_target(&target("203.0.113.7", 443));
        let other = target("192.0.2.99", 5000);
        assert_eq!(table.source(other.clone()), other);
        table.note_real_target(&target("fe80::1%7", 443));
        assert_eq!(
            table.source(target("fe80::1", 9999)),
            target("fe80::1%7", 9999)
        );
        table.note_real_target(&target("fe80::1%7", 8443));
        assert_eq!(
            table.source(target("fe80::1", 5555)),
            target("fe80::1%7", 5555)
        );
        assert_eq!(
            table.source(target("fe80::1%8", 5555)),
            target("fe80::1%8", 5555)
        );
        table.note_real_target(&target("fe80::1%8", 443));
        assert_eq!(
            table.source(target("fe80::1", 5555)),
            target("fe80::1", 5555),
            "ambiguous local interface scopes must not be guessed"
        );
    }
}

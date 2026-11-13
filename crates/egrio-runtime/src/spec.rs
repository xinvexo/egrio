use std::error::Error;
use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{
    DnsSettings, FirewallSettings, LeaseRequestSet, PacketCaptureSettings, PlatformLeaseKey,
    RouteSettings, RuntimeId, SystemProxySettings,
};

/// Declares the Runtime-owned local Core and its inbound listener endpoints.
/// The spec expresses only topology; the Core's content (profile, egress,
/// socket guard) comes from the assembled [`crate::CoreConfigSource`] at the
/// head of every start transaction, so profile edits never require a spec
/// change.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeCoreSpec {
    /// Requested mixed (HTTP proxy + SOCKS5) listener endpoint; `None`
    /// binds an ephemeral loopback port.
    pub listen_addr: Option<SocketAddr>,
    /// Requested plain-UDP DNS listener endpoint; `None` binds an ephemeral
    /// loopback port.
    pub dns_listen_addr: Option<SocketAddr>,
    /// Lets a free port stand in for a requested mixed port that is taken or
    /// reserved, instead of failing the start. The Core status then names the
    /// requested address and why it was refused, and the system proxy follows
    /// the port actually bound.
    #[serde(default)]
    pub listen_port_fallback: bool,
}

/// A system-proxy endpoint in the spec: either an explicit socket address or
/// the Runtime Core listener bound by the current generation. Core-listener
/// endpoints are resolved to concrete [`SystemProxySettings`] only after the
/// listener has bound (start order: compile Core → bind listener → resolve
/// platform settings → lease → checkpoint → OS apply).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "endpoint", content = "addr", rename_all = "kebab-case")]
pub enum SystemProxyEndpoint {
    CoreListener,
    Socket(SocketAddr),
}

impl SystemProxyEndpoint {
    fn resolve(self, core_listener: Option<SocketAddr>) -> Result<SocketAddr, RuntimeSpecError> {
        match self {
            Self::Socket(addr) => Ok(addr),
            Self::CoreListener => core_listener
                .map(egrio_core::inbound::local_listener_address)
                .ok_or_else(|| {
                    RuntimeSpecError::new(
                        RuntimeSpecErrorCode::UnresolvedCoreListener,
                        "system proxy references the Core listener before it is bound",
                    )
                }),
        }
    }
}

/// The spec-level system-proxy declaration. Resolves to the adapter-facing
/// [`SystemProxySettings`] once the Core listener endpoint is known.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemProxySpec {
    pub http_proxy: Option<SystemProxyEndpoint>,
    pub https_proxy: Option<SystemProxyEndpoint>,
    pub bypass: Vec<String>,
}

impl SystemProxySpec {
    #[must_use]
    pub fn from_settings(settings: SystemProxySettings) -> Self {
        Self {
            http_proxy: settings.http_proxy.map(SystemProxyEndpoint::Socket),
            https_proxy: settings.https_proxy.map(SystemProxyEndpoint::Socket),
            bypass: settings.bypass,
        }
    }

    fn references_core_listener(&self) -> bool {
        matches!(self.http_proxy, Some(SystemProxyEndpoint::CoreListener))
            || matches!(self.https_proxy, Some(SystemProxyEndpoint::CoreListener))
    }

    pub fn resolve(
        &self,
        core_listener: Option<SocketAddr>,
    ) -> Result<SystemProxySettings, RuntimeSpecError> {
        Ok(SystemProxySettings {
            http_proxy: self
                .http_proxy
                .map(|endpoint| endpoint.resolve(core_listener))
                .transpose()?,
            https_proxy: self
                .https_proxy
                .map(|endpoint| endpoint.resolve(core_listener))
                .transpose()?,
            bypass: self.bypass.clone(),
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimePlatformSpec {
    pub packet_capture: Option<PacketCaptureSettings>,
    pub system_proxy: Option<SystemProxySpec>,
    pub route: Option<RouteSettings>,
    pub dns: Option<DnsSettings>,
    pub firewall: Option<FirewallSettings>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSpec {
    pub id: RuntimeId,
    /// The Runtime-owned local Core and listener for this Runtime. Required
    /// whenever the platform spec captures packets: the packet data plane
    /// runs on this Core, and the listener session shares it.
    #[serde(default)]
    pub core: Option<RuntimeCoreSpec>,
    #[serde(default)]
    pub platform: RuntimePlatformSpec,
}

impl RuntimeSpec {
    pub fn new(id: RuntimeId, platform: RuntimePlatformSpec) -> Result<Self, RuntimeSpecError> {
        Self::with_core(id, None, platform)
    }

    pub fn with_core(
        id: RuntimeId,
        core: Option<RuntimeCoreSpec>,
        platform: RuntimePlatformSpec,
    ) -> Result<Self, RuntimeSpecError> {
        let spec = Self { id, core, platform };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), RuntimeSpecError> {
        if self.id.as_uuid().is_nil() {
            return Err(RuntimeSpecError::new(
                RuntimeSpecErrorCode::NilRuntimeId,
                "runtime id must not be nil",
            ));
        }
        if self
            .platform
            .packet_capture
            .as_ref()
            .is_some_and(|settings| settings.install_default_route)
            && self.platform.route.is_some()
        {
            return Err(RuntimeSpecError::new(
                RuntimeSpecErrorCode::DuplicateLeaseScope,
                "packet capture and route control both request the default route",
            ));
        }
        if self
            .platform
            .packet_capture
            .as_ref()
            .is_some_and(|settings| settings.install_dns)
            && self.platform.dns.is_some()
        {
            return Err(RuntimeSpecError::new(
                RuntimeSpecErrorCode::DuplicateLeaseScope,
                "packet capture and DNS control both request system DNS",
            ));
        }
        if let Some(settings) = &self.platform.packet_capture {
            egrio_core::NativeCoreCaptureConfig::validate_mtu(settings.mtu).map_err(|message| {
                RuntimeSpecError::new(RuntimeSpecErrorCode::InvalidPacketMtu, message)
            })?;
            settings.validate().map_err(|message| {
                RuntimeSpecError::new(RuntimeSpecErrorCode::InvalidExcludedPrefixes, message)
            })?;
        }
        if let Some(settings) = &self.platform.route {
            settings.validate().map_err(|message| {
                RuntimeSpecError::new(RuntimeSpecErrorCode::InvalidExcludedPrefixes, message)
            })?;
        }
        if let Some(firewall) = &self.platform.firewall {
            let routed = self
                .platform
                .route
                .as_ref()
                .map(|route| route.excluded_prefixes.as_slice())
                .unwrap_or_default();
            if firewall.excluded_prefixes != routed {
                return Err(RuntimeSpecError::new(
                    RuntimeSpecErrorCode::InvalidExcludedPrefixes,
                    "the kill switch must let through exactly the destinations the routes exclude",
                ));
            }
        }
        if self.platform.packet_capture.is_some() && self.core.is_none() {
            return Err(RuntimeSpecError::new(
                RuntimeSpecErrorCode::MissingCoreSpec,
                "packet capture requires the Runtime-owned Core in the spec",
            ));
        }
        if self
            .platform
            .system_proxy
            .as_ref()
            .is_some_and(SystemProxySpec::references_core_listener)
            && self.core.is_none()
        {
            return Err(RuntimeSpecError::new(
                RuntimeSpecErrorCode::MissingCoreSpec,
                "system proxy references the Core listener but the spec declares no Core",
            ));
        }
        Ok(())
    }

    pub fn lease_request(&self) -> Result<Option<LeaseRequestSet>, RuntimeSpecError> {
        self.validate()?;
        let mut keys = Vec::new();
        if let Some(settings) = &self.platform.packet_capture {
            keys.push(PlatformLeaseKey::packet_capture());
            if settings.install_default_route {
                keys.push(PlatformLeaseKey::default_route());
            }
            if settings.install_dns {
                keys.push(PlatformLeaseKey::system_dns());
            }
        }
        if self.platform.system_proxy.is_some() {
            keys.push(PlatformLeaseKey::system_proxy());
        }
        if self.platform.route.is_some() {
            keys.push(PlatformLeaseKey::default_route());
        }
        if self.platform.dns.is_some() {
            keys.push(PlatformLeaseKey::system_dns());
        }
        if self.platform.firewall.is_some() {
            keys.push(PlatformLeaseKey::kill_switch());
        }
        if keys.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                LeaseRequestSet::new(self.id, keys).expect("non-empty lease request"),
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeSpecErrorCode {
    NilRuntimeId,
    DuplicateLeaseScope,
    MissingCoreSpec,
    InvalidPacketMtu,
    UnresolvedCoreListener,
    InvalidExcludedPrefixes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSpecError {
    pub code: RuntimeSpecErrorCode,
    pub message: String,
}

impl RuntimeSpecError {
    fn new(code: RuntimeSpecErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for RuntimeSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}
impl Error for RuntimeSpecError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketCaptureSource;

    fn capture_platform() -> RuntimePlatformSpec {
        RuntimePlatformSpec {
            packet_capture: Some(PacketCaptureSettings {
                mtu: 1500,
                source: PacketCaptureSource::Tun,
                install_default_route: false,
                install_dns: false,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        }
    }

    #[test]
    fn explicit_route_and_firewall_controls_lease_even_without_default_route_or_blocking() {
        let spec = RuntimeSpec::new(
            RuntimeId::new(),
            RuntimePlatformSpec {
                route: Some(crate::RouteSettings {
                    default_route: false,
                    excluded_prefixes: Vec::new(),
                }),
                firewall: Some(crate::FirewallSettings {
                    kill_switch: false,
                    allow_lan: true,
                    excluded_prefixes: Vec::new(),
                    fake_ip_prefixes: Vec::new(),
                }),
                ..RuntimePlatformSpec::default()
            },
        )
        .unwrap();
        let request = spec.lease_request().unwrap().unwrap();
        assert!(request.keys().contains(&PlatformLeaseKey::default_route()));
        assert!(request.keys().contains(&PlatformLeaseKey::kill_switch()));
    }

    #[test]
    fn capture_owned_dns_is_exclusive_and_included_in_recovery_leases() {
        let mut platform = capture_platform();
        platform.packet_capture.as_mut().unwrap().install_dns = true;
        let spec = RuntimeSpec::with_core(
            RuntimeId::new(),
            Some(RuntimeCoreSpec::default()),
            platform.clone(),
        )
        .unwrap();
        let leases = spec.lease_request().unwrap().unwrap();
        assert!(leases.keys().contains(&PlatformLeaseKey::system_dns()));
        platform.dns = Some(DnsSettings {
            servers: Vec::new(),
            search_domains: Vec::new(),
        });
        let error =
            RuntimeSpec::with_core(RuntimeId::new(), Some(RuntimeCoreSpec::default()), platform)
                .unwrap_err();
        assert_eq!(error.code, RuntimeSpecErrorCode::DuplicateLeaseScope);
    }

    #[test]
    fn the_kill_switch_must_let_through_exactly_what_the_routes_exclude() {
        let excluded = vec!["100.64.0.0/10".parse::<crate::IpPrefix>().unwrap()];
        let spec = |routed: Vec<crate::IpPrefix>, permitted: Vec<crate::IpPrefix>| {
            RuntimeSpec::with_core(
                RuntimeId::new(),
                Some(RuntimeCoreSpec::default()),
                RuntimePlatformSpec {
                    route: Some(crate::RouteSettings {
                        default_route: true,
                        excluded_prefixes: routed,
                    }),
                    firewall: Some(crate::FirewallSettings {
                        kill_switch: true,
                        allow_lan: true,
                        excluded_prefixes: permitted,
                        fake_ip_prefixes: Vec::new(),
                    }),
                    ..RuntimePlatformSpec::default()
                },
            )
        };
        assert!(spec(excluded.clone(), excluded.clone()).is_ok());
        let error = spec(excluded.clone(), Vec::new()).unwrap_err();
        assert_eq!(error.code, RuntimeSpecErrorCode::InvalidExcludedPrefixes);
        let error = spec(Vec::new(), excluded).unwrap_err();
        assert_eq!(error.code, RuntimeSpecErrorCode::InvalidExcludedPrefixes);
    }

    #[test]
    fn packet_capture_requires_a_core_spec() {
        let error = RuntimeSpec::new(RuntimeId::new(), capture_platform())
            .expect_err("capture without a core must fail validation");
        assert_eq!(error.code, RuntimeSpecErrorCode::MissingCoreSpec);

        RuntimeSpec::with_core(
            RuntimeId::new(),
            Some(RuntimeCoreSpec::default()),
            capture_platform(),
        )
        .expect("capture with a core validates");
    }

    #[test]
    fn core_listener_proxy_endpoints_require_a_core_spec() {
        let platform = RuntimePlatformSpec {
            system_proxy: Some(SystemProxySpec {
                http_proxy: Some(SystemProxyEndpoint::CoreListener),
                https_proxy: None,
                bypass: Vec::new(),
            }),
            ..RuntimePlatformSpec::default()
        };
        let error = RuntimeSpec::new(RuntimeId::new(), platform.clone())
            .expect_err("core-listener endpoint without a core must fail validation");
        assert_eq!(error.code, RuntimeSpecErrorCode::MissingCoreSpec);

        RuntimeSpec::with_core(RuntimeId::new(), Some(RuntimeCoreSpec::default()), platform)
            .expect("core-listener endpoint with a core validates");
    }

    #[test]
    fn system_proxy_spec_resolves_core_listener_after_bind() {
        let spec = SystemProxySpec {
            http_proxy: Some(SystemProxyEndpoint::CoreListener),
            https_proxy: Some(SystemProxyEndpoint::Socket(
                "127.0.0.1:7899".parse().unwrap(),
            )),
            bypass: vec!["localhost".into()],
        };
        let bound: SocketAddr = "127.0.0.1:52011".parse().unwrap();

        let unresolved = spec
            .resolve(None)
            .expect_err("core listener endpoint cannot resolve before bind");
        assert_eq!(
            unresolved.code,
            RuntimeSpecErrorCode::UnresolvedCoreListener
        );

        let resolved = spec.resolve(Some(bound)).expect("resolves after bind");
        assert_eq!(resolved.http_proxy, Some(bound));
        assert_eq!(
            resolved.https_proxy,
            Some("127.0.0.1:7899".parse().unwrap())
        );
        assert_eq!(resolved.bypass, vec!["localhost".to_string()]);
    }

    #[test]
    fn wildcard_core_listener_resolves_to_a_local_proxy_destination() {
        let spec = SystemProxySpec {
            http_proxy: Some(SystemProxyEndpoint::CoreListener),
            https_proxy: None,
            bypass: Vec::new(),
        };
        for (bound, expected) in [
            ("0.0.0.0:7890", "127.0.0.1:7890"),
            ("[::]:7891", "[::1]:7891"),
            ("192.0.2.1:7892", "192.0.2.1:7892"),
        ] {
            assert_eq!(
                spec.resolve(Some(bound.parse().unwrap()))
                    .unwrap()
                    .http_proxy,
                Some(expected.parse().unwrap())
            );
        }
    }

    #[test]
    fn explicit_settings_round_trip_through_the_spec() {
        let settings = SystemProxySettings {
            http_proxy: Some("127.0.0.1:7890".parse().unwrap()),
            https_proxy: Some("127.0.0.1:7890".parse().unwrap()),
            bypass: vec!["localhost".into()],
        };
        let resolved = SystemProxySpec::from_settings(settings.clone())
            .resolve(None)
            .expect("explicit endpoints resolve without a listener");
        assert_eq!(resolved, settings);
    }
}

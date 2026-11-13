//! The tunnel's resolver as the system's default. The service publishes
//! `State:/Network/Service/<id>/DNS` naming the tunnel's virtual resolver
//! from a dynamic store session with session keys (SCDynamicStore.h
//! `kSCDynamicStoreUseSessionKeys`), so it disappears with the session, even
//! when the service process dies. One empty supplemental match domain
//! (SCSchemaDefinitions.h `kSCPropNetDNSSupplementalMatchDomains`) makes it
//! match every name: configd builds a resolver without a domain from it,
//! ahead of the primary service's, and exports the first such resolver as
//! the default (configd `Plugins/IPMonitor/dns-configuration.c`,
//! `add_supplemental_resolvers` and `dns_configuration_set`; `scutil --dns`
//! lists it as resolver #1). No other entity is published: the physical
//! network service stays primary with its routes, proxies and multicast
//! route, and routes alone steer traffic into the utun.

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use system_configuration::sys::dynamic_store::SCDynamicStoreSetMultiple;

use super::MACOS_TUN_VIRTUAL_DNS;

/// The network service ID the resolver is published under; no network
/// service of that ID exists.
const SERVICE_ID: &str = "com.xinvexo.egrio.tun";

/// The dynamic store session. Its functions take one store from any
/// thread; the session is only ever used under its owner's lock.
struct Store(SCDynamicStore);

// SAFETY: see above; nothing else references the session.
unsafe impl Send for Store {}

pub(super) struct TunnelResolver {
    store: Store,
}

impl std::fmt::Debug for TunnelResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunnelResolver")
            .finish_non_exhaustive()
    }
}

impl TunnelResolver {
    /// Makes the virtual resolver the system's default.
    pub(super) fn publish() -> Result<Self, String> {
        let store = SCDynamicStoreBuilder::new("egrio-service")
            .session_keys(true)
            .build()
            .ok_or("open a dynamic store session")?;
        let resolver = Self {
            store: Store(store),
        };
        let dns = CFDictionary::from_CFType_pairs(&[
            (
                CFString::new("ServerAddresses"),
                strings(&[MACOS_TUN_VIRTUAL_DNS.to_string()]),
            ),
            (
                CFString::new("SupplementalMatchDomains"),
                strings(&[String::new()]),
            ),
        ]);
        if !resolver.change(&[(key(), dns.into_CFType())], &[]) {
            return Err("publish the tunnel's resolver".into());
        }
        Ok(resolver)
    }

    fn change(&self, set: &[(CFString, CFType)], remove: &[CFString]) -> bool {
        let set = CFDictionary::from_CFType_pairs(set);
        let remove = CFArray::from_CFTypes(remove);
        // SAFETY: valid CF objects of the types the function takes.
        unsafe {
            SCDynamicStoreSetMultiple(
                self.store.0.as_concrete_TypeRef(),
                set.as_concrete_TypeRef(),
                remove.as_concrete_TypeRef(),
                std::ptr::null(),
            ) != 0
        }
    }
}

impl Drop for TunnelResolver {
    /// The session key goes with the session; removing it first tells
    /// configd at once.
    fn drop(&mut self) {
        self.change(&[], &[key()]);
    }
}

fn key() -> CFString {
    CFString::new(&format!("State:/Network/Service/{SERVICE_ID}/DNS"))
}

fn strings(values: &[String]) -> CFType {
    let values: Vec<CFString> = values.iter().map(|value| CFString::new(value)).collect();
    CFArray::from_CFTypes(&values).into_CFType()
}

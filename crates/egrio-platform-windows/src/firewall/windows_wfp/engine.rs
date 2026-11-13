//! The filtering engine: one open handle to the Base Filtering Engine, the
//! provider, sublayers and filters added through it, and the enumeration of
//! the filters that carry Egrio's mark.

use super::*;

pub(super) struct WfpEngine {
    pub(super) handle: HANDLE,
}

// WFP engine handles are process handles managed by BFE/fwpuclnt. The wrapper only
// closes the handle on Drop and does not expose concurrent mutable access.
unsafe impl Send for WfpEngine {}

impl WfpEngine {
    pub(super) fn begin_transaction(&self) -> Result<(), String> {
        ensure_wfp_ok(
            unsafe { FwpmTransactionBegin0(self.handle, 0) },
            "begin WFP transaction",
        )
    }

    pub(super) fn commit_transaction(&self) -> Result<(), String> {
        ensure_wfp_ok(
            unsafe { FwpmTransactionCommit0(self.handle) },
            "commit WFP transaction",
        )
    }

    pub(super) fn abort_transaction(&self) {
        unsafe { FwpmTransactionAbort0(self.handle) };
    }

    pub(super) fn delete_filter(&self, id: u64, key: &str) -> Result<(), String> {
        ensure_wfp_ok(
            unsafe { FwpmFilterDeleteById0(self.handle, id) },
            &format!("delete Egrio WFP filter '{key}'"),
        )
    }

    pub(super) fn open_dynamic(name: &str, description: &str) -> Result<Self, String> {
        Self::open_session(name, description, FWPM_SESSION_FLAG_DYNAMIC)
    }

    pub(super) fn open_read_only(name: &str) -> Result<Self, String> {
        Self::open_session(
            name,
            "Egrio read-only WFP diagnostic session; no filters or providers are installed",
            0,
        )
    }

    fn open_session(name: &str, description: &str, flags: u32) -> Result<Self, String> {
        let mut name = wide_null(name);
        let mut description = wide_null(description);
        let session = FWPM_SESSION0 {
            displayData: display_data(&mut name, &mut description),
            flags,
            ..FWPM_SESSION0::default()
        };
        let mut handle = ptr::null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut handle,
            )
        };
        ensure_wfp_ok(status, "open WFP engine")?;

        Ok(Self { handle })
    }

    pub(super) fn create_net_event_enum_handle(
        &self,
        template: Option<&FWPM_NET_EVENT_ENUM_TEMPLATE0>,
    ) -> Result<WfpNetEventEnumHandle<'_>, u32> {
        let mut handle = ptr::null_mut();
        let template = template
            .map(|template| template as *const FWPM_NET_EVENT_ENUM_TEMPLATE0)
            .unwrap_or(ptr::null());
        let status = unsafe { FwpmNetEventCreateEnumHandle0(self.handle, template, &mut handle) };
        if status == ERROR_SUCCESS {
            Ok(WfpNetEventEnumHandle {
                engine: self,
                handle,
            })
        } else {
            Err(status)
        }
    }

    /// Opens an enumeration over every filter in the engine snapshot. A null
    /// template enumerates all filters across all layers; the caller narrows to
    /// this provider's filters by reading each entry's provider key, which sidesteps
    /// the per-template `layerKey` constraint and stays layer-agnostic.
    pub(super) fn create_filter_enum_handle(&self) -> Result<WfpFilterEnumHandle<'_>, u32> {
        let mut handle = ptr::null_mut();
        let status = unsafe { FwpmFilterCreateEnumHandle0(self.handle, ptr::null(), &mut handle) };
        if status == ERROR_SUCCESS {
            Ok(WfpFilterEnumHandle {
                engine: self,
                handle,
            })
        } else {
            Err(status)
        }
    }

    pub(super) fn add_provider(&self, profile: &WfpSessionProfile) -> Result<bool, String> {
        let mut name = wide_null(profile.provider_name);
        let mut description = wide_null(profile.provider_description);
        let provider = FWPM_PROVIDER0 {
            providerKey: profile.provider_key,
            displayData: display_data(&mut name, &mut description),
            ..FWPM_PROVIDER0::default()
        };
        ensure_wfp_add_ok(
            unsafe { FwpmProviderAdd0(self.handle, &provider, ptr::null_mut()) },
            "add Egrio WFP provider",
        )
    }

    pub(super) fn add_sublayers(
        &self,
        profile: &WfpSessionProfile,
    ) -> Result<Vec<WindowsFirewallSublayerReport>, String> {
        profile
            .sublayers
            .iter()
            .map(|sublayer| {
                Ok(WindowsFirewallSublayerReport {
                    kind: sublayer.kind,
                    key: guid_string(sublayer.key),
                    registered: self.add_sublayer(profile, sublayer)?,
                })
            })
            .collect()
    }

    fn add_sublayer(
        &self,
        profile: &WfpSessionProfile,
        sublayer: &WfpSublayerProfile,
    ) -> Result<bool, String> {
        let mut provider_key = profile.provider_key;
        let mut name = wide_null(sublayer.name);
        let mut description = wide_null(sublayer.description);
        let sublayer_object = FWPM_SUBLAYER0 {
            subLayerKey: sublayer.key,
            displayData: display_data(&mut name, &mut description),
            providerKey: &mut provider_key,
            weight: sublayer.weight,
            ..FWPM_SUBLAYER0::default()
        };
        ensure_wfp_add_ok(
            unsafe { FwpmSubLayerAdd0(self.handle, &sublayer_object, ptr::null_mut()) },
            "add Egrio WFP sublayer",
        )
    }

    pub(super) fn add_filter_plan(
        &self,
        profile: &WfpSessionProfile,
        plan: &WindowsFirewallKillSwitchFilterPlan,
    ) -> Result<Vec<String>, String> {
        if !plan.production_ready {
            return Err(format!(
                "Windows WFP filter plan is not production ready: {}",
                plan.blockers.join("; ")
            ));
        }

        self.add_filters(profile, &plan.filters)
    }

    fn add_filters(
        &self,
        profile: &WfpSessionProfile,
        filters: &[WindowsFirewallKillSwitchFilterSpec],
    ) -> Result<Vec<String>, String> {
        filters
            .iter()
            .map(|filter| self.add_filter(profile, filter))
            .collect()
    }

    pub(super) fn add_filter(
        &self,
        profile: &WfpSessionProfile,
        spec: &WindowsFirewallKillSwitchFilterSpec,
    ) -> Result<String, String> {
        validate_filter_spec_conditions(spec)?;
        let mut provider_key = profile.provider_key;
        let sublayer_key = profile.sublayer_key_for(spec.sublayer)?;
        let mut name = wide_null(&spec.name);
        let mut description = wide_null(&spec.rationale);
        let mut resources = FilterConditionResources::default();
        let mut conditions = spec
            .conditions
            .iter()
            .map(|condition| build_wfp_condition(condition, &mut resources))
            .collect::<Result<Vec<_>, _>>()?;
        let mut weight_value = spec.weight;
        // Tag the filter with its logical key (UTF-8) in the provider data blob so
        // the reconciler's observer can recover the key by enumerating this
        // provider's filters. `spec.key` is always non-empty, and the
        // bytes only need to outlive the marshalling `FwpmFilterAdd0` copy below.
        let mut provider_data = spec.key.clone().into_bytes();
        let filter = FWPM_FILTER0 {
            displayData: display_data(&mut name, &mut description),
            providerKey: &mut provider_key,
            providerData: FWP_BYTE_BLOB {
                size: provider_data.len() as u32,
                data: provider_data.as_mut_ptr(),
            },
            layerKey: layer_key(&spec.layer),
            subLayerKey: sublayer_key,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight_value,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action_type(&spec.action),
                ..FWPM_ACTION0::default()
            },
            ..FWPM_FILTER0::default()
        };
        let mut filter_id = 0_u64;
        ensure_wfp_ok(
            unsafe { FwpmFilterAdd0(self.handle, &filter, ptr::null_mut(), &mut filter_id) },
            &format!("add Egrio WFP filter '{}'", spec.key),
        )?;

        Ok(format!("{}:{filter_id}", spec.key))
    }
}

/// Page size for a filter enumeration. The observer runs on mode transitions, not
/// on the hot path, so a modest page keeps peak allocation small while still
/// draining the snapshot in a few round-trips.
const WFP_FILTER_ENUM_PAGE: u32 = 64;

pub(super) struct WfpFilterEnumHandle<'a> {
    engine: &'a WfpEngine,
    handle: HANDLE,
}

impl WfpFilterEnumHandle<'_> {
    /// Drains the enumeration snapshot and returns the logical filter keys of the
    /// filters owned by this provider — recovered from the provider-data blob each
    /// filter was tagged with at install time (see `add_filter`). Filters from
    /// other providers are skipped. A this-provider filter without a decodable
    /// tag is an observation error because silently dropping it would make apply
    /// and restore treat an unknown live filter as absent. Pages until a short
    /// page signals the snapshot is exhausted.
    pub(super) fn enumerate_egrio_filter_keys(&self) -> Result<Vec<String>, String> {
        let mut keys = Vec::new();
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
            let mut returned = 0_u32;
            let status = unsafe {
                FwpmFilterEnum0(
                    self.engine.handle,
                    self.handle,
                    WFP_FILTER_ENUM_PAGE,
                    &mut entries,
                    &mut returned,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(format!("WFP status 0x{status:08x}"));
            }
            let mut decode_error = None;
            if !entries.is_null() {
                let entry_slice = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
                for filter in entry_slice
                    .iter()
                    .filter_map(|filter| unsafe { filter.as_ref() })
                {
                    match egrio_filter_key(filter) {
                        Ok(Some(key)) => keys.push(key),
                        Ok(None) => {}
                        Err(error) => {
                            decode_error = Some(error);
                            break;
                        }
                    }
                }
                let mut memory = entries as *mut c_void;
                unsafe { FwpmFreeMemory0(&mut memory) };
            }
            if let Some(error) = decode_error {
                return Err(error);
            }
            // Per FwpmFilterEnum0: a page shorter than requested exhausts the snapshot.
            if returned < WFP_FILTER_ENUM_PAGE {
                break;
            }
        }
        Ok(keys)
    }
}

impl Drop for WfpFilterEnumHandle<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let _ = unsafe { FwpmFilterDestroyEnumHandle0(self.engine.handle, self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

/// True when `filter`'s provider key is the Egrio leak-protection provider. The
/// field is a pointer that is null for provider-less filters. Compared field by
/// field so it does not depend on a `GUID: PartialEq` derive.
pub(super) fn filter_provider_is_egrio(filter: &FWPM_FILTER0) -> bool {
    match unsafe { filter.providerKey.as_ref() } {
        Some(key) => guid_eq(key, &EGRIO_WFP_PROVIDER_KEY),
        None => false,
    }
}

/// Decodes the logical filter key from a filter's provider-data blob, or `None`
/// when the blob is empty or not valid UTF-8.
pub(super) fn filter_provider_data_key(filter: &FWPM_FILTER0) -> Option<String> {
    let blob = &filter.providerData;
    if blob.data.is_null() || blob.size == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) };
    String::from_utf8(bytes.to_vec()).ok()
}

pub(super) fn egrio_filter_key(filter: &FWPM_FILTER0) -> Result<Option<String>, String> {
    if !filter_provider_is_egrio(filter) {
        return Ok(None);
    }
    let key = filter_provider_data_key(filter).filter(|key| !key.is_empty());
    key.map(Some).ok_or_else(|| {
        format!(
            "Egrio WFP filter {} has missing or invalid provider-data key",
            filter.filterId
        )
    })
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let _ = unsafe { FwpmEngineClose0(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

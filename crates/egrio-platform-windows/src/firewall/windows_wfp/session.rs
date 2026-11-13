//! A leak-protection session: the dynamic WFP session that holds a plan's
//! filters for as long as the tunnel they guard carries packets.

use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallKillSwitchSessionReport {
    pub provider_key: String,
    pub sublayer_key: String,
    pub provider_registered: bool,
    pub sublayer_registered: bool,
    pub sublayers_registered: Vec<WindowsFirewallSublayerReport>,
    pub filters_registered: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallSublayerReport {
    pub kind: WindowsFirewallSublayerKind,
    pub key: String,
    pub registered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFirewallKillSwitchRestoreReport {
    pub dynamic_session_closed: bool,
    pub warnings: Vec<String>,
}

pub struct WindowsFirewallKillSwitchSession {
    _engine: WfpEngine,
    report: WindowsFirewallKillSwitchSessionReport,
    profile: WfpSessionProfile,
}

impl WindowsFirewallKillSwitchSession {
    pub fn report(&self) -> WindowsFirewallKillSwitchSessionReport {
        self.report.clone()
    }

    pub fn install_filter_plan(
        &mut self,
        plan: &WindowsFirewallKillSwitchFilterPlan,
    ) -> Result<WindowsFirewallKillSwitchSessionReport, String> {
        let filters_registered = self._engine.add_filter_plan(&self.profile, plan)?;
        self.report.filters_registered = filters_registered;
        Ok(self.report.clone())
    }

    /// Brings this session's filters to `plan` in one WFP transaction: adds
    /// the filters the plan has and the session lacks, then deletes the ones
    /// the plan dropped. An aborted transaction leaves the previous set in
    /// force, so leak protection never has a gap. Filters can only be deleted
    /// by the dynamic session that added them, which is this one.
    pub fn reconcile_filter_plan(
        &mut self,
        plan: &WindowsFirewallKillSwitchFilterPlan,
    ) -> Result<WindowsFirewallKillSwitchSessionReport, String> {
        if !plan.production_ready {
            return Err(format!(
                "Windows WFP filter plan is not production ready: {}",
                plan.blockers.join("; ")
            ));
        }
        let installed = self
            .report
            .filters_registered
            .iter()
            .filter_map(|entry| {
                let (key, id) = entry.rsplit_once(':')?;
                Some((key.to_string(), id.parse::<u64>().ok()?))
            })
            .collect::<Vec<_>>();
        let wanted = plan
            .filters
            .iter()
            .map(|filter| filter.key.as_str())
            .collect::<BTreeSet<_>>();
        let present = installed
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<BTreeSet<_>>();
        self._engine.begin_transaction()?;
        let changes = plan
            .filters
            .iter()
            .filter(|filter| !present.contains(filter.key.as_str()))
            .map(|filter| self._engine.add_filter(&self.profile, filter))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|added| {
                installed
                    .iter()
                    .filter(|(key, _)| !wanted.contains(key.as_str()))
                    .try_for_each(|(key, id)| self._engine.delete_filter(*id, key))
                    .map(|()| added)
            });
        let added = match changes {
            Ok(added) => added,
            Err(error) => {
                self._engine.abort_transaction();
                return Err(error);
            }
        };
        self._engine.commit_transaction()?;
        let mut registered = installed
            .into_iter()
            .filter(|(key, _)| wanted.contains(key.as_str()))
            .map(|(key, id)| format!("{key}:{id}"))
            .collect::<Vec<_>>();
        registered.extend(added);
        self.report.filters_registered = registered;
        Ok(self.report.clone())
    }

    pub fn stop(self) -> WindowsFirewallKillSwitchRestoreReport {
        WindowsFirewallKillSwitchRestoreReport {
            dynamic_session_closed: true,
            warnings: vec![
                "WFP dynamic session closed; dynamic provider, sublayer, and filters are released by BFE"
                    .into(),
            ],
        }
    }
}

pub(super) fn layer_of(address: std::net::IpAddr) -> WindowsFirewallKillSwitchLayer {
    match address {
        std::net::IpAddr::V4(_) => WindowsFirewallKillSwitchLayer::AleAuthConnectV4,
        std::net::IpAddr::V6(_) => WindowsFirewallKillSwitchLayer::AleAuthConnectV6,
    }
}

pub fn start_windows_firewall_kill_switch_session(
) -> Result<WindowsFirewallKillSwitchSession, String> {
    start_windows_firewall_session(EGRIO_WFP_KILL_SWITCH_PROFILE, "Egrio WFP dynamic session")
}

/// Observes the Egrio leak-protection filters currently installed in BFE by
/// enumerating this provider's filters and recovering each one's logical key from
/// its provider-data tag. Read-only: opens a non-dynamic engine
/// session that installs nothing, so it never mutates host state. The returned
/// keys are the reconciler's observed WFP-filter resource set — deduplicated and
/// sorted so the diff is order-stable.
///
/// A stale Egrio session's filters are auto-released by BFE when its dynamic
/// session closed, so a key returned here reflects a filter that is genuinely
/// still present.
pub fn windows_firewall_observe_kill_switch_filter_keys() -> Result<Vec<String>, String> {
    let engine = WfpEngine::open_read_only("Egrio WFP filter observation session")?;
    let enum_handle = engine.create_filter_enum_handle().map_err(|status| {
        format!("create Egrio WFP filter enumeration handle failed with status 0x{status:08x}")
    })?;
    let mut keys = enum_handle
        .enumerate_egrio_filter_keys()
        .map_err(|error| format!("enumerate Egrio WFP filters failed: {error}"))?;
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn start_windows_firewall_session(
    profile: WfpSessionProfile,
    session_name: &str,
) -> Result<WindowsFirewallKillSwitchSession, String> {
    let engine = WfpEngine::open_dynamic(session_name, profile.session_description)?;
    let provider_registered = engine.add_provider(&profile)?;
    let sublayers_registered = engine.add_sublayers(&profile)?;
    let sublayer_registered = sublayers_registered
        .iter()
        .all(|sublayer| sublayer.registered);
    let primary_sublayer_key = profile
        .sublayers
        .first()
        .map(|sublayer| guid_string(sublayer.key))
        .unwrap_or_default();
    let report = WindowsFirewallKillSwitchSessionReport {
        provider_key: guid_string(profile.provider_key),
        sublayer_key: primary_sublayer_key,
        provider_registered,
        sublayer_registered,
        sublayers_registered,
        filters_registered: Vec::new(),
        warnings: vec![profile.active_warning.into()],
    };

    Ok(WindowsFirewallKillSwitchSession {
        _engine: engine,
        report,
        profile,
    })
}

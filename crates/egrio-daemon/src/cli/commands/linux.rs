use egrio_core::{CoreStartInputs, EgressSocketGuard, RuntimeProfile};
use egrio_platform_linux::{
    linux_tun_core_capture_config, linux_tun_preflight, LinuxFlowScanner, LinuxTun, LinuxTunConfig,
};
use egrio_runtime::{
    CoreConfigSource, DnsSettings, FirewallSettings, IpPrefix, PacketCaptureSettings,
    PacketCaptureSource, RouteSettings, RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec,
    RuntimeSpec,
};
use egrio_sdk::{EgrioSdk, FileCheckpointStore, NativeCorePacketDataPlane};
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};

pub(crate) fn print_tun_preflight() -> Result<(), String> {
    print_json(&linux_tun_preflight(&LinuxTunConfig::default()))
}

#[derive(Debug)]
struct LinuxCoreConfig {
    profile: RuntimeProfile,
    guard: Arc<dyn EgressSocketGuard>,
}
impl CoreConfigSource for LinuxCoreConfig {
    fn load(&self) -> Result<CoreStartInputs, String> {
        // The Runtime rejects a fake-IP pool covering the TUN's addresses, and
        // the guard supplies the physical resolvers once the TUN opens.
        Ok(CoreStartInputs {
            capture: linux_tun_core_capture_config(),
            profile: self.profile.clone(),
            egress: Default::default(),
            egress_socket_guard: Some(self.guard.clone()),
            flow_scanner: Some(Arc::new(LinuxFlowScanner)),
            fake_ip_mappings: None,
        })
    }
}

fn assemble(profile: RuntimeProfile, directory: Option<String>) -> Result<EgrioSdk, String> {
    let tun = LinuxTun::new(LinuxTunConfig::default())?;
    let guard = tun.egress_socket_guard();
    let directory = directory
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/egrio/runtime-checkpoints/linux-tun"));
    EgrioSdk::builder()
        .checkpoint_store(Arc::new(FileCheckpointStore::new(directory)))
        .packet_capture(tun.capture)
        .route_control(tun.route)
        .dns_control(tun.dns)
        .firewall_control(tun.firewall)
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(LinuxCoreConfig { profile, guard }))
        .build()
        .map_err(|e| e.to_string())
}

pub(crate) fn recover_tun(directory: Option<String>) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("Linux TUN recovery requires Linux".into());
    }
    // Recovery never starts the Core.
    let sdk = assemble(crate::profile_handoff::default_direct_profile(), directory)?;
    eprintln!("Linux TUN recovery restores only checkpoint-owned interfaces, policy rules, link DNS and nftables tables, and verifies their removal.");
    tokio::runtime::Runtime::new().map_err(|e|e.to_string())?.block_on(async move {
        let report=sdk.recover_unresolved().await.map_err(|e|e.to_string())?;
        print_json(&report.into_iter().map(|report|serde_json::json!({"checkpoint_id":report.checkpoint_id,"restored":report.restored,"resources":report.resources})).collect::<Vec<_>>())
    })
}

pub(crate) fn run_tun(
    profile_path: Option<String>,
    directory: Option<String>,
) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("Linux TUN capture requires Linux".into());
    }
    let preflight = linux_tun_preflight(&LinuxTunConfig::default());
    if !preflight.ready {
        return Err(preflight.blockers.join("; "));
    }
    let profile = crate::profile_handoff::load_profile(profile_path)?;
    let fake_ip_prefixes = IpPrefix::fake_ip_pool(profile.dns.fake_ip_range);
    let sdk = assemble(profile, directory)?;
    eprintln!("Linux TUN will create egrio0, install dual-stack policy routes, set DNS only on that link and reject the leaks around it (DNS and fake IPs outside it, IPv6 it does not carry) in an owned nftables table. SIGINT/SIGTERM restores and verifies these resources; unresolved checkpoints are recovered before a new start.");
    tokio::runtime::Runtime::new().map_err(|e|e.to_string())?.block_on(async move {
        let shutdown=LinuxShutdown::new()?;
        sdk.recover_unresolved().await.map_err(|e|e.to_string())?;
        let spec=RuntimeSpec::with_core(RuntimeId::new(),Some(RuntimeCoreSpec::default()),RuntimePlatformSpec{
            packet_capture:Some(PacketCaptureSettings{
                mtu: LinuxTunConfig::default().mtu,source:PacketCaptureSource::Tun,install_default_route:false,install_dns:false,excluded_prefixes:Vec::new(),fake_ip_prefixes:Vec::new()}),
            route:Some(RouteSettings{default_route:true,excluded_prefixes:Vec::new()}),
            dns:Some(DnsSettings{servers:Vec::new(),search_domains:Vec::new()}),
            firewall:Some(FirewallSettings{kill_switch:true,allow_lan:true,excluded_prefixes:Vec::new(),fake_ip_prefixes}),
            ..Default::default()
        }).map_err(|e|e.to_string())?;
        let runtime=sdk.create_runtime(spec).await.map_err(|e|e.to_string())?;
        let start=runtime.start().await.map_err(|e|e.to_string())?;
        let output=print_json(&serde_json::json!({"event":"linux-tun-started","generation":start.generation,"changed":start.changed,"checkpoint_id":start.checkpoint_id,"resources":start.resources}));
        let exit=match output {Ok(())=>shutdown.wait(&runtime).await,Err(error)=>Err(error)};
        let stopped=runtime.stop().await.map_err(|e|e.to_string())?;
        print_json(&serde_json::json!({"event":"linux-tun-stopped","generation":stopped.generation,"changed":stopped.changed,"restored":stopped.restored,"resources":stopped.resources}))?;
        exit
    })
}

struct LinuxShutdown {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}
impl LinuxShutdown {
    fn new() -> Result<Self, String> {
        #[cfg(unix)]
        {
            Ok(Self {
                interrupt:
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                        .map_err(|e| e.to_string())?,
                terminate:
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .map_err(|e| e.to_string())?,
            })
        }
        #[cfg(not(unix))]
        {
            Err("Linux TUN signals require a Unix host".into())
        }
    }
    async fn wait(self, runtime: &Arc<egrio_runtime::Runtime>) -> Result<(), String> {
        #[cfg(unix)]
        {
            let Self {
                mut interrupt,
                mut terminate,
            } = self;
            // A lost platform session is announced at once; the slow check
            // catches the Runtime leaving its active state any other way
            // without waking an idle process several times a second.
            let mut losses = runtime.subscribe_session_loss();
            loop {
                let status = runtime.status();
                if status.state != egrio_runtime::RuntimeState::Running {
                    return Err(format!(
                        "Linux TUN Runtime exited active state: {:?}",
                        status.state
                    ));
                }
                tokio::select! {
                    _=interrupt.recv()=>return Ok(()),
                    _=terminate.recv()=>return Ok(()),
                    changed=losses.changed()=>{if changed.is_err(){return Err("Linux TUN Runtime ended".into());}}
                    _=tokio::time::sleep(std::time::Duration::from_secs(10))=>{}
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (self, runtime);
            Err("Linux TUN signals require a Unix host".into())
        }
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|e| e.to_string())?
    );
    io::stdout().flush().map_err(|e| e.to_string())
}

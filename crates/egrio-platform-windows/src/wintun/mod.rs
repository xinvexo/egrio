//! The Wintun tunnel: the packet session the service opens on the adapter it
//! creates. Its parts hold the rest:
//!
//! - `library` — `wintun.dll`, and whether the adapter exists;
//! - `interface` — the adapter's addresses and interface settings;
//! - `capture_routes` — the routes into the tunnel that Egrio owns;
//! - `interface_dns` — an interface's DNS servers;
//! - `physical` — the host's route tables and the physical uplink;
//! - `network_state` — the uplink every DIRECT dial binds to, kept current.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW, ERROR_NOT_FOUND,
    ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid, CreateIpForwardEntry2,
    CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, FreeMibTable, GetAdaptersAddresses,
    GetIfEntry2, GetIpAddrTable, GetIpForwardTable2, GetIpInterfaceEntry, GetUnicastIpAddressEntry,
    GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, SetInterfaceDnsSettings, SetIpInterfaceEntry,
    SetUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_WWANPP, IF_TYPE_WWANPP2,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP, IP_ADDRESS_PREFIX, MIB_IF_ROW2,
    MIB_IPADDRTABLE, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, NlroManual,
    RouterDiscoveryDisabled, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR,
    IN_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
    SOCKET_ADDRESS,
};

use crate::config::WindowsWintunConfig;
use crate::ipv6::resolve_windows_ipv6_mode;
use crate::packet_loop::{RawPacketSend, RawWaitHandle, WindowsRawPacketSession};
use crate::routes::{
    windows_wintun_ipv4_capture_routes, windows_wintun_ipv6_capture_routes,
    windows_wintun_route_cidr_key, WindowsWintunRoute, WindowsWintunRoute6,
    WindowsWintunRouteRestoreReport,
};

mod capture_routes;
mod interface;
mod interface_dns;
mod library;
pub(crate) mod network_state;
mod physical;

pub use capture_routes::*;
use interface::*;
pub use interface_dns::*;
use library::*;
pub(crate) use physical::*;

pub struct WindowsRawWintunSession {
    adapter_name: String,
    adapter_index: u32,
    _adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
}

/// The configured adapter, opened or created for one packet session.
struct PreparedAdapter {
    adapter: Arc<wintun::Adapter>,
    adapter_created: bool,
    adapter_index: u32,
}

impl WindowsRawPacketSession for WindowsRawWintunSession {
    fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    fn interface_index(&self) -> u32 {
        self.adapter_index
    }

    fn receive_with(
        &self,
        deliver: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<bool, String> {
        // The packet stays in Wintun's receive ring until it drops here.
        let Some(packet) = self
            .session
            .try_receive()
            .map_err(|error| error.to_string())?
        else {
            return Ok(false);
        };
        deliver(packet.bytes())?;
        Ok(true)
    }

    fn try_send_with(
        &self,
        len: usize,
        fill: &mut dyn FnMut(&mut [u8]),
    ) -> Result<RawPacketSend, String> {
        let packet_len = u16::try_from(len)
            .map_err(|_| format!("Wintun packet exceeds maximum length: {len}"))?;
        let mut packet = match self.session.allocate_send_packet(packet_len) {
            Ok(packet) => packet,
            Err(wintun::Error::Io(error))
                if error.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW as i32) =>
            {
                return Ok(RawPacketSend::Backpressured);
            }
            Err(error) => return Err(error.to_string()),
        };
        fill(packet.bytes_mut());
        self.session.send_packet(packet);
        Ok(RawPacketSend::Sent)
    }

    /// Wintun 0.14.1, the current release, publishes a sent packet with a
    /// release store of the ring's tail followed by a load of the reader's
    /// alertable flag, and its driver arms that flag and re-reads the tail the
    /// same way, with no full barrier on either side. x86 may reorder each
    /// store-load pair, so both sides can read the other's old value and the
    /// driver sleeps with the packet unread until the next send signals it:
    /// a reply that ends a burst then waits for the peer's retransmission.
    /// Upstream fixed it on both sides in commit ec0a6b98 (2026-03), not yet
    /// released. A later send reads the long-set flag and signals, so this
    /// one goes out once a burst has ended: an IPv4 header with a wrong
    /// checksum, which hosts silently discard (RFC 1122 section 3.2.1.2).
    fn nudge_reader(&self) -> Result<RawPacketSend, String> {
        self.try_send_with(DISCARDED_IPV4_HEADER.len(), &mut |packet| {
            packet.copy_from_slice(&DISCARDED_IPV4_HEADER);
        })
    }

    fn read_wait_handle(&self) -> Result<RawWaitHandle, String> {
        self.session
            .get_read_wait_event()
            .map(|handle| RawWaitHandle::new(handle as usize as u64))
            .map_err(|error| error.to_string())
    }
}

pub fn open_windows_raw_packet_session(
    config: &WindowsWintunConfig,
) -> Result<WindowsRawWintunSession, String> {
    let prepared = prepare_adapter(config)?;
    validate_windows_wintun_active_adapter_ownership(
        prepared.adapter_created,
        &config.adapter_name,
    )?;
    let adapter = Arc::clone(&prepared.adapter);
    let adapter_index = prepared.adapter_index;
    if config.configure_interface {
        configure_windows_wintun_ipv4_address(adapter_index, config)?;
        configure_windows_wintun_ipv4_interface(
            adapter_index,
            config.interface_metric,
            u32::from(config.mtu),
        )?;
        if resolve_windows_ipv6_mode(config).tunnels_v6() {
            configure_windows_wintun_ipv6_address(
                adapter_index,
                config.adapter_address6,
                config.adapter_prefix_length6,
            )?;
            configure_windows_wintun_ipv6_interface(
                adapter_index,
                config.interface_metric,
                u32::from(config.mtu),
            )?;
        }
        adapter
            .set_mtu(config.mtu as usize)
            .map_err(|error| error.to_string())?;
    }
    let session = adapter
        .start_session(config.ring_capacity)
        .map(Arc::new)
        .map_err(|error| error.to_string())?;
    Ok(WindowsRawWintunSession {
        adapter_name: config.adapter_name.clone(),
        adapter_index,
        _adapter: adapter,
        session,
    })
}

fn validate_windows_wintun_active_adapter_ownership(
    adapter_created: bool,
    adapter_name: &str,
) -> Result<(), String> {
    if adapter_created {
        return Ok(());
    }

    Err(format!(
        "refusing to start active capture on pre-existing Wintun adapter '{adapter_name}': Egrio cannot prove ownership or restore its IPv4/IPv6 address, metric, and MTU baseline"
    ))
}

fn prepare_adapter(config: &WindowsWintunConfig) -> Result<PreparedAdapter, String> {
    let wintun = load_wintun(config)?;
    if let Some(adapter) = open_wintun_adapter_if_present(&wintun, &config.adapter_name)? {
        let adapter_index = adapter.get_adapter_index().map_err(|error| {
            format!(
                "Wintun adapter '{}' exists but its interface index is not available: {error}",
                config.adapter_name
            )
        })?;
        return Ok(PreparedAdapter {
            adapter,
            adapter_created: false,
            adapter_index,
        });
    }

    let adapter = wintun::Adapter::create(&wintun, &config.adapter_name, &config.tunnel_type, None)
        .map_err(|error| {
            format!(
                "failed to create service-held Wintun adapter '{}': {error}",
                config.adapter_name
            )
        })?;
    let adapter_index = adapter.get_adapter_index().map_err(|error| {
        format!(
            "created Wintun adapter '{}' but failed to read its interface index: {error}",
            config.adapter_name
        )
    })?;
    Ok(PreparedAdapter {
        adapter,
        adapter_created: true,
        adapter_index,
    })
}

/// An IPv4 header between two TEST-NET-1 addresses (RFC 5737) whose checksum
/// is the complement of the valid one, so the stack drops it before any
/// protocol sees it.
const DISCARDED_IPV4_HEADER: [u8; 20] = {
    let mut header = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ];
    let mut sum = 0_u32;
    let mut index = 0;
    while index < header.len() {
        sum += ((header[index] as u32) << 8) | header[index + 1] as u32;
        index += 2;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // The valid checksum is the complement of `sum`; store `sum` itself.
    header[10] = (sum >> 8) as u8;
    header[11] = sum as u8;
    header
};

// --- IPv6 tunnel setup ---
//
// Every call here mirrors its IPv4 sibling above and uses the same
// family-neutral IP Helper APIs (`CreateUnicastIpAddressEntry`,
// `SetIpInterfaceEntry`, `CreateIpForwardEntry2`), only swapping the
// `SOCKADDR_INET` variant to `Ipv6` and adding the two IPv6-only interface
// settings that disable router discovery and duplicate address detection.

#[cfg(test)]
mod tests;

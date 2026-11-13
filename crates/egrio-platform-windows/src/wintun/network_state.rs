//! The single source of truth for the physical uplink ("underlying") interface
//! Egrio egress binds to.
//!
//! [`WindowsNetworkState`] is the authority every Direct egress dial reads to
//! find the real physical interface. It is maintained network state, not
//! something re-derived per socket: one interface index per family, plus the
//! stable identity of our own Wintun adapter so recomputing the uplink never
//! selects the tunnel.
//!
//! Loop protection is deterministic, not time-ordered. Our own Wintun is
//! excluded from underlying selection by its interface index (resolved live
//! from a stored LUID), so the underlying can be recomputed at any moment —
//! including after the tunnel has installed its `/1` capture routes, which are
//! longer-prefix than the physical `/0` default — and still resolve the real
//! uplink. That is what lets the network-change monitor follow a Wi-Fi→Ethernet
//! switch live (its handler calls [`WindowsNetworkState::recompute`]); the core
//! never has to know the tunnel exists, it only reads `underlying_*`.
//!
//! The Wintun identity is held as a `NET_LUID_LH` value rather than a raw
//! interface index because indexes reshuffle across adapter churn while the
//! LUID is stable for the adapter's lifetime; the current index is resolved
//! from it on each recompute.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToIndex,
    NotifyIpInterfaceChange, NotifyRouteChange2, NotifyUnicastIpAddressChange, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use super::physical_egress_interface_index;

/// The public-internet probe targets whose route resolves the default physical
/// egress for each family (same policy as the deleted egress source-IP probe).
const IPV4_PROBE_TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const IPV6_PROBE_TARGET: IpAddr =
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

/// Interface index 0 is never a valid Windows interface, so it doubles as the
/// "no physical uplink for this family" sentinel in the atomics.
const NO_INTERFACE: u32 = 0;

/// The maintained physical-uplink state shared between the egress binder (reader)
/// and the network-change monitor (writer). `Arc`-shared; all fields are read on
/// the dial hot path, so reads are lock-free atomic loads.
#[derive(Debug)]
pub struct WindowsNetworkState {
    /// Stable identity of our own Wintun adapter, excluded from underlying
    /// selection. Held as a LUID value so an interface-index reshuffle does not
    /// lose track of which adapter is the tunnel.
    wintun_luid: u64,
    underlying_v4: AtomicU32,
    underlying_v6: AtomicU32,
}

impl WindowsNetworkState {
    /// Capture the initial physical uplink for a session whose Wintun adapter is
    /// at `wintun_ifindex`. IPv4 is required — a host with no usable physical
    /// IPv4 uplink cannot serve capture, so this fails loudly rather than
    /// starting a tunnel that silently drops every dial. IPv6 is optional and
    /// recorded absent when the host has no v6 default.
    ///
    /// Excluding our own Wintun by index means this is correct whether it runs
    /// before or after the capture routes are installed; the caller no longer
    /// has to sequence it against the hijack.
    pub fn capture(wintun_ifindex: u32) -> Result<Self, String> {
        let wintun_luid = luid_value_from_ifindex(wintun_ifindex)?;
        let exclude = Some(wintun_ifindex);
        let underlying_v4 = physical_egress_interface_index(IPV4_PROBE_TARGET, exclude)?;
        let underlying_v6 =
            physical_egress_interface_index(IPV6_PROBE_TARGET, exclude).unwrap_or(NO_INTERFACE);
        Ok(Self {
            wintun_luid,
            underlying_v4: AtomicU32::new(underlying_v4),
            underlying_v6: AtomicU32::new(underlying_v6),
        })
    }

    /// Recompute both families from the live route table, excluding our own
    /// Wintun (resolved from the stored LUID to its current index). The
    /// network-change monitor's handler calls this on every route or interface
    /// change.
    ///
    /// Infallible by design: a family with no usable uplink right now (cable
    /// unplugged, Wi-Fi off mid-switch) is stored as absent, and the binder
    /// fails that family's dials with a clear message until an uplink returns.
    /// A recompute must never poison the shared state.
    pub fn recompute(&self) {
        let (v4, v6) = physical_uplinks(self.wintun_ifindex());
        self.underlying_v4
            .store(v4.unwrap_or(NO_INTERFACE), Ordering::Relaxed);
        self.underlying_v6
            .store(v6.unwrap_or(NO_INTERFACE), Ordering::Relaxed);
    }

    /// The current physical IPv4 uplink index, or `None` when the host has no
    /// usable physical IPv4 default right now.
    pub fn underlying_ipv4(&self) -> Option<u32> {
        interface_index_or_none(self.underlying_v4.load(Ordering::Relaxed))
    }

    /// State pinned to fixed uplink values — no OS reads, no Wintun identity —
    /// so binder policy tests can exercise the built-state paths host-safely.
    #[cfg(test)]
    pub(crate) fn pinned_for_tests(underlying_v4: Option<u32>, underlying_v6: Option<u32>) -> Self {
        Self {
            wintun_luid: 0,
            underlying_v4: AtomicU32::new(underlying_v4.unwrap_or(NO_INTERFACE)),
            underlying_v6: AtomicU32::new(underlying_v6.unwrap_or(NO_INTERFACE)),
        }
    }

    /// The current physical IPv6 uplink index, or `None` when the host has no
    /// usable physical IPv6 default right now.
    pub fn underlying_ipv6(&self) -> Option<u32> {
        interface_index_or_none(self.underlying_v6.load(Ordering::Relaxed))
    }

    /// Our own Wintun's current interface index, resolved from the stored LUID.
    /// `None` when the adapter is gone (session teardown) — then there is
    /// nothing to exclude and the recompute proceeds unfiltered.
    fn wintun_ifindex(&self) -> Option<u32> {
        ifindex_from_luid_value(self.wintun_luid).ok()
    }
}

/// The physical interface each family's default traffic leaves through now,
/// never `exclude` (our own Wintun); `None` for a family without one.
pub(crate) fn physical_uplinks(exclude: Option<u32>) -> (Option<u32>, Option<u32>) {
    (
        physical_egress_interface_index(IPV4_PROBE_TARGET, exclude).ok(),
        physical_egress_interface_index(IPV6_PROBE_TARGET, exclude).ok(),
    )
}

fn interface_index_or_none(index: u32) -> Option<u32> {
    (index != NO_INTERFACE).then_some(index)
}

/// `ConvertInterfaceIndexToLuid`: the documented IP Helper index→LUID mapping.
fn luid_value_from_ifindex(ifindex: u32) -> Result<u64, String> {
    let mut luid = NET_LUID_LH { Value: 0 };
    let status = unsafe { ConvertInterfaceIndexToLuid(ifindex, &mut luid) };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "failed to resolve Wintun interface LUID for index {ifindex}: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    Ok(unsafe { luid.Value })
}

/// `ConvertInterfaceLuidToIndex`: the documented IP Helper LUID→index mapping,
/// the inverse of [`luid_value_from_ifindex`].
fn ifindex_from_luid_value(value: u64) -> Result<u32, String> {
    let luid = NET_LUID_LH { Value: value };
    let mut ifindex = NO_INTERFACE;
    let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut ifindex) };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "failed to resolve interface index for Wintun LUID: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    Ok(ifindex)
}

/// Runs a handler on every route-table, IP interface and unicast address
/// change, so state derived from the uplink is re-derived within one event: a
/// Wi-Fi→Ethernet switch and a cable unplug change routes, a changed interface
/// metric (Windows also adjusts automatic metrics to link speed) changes only
/// the interface and fires no route notification, and a new DHCP lease
/// changes an address.
///
/// The subscriptions share one handler, kept alive by the monitor and
/// cancelled on `Drop`, which ties the OS callbacks' lifetime to this value.
/// Callbacks of different subscriptions can run at once.
pub struct WindowsNetworkChangeMonitor {
    routes: NotificationHandle,
    interfaces: NotificationHandle,
    addresses: NotificationHandle,
    /// Kept alive because the raw pointer handed to both registrations as the
    /// caller context aliases this allocation; dropping it before cancellation
    /// would leave a callback dereferencing freed memory.
    _handler: Arc<ChangeHandler>,
}

struct ChangeHandler(Box<dyn Fn() + Send + Sync>);

impl std::fmt::Debug for WindowsNetworkChangeMonitor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WindowsNetworkChangeMonitor")
    }
}

impl WindowsNetworkChangeMonitor {
    /// Registers the subscriptions with `AF_UNSPEC`, so one set covers IPv4
    /// and IPv6. A failure is returned for the caller to log.
    pub fn register(on_change: impl Fn() + Send + Sync + 'static) -> Result<Self, String> {
        let handler = Arc::new(ChangeHandler(Box::new(on_change)));
        let context = Arc::as_ptr(&handler) as *const c_void;
        let mut routes: HANDLE = std::ptr::null_mut();
        // initialnotification = false: the caller derived the initial state
        // synchronously, so only changes from here on matter.
        let status = unsafe {
            NotifyRouteChange2(AF_UNSPEC, Some(route_callback), context, false, &mut routes)
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "failed to register the Windows route-change notification: {}",
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        let routes = NotificationHandle(routes);
        let mut interfaces: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(interface_callback),
                context,
                false,
                &mut interfaces,
            )
        };
        if status != ERROR_SUCCESS {
            unsafe { CancelMibChangeNotify2(routes.0) };
            return Err(format!(
                "failed to register the Windows interface-change notification: {}",
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        let interfaces = NotificationHandle(interfaces);
        let mut addresses: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(address_callback),
                context,
                false,
                &mut addresses,
            )
        };
        if status != ERROR_SUCCESS {
            unsafe {
                CancelMibChangeNotify2(routes.0);
                CancelMibChangeNotify2(interfaces.0);
            }
            return Err(format!(
                "failed to register the Windows address-change notification: {}",
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        Ok(Self {
            routes,
            interfaces,
            addresses: NotificationHandle(addresses),
            _handler: handler,
        })
    }
}

impl Drop for WindowsNetworkChangeMonitor {
    fn drop(&mut self) {
        // Cancel first so no callback can fire against the handler after this
        // returns; `CancelMibChangeNotify2` is synchronous and waits for any
        // in-progress callback to finish (documented). Only then may the
        // handler drop.
        unsafe {
            CancelMibChangeNotify2(self.routes.0);
            CancelMibChangeNotify2(self.interfaces.0);
            CancelMibChangeNotify2(self.addresses.0);
        }
    }
}

/// A notification handle is an opaque OS handle (a raw pointer), so it is not
/// `Send`/`Sync` by default. It is only ever created, stored, and passed to
/// `CancelMibChangeNotify2` — never dereferenced by us — and the monitor is
/// moved across the thread boundary into the service worker, so wrap it to
/// carry the handle safely.
#[derive(Debug)]
struct NotificationHandle(HANDLE);

// SAFETY: the handle is an opaque token we only pass back to
// `CancelMibChangeNotify2`; we never read through it, and the OS owns the
// underlying object. Moving the token between threads is sound.
unsafe impl Send for NotificationHandle {}
unsafe impl Sync for NotificationHandle {}

/// The notification callbacks run on an OS worker thread and only run the
/// shared handler. Re-entrancy is documented-safe: MSDN's remarks direct the
/// callbacks to complete the changed row with sibling reads such as
/// `GetIpForwardEntry2`, so the reads a handler issues (`GetIpForwardTable2`,
/// `GetAdaptersAddresses`, `GetUnicastIpAddressTable`, `GetIfEntry2`) are
/// supported queries, not mutations that would re-enter a notification. Callbacks are serialized per registration. We
/// never call `CancelMibChangeNotify2` from here — that would deadlock (MSDN);
/// cancellation happens only on the monitor's `Drop`, on another thread.
unsafe fn run_handler(caller_context: *const c_void) {
    if !caller_context.is_null() {
        (*(caller_context as *const ChangeHandler)).0();
    }
}

unsafe extern "system" fn route_callback(
    caller_context: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    run_handler(caller_context);
}

unsafe extern "system" fn interface_callback(
    caller_context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    run_handler(caller_context);
}

unsafe extern "system" fn address_callback(
    caller_context: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    run_handler(caller_context);
}

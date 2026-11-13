//! The physical interfaces in the system's preference order, followed through
//! the Network.framework path monitor in `native/path_monitor.c`.

use std::ffi::c_void;

#[repr(C)]
struct RawPathMonitor {
    _private: [u8; 0],
}

type PathUpdate = unsafe extern "C" fn(context: *mut c_void, interfaces: *const u32, count: u32);

extern "C" {
    fn egrio_path_monitor_start(update: PathUpdate, context: *mut c_void) -> *mut RawPathMonitor;
    fn egrio_path_monitor_stop(monitor: *mut RawPathMonitor);
}

type Handler = Box<dyn Fn(&[u32]) + Send + Sync>;

/// Calls its handler with the indexes of the Wi-Fi, wired and cellular
/// interfaces, most preferred first, once at start and then on every path
/// change until dropped. The handler runs on the monitor's own serial queue;
/// it must not drop the monitor.
pub(crate) struct PathMonitor {
    raw: *mut RawPathMonitor,
    handler: *mut Handler,
}

// The raw monitor is only cancelled, once, by drop; the handler it calls is
// `Send + Sync`.
unsafe impl Send for PathMonitor {}
unsafe impl Sync for PathMonitor {}

impl PathMonitor {
    pub(crate) fn start(handler: impl Fn(&[u32]) + Send + Sync + 'static) -> Result<Self, String> {
        let handler: *mut Handler = Box::into_raw(Box::new(Box::new(handler)));
        let raw = unsafe { egrio_path_monitor_start(on_update, handler.cast()) };
        if raw.is_null() {
            drop(unsafe { Box::from_raw(handler) });
            return Err("could not start the macOS network path monitor".into());
        }
        Ok(Self { raw, handler })
    }
}

unsafe extern "C" fn on_update(context: *mut c_void, interfaces: *const u32, count: u32) {
    let handler = unsafe { &*context.cast::<Handler>() };
    let interfaces = if interfaces.is_null() {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(interfaces, count as usize) }
    };
    // A panic must not unwind into the dispatch queue.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(interfaces)));
}

impl Drop for PathMonitor {
    fn drop(&mut self) {
        // Returns once the last update has run, so the handler can go.
        unsafe { egrio_path_monitor_stop(self.raw) };
        drop(unsafe { Box::from_raw(self.handler) });
    }
}

impl std::fmt::Debug for PathMonitor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PathMonitor")
    }
}

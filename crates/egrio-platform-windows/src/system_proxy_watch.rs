//! Watches the per-user WinINET `Internet Settings` registry key for
//! modification, backing the daemon's system-proxy guard.
//!
//! API basis (official documentation): `RegOpenKeyExW` with `KEY_NOTIFY`
//! and `RegNotifyChangeKeyValue` (winreg.h) in asynchronous event mode with
//! `REG_NOTIFY_CHANGE_LAST_SET`, re-armed after every signal
//! (<https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue>),
//! plus Win32 event objects (`CreateEventW`/`SetEvent`) and
//! `WaitForMultipleObjects` (synchapi.h). The notify registration is bound
//! to the arming thread, so `wait_for_change` must be driven from one
//! thread — the guard thread — for the watcher's lifetime; the stop handle
//! may be signaled from any thread.

use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Registry::{RegNotifyChangeKeyValue, REG_NOTIFY_CHANGE_LAST_SET};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};
use winreg::enums::{HKEY_CURRENT_USER, KEY_NOTIFY};
use winreg::RegKey;

use crate::system_proxy::WINDOWS_INTERNET_SETTINGS;

/// What a bounded wait on the watcher observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxyWatchOutcome {
    /// The Internet Settings key was written (any value under it).
    Changed,
    /// The paired stop handle was signaled; the watch loop should exit.
    Stopped,
    /// Nothing happened within the timeout (callers use this for periodic
    /// belt-and-braces verification).
    TimedOut,
}

/// An owned Win32 event handle. Kernel event objects are thread-safe; the
/// wrapper only ties the handle's lifetime to Rust ownership.
struct OwnedEvent(HANDLE);

unsafe impl Send for OwnedEvent {}
unsafe impl Sync for OwnedEvent {}

impl OwnedEvent {
    /// A manual-reset unnamed event (manual so a signaled stop stays
    /// signaled for every subsequent wait).
    fn manual_reset() -> Result<Self, String> {
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(format!("CreateEventW failed with Win32 error {}", unsafe {
                GetLastError()
            }));
        }
        Ok(Self(handle))
    }

    /// An auto-reset unnamed event (the registry notify signal resets on
    /// consumption, matching the one-shot re-arm cycle).
    fn auto_reset() -> Result<Self, String> {
        let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(format!("CreateEventW failed with Win32 error {}", unsafe {
                GetLastError()
            }));
        }
        Ok(Self(handle))
    }

    fn signal(&self) {
        unsafe { SetEvent(self.0) };
    }
}

impl Drop for OwnedEvent {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Signals a [`WindowsSystemProxyChangeWatcher`] to stop; cloneable and
/// callable from any thread.
#[derive(Clone)]
pub struct WindowsSystemProxyWatchStopHandle {
    stop_event: Arc<OwnedEvent>,
}

impl WindowsSystemProxyWatchStopHandle {
    pub fn signal(&self) {
        self.stop_event.signal();
    }
}

/// A registry-change watcher over `HKCU\...\Internet Settings`.
pub struct WindowsSystemProxyChangeWatcher {
    // Held for the `KEY_NOTIFY` handle's lifetime; the raw handle is what
    // `RegNotifyChangeKeyValue` re-arms against.
    key: RegKey,
    notify_event: OwnedEvent,
    stop_event: Arc<OwnedEvent>,
    armed: bool,
}

impl WindowsSystemProxyChangeWatcher {
    pub fn open() -> Result<Self, String> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(WINDOWS_INTERNET_SETTINGS, KEY_NOTIFY)
            .map_err(|error| {
                format!("failed to open the Internet Settings key for notification: {error}")
            })?;
        Self::from_key(key)
    }

    fn from_key(key: RegKey) -> Result<Self, String> {
        Ok(Self {
            key,
            notify_event: OwnedEvent::auto_reset()?,
            stop_event: Arc::new(OwnedEvent::manual_reset()?),
            armed: false,
        })
    }

    pub fn stop_handle(&self) -> WindowsSystemProxyWatchStopHandle {
        WindowsSystemProxyWatchStopHandle {
            stop_event: Arc::clone(&self.stop_event),
        }
    }

    /// Waits up to `timeout` for the key to change or the stop handle to be
    /// signaled, re-arming the one-shot registry notification as needed.
    /// Must be called from the same thread for the watcher's lifetime (the
    /// notify registration is bound to the arming thread).
    pub fn wait_for_change(
        &mut self,
        timeout: Duration,
    ) -> Result<SystemProxyWatchOutcome, String> {
        if !self.armed {
            let status = unsafe {
                RegNotifyChangeKeyValue(
                    self.key.raw_handle(),
                    0, // the proxy values live directly under the key; no subtree
                    REG_NOTIFY_CHANGE_LAST_SET,
                    self.notify_event.0,
                    1, // asynchronous: signal the event, do not block here
                )
            };
            if status != 0 {
                return Err(format!(
                    "RegNotifyChangeKeyValue failed with Win32 error {status}"
                ));
            }
            self.armed = true;
        }

        // Stop first, so a stop signaled during a change burst wins the race.
        let handles = [self.stop_event.0, self.notify_event.0];
        let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let waited = unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout_ms)
        };
        match waited {
            value if value == WAIT_OBJECT_0 => Ok(SystemProxyWatchOutcome::Stopped),
            value if value == WAIT_OBJECT_0 + 1 => {
                // The one-shot notification fired; re-arm on the next wait.
                self.armed = false;
                Ok(SystemProxyWatchOutcome::Changed)
            }
            WAIT_TIMEOUT => Ok(SystemProxyWatchOutcome::TimedOut),
            _ => Err(format!(
                "WaitForMultipleObjects failed with Win32 error {}",
                unsafe { GetLastError() }
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_KEY: AtomicU64 = AtomicU64::new(0);

    struct TestRegistryKey {
        path: String,
    }

    impl TestRegistryKey {
        fn create() -> Self {
            let sequence = NEXT_TEST_KEY.fetch_add(1, Ordering::Relaxed);
            let path = format!(
                r"Software\Egrio-SystemProxyWatch-Test-{}-{sequence}",
                std::process::id()
            );
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&path)
                .expect("create isolated registry key");
            Self { path }
        }

        fn open_notify(&self) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(&self.path, KEY_NOTIFY)
                .expect("open isolated registry key for notification")
        }

        fn open_write(&self) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&self.path)
                .expect("open isolated registry key for writing")
                .0
        }
    }

    impl Drop for TestRegistryKey {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.path);
        }
    }

    fn isolated_watcher(key: &TestRegistryKey) -> WindowsSystemProxyChangeWatcher {
        WindowsSystemProxyChangeWatcher::from_key(key.open_notify()).expect("open watcher")
    }

    #[test]
    fn a_signaled_stop_handle_ends_the_wait() {
        let key = TestRegistryKey::create();
        let mut watcher = isolated_watcher(&key);
        let stop = watcher.stop_handle();

        stop.signal();

        assert_eq!(
            watcher
                .wait_for_change(Duration::from_secs(5))
                .expect("wait succeeds"),
            SystemProxyWatchOutcome::Stopped
        );
        // Manual-reset: the stop stays signaled for every later wait.
        assert_eq!(
            watcher
                .wait_for_change(Duration::from_secs(5))
                .expect("wait succeeds"),
            SystemProxyWatchOutcome::Stopped
        );
    }

    #[test]
    fn an_idle_key_times_out() {
        let key = TestRegistryKey::create();
        let mut watcher = isolated_watcher(&key);

        assert_eq!(
            watcher
                .wait_for_change(Duration::from_millis(20))
                .expect("wait succeeds"),
            SystemProxyWatchOutcome::TimedOut
        );
    }

    #[test]
    fn a_key_write_reports_changed() {
        let key = TestRegistryKey::create();
        let writer = key.open_write();
        let mut watcher = isolated_watcher(&key);

        assert_eq!(
            watcher
                .wait_for_change(Duration::ZERO)
                .expect("arm watcher"),
            SystemProxyWatchOutcome::TimedOut
        );
        writer
            .set_value("ValidationProbe", &1u32)
            .expect("write isolated registry key");
        assert_eq!(
            watcher
                .wait_for_change(Duration::from_secs(1))
                .expect("observe write"),
            SystemProxyWatchOutcome::Changed
        );
    }
}

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[cfg(windows)]
use std::sync::atomic::Ordering;
#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT,
};

#[cfg(windows)]
static WINDOWS_FOREGROUND_SHUTDOWN_SIGNAL: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

pub(crate) struct ForegroundShutdownGuard;

#[cfg(windows)]
impl ForegroundShutdownGuard {
    pub(crate) fn install(shutdown_signal: Arc<AtomicBool>) -> Result<Self, String> {
        {
            let mut signal = WINDOWS_FOREGROUND_SHUTDOWN_SIGNAL.lock().map_err(|_| {
                "failed to acquire Windows foreground shutdown signal lock".to_string()
            })?;
            *signal = Some(shutdown_signal);
        }

        let installed =
            unsafe { SetConsoleCtrlHandler(Some(windows_foreground_console_shutdown_handler), 1) };
        if installed == 0 {
            if let Ok(mut signal) = WINDOWS_FOREGROUND_SHUTDOWN_SIGNAL.lock() {
                *signal = None;
            }
            return Err(format!(
                "failed to install Windows console control handler: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(Self)
    }
}

#[cfg(windows)]
impl Drop for ForegroundShutdownGuard {
    fn drop(&mut self) {
        unsafe {
            SetConsoleCtrlHandler(Some(windows_foreground_console_shutdown_handler), 0);
        }
        if let Ok(mut signal) = WINDOWS_FOREGROUND_SHUTDOWN_SIGNAL.lock() {
            *signal = None;
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn windows_foreground_console_shutdown_handler(event: u32) -> i32 {
    match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT
        | CTRL_SHUTDOWN_EVENT => {
            if let Ok(signal) = WINDOWS_FOREGROUND_SHUTDOWN_SIGNAL.lock() {
                if let Some(signal) = signal.as_ref() {
                    signal.store(true, Ordering::SeqCst);
                }
            }
            1
        }
        _ => 0,
    }
}

#[cfg(not(windows))]
impl ForegroundShutdownGuard {
    pub(crate) fn install(_shutdown_signal: Arc<AtomicBool>) -> Result<Self, String> {
        Ok(Self)
    }
}

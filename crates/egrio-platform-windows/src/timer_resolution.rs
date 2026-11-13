//! A 1 ms timer resolution for the process that runs the Core.
//!
//! Since Windows 10 version 2004 a process gets timers finer than the default
//! system tick (about 15.6 ms) only if it requests them itself, even while
//! another process keeps the hardware tick fast
//! ([timeBeginPeriod](https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timebeginperiod)).
//! The Core's QUIC pacing wakes on timers when acknowledgements are sparse,
//! so at the default tick a fast or bursty upload falls behind its rate and
//! BBR ramps up more slowly. Windows 11 may ignore the request while the
//! process's windows are hidden, the desktop's usual state in the tray, so
//! holding also opts the process out of that throttling
//! ([SetProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessinformation)).

use windows_sys::Win32::Media::{timeBeginPeriod, timeEndPeriod, TIMERR_NOERROR};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, ProcessPowerThrottling, SetProcessInformation,
    PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
    PROCESS_POWER_THROTTLING_STATE,
};

const RESOLUTION_MS: u32 = 1;

/// The process's 1 ms timer resolution, held until dropped. Windows also
/// drops the request when the process exits.
#[derive(Debug)]
pub struct FineTimerResolution(());

impl FineTimerResolution {
    /// Requests 1 ms for this process and keeps Windows from ignoring the
    /// request while the process's windows are hidden.
    pub fn hold() -> Result<Self, String> {
        set_ignore_timer_resolution_control(PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION);
        let result = unsafe { timeBeginPeriod(RESOLUTION_MS) };
        if result != TIMERR_NOERROR {
            set_ignore_timer_resolution_control(0);
            return Err(format!(
                "timeBeginPeriod({RESOLUTION_MS}) failed with {result}"
            ));
        }
        Ok(Self(()))
    }
}

impl Drop for FineTimerResolution {
    fn drop(&mut self) {
        unsafe { timeEndPeriod(RESOLUTION_MS) };
        set_ignore_timer_resolution_control(0);
    }
}

/// With `control` set to the ignore-timer-resolution flag and the state left
/// clear, the process opts out of Windows ignoring its timer resolution
/// request; with no control, power throttling goes back to the system. A
/// failure leaves the system's default in place.
fn set_ignore_timer_resolution_control(control: u32) {
    let state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: control,
        StateMask: 0,
    };
    unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            (&raw const state).cast(),
            std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        )
    };
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn holding_makes_this_process_sleep_close_to_a_millisecond() {
        let timer = FineTimerResolution::hold().expect("1 ms timer resolution");
        let mut sleeps: Vec<_> = (0..21)
            .map(|_| {
                let start = Instant::now();
                std::thread::sleep(Duration::from_millis(1));
                start.elapsed()
            })
            .collect();
        sleeps.sort();
        // At the default tick a 1 ms sleep lasts about 15.6 ms.
        assert!(
            sleeps[10] < Duration::from_millis(8),
            "median {:?}",
            sleeps[10]
        );
        drop(timer);
    }
}

//! The native Egrio desktop app. The interface is described once in
//! `egrio-ui`; each platform module here realizes it with the platform's own
//! toolkit and runs the event loop. A Windows release build is a GUI
//! subsystem program, so starting it opens no console window; a debug build
//! keeps the console for its log.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

fn main() {
    // The service registration command answers in JSON on standard output,
    // which carries log lines once the logger is installed.
    #[cfg(target_os = "macos")]
    if egrio_desktop::service_control::run_from_environment() {
        return;
    }
    egrio_desktop::logging::install();
    // The Runtime Core owns listener and packet sessions with real socket
    // counts; the platform's default soft fd limit can starve them under load.
    egrio_daemon::raise_fd_soft_limit();
    egrio_daemon::start_memory_reclaim();

    #[cfg(target_os = "linux")]
    linux::run();
    #[cfg(target_os = "macos")]
    macos::run();
    #[cfg(windows)]
    windows::run();
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        eprintln!("the native desktop app runs on Linux, macOS and Windows");
        std::process::exit(1);
    }
}

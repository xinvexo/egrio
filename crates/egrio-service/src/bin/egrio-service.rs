#[cfg(windows)]
fn main() {
    let exit_code = match egrio_service::windows::host::run_from_env() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };
    std::process::exit(exit_code);
}

#[cfg(target_os = "linux")]
fn main() {
    let exit_code = match egrio_service::linux::host::run_from_env() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };
    std::process::exit(exit_code);
}

#[cfg(target_os = "macos")]
fn main() {
    let exit_code = match egrio_service::macos::host::run_from_env() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };
    std::process::exit(exit_code);
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    let version = egrio_service::protocol_version();
    println!(
        "egrio-service protocol {}.{} (no service host on this OS)",
        version.major, version.minor
    );
}

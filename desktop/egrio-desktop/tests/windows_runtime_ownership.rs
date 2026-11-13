use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_SYMBOLS: &[&str] = &[
    "egrio_daemon::service_ipc",
    "ApplyDesiredState",
    "apply_windows_named_pipe_desired_state",
    "reload_windows_named_pipe_runtime_profile",
    "NativeCaptureSessionSupervisor",
];

#[test]
fn windows_desktop_uses_runtime_owned_capture() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut rust_sources = Vec::new();
    collect_rust_sources(&manifest_dir.join("src"), &mut rust_sources);

    for path in rust_sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for forbidden in FORBIDDEN_SYMBOLS {
            assert!(
                !source.contains(forbidden),
                "{} still imports obsolete Windows capture ownership symbol {forbidden}",
                path.display()
            );
        }
    }

    let cargo_toml = fs::read_to_string(manifest_dir.join("Cargo.toml"))
        .expect("desktop/egrio-desktop/Cargo.toml should be readable");
    assert!(
        cargo_toml.contains("egrio-sdk = { workspace = true, features = [\"platform-windows\"] }"),
        "the Windows desktop target must assemble capture through egrio-sdk/platform-windows"
    );
}

fn collect_rust_sources(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
    {
        let path = entry
            .expect("source directory entry should be readable")
            .path();
        if path.is_dir() {
            collect_rust_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
}

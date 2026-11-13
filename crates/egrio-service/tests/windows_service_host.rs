#![cfg(windows)]

use egrio_service::windows::host::{parse_service_command, ServiceCommand};

#[test]
fn installed_service_command_shapes_remain_supported() {
    assert_eq!(
        parse_service_command(["run-windows-service", "EgrioService"]),
        Ok(ServiceCommand::Run {
            service_name: "EgrioService".into(),
        })
    );
    assert_eq!(
        parse_service_command(["bootstrap-windows-service"]),
        Ok(ServiceCommand::Bootstrap)
    );
    assert_eq!(
        parse_service_command(["uninstall-windows-service"]),
        Ok(ServiceCommand::Uninstall)
    );
    assert!(parse_service_command(["uninstall-windows-service", "EgrioService"]).is_err());
}

#[test]
fn packaged_binary_delegates_to_the_service_host() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let binary = std::fs::read_to_string(manifest_dir.join("src/bin/egrio-service.rs"))
        .expect("service binary source should be readable");
    assert!(binary.contains("egrio_service::windows::host::run_from_env"));
    assert!(binary.contains("#[cfg(windows)]"));

    let service_sources = std::fs::read_to_string(manifest_dir.join("src/windows/host.rs"))
        .expect("Windows service host source should be readable");
    for forbidden in ["egrio_daemon", "NativeCoreDevice", "RuntimeProfile"] {
        assert!(
            !service_sources.contains(forbidden),
            "service host must not import {forbidden}"
        );
    }
}

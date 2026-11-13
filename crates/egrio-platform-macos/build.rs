// Compiles the C halves of process attribution (libproc and the user-space
// connection scan) and of the Network.framework path monitor into every
// macOS binary that depends on this crate.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    println!("cargo:rerun-if-changed=native/flow_attribution.h");
    println!("cargo:rerun-if-changed=native/flow_shared.c");
    println!("cargo:rerun-if-changed=native/socket_scan.c");
    println!("cargo:rerun-if-changed=native/userland_flow_scan.c");
    cc::Build::new()
        .file("native/flow_shared.c")
        .file("native/socket_scan.c")
        .file("native/userland_flow_scan.c")
        .flag("-std=c11")
        .warnings(true)
        .extra_warnings(true)
        .compile("egrio_macos_flow_attribution");
    println!("cargo:rerun-if-changed=native/path_monitor.c");
    cc::Build::new()
        .file("native/path_monitor.c")
        .flag("-std=c11")
        .flag("-fblocks")
        .warnings(true)
        .extra_warnings(true)
        .compile("egrio_macos_path_monitor");
    println!("cargo:rustc-link-lib=framework=Network");
}

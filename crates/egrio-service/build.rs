//! The Windows service's statically linked imports resolve from System32
//! only (`/DEPENDENTLOADFLAG:0x800`, `LOAD_LIBRARY_SEARCH_SYSTEM32`): it runs
//! as LocalSystem from wherever Egrio is installed, and a DLL planted in that
//! folder must never load into it. Its later loads by name go to System32
//! too (`SetDefaultDllDirectories` in `windows/host.rs`).

fn main() {
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows && msvc {
        println!("cargo::rustc-link-arg-bin=egrio-service=/DEPENDENTLOADFLAG:0x800");
    }
}

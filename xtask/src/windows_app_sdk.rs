//! The Windows App SDK the Windows app builds against: its pinned NuGet
//! packages, checked by SHA-256 and unpacked under
//! `target/windows-app-sdk/<version>`, which give the WinUI metadata the
//! checked-in bindings are generated from and the bootstrapper DLL the app
//! loads beside its executable. The Windows App Runtime itself is installed
//! on the machine, not shipped with the app (docs/platforms/windows.md).

use std::path::{Path, PathBuf};

use super::{pinned, root};

/// The Windows App SDK release; the app asks the bootstrapper for a runtime
/// of this major version at least this new (`windows/bootstrap.rs`), and the
/// installer installs this release's runtime when none is.
pub const VERSION: &str = "2.6.5";

/// The packages used and the SHA-256 of each `.nupkg` as nuget.org serves it.
const PACKAGES: [(&str, &str); 3] = [
    (
        "microsoft.windowsappsdk.foundation",
        "548033e51be965804f7119e1936fe7f78f324d668becb731fcacb101f3bb18e4",
    ),
    (
        "microsoft.windowsappsdk.winui",
        "8cd902f8abaf4ac0f75bdd187fd420eb98419818f39ab5e853ed126bc26a6af9",
    ),
    (
        "microsoft.windowsappsdk.interactiveexperiences",
        "3782df5d796dfe872175da0db2b64b616611532fd14b06d9e2102895286df136",
    ),
];

/// The interactive experiences package's metadata for the newest Windows it
/// targets; the older set describes the same types for Windows 10 1809.
const INTERACTIVE_METADATA: &str = "metadata/10.0.18362.0";

const BOOTSTRAP_DLL: &str = "Microsoft.WindowsAppRuntime.Bootstrap.dll";

/// Unpacks the packages and returns where they are, regenerating
/// `desktop/egrio/src/windows/bindings.rs` from the filter `bindings.txt`
/// beside it when `bindings` asks.
pub fn prepare(bindings: bool) -> Result<PathBuf, String> {
    let sdk = root().join("target").join("windows-app-sdk").join(VERSION);
    for (package, sha256) in PACKAGES {
        pinned::unpack(
            &format!(
                "https://api.nuget.org/v3-flatcontainer/{package}/{VERSION}/{package}.{VERSION}.nupkg"
            ),
            sha256,
            &sdk.join(package),
        )?;
    }
    if bindings {
        generate_bindings(&sdk);
    }
    Ok(sdk)
}

/// The bootstrapper for a Windows architecture (`win-x64` and the like).
pub fn bootstrapper(sdk: &Path, architecture: &str) -> (PathBuf, &'static str) {
    (
        sdk.join("microsoft.windowsappsdk.foundation/runtimes")
            .join(architecture)
            .join("native")
            .join(BOOTSTRAP_DLL),
        BOOTSTRAP_DLL,
    )
}

fn generate_bindings(sdk: &Path) {
    let windows = root().join("desktop/egrio/src/windows");
    eprintln!(
        "xtask: generating {}",
        windows.join("bindings.rs").display()
    );
    windows_bindgen::builder()
        .input(sdk.join("microsoft.windowsappsdk.foundation/metadata"))
        .input(sdk.join("microsoft.windowsappsdk.winui/metadata"))
        .input(
            sdk.join("microsoft.windowsappsdk.interactiveexperiences")
                .join(INTERACTIVE_METADATA),
        )
        .input_default()
        .output(windows.join("bindings.rs"))
        // The app's own WinUI application and the list virtualization
        // implement these.
        .implements([
            "Microsoft.UI.Xaml.IApplicationOverrides",
            "Microsoft.UI.Xaml.Markup.IXamlMetadataProvider",
        ])
        .compose("Microsoft.UI.Xaml.Application")
        .minimal()
        .flat()
        .filter_file(windows.join("bindings.txt"))
        .write();
}

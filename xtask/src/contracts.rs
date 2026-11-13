//! The macOS contracts every host checks: the launchd service the app
//! bundle carries matches the constants the Rust side reaches it by, the
//! app's Info.plist names the app the service trusts, and the package
//! carries the service where SMAppService looks for it, with no
//! entitlements that would need a provisioning profile.

use std::path::Path;

use regex::Regex;

const BUNDLE_FILES: &str = "desktop/egrio/macos";

pub fn run(root: &Path) -> Result<(), String> {
    let failures = check(root)?;
    if failures.is_empty() {
        eprintln!("macOS contracts: the bundled launchd service matches the Rust layout");
        Ok(())
    } else {
        Err(failures
            .iter()
            .map(|failure| format!("macOS contract gate: {failure}"))
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

fn read(root: &Path, relative: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(relative)).map_err(|error| format!("{relative}: {error}"))
}

/// A `<key>` followed by its `<string>` in a property list.
fn plist_string(plist: &str, key: &str) -> Option<String> {
    Regex::new(&format!(r"<key>{key}</key>\s*<string>([^<]*)</string>"))
        .ok()?
        .captures(plist)
        .map(|captures| captures[1].to_string())
}

/// The strings of a `<key>`'s `<array>` in a property list.
fn plist_array(plist: &str, key: &str) -> Vec<String> {
    let Some(array) = Regex::new(&format!(r"<key>{key}</key>\s*<array>([\s\S]*?)</array>"))
        .ok()
        .and_then(|pattern| pattern.captures(plist))
    else {
        return Vec::new();
    };
    Regex::new(r"<string>([^<]*)</string>")
        .expect("a valid pattern")
        .captures_iter(&array[1])
        .map(|captures| captures[1].to_string())
        .collect()
}

pub fn check(root: &Path) -> Result<Vec<String>, String> {
    let mut failures = Vec::new();
    let mut require = |condition: bool, message: &str| {
        if !condition {
            failures.push(message.to_string());
        }
    };
    let layout = read(root, "crates/egrio-platform-macos/src/service_layout.rs")?;
    let constant = |name: &str| {
        Regex::new(&format!(r#"pub const {name}: &str = "([^"]+)";"#))
            .ok()
            .and_then(|pattern| pattern.captures(&layout))
            .map(|captures| captures[1].to_string())
    };
    let (Some(label), Some(plist_name), Some(program), Some(run_command), Some(app)) = (
        constant("MACOS_SERVICE_LABEL"),
        constant("MACOS_SERVICE_PLIST"),
        constant("MACOS_SERVICE_BUNDLE_PROGRAM"),
        constant("MACOS_SERVICE_RUN_COMMAND"),
        constant("MACOS_APP_IDENTIFIER"),
    ) else {
        return Ok(vec![
            "service_layout.rs must define the service label, property list, program, run command and app identifier".into(),
        ]);
    };

    let plist = read(root, &format!("{BUNDLE_FILES}/{plist_name}"))?;
    require(
        plist_name == format!("{label}.plist"),
        "the property list is named after its launchd label",
    );
    require(
        plist_string(&plist, "Label").as_deref() == Some(label.as_str()),
        "the property list's Label must be MACOS_SERVICE_LABEL",
    );
    require(
        plist_string(&plist, "BundleProgram").as_deref() == Some(program.as_str()),
        "the property list must run the bundled service",
    );
    require(
        plist_array(&plist, "ProgramArguments") == [program.clone(), run_command],
        "the property list must start the service with its run command",
    );
    require(
        plist_array(&plist, "AssociatedBundleIdentifiers").contains(&app),
        "Login Items must attribute the service to the app",
    );
    for key in ["RunAtLoad", "KeepAlive"] {
        let kept = Regex::new(&format!(r"<key>{key}</key>\s*<true/>"))
            .expect("a valid pattern")
            .is_match(&plist);
        require(
            kept,
            &format!("launchd must keep the service running ({key})"),
        );
    }

    let info = read(root, &format!("{BUNDLE_FILES}/Info.plist"))?;
    require(
        plist_string(&info, "CFBundleIdentifier").as_deref() == Some(app.as_str()),
        "the app's identifier must be MACOS_APP_IDENTIFIER, which the service requires of its peers",
    );
    let minimum = plist_string(&info, "LSMinimumSystemVersion")
        .and_then(|version| {
            version
                .split('.')
                .next()
                .and_then(|major| major.parse::<u32>().ok())
        })
        .unwrap_or(0);
    require(minimum >= 13, "SMAppService needs macOS 13 or later");

    let packaging = read(root, "xtask/src/macos.rs")?;
    require(
        packaging.contains(r#""Contents/Library/LaunchDaemons""#)
            && packaging.contains(r#""Contents/MacOS/egrio-service""#),
        "the package must carry the service and its property list where SMAppService looks for them",
    );
    require(
        !packaging.contains("--entitlements"),
        "the app needs no entitlements, so no provisioning profile",
    );
    require(
        read(root, "desktop/egrio-desktop/src/runtime/macos.rs")?.contains(".macos_service("),
        "the desktop must run TUN through the macOS service",
    );
    Ok(failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_repository_meets_its_macos_contracts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        assert_eq!(check(root).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn property_list_values_are_read_by_key() {
        let plist = "<key>Label</key>\n\t<string>a.b</string>\n<key>ProgramArguments</key>\n<array>\n<string>x</string>\n<string>y</string>\n</array>";
        assert_eq!(plist_string(plist, "Label").as_deref(), Some("a.b"));
        assert_eq!(plist_array(plist, "ProgramArguments"), ["x", "y"]);
        assert!(plist_array(plist, "Missing").is_empty());
    }
}

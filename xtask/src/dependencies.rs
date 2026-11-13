//! The workspace dependency gate: every workspace package depends only on
//! the workspace packages `scripts/workspace-dependency-policy.json` allows
//! it, and the policy names exactly the workspace's packages. Two assemblies
//! are checked by what Cargo resolves for them: the server-only daemon links
//! none of the excluded packages, and the SDK takes its platform crates only
//! behind its `platform-*` features, each an optional dependency.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::process::Command;

use serde_json::Value;

use super::finished;

pub fn run(root: &Path) -> Result<(), String> {
    let policy_path = root.join("scripts/workspace-dependency-policy.json");
    let policy: Value = serde_json::from_str(
        &std::fs::read_to_string(&policy_path)
            .map_err(|error| format!("{}: {error}", policy_path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", policy_path.display()))?;
    let metadata: Value = serde_json::from_slice(
        &finished(cargo(root).args(["metadata", "--format-version", "1", "--all-features"]))?
            .stdout,
    )
    .map_err(|error| format!("cargo metadata: {error}"))?;
    let sdk = &policy["sdkAssembly"];
    let daemon = &policy["daemonServerAssembly"];
    let sdk_package = sdk["package"].as_str().unwrap_or_default();
    let platform_features: Vec<&str> = sdk["platformFeatures"]
        .as_object()
        .map(|features| features.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let daemon_features: Vec<&str> = daemon["features"]
        .as_array()
        .map(|features| features.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let resolves = Resolves {
        sdk_default: Some(resolved(root, sdk_package, &[])?),
        sdk_platform: Some(resolved(
            root,
            sdk_package,
            &["--features", &platform_features.join(",")],
        )?),
        daemon_server: Some(resolved(
            root,
            daemon["package"].as_str().unwrap_or_default(),
            &[
                "--no-default-features",
                "--features",
                &daemon_features.join(","),
            ],
        )?),
    };
    let report = check(&metadata, &policy, &resolves);
    if report.errors.is_empty() {
        eprintln!(
            "workspace dependency gate: ok ({} packages, {} internal edges)",
            report.packages, report.edges
        );
        Ok(())
    } else {
        Err(report.errors.join("\n"))
    }
}

fn cargo(root: &Path) -> Command {
    let mut command = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command.current_dir(root);
    command
}

/// Every package `package` links with `features`, on any target.
fn resolved(root: &Path, package: &str, features: &[&str]) -> Result<HashSet<String>, String> {
    let tree = finished(
        cargo(root)
            .args(["tree", "--locked", "-p", package])
            .args(features)
            .args([
                "--target",
                "all",
                "--edges",
                "normal,build",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ]),
    )?;
    Ok(String::from_utf8_lossy(&tree.stdout)
        .lines()
        .filter_map(|line| line.split(' ').next())
        .filter(|name| !name.is_empty())
        .map(String::from)
        .collect())
}

/// What Cargo resolves for the checked assemblies, by package name.
#[derive(Default)]
pub struct Resolves {
    pub sdk_default: Option<HashSet<String>>,
    pub sdk_platform: Option<HashSet<String>>,
    pub daemon_server: Option<HashSet<String>>,
}

pub struct Report {
    pub errors: Vec<String>,
    pub packages: usize,
    pub edges: usize,
}

fn names(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn json(names: &[String]) -> String {
    serde_json::to_string(names).unwrap_or_default()
}

/// Checks the workspace graph in `cargo metadata` against the policy.
pub fn check(metadata: &Value, policy: &Value, resolves: &Resolves) -> Report {
    let empty = Vec::new();
    let packages = metadata["packages"].as_array().unwrap_or(&empty);
    let by_id: HashMap<&str, &Value> = packages
        .iter()
        .filter_map(|package| Some((package["id"].as_str()?, package)))
        .collect();
    let nodes: HashMap<&str, &Value> = metadata["resolve"]["nodes"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|node| Some((node["id"].as_str()?, node)))
        .collect();
    let members: Vec<&str> = metadata["workspace_members"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let member_ids: HashSet<&str> = members.iter().copied().collect();
    let workspace: Vec<&Value> = members
        .iter()
        .filter_map(|id| by_id.get(id).copied())
        .collect();
    let workspace_names: HashSet<&str> = workspace
        .iter()
        .filter_map(|package| package["name"].as_str())
        .collect();
    let allowed_by_package = policy["workspaceDependencies"].as_object();
    let mut errors = Vec::new();
    let mut edges = 0;

    for package in &workspace {
        let name = package["name"].as_str().unwrap_or_default();
        let Some(allowed) = allowed_by_package.and_then(|allowed| allowed.get(name)) else {
            errors.push(format!(
                "workspace dependency gate: workspace package {name} is missing from policy"
            ));
            continue;
        };
        let allowed: HashSet<String> = names(allowed).into_iter().collect();
        let id = package["id"].as_str().unwrap_or_default();
        let internal: BTreeSet<&str> = nodes
            .get(id)
            .and_then(|node| node["deps"].as_array())
            .unwrap_or(&empty)
            .iter()
            .filter_map(|dependency| dependency["pkg"].as_str())
            .filter(|dependency| member_ids.contains(dependency))
            .filter_map(|dependency| by_id.get(dependency)?["name"].as_str())
            .collect();
        edges += internal.len();
        for dependency in internal {
            if !allowed.contains(dependency) {
                errors.push(format!(
                    "workspace dependency gate: {name} -> {dependency} is not allowed"
                ));
            }
        }
    }
    if let Some(allowed) = allowed_by_package {
        for name in allowed.keys() {
            if !workspace_names.contains(name.as_str()) {
                errors.push(format!(
                    "workspace dependency gate: policy package {name} is not in the workspace"
                ));
            }
        }
    }
    check_daemon_server(&policy["daemonServerAssembly"], resolves, &mut errors);
    check_sdk(&workspace, &policy["sdkAssembly"], resolves, &mut errors);
    errors.sort();
    Report {
        errors,
        packages: workspace.len(),
        edges,
    }
}

fn check_daemon_server(policy: &Value, resolves: &Resolves, errors: &mut Vec<String>) {
    let (Some(package), Some(resolved)) = (policy["package"].as_str(), &resolves.daemon_server)
    else {
        return;
    };
    for excluded in names(&policy["excludedPackages"]) {
        if resolved.contains(&excluded) {
            errors.push(format!(
                "workspace dependency gate: {package} server resolve includes {excluded}"
            ));
        }
    }
}

fn check_sdk(workspace: &[&Value], policy: &Value, resolves: &Resolves, errors: &mut Vec<String>) {
    let Some(package) = policy["package"].as_str() else {
        return;
    };
    let Some(sdk) = workspace
        .iter()
        .find(|entry| entry["name"].as_str() == Some(package))
    else {
        errors.push(format!(
            "workspace dependency gate: SDK package {package} is not in the workspace"
        ));
        return;
    };
    let empty = Vec::new();
    let dependencies = sdk["dependencies"].as_array().unwrap_or(&empty);
    let features = &sdk["features"];

    let expected_default = names(&policy["defaultFeatures"]);
    let actual_default = names(&features["default"]);
    if actual_default != expected_default {
        errors.push(format!(
            "workspace dependency gate: {package} feature default must equal {} but found {}",
            json(&expected_default),
            json(&actual_default)
        ));
    }

    let platform_features = policy["platformFeatures"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let expected_platforms: Vec<String> = platform_features
        .values()
        .filter_map(Value::as_str)
        .map(String::from)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let actual_platforms: Vec<String> = dependencies
        .iter()
        .filter_map(|dependency| dependency["name"].as_str())
        .filter(|name| name.starts_with("egrio-platform-"))
        .map(String::from)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if actual_platforms != expected_platforms {
        errors.push(format!(
            "workspace dependency gate: {package} platform dependencies must equal {} but found {}",
            json(&expected_platforms),
            json(&actual_platforms)
        ));
    }

    for (feature, dependency) in &platform_features {
        let mut wanted = vec![dependency.as_str().unwrap_or_default().to_string()];
        wanted.extend(names(&policy["featureExtras"][feature]));
        for name in &wanted {
            let matching: Vec<&Value> = dependencies
                .iter()
                .filter(|entry| entry["name"].as_str() == Some(name))
                .collect();
            if matching.is_empty() {
                errors.push(format!(
                    "workspace dependency gate: {package} dependency {name} is missing"
                ));
            } else if matching
                .iter()
                .any(|entry| !entry["optional"].as_bool().unwrap_or(false))
            {
                errors.push(format!(
                    "workspace dependency gate: {package} dependency {name} must be optional"
                ));
            }
        }
        let expected: Vec<String> = wanted.iter().map(|name| format!("dep:{name}")).collect();
        let actual = names(&features[feature]);
        if actual != expected {
            errors.push(format!(
                "workspace dependency gate: {package} feature {feature} must equal {} but found {}",
                json(&expected),
                json(&actual)
            ));
        }
    }

    let platform_packages: HashSet<String> = platform_features
        .values()
        .filter_map(Value::as_str)
        .map(String::from)
        .chain(
            policy["featureExtras"]
                .as_object()
                .into_iter()
                .flat_map(|extras| extras.values().flat_map(names)),
        )
        .collect();
    if let Some(resolved) = &resolves.sdk_default {
        let mut leaked: Vec<&String> = resolved.intersection(&platform_packages).collect();
        leaked.sort();
        for name in leaked {
            errors.push(format!(
                "workspace dependency gate: {package} default resolve includes {name}"
            ));
        }
    }
    // Packages the SDK never links, even with every platform feature on.
    if let Some(resolved) = &resolves.sdk_platform {
        for excluded in names(&policy["excludedPackages"]) {
            if resolved.contains(&excluded) {
                errors.push(format!(
                    "workspace dependency gate: {package} platform resolve includes {excluded}"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PLATFORMS: [(&str, &str); 3] = [
        ("platform-linux", "egrio-platform-linux"),
        ("platform-macos", "egrio-platform-macos"),
        ("platform-windows", "egrio-platform-windows"),
    ];

    fn policy() -> Value {
        let platforms: Vec<&str> = PLATFORMS.iter().map(|(_, name)| *name).collect();
        let mut sdk = vec!["egrio-core", "egrio-runtime", "egrio-service"];
        sdk.extend(&platforms);
        let mut excluded = vec!["egrio-runtime"];
        excluded.extend(&platforms);
        json!({
            "workspaceDependencies": {
                "egrio-core": [],
                "egrio-runtime": ["egrio-core"],
                "egrio-service": ["egrio-platform-windows", "egrio-runtime"],
                "egrio-platform-linux": ["egrio-core", "egrio-runtime"],
                "egrio-platform-macos": ["egrio-core", "egrio-runtime"],
                "egrio-platform-windows": ["egrio-core", "egrio-runtime"],
                "egrio-sdk": sdk,
                "egrio": ["egrio-sdk"],
            },
            "daemonServerAssembly": {
                "package": "egrio-daemon",
                "features": ["server"],
                "excludedPackages": excluded,
            },
            "sdkAssembly": {
                "package": "egrio-sdk",
                "defaultFeatures": [],
                "excludedPackages": ["excluded-crate"],
                "platformFeatures": PLATFORMS.iter().map(|(feature, name)| (feature.to_string(), json!(name))).collect::<serde_json::Map<_, _>>(),
                "featureExtras": { "platform-windows": ["egrio-service"] },
            },
        })
    }

    #[derive(Clone)]
    struct Dependency {
        name: &'static str,
        optional: bool,
        rename: Option<&'static str>,
    }

    fn on(name: &'static str) -> Dependency {
        Dependency {
            name,
            optional: false,
            rename: None,
        }
    }

    fn optional(name: &'static str) -> Dependency {
        Dependency {
            optional: true,
            ..on(name)
        }
    }

    fn sdk_features() -> Value {
        let mut features = serde_json::Map::new();
        features.insert("default".into(), json!([]));
        for (feature, name) in PLATFORMS {
            let mut deps = vec![format!("dep:{name}")];
            if feature == "platform-windows" {
                deps.push("dep:egrio-service".into());
            }
            features.insert(feature.into(), json!(deps));
        }
        Value::Object(features)
    }

    fn graph() -> Vec<(&'static str, Vec<Dependency>)> {
        let mut graph = vec![
            ("egrio-core", vec![]),
            ("egrio-runtime", vec![on("egrio-core")]),
            (
                "egrio-service",
                vec![on("egrio-runtime"), on("egrio-platform-windows")],
            ),
        ];
        for (_, name) in PLATFORMS {
            graph.push((name, vec![on("egrio-core"), on("egrio-runtime")]));
        }
        let mut sdk = vec![on("egrio-core"), on("egrio-runtime")];
        sdk.extend(PLATFORMS.iter().map(|(_, name)| optional(name)));
        sdk.push(optional("egrio-service"));
        graph.push(("egrio-sdk", sdk));
        graph.push(("egrio", vec![on("egrio-sdk")]));
        graph
    }

    fn metadata(graph: &[(&'static str, Vec<Dependency>)], features: &Value) -> Value {
        let id = |name: &str| format!("{name} 0.1.0 (path+file:///repo/{name})");
        let packages: Vec<Value> = graph
            .iter()
            .map(|(name, dependencies)| {
                json!({
                    "id": id(name),
                    "name": name,
                    "dependencies": dependencies.iter().map(|dependency| json!({
                        "name": dependency.name,
                        "optional": dependency.optional,
                        "rename": dependency.rename,
                    })).collect::<Vec<_>>(),
                    "features": if *name == "egrio-sdk" { features.clone() } else { json!({}) },
                })
            })
            .collect();
        let nodes: Vec<Value> = graph
            .iter()
            .map(|(name, dependencies)| {
                json!({
                    "id": id(name),
                    "deps": dependencies.iter().map(|dependency| json!({
                        "name": dependency.rename.unwrap_or(dependency.name),
                        "pkg": id(dependency.name),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        json!({
            "packages": packages,
            "workspace_members": graph.iter().map(|(name, _)| id(name)).collect::<Vec<_>>(),
            "resolve": { "nodes": nodes },
        })
    }

    fn sdk_default() -> HashSet<String> {
        ["egrio-core", "egrio-runtime", "egrio-sdk"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn errors_for(graph: &[(&'static str, Vec<Dependency>)], resolves: Resolves) -> Vec<String> {
        check(&metadata(graph, &sdk_features()), &policy(), &resolves).errors
    }

    fn defaults() -> Resolves {
        Resolves {
            sdk_default: Some(sdk_default()),
            ..Resolves::default()
        }
    }

    fn set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn accepts_an_explicitly_allowed_graph() {
        assert_eq!(errors_for(&graph(), defaults()), Vec::<String>::new());
    }

    #[test]
    fn the_server_only_daemon_links_no_runtime_or_platform_adapter() {
        let server = set(&["egrio-core", "egrio-platform", "egrio-daemon"]);
        let resolves = Resolves {
            daemon_server: Some(server.clone()),
            ..defaults()
        };
        assert_eq!(errors_for(&graph(), resolves), Vec::<String>::new());
        let mut leaked = server;
        leaked.insert("egrio-runtime".into());
        let resolves = Resolves {
            daemon_server: Some(leaked),
            ..defaults()
        };
        assert_eq!(
            errors_for(&graph(), resolves),
            ["workspace dependency gate: egrio-daemon server resolve includes egrio-runtime"]
        );
    }

    #[test]
    fn rejects_a_dependency_the_policy_does_not_list() {
        let mut graph = graph();
        graph[2].1.push(on("egrio-core"));
        assert_eq!(
            errors_for(&graph, defaults()),
            ["workspace dependency gate: egrio-service -> egrio-core is not allowed"]
        );
    }

    #[test]
    fn rejects_reverse_and_renamed_dependencies() {
        let mut graph = graph();
        graph[0].1 = vec![Dependency {
            rename: Some("runtime-alias"),
            ..on("egrio-runtime")
        }];
        assert_eq!(
            errors_for(&graph, defaults()),
            ["workspace dependency gate: egrio-core -> egrio-runtime is not allowed"]
        );
        let mut graph = self::graph();
        graph[1].1 = vec![on("egrio-platform-windows"), optional("egrio")];
        assert_eq!(
            errors_for(&graph, defaults()),
            [
                "workspace dependency gate: egrio-runtime -> egrio is not allowed",
                "workspace dependency gate: egrio-runtime -> egrio-platform-windows is not allowed",
            ]
        );
    }

    #[test]
    fn rejects_packages_missing_from_either_side_of_the_policy() {
        let graph = vec![("egrio-core", vec![]), ("rogue", vec![])];
        let policy = json!({ "workspaceDependencies": { "egrio-core": [] } });
        assert_eq!(
            check(&metadata(&graph, &json!({})), &policy, &Resolves::default()).errors,
            ["workspace dependency gate: workspace package rogue is missing from policy"]
        );
        let graph = vec![("egrio-core", vec![])];
        let policy = json!({ "workspaceDependencies": { "egrio-core": [], "stale": [] } });
        assert_eq!(
            check(&metadata(&graph, &json!({})), &policy, &Resolves::default()).errors,
            ["workspace dependency gate: policy package stale is not in the workspace"]
        );
    }

    #[test]
    fn requires_every_sdk_platform_dependency_to_be_optional() {
        let mut graph = graph();
        let sdk = graph
            .iter_mut()
            .find(|(name, _)| *name == "egrio-sdk")
            .unwrap();
        for dependency in &mut sdk.1 {
            if dependency.name == "egrio-platform-windows" {
                dependency.optional = false;
            }
        }
        assert_eq!(
            errors_for(&graph, defaults()),
            ["workspace dependency gate: egrio-sdk dependency egrio-platform-windows must be optional"]
        );
    }

    #[test]
    fn requires_empty_sdk_defaults_and_exact_dep_features() {
        let mut features = sdk_features();
        features["default"] = json!(["platform-windows"]);
        features["platform-windows"] = json!(["egrio-runtime", "dep:egrio-platform-windows"]);
        assert_eq!(
            check(&metadata(&graph(), &features), &policy(), &defaults()).errors,
            [
                r#"workspace dependency gate: egrio-sdk feature default must equal [] but found ["platform-windows"]"#,
                r#"workspace dependency gate: egrio-sdk feature platform-windows must equal ["dep:egrio-platform-windows","dep:egrio-service"] but found ["egrio-runtime","dep:egrio-platform-windows"]"#,
            ]
        );
    }

    #[test]
    fn rejects_excluded_packages_in_the_all_platform_sdk_resolve() {
        let mut all = sdk_default();
        all.extend(PLATFORMS.iter().map(|(_, name)| name.to_string()));
        let resolves = Resolves {
            sdk_platform: Some(all.clone()),
            ..defaults()
        };
        assert_eq!(errors_for(&graph(), resolves), Vec::<String>::new());
        all.insert("excluded-crate".into());
        let resolves = Resolves {
            sdk_platform: Some(all),
            ..defaults()
        };
        assert_eq!(
            errors_for(&graph(), resolves),
            ["workspace dependency gate: egrio-sdk platform resolve includes excluded-crate"]
        );
    }

    #[test]
    fn rejects_platform_packages_in_the_default_sdk_resolve() {
        let mut leaked = sdk_default();
        leaked.insert("egrio-platform-windows".into());
        let resolves = Resolves {
            sdk_default: Some(leaked),
            ..Resolves::default()
        };
        assert_eq!(
            errors_for(&graph(), resolves),
            ["workspace dependency gate: egrio-sdk default resolve includes egrio-platform-windows"]
        );
    }
}

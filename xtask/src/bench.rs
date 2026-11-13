//! `cargo xtask bench-compare <baseline.json> <candidate.json>`: the
//! same-host gate for the Core's throughput benchmarks
//! (crates/egrio-core/bench/README.md). Every candidate scenario keeps at
//! least 90 % of its baseline, and the packet benchmark's aggregate
//! download and upload stay at or above the single-flow rows. The result
//! is printed as JSON; the exit status is 0 when it passes, 1 for a
//! regression and 2 for reports that cannot be compared.

use std::collections::BTreeMap;
use std::process::ExitCode;

use serde::Serialize;
use serde_json::Value;

pub const MINIMUM_RATIO: f64 = 0.9;
const PACKET_HARNESS: &str = "egrio-core e2e_packet_throughput";

pub fn run(args: &[String]) -> ExitCode {
    let [baseline, candidate] = args else {
        eprintln!("usage: cargo xtask bench-compare <baseline.json> <candidate.json>");
        return ExitCode::from(2);
    };
    let read = |path: &String| {
        std::fs::read_to_string(path)
            .map_err(|error| format!("{path}: {error}"))
            .and_then(|text| parse(&text, path))
    };
    let (baseline, candidate) = match (read(baseline), read(candidate)) {
        (Ok(baseline), Ok(candidate)) => (baseline, candidate),
        (Err(error), _) | (_, Err(error)) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let result = compare(&baseline, &candidate, MINIMUM_RATIO);
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
    ExitCode::from(match (result.comparable, result.passed) {
        (false, _) => 2,
        (true, false) => 1,
        (true, true) => 0,
    })
}

/// A throughput report: what produced it and its scenarios by name.
#[derive(Debug)]
pub struct Report {
    harness: String,
    os: String,
    arch: String,
    data_plane: Option<String>,
    scenarios: BTreeMap<String, Scenario>,
}

#[derive(Debug, Clone)]
struct Scenario {
    bytes: f64,
    flows: Option<f64>,
    mib_per_s: f64,
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    comparable: bool,
    passed: bool,
    minimum_ratio: f64,
    errors: Vec<String>,
    scenarios: Vec<Row>,
    regressions: Vec<Regression>,
}

#[derive(Debug, Clone, Serialize)]
struct Row {
    scenario: String,
    baseline_mib_per_s: f64,
    candidate_mib_per_s: f64,
    ratio: f64,
    minimum_ratio: f64,
}

#[derive(Debug, Serialize)]
struct Regression {
    kind: &'static str,
    #[serde(flatten)]
    row: Row,
}

fn text(value: &Value, label: &str) -> Result<String, String> {
    value
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .map(String::from)
        .ok_or_else(|| format!("{label} must be a non-empty string"))
}

fn positive(value: &Value, label: &str) -> Result<f64, String> {
    value
        .as_f64()
        .filter(|number| number.is_finite() && *number > 0.0)
        .ok_or_else(|| format!("{label} must be a positive finite number"))
}

pub fn parse(source: &str, label: &str) -> Result<Report, String> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let report: Value = serde_json::from_str(source)
        .map_err(|error| format!("{label} is not valid JSON: {error}"))?;
    if !report.is_object() {
        return Err(format!("{label} must be a JSON object"));
    }
    let data_plane = match &report["data_plane"] {
        Value::Null => None,
        value => Some(text(value, &format!("{label}.data_plane"))?),
    };
    let rows = report["scenarios"]
        .as_array()
        .filter(|rows| !rows.is_empty())
        .ok_or_else(|| format!("{label}.scenarios must be a non-empty array"))?;
    let mut scenarios = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        if !row.is_object() {
            return Err(format!("{label}.scenarios[{index}] must be an object"));
        }
        let name = text(
            &row["scenario"],
            &format!("{label}.scenarios[{index}].scenario"),
        )?;
        if scenarios.contains_key(&name) {
            return Err(format!("{label} contains duplicate scenario '{name}'"));
        }
        positive(&row["seconds"], &format!("{label}.{name}.seconds"))?;
        let scenario = Scenario {
            bytes: positive(&row["bytes"], &format!("{label}.{name}.bytes"))?,
            flows: match &row["flows"] {
                Value::Null => None,
                value => Some(positive(value, &format!("{label}.{name}.flows"))?),
            },
            mib_per_s: positive(&row["mib_per_s"], &format!("{label}.{name}.mib_per_s"))?,
        };
        scenarios.insert(name, scenario);
    }
    Ok(Report {
        harness: text(&report["harness"], &format!("{label}.harness"))?,
        os: text(&report["os"], &format!("{label}.os"))?,
        arch: text(&report["arch"], &format!("{label}.arch"))?,
        data_plane,
        scenarios,
    })
}

fn incomparable(minimum_ratio: f64, errors: Vec<String>) -> Comparison {
    Comparison {
        comparable: false,
        passed: false,
        minimum_ratio,
        errors,
        scenarios: Vec::new(),
        regressions: Vec::new(),
    }
}

fn shown<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

pub fn compare(baseline: &Report, candidate: &Report, minimum_ratio: f64) -> Comparison {
    let mut errors = Vec::new();
    for (field, before, after) in [
        ("harness", Some(&baseline.harness), Some(&candidate.harness)),
        ("os", Some(&baseline.os), Some(&candidate.os)),
        ("arch", Some(&baseline.arch), Some(&candidate.arch)),
        (
            "data_plane",
            baseline.data_plane.as_ref(),
            candidate.data_plane.as_ref(),
        ),
    ] {
        if before != after {
            errors.push(format!(
                "{field} differs: baseline={}, candidate={}",
                shown(&before),
                shown(&after)
            ));
        }
    }
    let names: Vec<&String> = baseline.scenarios.keys().collect();
    let candidate_names: Vec<&String> = candidate.scenarios.keys().collect();
    if names != candidate_names {
        errors.push(format!(
            "scenario sets differ: baseline={}, candidate={}",
            names
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(","),
            candidate_names
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if !errors.is_empty() {
        return incomparable(minimum_ratio, errors);
    }
    let mut scenarios = Vec::new();
    let mut regressions = Vec::new();
    for name in names {
        let (before, after) = (&baseline.scenarios[name], &candidate.scenarios[name]);
        if before.bytes != after.bytes {
            errors.push(format!(
                "{name}.bytes differs: baseline={}, candidate={}",
                before.bytes, after.bytes
            ));
        }
        if before.flows != after.flows {
            errors.push(format!(
                "{name}.flows differs: baseline={}, candidate={}",
                shown(&before.flows),
                shown(&after.flows)
            ));
        }
        let row = Row {
            scenario: name.clone(),
            baseline_mib_per_s: before.mib_per_s,
            candidate_mib_per_s: after.mib_per_s,
            ratio: after.mib_per_s / before.mib_per_s,
            minimum_ratio,
        };
        if row.ratio < minimum_ratio {
            regressions.push(Regression {
                kind: "throughput",
                row: row.clone(),
            });
        }
        scenarios.push(row);
    }
    if !errors.is_empty() {
        return incomparable(minimum_ratio, errors);
    }
    regressions.extend(packet_scaling(candidate));
    Comparison {
        comparable: true,
        passed: regressions.is_empty(),
        minimum_ratio,
        errors,
        scenarios,
        regressions,
    }
}

/// The packet benchmark's aggregate rows that move less than its single
/// flow does.
fn packet_scaling(candidate: &Report) -> Vec<Regression> {
    if candidate.harness != PACKET_HARNESS {
        return Vec::new();
    }
    let mut regressions = Vec::new();
    for direction in ["download", "upload"] {
        let mut rows: Vec<(&String, &Scenario)> = candidate
            .scenarios
            .iter()
            .filter(|(name, _)| name.starts_with(&format!("{direction}-")))
            .collect();
        rows.sort_by(|left, right| {
            left.1
                .flows
                .unwrap_or(0.0)
                .total_cmp(&right.1.flows.unwrap_or(0.0))
        });
        let single = rows
            .iter()
            .find(|(_, scenario)| scenario.flows == Some(1.0));
        let aggregate = rows.last();
        if let (Some((_, single)), Some((name, aggregate))) = (single, aggregate) {
            if aggregate.flows.unwrap_or(0.0) > 1.0 && aggregate.mib_per_s < single.mib_per_s {
                regressions.push(Regression {
                    kind: "packet-scaling",
                    row: Row {
                        scenario: (*name).clone(),
                        baseline_mib_per_s: single.mib_per_s,
                        candidate_mib_per_s: aggregate.mib_per_s,
                        ratio: aggregate.mib_per_s / single.mib_per_s,
                        minimum_ratio: 1.0,
                    },
                });
            }
        }
    }
    regressions
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report(scenarios: Vec<Value>, os: &str, harness: &str, data_plane: Option<&str>) -> String {
        let mut report =
            json!({ "harness": harness, "os": os, "arch": "x86_64", "scenarios": scenarios });
        if let Some(data_plane) = data_plane {
            report["data_plane"] = json!(data_plane);
        }
        report.to_string()
    }

    fn plain(scenarios: Vec<Value>) -> Report {
        parse(
            &report(scenarios, "windows", "egrio-core e2e_throughput", None),
            "report",
        )
        .unwrap()
    }

    fn scenario(name: &str, mib_per_s: f64, bytes: f64, flows: Option<f64>) -> Value {
        let mut row =
            json!({ "scenario": name, "bytes": bytes, "seconds": 1, "mib_per_s": mib_per_s });
        if let Some(flows) = flows {
            row["flows"] = json!(flows);
        }
        row
    }

    #[test]
    fn the_ninety_percent_boundary_passes_and_below_it_regresses() {
        let baseline = plain(vec![scenario("http-upload", 100.0, 1024.0, None)]);
        let at = plain(vec![scenario("http-upload", 90.0, 1024.0, None)]);
        assert!(compare(&baseline, &at, MINIMUM_RATIO).passed);
        let below = plain(vec![scenario("http-upload", 89.9, 1024.0, None)]);
        let result = compare(&baseline, &below, MINIMUM_RATIO);
        assert!(!result.passed);
        assert_eq!(result.regressions[0].kind, "throughput");
    }

    #[test]
    fn scenarios_compare_by_name_whatever_their_order() {
        let baseline = plain(vec![
            scenario("a", 100.0, 1024.0, None),
            scenario("b", 200.0, 1024.0, None),
        ]);
        let candidate = plain(vec![
            scenario("b", 200.0, 1024.0, None),
            scenario("a", 100.0, 1024.0, None),
        ]);
        assert!(compare(&baseline, &candidate, MINIMUM_RATIO).passed);
    }

    #[test]
    fn other_metadata_or_workloads_are_incomparable() {
        let baseline = plain(vec![scenario("a", 100.0, 1024.0, None)]);
        let other_os = parse(
            &report(
                vec![scenario("a", 100.0, 1024.0, None)],
                "linux",
                "egrio-core e2e_throughput",
                None,
            ),
            "report",
        )
        .unwrap();
        assert!(!compare(&baseline, &other_os, MINIMUM_RATIO).comparable);
        let other_bytes = plain(vec![scenario("a", 100.0, 2048.0, None)]);
        assert!(!compare(&baseline, &other_bytes, MINIMUM_RATIO).comparable);
    }

    #[test]
    fn duplicate_and_missing_scenarios_are_refused() {
        let duplicate = report(
            vec![
                scenario("a", 100.0, 1024.0, None),
                scenario("a", 100.0, 1024.0, None),
            ],
            "windows",
            "egrio-core e2e_throughput",
            None,
        );
        assert!(parse(&duplicate, "report")
            .unwrap_err()
            .contains("duplicate scenario"));
        let baseline = plain(vec![
            scenario("a", 100.0, 1024.0, None),
            scenario("b", 100.0, 1024.0, None),
        ]);
        let candidate = plain(vec![scenario("a", 100.0, 1024.0, None)]);
        assert!(!compare(&baseline, &candidate, MINIMUM_RATIO).comparable);
    }

    #[test]
    fn a_packet_aggregate_below_its_single_flow_regresses() {
        let rows = vec![
            scenario("download-1flow", 100.0, 1024.0, Some(1.0)),
            scenario("download-8flow", 90.0, 8192.0, Some(8.0)),
            scenario("upload-1flow", 80.0, 1024.0, Some(1.0)),
            scenario("upload-8flow", 160.0, 8192.0, Some(8.0)),
        ];
        let text = report(rows, "windows", PACKET_HARNESS, Some("netstack"));
        let (baseline, candidate) = (parse(&text, "a").unwrap(), parse(&text, "b").unwrap());
        let result = compare(&baseline, &candidate, MINIMUM_RATIO);
        assert!(!result.passed);
        assert_eq!(result.regressions[0].kind, "packet-scaling");
    }

    #[test]
    fn a_byte_order_mark_is_skipped() {
        let text = format!(
            "\u{feff}{}",
            report(
                vec![scenario("a", 100.0, 1024.0, None)],
                "windows",
                "egrio-core e2e_throughput",
                None
            )
        );
        assert_eq!(
            parse(&text, "report").unwrap().harness,
            "egrio-core e2e_throughput"
        );
    }
}

//! Targeted edits of a profile's YAML text for the changes the app's own
//! controls make: a top-level setting and the `rules` list. An edit rewrites
//! only the lines it changes, so the rest of the file keeps the comments,
//! order and formatting its author gave it. Every result is read back and
//! must differ from the original document by the intended change alone; a
//! shape a line edit cannot change safely, such as a duplicated key or a
//! rules list another key aliases, is refused with a pointer to the editor.

use serde_yaml::{Mapping, Value};

/// A change to the `rules` list, by position in it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RulesEdit<'a> {
    /// A new rule placed before the rule at `at`, or last.
    Insert {
        at: usize,
        line: &'a str,
    },
    Replace {
        index: usize,
        line: &'a str,
    },
    Delete {
        indices: &'a [usize],
    },
    /// Every rule's old position, in its new order.
    Reorder {
        order: &'a [usize],
    },
}

/// Sets the top-level `key` to the YAML text `value`, keeping a comment that
/// follows it. A missing key is added before the first top-level entry.
pub(crate) fn set_top_level_scalar(raw: &str, key: &str, value: &str) -> Result<String, String> {
    let before = document(raw)?;
    let intended: Value = serde_yaml::from_str(value).map_err(|error| error.to_string())?;
    let eol = line_break(raw);
    let mut lines: Vec<String> = raw.split_inclusive('\n').map(str::to_string).collect();
    let found: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| top_level_key(line) == Some(key))
        .map(|(index, _)| index)
        .collect();
    match found.as_slice() {
        [] => {
            let at = lines
                .iter()
                .position(|line| top_level_key(line).is_some())
                .unwrap_or(lines.len());
            lines.insert(at, format!("{key}: {value}{eol}"));
        }
        [index] => {
            let line = &lines[*index];
            let text = content(line);
            let colon = key_colon(text).expect("a top-level key has its colon");
            let (current, comment) = split_comment(&text[colon + 1..]);
            if current.is_empty() {
                return Err(format!(
                    "{key} is written as a block; change it in the editor"
                ));
            }
            let ending = &line[text.len()..];
            lines[*index] = format!("{}: {value}{comment}{ending}", &text[..colon]);
        }
        _ => {
            return Err(format!(
                "{key} appears more than once; fix it in the editor"
            ))
        }
    }
    verify(&before, join(lines, eol), key, |written| {
        written == Some(&intended)
    })
}

/// Applies `edit` to the top-level `rules` list. A block list keeps every
/// line the edit does not touch, and a comment above a rule moves and goes
/// with it; a flow list (`rules: [...]`) is rewritten as a block list.
pub(crate) fn edit_rules(raw: &str, edit: RulesEdit<'_>) -> Result<String, String> {
    let before = document(raw)?;
    let rules = rule_list(before.get("rules"))?;
    let unexpected =
        || "the rules list has an unexpected shape; change it in the editor".to_string();
    let eol = line_break(raw);
    let lines: Vec<String> = raw.split_inclusive('\n').map(str::to_string).collect();
    let found: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| top_level_key(line) == Some("rules"))
        .map(|(index, _)| index)
        .collect();
    let start = match found.as_slice() {
        [] => {
            let RulesEdit::Insert { line, .. } = edit else {
                return Err("the profile has no rules".into());
            };
            // Rules without a `rules:` line come from a merge key.
            if !rules.is_empty() {
                return Err(unexpected());
            }
            let mut lines = lines;
            lines.push(format!("rules:{eol}"));
            lines.push(format!("  - {}{eol}", yaml_scalar(line)));
            return verify(&before, join(lines, eol), "rules", |written| {
                rule_list(written).is_ok_and(|written| written == [line])
            });
        }
        [start] => *start,
        _ => return Err("rules appears more than once; fix it in the editor".into()),
    };
    // The list runs to the next top-level entry.
    let end = lines[start + 1..]
        .iter()
        .position(|line| top_level_key(line).is_some())
        .map_or(lines.len(), |offset| start + 1 + offset);
    let header = content(&lines[start]);
    let colon = key_colon(header).expect("a top-level key has its colon");
    let (value, comment) = split_comment(&header[colon + 1..]);
    let (mut header_line, indent, items, trailing) = if value.is_empty() || is_anchor(value) {
        let (indent, items, trailing) = block_items(&lines[start + 1..end])?;
        (lines[start].clone(), indent, items, trailing)
    } else if value.starts_with('[') {
        // The flow text may span lines; all of it is replaced.
        let indent = "  ".to_string();
        let items = rules
            .iter()
            .map(|rule| Item {
                leading: Vec::new(),
                lines: vec![format!("{indent}- {}{eol}", yaml_scalar(rule))],
            })
            .collect();
        let ending = &lines[start][header.len()..];
        let header_line = format!("{}:{comment}{ending}", &header[..colon]);
        (header_line, indent, items, Vec::new())
    } else {
        return Err("rules is not a plain list; change it in the editor".into());
    };
    if items.len() != rules.len() {
        return Err(unexpected());
    }

    let slots = layout(items.len(), edit)?;
    let intended: Vec<&str> = slots
        .iter()
        .map(|slot| match *slot {
            Slot::Kept(index) => rules[index].as_str(),
            Slot::Written { line, .. } => line,
        })
        .collect();
    if !header_line.ends_with('\n') {
        header_line.push_str(eol);
    }
    let mut out: Vec<String> = lines[..start].to_vec();
    out.push(header_line);
    for slot in slots {
        let item = match slot {
            Slot::Kept(index) => items[index].clone(),
            Slot::Written { line, replaces } => Item {
                leading: replaces
                    .map(|index| items[index].leading.clone())
                    .unwrap_or_default(),
                lines: vec![format!("{indent}- {}{eol}", yaml_scalar(line))],
            },
        };
        out.extend(item.leading);
        out.extend(item.lines);
    }
    out.extend(trailing);
    out.extend_from_slice(&lines[end..]);
    verify(&before, join(out, eol), "rules", |written| {
        rule_list(written).is_ok_and(|written| written == intended)
    })
}

/// What one position of the edited list holds.
#[derive(Debug, Clone, Copy)]
enum Slot<'a> {
    /// The rule at this old position.
    Kept(usize),
    /// A rule the edit writes, in place of the one at `replaces`.
    Written {
        line: &'a str,
        replaces: Option<usize>,
    },
}

/// The edited list of a list of `len` rules, position by position.
fn layout(len: usize, edit: RulesEdit<'_>) -> Result<Vec<Slot<'_>>, String> {
    let mut slots: Vec<Slot> = (0..len).map(Slot::Kept).collect();
    match edit {
        RulesEdit::Insert { at, line } => slots.insert(
            at.min(len),
            Slot::Written {
                line,
                replaces: None,
            },
        ),
        RulesEdit::Replace { index, line } => {
            *slots
                .get_mut(index)
                .ok_or("the rule to change no longer exists")? = Slot::Written {
                line,
                replaces: Some(index),
            };
        }
        RulesEdit::Delete { indices } => {
            let mut sorted = indices.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            if sorted.len() != indices.len() || sorted.last().is_some_and(|&last| last >= len) {
                return Err("the rules to delete no longer exist".into());
            }
            for index in sorted.into_iter().rev() {
                slots.remove(index);
            }
        }
        RulesEdit::Reorder { order } => {
            let mut seen = vec![false; len];
            if order.len() != len
                || !order
                    .iter()
                    .all(|&index| index < len && !std::mem::replace(&mut seen[index], true))
            {
                return Err("the new order does not list every rule once".into());
            }
            slots = order.iter().map(|&index| Slot::Kept(index)).collect();
        }
    }
    Ok(slots)
}

/// The document as the profile parser reads it: a mapping, merge keys
/// applied.
fn document(raw: &str) -> Result<Mapping, String> {
    let mut value: Value =
        serde_yaml::from_str(raw).map_err(|error| format!("invalid profile YAML: {error}"))?;
    value
        .apply_merge()
        .map_err(|error| format!("invalid profile YAML: {error}"))?;
    match value {
        Value::Mapping(mapping) => Ok(mapping),
        _ => Err("profile YAML must be a mapping".into()),
    }
}

/// Returns `edited` if it reads as `before` with only the top-level `key`
/// changed, to a value `intended` accepts.
fn verify(
    before: &Mapping,
    edited: String,
    key: &str,
    intended: impl FnOnce(Option<&Value>) -> bool,
) -> Result<String, String> {
    let refused = || format!("could not change {key} safely in this file; change it in the editor");
    let after = document(&edited).map_err(|_| refused())?;
    let others = |document: &Mapping| document.len() - usize::from(document.contains_key(key));
    let others_kept = others(before) == others(&after)
        && before
            .iter()
            .all(|(name, value)| name.as_str() == Some(key) || after.get(name) == Some(value));
    if others_kept && intended(after.get(key)) {
        Ok(edited)
    } else {
        Err(refused())
    }
}

/// A `rules` value as its lines; a key without a value is an empty list.
fn rule_list(value: Option<&Value>) -> Result<Vec<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Sequence(rules)) => rules
            .iter()
            .map(|rule| {
                rule.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "a rule is not a line of text".to_string())
            })
            .collect(),
        Some(_) => Err("rules is not a list".into()),
    }
}

/// One entry of a block list: the comment and blank lines above it, then its
/// own lines (the `- ` line and any continuation).
#[derive(Debug, Clone)]
struct Item {
    leading: Vec<String>,
    lines: Vec<String>,
}

/// Splits a block list's lines into entries, with the item indentation and
/// the comment and blank lines that follow the last entry.
fn block_items(body: &[String]) -> Result<(String, Vec<Item>, Vec<String>), String> {
    let unexpected =
        || "the rules list has an unexpected shape; change it in the editor".to_string();
    let mut indent = None;
    let mut items: Vec<Item> = Vec::new();
    let mut pending = Vec::new();
    for line in body {
        let text = content(line);
        let stripped = text.trim_start();
        if stripped.is_empty() || stripped.starts_with('#') {
            pending.push(line.clone());
            continue;
        }
        let lead = text.len() - stripped.len();
        let is_item = stripped == "-" || stripped.starts_with("- ");
        let item_indent = *indent.get_or_insert(lead);
        if is_item && lead == item_indent {
            items.push(Item {
                leading: std::mem::take(&mut pending),
                lines: vec![line.clone()],
            });
        } else if lead > item_indent {
            let current = items.last_mut().ok_or_else(unexpected)?;
            current.lines.append(&mut pending);
            current.lines.push(line.clone());
        } else {
            return Err(unexpected());
        }
    }
    Ok((" ".repeat(indent.unwrap_or(2)), items, pending))
}

/// A rule as a list item's YAML text: plain when it reads back unchanged,
/// single-quoted otherwise.
fn yaml_scalar(text: &str) -> String {
    let reads_back = serde_yaml::from_str::<Value>(&format!("- {text}"))
        .is_ok_and(|value| value == Value::Sequence(vec![Value::String(text.into())]));
    if reads_back {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "''"))
    }
}

/// The key of a line that opens a top-level mapping entry: it starts at the
/// first column with neither a comment, a list item nor a document marker.
fn top_level_key(line: &str) -> Option<&str> {
    let text = content(line);
    let first = text.chars().next()?;
    if first.is_whitespace() || matches!(first, '#' | '-' | '.') {
        return None;
    }
    let colon = key_colon(text)?;
    Some(text[..colon].trim_end())
}

/// The colon that ends a plain key: the first one followed by a space, a tab
/// or the end of the line.
fn key_colon(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    (0..bytes.len()).find(|&index| {
        bytes[index] == b':' && matches!(bytes.get(index + 1), None | Some(b' ' | b'\t'))
    })
}

/// Splits the text after a key's colon into its value and a trailing
/// comment, the comment keeping the spaces before it.
fn split_comment(rest: &str) -> (&str, &str) {
    let bytes = rest.as_bytes();
    let mut quote = None;
    for (index, &byte) in bytes.iter().enumerate() {
        match quote {
            Some(open) if byte == open => quote = None,
            Some(_) => {}
            None if byte == b'\'' || byte == b'"' => quote = Some(byte),
            None if byte == b'#' && (index == 0 || matches!(bytes[index - 1], b' ' | b'\t')) => {
                let value = rest[..index].trim();
                let comment_start = rest[..index].trim_end().len();
                return (value, &rest[comment_start..]);
            }
            None => {}
        }
    }
    (rest.trim(), "")
}

fn is_anchor(value: &str) -> bool {
    value.starts_with('&') && !value.contains(char::is_whitespace)
}

/// A line's text without its line break.
fn content(line: &str) -> &str {
    line.trim_end_matches(['\n', '\r'])
}

fn line_break(raw: &str) -> &'static str {
    if raw.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Joins lines, giving any line that lacks one a line break before more text
/// follows it.
fn join(lines: Vec<String>, eol: &str) -> String {
    let mut out = String::new();
    for line in lines {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(eol);
        }
        out.push_str(&line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "\
# my profile
mixed-port: 7890
ipv6: false # keep it off
rules:
  # LAN first
  - DOMAIN-SUFFIX,lan,DIRECT
  - GEOIP,CN,DIRECT
  # everything else
  - MATCH,Proxy

dns:
  enable: true
";

    #[test]
    fn a_setting_changes_in_place_and_keeps_its_comment() {
        let edited = set_top_level_scalar(PROFILE, "ipv6", "true").unwrap();
        assert_eq!(
            edited,
            PROFILE.replace("ipv6: false # keep it off", "ipv6: true # keep it off")
        );
    }

    #[test]
    fn a_missing_setting_is_added_before_the_first_entry() {
        let edited = set_top_level_scalar(PROFILE, "allow-lan", "true").unwrap();
        assert_eq!(
            edited,
            PROFILE.replace("# my profile\n", "# my profile\nallow-lan: true\n")
        );
    }

    #[test]
    fn a_duplicated_or_block_setting_is_refused() {
        assert!(set_top_level_scalar("ipv6: true\nipv6: false\n", "ipv6", "true").is_err());
        assert!(set_top_level_scalar("ipv6:\n  nested: 1\n", "ipv6", "true").is_err());
    }

    #[test]
    fn crlf_files_keep_their_line_breaks() {
        let raw = "ipv6: false\r\nrules:\r\n  - MATCH,DIRECT\r\n";
        assert_eq!(
            set_top_level_scalar(raw, "ipv6", "true").unwrap(),
            "ipv6: true\r\nrules:\r\n  - MATCH,DIRECT\r\n"
        );
        assert_eq!(
            edit_rules(
                raw,
                RulesEdit::Insert {
                    at: 0,
                    line: "DOMAIN,a,DIRECT"
                }
            )
            .unwrap(),
            "ipv6: false\r\nrules:\r\n  - DOMAIN,a,DIRECT\r\n  - MATCH,DIRECT\r\n"
        );
    }

    #[test]
    fn a_new_rule_goes_above_the_first_rule_and_its_comment() {
        let edited = edit_rules(
            PROFILE,
            RulesEdit::Insert {
                at: 0,
                line: "DOMAIN,example.org,DIRECT",
            },
        )
        .unwrap();
        assert_eq!(
            edited,
            PROFILE.replace("rules:\n", "rules:\n  - DOMAIN,example.org,DIRECT\n")
        );
    }

    #[test]
    fn replace_and_delete_touch_only_their_rules() {
        let replaced = edit_rules(
            PROFILE,
            RulesEdit::Replace {
                index: 0,
                line: "DOMAIN-SUFFIX,home,DIRECT",
            },
        )
        .unwrap();
        assert_eq!(
            replaced,
            PROFILE.replace("DOMAIN-SUFFIX,lan,DIRECT", "DOMAIN-SUFFIX,home,DIRECT")
        );
        let deleted = edit_rules(PROFILE, RulesEdit::Delete { indices: &[0, 2] }).unwrap();
        assert_eq!(
            deleted,
            "# my profile\nmixed-port: 7890\nipv6: false # keep it off\nrules:\n  - GEOIP,CN,DIRECT\n\ndns:\n  enable: true\n"
        );
        assert!(edit_rules(PROFILE, RulesEdit::Delete { indices: &[3] }).is_err());
        let emptied = edit_rules(
            "rules:\n  - MATCH,DIRECT\n",
            RulesEdit::Delete { indices: &[0] },
        )
        .unwrap();
        assert_eq!(emptied, "rules:\n");
    }

    #[test]
    fn reordering_moves_each_rule_with_the_comment_above_it() {
        let edited = edit_rules(PROFILE, RulesEdit::Reorder { order: &[2, 0, 1] }).unwrap();
        assert_eq!(
            edited,
            "# my profile\nmixed-port: 7890\nipv6: false # keep it off\nrules:\n  # everything else\n  - MATCH,Proxy\n  # LAN first\n  - DOMAIN-SUFFIX,lan,DIRECT\n  - GEOIP,CN,DIRECT\n\ndns:\n  enable: true\n"
        );
        assert!(edit_rules(PROFILE, RulesEdit::Reorder { order: &[0, 0, 1] }).is_err());
        assert!(edit_rules(PROFILE, RulesEdit::Reorder { order: &[0, 1] }).is_err());
    }

    #[test]
    fn indentless_lists_keep_their_style() {
        let raw = "rules:\n- MATCH,DIRECT\nproxies: []\n";
        assert_eq!(
            edit_rules(
                raw,
                RulesEdit::Insert {
                    at: 0,
                    line: "DOMAIN,a,DIRECT"
                }
            )
            .unwrap(),
            "rules:\n- DOMAIN,a,DIRECT\n- MATCH,DIRECT\nproxies: []\n"
        );
    }

    #[test]
    fn a_flow_list_becomes_a_block_list() {
        let raw = "mode: rule\nrules: ['DOMAIN,a,DIRECT', 'MATCH,DIRECT'] # flow\n";
        assert_eq!(
            edit_rules(raw, RulesEdit::Insert { at: 1, line: "DOMAIN,b,REJECT" }).unwrap(),
            "mode: rule\nrules: # flow\n  - DOMAIN,a,DIRECT\n  - DOMAIN,b,REJECT\n  - MATCH,DIRECT\n"
        );
        assert_eq!(
            edit_rules(
                "rules: []\n",
                RulesEdit::Insert {
                    at: 0,
                    line: "MATCH,DIRECT"
                }
            )
            .unwrap(),
            "rules:\n  - MATCH,DIRECT\n"
        );
    }

    #[test]
    fn a_profile_without_rules_gains_a_list_and_odd_shapes_are_refused() {
        assert_eq!(
            edit_rules(
                "mixed-port: 7890",
                RulesEdit::Insert {
                    at: 0,
                    line: "MATCH,DIRECT"
                }
            )
            .unwrap(),
            "mixed-port: 7890\nrules:\n  - MATCH,DIRECT\n"
        );
        assert!(edit_rules("mixed-port: 7890\n", RulesEdit::Delete { indices: &[0] }).is_err());
        assert!(edit_rules(
            "shared: &shared ['MATCH,DIRECT']\nrules: *shared\n",
            RulesEdit::Insert {
                at: 0,
                line: "MATCH,DIRECT"
            }
        )
        .is_err());
    }

    #[test]
    fn an_edit_that_would_change_anything_else_is_refused() {
        // Another key aliases the list, so editing it would change both.
        let aliased = "rules: &shared\n  - MATCH,DIRECT\ncopy: *shared\n";
        assert!(edit_rules(aliased, RulesEdit::Delete { indices: &[0] }).is_err());
        // The rules come from a merge key; a new `rules:` line would drop them.
        let merged = "base: &base\n  rules: ['MATCH,DIRECT']\n<<: *base\n";
        assert!(edit_rules(
            merged,
            RulesEdit::Insert {
                at: 0,
                line: "DOMAIN,a,DIRECT"
            }
        )
        .is_err());
        // A flow mapping continued on a first-column line reads as two keys.
        let continued = "dns: {enable: true,\nipv6: true}\n";
        assert!(set_top_level_scalar(continued, "ipv6", "false").is_err());
    }

    #[test]
    fn rules_that_would_not_read_back_as_written_are_quoted() {
        assert_eq!(
            yaml_scalar("DOMAIN-SUFFIX,example.com,DIRECT"),
            "DOMAIN-SUFFIX,example.com,DIRECT"
        );
        assert_eq!(
            yaml_scalar("DOMAIN-KEYWORD,a #b,DIRECT"),
            "'DOMAIN-KEYWORD,a #b,DIRECT'"
        );
        assert_eq!(
            yaml_scalar("DOMAIN,it's: odd,DIRECT"),
            "'DOMAIN,it''s: odd,DIRECT'"
        );
        assert_eq!(yaml_scalar("true"), "'true'");
    }
}

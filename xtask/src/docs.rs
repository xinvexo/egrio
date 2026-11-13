//! `cargo xtask docs`: the documentation rules `docs/README.md` sets that a
//! machine can check. Every Markdown file in the repository has working
//! relative links and heading anchors (GitHub's anchor rules); every
//! document under `docs/` starts with its one level-one title, uses no front
//! matter and no struck-through text, has a title no other document has,
//! and is linked from the document map.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

const DOCS_ROOT: &str = "docs";
const DOCS_MAP: &str = "docs/README.md";

/// Directories never walked, wherever they are.
const IGNORED_DIRECTORIES: [&str; 4] = [".git", "node_modules", "target", "dist"];
/// Tool worktrees, by their path from the root.
const IGNORED_TOOL_WORKTREES: [&str; 2] = [".claude/worktrees", ".tmp-staged-verify"];

static FENCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(`{3,}|~{3,})").unwrap());
static LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"!?\[[^\]]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)"#)
        .unwrap()
});
static HEADING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(#{1,6})\s+(.*?)\s*#*\s*$").unwrap());
static SCHEME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*:").unwrap());
static LINK_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"!?\[([^\]]*)\]\([^)]*\)").unwrap());
static CODE_TEXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`+([^`]*)`+").unwrap());
static STRONG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\*\*(.+?)\*\*").unwrap());
static EMPHASIS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\*(.+?)\*").unwrap());
static NOT_ANCHOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^\p{L}\p{M}\p{N}\p{Pc} -]").unwrap());
static TITLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^#\s+\S").unwrap());
static STRUCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"~~[^~\s][^~]*~~").unwrap());

pub fn run(root: &Path) -> Result<(), String> {
    let errors = check(root)?;
    if errors.is_empty() {
        eprintln!("documentation checks passed");
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// The problems found, as `path:line: problem`.
pub fn check(root: &Path) -> Result<Vec<String>, String> {
    let mut errors = Vec::new();
    let files = markdown_files(root)?;
    let mut contents: HashMap<String, String> = HashMap::new();
    for file in &files {
        contents.insert(file.clone(), read(&root.join(file))?);
    }
    let mut anchors: HashMap<String, HashSet<String>> = HashMap::new();
    let mut titles: HashMap<String, String> = HashMap::new();
    let mut mapped: HashSet<String> = HashSet::new();

    for file in &files {
        let text = &contents[file];
        let visible = mask_fenced_code(text);
        if is_document(file) {
            errors.extend(shape_errors(file, text, &visible));
            if let Some(title) = headings(&visible)
                .into_iter()
                .find(|heading| heading.level == 1)
            {
                match titles.get(&title.text) {
                    Some(first) => errors.push(format!(
                        "{file}:{}: duplicate title {}; first declared at {first}",
                        title.line, title.text
                    )),
                    None => {
                        titles.insert(title.text.clone(), format!("{file}:{}", title.line));
                    }
                }
            }
        }
        for link in links(&visible) {
            if is_external(&link.target) {
                continue;
            }
            let (target_file, fragment) = split_target(&link.target);
            let mut target_path = file.clone();
            if !target_file.is_empty() {
                let directory = root.join(file);
                let directory = directory.parent().unwrap_or(root);
                let absolute = normalize(&directory.join(&target_file));
                if !absolute.exists() {
                    errors.push(format!(
                        "{file}:{}: missing relative Markdown target {}",
                        link.line, link.target
                    ));
                    continue;
                }
                target_path = relative(root, &absolute);
                if file == DOCS_MAP {
                    mapped.insert(target_path.clone());
                }
            }
            if let Some(fragment) = fragment {
                if target_path.to_lowercase().ends_with(".md") {
                    if !anchors.contains_key(&target_path) {
                        let text = match contents.get(&target_path) {
                            Some(text) => text.clone(),
                            None => read(&root.join(&target_path))?,
                        };
                        anchors.insert(target_path.clone(), heading_anchors(&text));
                    }
                    if !anchors[&target_path].contains(&fragment) {
                        errors.push(format!(
                            "{file}:{}: missing heading anchor {}",
                            link.line, link.target
                        ));
                    }
                }
            }
        }
    }

    if contents.contains_key(DOCS_MAP) {
        for file in &files {
            if is_document(file) && file != DOCS_MAP && !mapped.contains(file) {
                errors.push(format!(
                    "{DOCS_MAP}:1: the document map does not link {file}"
                ));
            }
        }
    } else if files.iter().any(|file| is_document(file)) {
        errors.push(format!("{DOCS_MAP}:1: missing the document map"));
    }
    Ok(errors)
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn is_document(file: &str) -> bool {
    file.starts_with(&format!("{DOCS_ROOT}/"))
}

/// Every Markdown file under `root`, by its path from the root with `/`
/// separators, sorted.
fn markdown_files(root: &Path) -> Result<Vec<String>, String> {
    let mut files = BTreeSet::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let kind = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", entry.path().display()))?;
            if kind.is_dir() {
                let ignored = IGNORED_DIRECTORIES.contains(&name.as_str())
                    || IGNORED_TOOL_WORKTREES.contains(&path.as_str())
                    || (prefix.is_empty() && name == "reference");
                if !ignored {
                    pending.push((entry.path(), path));
                }
            } else if kind.is_file() && name.to_lowercase().ends_with(".md") {
                files.insert(path);
            }
        }
    }
    Ok(files.into_iter().collect())
}

/// `contents` with every fenced code block, fences included, blanked out,
/// its line breaks kept.
fn mask_fenced_code(contents: &str) -> String {
    let mut fence: Option<String> = None;
    let mut masked = String::with_capacity(contents.len());
    for line in contents.split_inclusive('\n') {
        let (body, end) = match line.strip_suffix("\r\n") {
            Some(body) => (body, "\r\n"),
            None => match line.strip_suffix('\n') {
                Some(body) => (body, "\n"),
                None => (line, ""),
            },
        };
        let marker = FENCE.captures(body).map(|captures| captures[1].to_string());
        let closing = match (&fence, &marker) {
            (Some(open), Some(marker)) => {
                marker.starts_with(open.chars().next().unwrap_or('`')) && marker.len() >= open.len()
            }
            _ => false,
        };
        if fence.is_some() || marker.is_some() {
            masked.extend(std::iter::repeat_n(' ', body.chars().count()));
        } else {
            masked.push_str(body);
        }
        masked.push_str(end);
        if closing {
            fence = None;
        } else if fence.is_none() {
            if let Some(marker) = marker {
                fence = Some(marker);
            }
        }
    }
    masked
}

/// `line` with each inline code span blanked out: a run of backticks up to
/// the next run of the same length.
fn mask_inline_code(line: &str) -> String {
    let characters: Vec<char> = line.chars().collect();
    let mut masked: Vec<char> = characters.clone();
    let run_at = |index: usize| {
        characters[index..]
            .iter()
            .take_while(|character| **character == '`')
            .count()
    };
    let mut index = 0;
    while index < characters.len() {
        if characters[index] != '`' {
            index += 1;
            continue;
        }
        let length = run_at(index);
        let mut search = index + length;
        let mut closing = None;
        while search < characters.len() {
            if characters[search] == '`' {
                let other = run_at(search);
                if other == length {
                    closing = Some(search);
                    break;
                }
                search += other;
            } else {
                search += 1;
            }
        }
        match closing {
            Some(close) => {
                for character in &mut masked[index..close + length] {
                    *character = ' ';
                }
                index = close + length;
            }
            None => index += length,
        }
    }
    masked.into_iter().collect()
}

struct Link {
    line: usize,
    target: String,
}

fn line_at(contents: &str, offset: usize) -> usize {
    1 + contents[..offset].matches('\n').count()
}

fn links(visible: &str) -> Vec<Link> {
    LINK.captures_iter(visible)
        .map(|captures| {
            let whole = captures.get(0).expect("a match");
            let target = &captures[1];
            let target = target
                .strip_prefix('<')
                .and_then(|target| target.strip_suffix('>'))
                .unwrap_or(target);
            Link {
                line: line_at(visible, whole.start()),
                target: target.to_string(),
            }
        })
        .collect()
}

/// Percent-decodes `value`, or gives it back when it does not decode.
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let byte = value
                .get(index + 1..index + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            match byte {
                Some(byte) => {
                    decoded.push(byte);
                    index += 3;
                    continue;
                }
                None => return value.to_string(),
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_string())
}

/// A link target's file and its decoded fragment.
fn split_target(target: &str) -> (String, Option<String>) {
    let (before, fragment) = match target.split_once('#') {
        Some((before, fragment)) => (before, Some(decode(fragment))),
        None => (target, None),
    };
    let file = before.split('?').next().unwrap_or_default();
    (decode(file), fragment)
}

fn is_external(target: &str) -> bool {
    target.starts_with("//") || target.starts_with('/') || SCHEME.is_match(target)
}

/// `path` with `.` and `..` resolved without touching the file system.
fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn relative(root: &Path, path: &Path) -> String {
    let root = normalize(root);
    let relative = path.strip_prefix(&root).unwrap_or(path);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

struct Heading {
    level: usize,
    line: usize,
    text: String,
}

fn headings(visible: &str) -> Vec<Heading> {
    visible
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let captures = HEADING.captures(line)?;
            Some(Heading {
                level: captures[1].len(),
                line: index + 1,
                text: captures[2].to_string(),
            })
        })
        .collect()
}

fn plain_text(text: &str) -> String {
    let text = LINK_TEXT.replace_all(text, "$1");
    let text = CODE_TEXT.replace_all(&text, "$1");
    let text = STRONG.replace_all(&text, "$1");
    EMPHASIS.replace_all(&text, "$1").into_owned()
}

/// GitHub's heading anchors: lowercase, everything but letters, marks,
/// numbers, connector punctuation, hyphens and spaces dropped, each space
/// a hyphen; repeated headings get `-1`, `-2`, … suffixes.
fn heading_anchors(contents: &str) -> HashSet<String> {
    let mut anchors = HashSet::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for heading in headings(&mask_fenced_code(contents)) {
        let base = NOT_ANCHOR
            .replace_all(&plain_text(&heading.text).to_lowercase(), "")
            .replace(' ', "-");
        let seen = counts.entry(base.clone()).or_default();
        anchors.insert(if *seen == 0 {
            base.clone()
        } else {
            format!("{base}-{seen}")
        });
        *seen += 1;
    }
    anchors
}

fn shape_errors(file: &str, contents: &str, visible: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let first = contents.lines().next().unwrap_or_default();
    if first == "---" {
        errors.push(format!(
            "{file}:1: front matter is not used; start with the level-one title"
        ));
    } else if !TITLE.is_match(first) {
        errors.push(format!(
            "{file}:1: the first line must be the level-one title"
        ));
    }
    for extra in headings(visible)
        .into_iter()
        .filter(|heading| heading.level == 1)
        .skip(1)
    {
        errors.push(format!(
            "{file}:{}: a document has exactly one level-one title",
            extra.line
        ));
    }
    for (index, line) in visible.lines().enumerate() {
        if STRUCK.is_match(&mask_inline_code(line)) {
            errors.push(format!(
                "{file}:{}: struck-through text is history; delete it instead",
                index + 1
            ));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(title: &str, body: &str) -> String {
        format!("# {title}\n\n{body}\n")
    }

    fn map(targets: &[&str]) -> String {
        doc(
            "Map",
            &targets
                .iter()
                .map(|target| format!("- [{target}]({target})"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    /// The errors for a repository holding `files`.
    fn errors(name: &str, files: &[(&str, String)]) -> String {
        let root =
            std::env::temp_dir().join(format!("egrio-xtask-docs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (path, contents) in files {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        let errors = check(&root).unwrap().join("\n");
        let _ = std::fs::remove_dir_all(&root);
        errors
    }

    #[test]
    fn accepts_a_mapped_document_set() {
        let found = errors(
            "mapped",
            &[
                ("docs/README.md", map(&["a.md", "platforms/b.md"])),
                ("docs/a.md", doc("A", "[B](platforms/b.md#b-section)")),
                ("docs/platforms/b.md", doc("B", "## B section")),
            ],
        );
        assert_eq!(found, "");
    }

    #[test]
    fn rejects_a_missing_relative_target() {
        let found = errors(
            "missing",
            &[("docs/README.md", doc("Map", "[missing](missing.md)"))],
        );
        assert!(found.contains("docs/README.md:3: missing relative Markdown target missing.md"));
    }

    #[test]
    fn resolves_url_encoded_targets_before_checking_the_anchor() {
        let found = errors(
            "encoded",
            &[
                ("docs/README.md", map(&["a%20b.md"])),
                ("docs/a b.md", doc("Target", "## 取值规则与作用域")),
                (
                    "README.md",
                    "[target](docs/a%20b.md#%E5%8F%96%E5%80%BC%E8%A7%84%E5%88%99%E4%B8%8E%E4%BD%9C%E7%94%A8%E5%9F%9F)"
                        .into(),
                ),
            ],
        );
        assert_eq!(found, "");
    }

    #[test]
    fn rejects_an_anchor_that_names_no_heading() {
        let found = errors(
            "anchor",
            &[
                ("docs/README.md", map(&["a.md"])),
                ("docs/a.md", doc("A", "## Present")),
                ("README.md", "[gone](docs/a.md#absent)".into()),
            ],
        );
        assert!(found.contains("README.md:1: missing heading anchor docs/a.md#absent"));
    }

    #[test]
    fn checks_anchors_in_the_same_document() {
        let found = errors(
            "same",
            &[(
                "docs/README.md",
                doc("Map", "## Rules\n\n[rules](#rules) [gone](#gone)"),
            )],
        );
        assert!(!found.contains("#rules"));
        assert!(found.contains("missing heading anchor #gone"));
    }

    #[test]
    fn derives_anchors_from_punctuation_inline_code_and_repeats() {
        let anchors = heading_anchors(
            &[
                "# Title",
                "### egrio-core：内核式模块布局",
                "## 本地 IPC 与连接结束",
                "## 7. 规则语义对齐",
                "## `Runtime::reload` and **bold**",
                "## Repeat",
                "## Repeat",
                "```",
                "## Not a heading",
                "```",
            ]
            .join("\n"),
        );
        for anchor in [
            "title",
            "egrio-core内核式模块布局",
            "本地-ipc-与连接结束",
            "7-规则语义对齐",
            "runtimereload-and-bold",
            "repeat",
            "repeat-1",
        ] {
            assert!(anchors.contains(anchor), "{anchor} in {anchors:?}");
        }
        assert!(!anchors.contains("not-a-heading"));
    }

    #[test]
    fn ignores_links_inside_fenced_code() {
        let found = errors(
            "fenced",
            &[(
                "docs/README.md",
                doc("Map", "```markdown\n[missing](missing.md)\n```"),
            )],
        );
        assert_eq!(found, "");
    }

    #[test]
    fn rejects_front_matter() {
        let found = errors(
            "front",
            &[
                ("docs/README.md", map(&["a.md"])),
                ("docs/a.md", "---\ntitle: A\n---\n\n# A\n".into()),
            ],
        );
        assert!(found.contains("docs/a.md:1: front matter is not used"));
    }

    #[test]
    fn requires_the_title_on_the_first_line_and_only_once() {
        let found = errors(
            "title",
            &[
                ("docs/README.md", map(&["a.md", "b.md"])),
                ("docs/a.md", "Intro\n\n# A\n".into()),
                ("docs/b.md", "# B\n\n# B again\n".into()),
            ],
        );
        assert!(found.contains("docs/a.md:1: the first line must be the level-one title"));
        assert!(found.contains("docs/b.md:3: a document has exactly one level-one title"));
    }

    #[test]
    fn rejects_a_duplicate_title() {
        let found = errors(
            "duplicate",
            &[
                ("docs/README.md", map(&["a.md", "b.md"])),
                ("docs/a.md", doc("Same", "")),
                ("docs/b.md", doc("Same", "")),
            ],
        );
        assert!(found.contains("docs/b.md:1: duplicate title Same; first declared at docs/a.md:1"));
    }

    #[test]
    fn rejects_struck_through_text_outside_code() {
        let found = errors(
            "struck",
            &[
                ("docs/README.md", map(&["backlog.md"])),
                (
                    "docs/backlog.md",
                    doc(
                        "Backlog",
                        "- ~~done~~ item\n- `a ~~b~~ c` code\n\n```\n~~fenced~~\n```",
                    ),
                ),
            ],
        );
        assert!(found.contains("docs/backlog.md:3: struck-through text is history"));
        assert!(!found.contains("docs/backlog.md:4:") && !found.contains("docs/backlog.md:7:"));
    }

    #[test]
    fn requires_the_map_to_link_every_document() {
        let found = errors(
            "unmapped",
            &[
                ("docs/README.md", map(&["a.md"])),
                ("docs/a.md", doc("A", "")),
                ("docs/designs/b.md", doc("B", "")),
            ],
        );
        assert!(
            found.contains("docs/README.md:1: the document map does not link docs/designs/b.md")
        );
        assert!(!found.contains("does not link docs/a.md"));
    }

    #[test]
    fn requires_the_map_when_documents_exist() {
        let found = errors("no-map", &[("docs/a.md", doc("A", ""))]);
        assert!(found.contains("docs/README.md:1: missing the document map"));
    }

    #[test]
    fn checks_links_but_not_shape_outside_docs() {
        let found = errors(
            "outside",
            &[(
                "crates/x/README.md",
                "Intro without a title\n\n[gone](missing.md)\n".into(),
            )],
        );
        assert!(found.contains("crates/x/README.md:3: missing relative Markdown target missing.md"));
        assert!(!found.contains("first line"));
    }

    #[test]
    fn ignores_tool_worktrees_and_the_reference_snapshot() {
        let found = errors(
            "ignored",
            &[
                (
                    ".claude/worktrees/agent/docs/README.md",
                    "[bad](missing.md)".into(),
                ),
                (
                    ".tmp-staged-verify/docs/README.md",
                    "[bad](missing.md)".into(),
                ),
                (
                    ".claude/skills/verify/SKILL.md",
                    "[project](../../../docs/README.md)".into(),
                ),
                ("reference/vendor/README.md", "[bad](missing.md)".into()),
                ("docs/README.md", doc("Map", "")),
            ],
        );
        assert_eq!(found, "");
    }
}

//! The file a Core keeps its fake-IP mappings in for the next one: a header
//! line, then one address and name per line, the most recently used first.
//! Names are normalized DNS names, which hold no spaces or line breaks. A
//! file with another header, from a later format, is read as empty.

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::path::Path;

const HEADER: &str = "egrio fake-ip mappings 1";

/// Writes `mappings` to `path` through a temporary file renamed into place,
/// so a reader never sees half a file.
pub(crate) fn save(path: &Path, mappings: &[(Ipv4Addr, String)]) -> std::io::Result<()> {
    let mut text = String::with_capacity(HEADER.len() + 1 + mappings.len() * 32);
    text.push_str(HEADER);
    text.push('\n');
    for (ip, domain) in mappings {
        let _ = writeln!(text, "{ip} {domain}");
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, text)?;
    std::fs::rename(&temporary, path)
}

/// The mappings `save` wrote to `path`; none when there is no file yet.
/// Lines that do not hold an address and a name are skipped.
pub(crate) fn load(path: &Path) -> std::io::Result<Vec<(Ipv4Addr, String)>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Ok(Vec::new());
    }
    Ok(lines
        .filter_map(|line| {
            let (ip, domain) = line.split_once(' ')?;
            (!domain.is_empty() && !domain.contains(' '))
                .then(|| Some((ip.parse().ok()?, domain.to_string())))
                .flatten()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappings_come_back_in_order_and_bad_lines_are_skipped() {
        let directory = std::env::temp_dir().join(format!(
            "egrio-fake-ip-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("fake-ip-mappings");
        assert!(load(&path).unwrap().is_empty(), "no file yet");
        let mappings = vec![
            (Ipv4Addr::new(198, 18, 0, 7), "recent.example".to_string()),
            (Ipv4Addr::new(198, 18, 3, 1), "older.example".to_string()),
        ];
        save(&path, &mappings).unwrap();
        assert!(!path.with_extension("tmp").exists());
        assert_eq!(load(&path).unwrap(), mappings);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!("{text}not-an-address x.example\n198.18.0.9\n"),
        )
        .unwrap();
        assert_eq!(load(&path).unwrap(), mappings);

        std::fs::write(
            &path,
            "egrio fake-ip mappings 2\n198.18.0.7 recent.example\n",
        )
        .unwrap();
        assert!(load(&path).unwrap().is_empty(), "another format");
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

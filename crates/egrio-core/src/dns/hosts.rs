//! Names mapped to fixed addresses: the profile's `hosts`, then the system's
//! hosts file. Wherever the Core resolves a name itself, a mapped name has
//! its mapped addresses and no DNS server is asked for it; the apps' address
//! questions for it are answered from the mapping too (see `service.rs`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime};

use super::config::{DnsHost, RuntimeDnsConfig};
use super::pattern::PatternTrie;
use super::resolver::normalize_domain;

/// How long the system's hosts file goes unlooked-at after a look.
const SYSTEM_RECHECK: Duration = Duration::from_secs(5);

type Addresses = Arc<[IpAddr]>;

/// The profile's mappings, by the pattern that maps them, and whether the
/// system's hosts file maps the names they do not.
#[derive(Debug, Default)]
pub(crate) struct Hosts {
    mapped: PatternTrie<Addresses>,
    system: bool,
}

impl Hosts {
    pub(crate) fn new(config: &RuntimeDnsConfig) -> Self {
        let mut mapped = PatternTrie::default();
        // The first entry for a pattern is the one that counts.
        for DnsHost { pattern, addresses } in &config.hosts {
            mapped.insert(pattern, Arc::from(addresses.as_slice()));
        }
        Self {
            mapped,
            system: config.use_system_hosts,
        }
    }

    /// The addresses `name` maps to. The most specific of the profile's
    /// patterns wins (see [`PatternTrie`]);
    /// the system's hosts file, exact names only, maps what the profile does
    /// not.
    pub(crate) fn lookup(&self, name: &str) -> Option<Addresses> {
        let name = normalize_domain(name);
        if name.is_empty() {
            return None;
        }
        self.mapped.get(&name).cloned().or_else(|| {
            self.system
                .then(|| SYSTEM_HOSTS.names().get(&name).cloned())
                .flatten()
        })
    }
}

/// The system's hosts file, read again when it changed (hosts(5): an
/// address, then the names it has, `#` starting a comment).
static SYSTEM_HOSTS: LazyLock<SystemHostsFile> =
    LazyLock::new(|| SystemHostsFile::new(system_hosts_path()));

/// Unix keeps the file at `/etc/hosts`; Windows at
/// `%SystemRoot%\System32\drivers\etc\hosts`. Unit tests read none.
fn system_hosts_path() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    }
    #[cfg(windows)]
    {
        std::env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join(r"System32\drivers\etc\hosts"))
    }
    #[cfg(not(windows))]
    {
        Some(PathBuf::from("/etc/hosts"))
    }
}

#[derive(Debug)]
struct SystemHostsFile {
    path: Option<PathBuf>,
    state: Mutex<FileState>,
}

#[derive(Debug, Default)]
struct FileState {
    checked: Option<Instant>,
    /// The file's modification time and length when it was read.
    stamp: Option<(SystemTime, u64)>,
    names: Arc<HashMap<String, Addresses>>,
}

impl SystemHostsFile {
    fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            state: Mutex::default(),
        }
    }

    /// The file's names, looking at it at most every [`SYSTEM_RECHECK`] and
    /// reading it again only when it changed; a missing or unreadable file
    /// maps nothing.
    ///
    /// Every capture queue's pump reaches this per DNS query it answers, so
    /// the file calls happen with the lock released: one caller claims the
    /// look and the others take the names it published last, rather than all
    /// of them waiting behind a `metadata` or a read of `/etc/hosts` that is
    /// quick on a local disk and not on a loaded or networked one.
    fn names(&self) -> Arc<HashMap<String, Addresses>> {
        let Some(path) = &self.path else {
            return Arc::default();
        };
        let known = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if state
                .checked
                .is_some_and(|checked| checked.elapsed() < SYSTEM_RECHECK)
            {
                return state.names.clone();
            }
            state.checked = Some(Instant::now());
            state.stamp
        };
        let stamp = std::fs::metadata(path).ok().map(|metadata| {
            (
                metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                metadata.len(),
            )
        });
        if stamp == known {
            return self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .names
                .clone();
        }
        let names = Arc::new(
            std::fs::read_to_string(path)
                .map(|text| parse_hosts_file(&text))
                .unwrap_or_default(),
        );
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.stamp = stamp;
        state.names = Arc::clone(&names);
        names
    }
}

/// Each name with the addresses its lines give, in the file's order. A line
/// whose first field is no address (a zoned IPv6 address among them) maps
/// nothing.
fn parse_hosts_file(text: &str) -> HashMap<String, Addresses> {
    let mut names: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in text.lines() {
        let line = line.split_once('#').map_or(line, |(content, _)| content);
        let mut fields = line.split_whitespace();
        let Some(address) = fields.next().and_then(|field| field.parse::<IpAddr>().ok()) else {
            continue;
        };
        let address = match address {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
            v4 => v4,
        };
        for name in fields {
            let name = normalize_domain(name);
            let addresses = names.entry(name).or_default();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    names
        .into_iter()
        .map(|(name, addresses)| (name, Arc::from(addresses)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn hosts(entries: &[(&str, &[&str])]) -> Hosts {
        Hosts::new(&RuntimeDnsConfig {
            hosts: entries
                .iter()
                .map(|(pattern, addresses)| DnsHost {
                    pattern: pattern.parse().unwrap(),
                    addresses: addresses.iter().map(|text| ip(text)).collect(),
                })
                .collect(),
            ..RuntimeDnsConfig::default()
        })
    }

    #[test]
    fn the_most_specific_pattern_maps_a_name() {
        let hosts = hosts(&[
            ("*", &["10.0.0.9"]),
            ("+.example.com", &["10.0.0.1"]),
            ("+.deep.example.com", &["10.0.0.2"]),
            ("*.example.com", &["10.0.0.3"]),
            ("www.example.com", &["10.0.0.4"]),
            ("ntp.*.example.com", &["10.0.0.5"]),
        ]);
        let first = |name: &str| hosts.lookup(name).map(|addresses| addresses[0]);
        assert_eq!(first("WWW.Example.com."), Some(ip("10.0.0.4")), "exact");
        assert_eq!(first("api.example.com"), Some(ip("10.0.0.3")), "one label");
        assert_eq!(
            first("example.com"),
            Some(ip("10.0.0.1")),
            "the suffix's own name"
        );
        assert_eq!(first("a.b.example.com"), Some(ip("10.0.0.1")), "suffix");
        assert_eq!(
            first("x.deep.example.com"),
            Some(ip("10.0.0.2")),
            "longest suffix"
        );
        assert_eq!(first("other.org"), Some(ip("10.0.0.9")), "any name");
        // A `+.` pattern's own name is as specific as an exact entry.
        assert_eq!(first("deep.example.com"), Some(ip("10.0.0.2")));
        assert_eq!(
            first("ntp.pool.example.com"),
            Some(ip("10.0.0.5")),
            "a `*` between labels"
        );
    }

    #[test]
    fn the_first_entry_for_a_pattern_counts_and_unmapped_names_have_none() {
        let hosts = hosts(&[
            ("nas.home", &["192.168.1.10", "fd00::10"]),
            ("nas.home", &["192.168.1.11"]),
        ]);
        assert_eq!(
            hosts.lookup("nas.home").as_deref(),
            Some([ip("192.168.1.10"), ip("fd00::10")].as_slice())
        );
        assert!(hosts.lookup("printer.home").is_none());
        assert!(hosts.lookup("").is_none());
    }

    #[test]
    fn a_hosts_file_maps_its_names_to_every_address_they_have() {
        let names = parse_hosts_file(
            "# comment\n\
             127.0.0.1\tlocalhost\n\
             185.199.108.133 raw.githubusercontent.com   # GitHub\n\
             185.199.109.133 RAW.githubusercontent.com. gist.githubusercontent.com\n\
             ::ffff:10.0.0.1 mapped.test\n\
             fe80::1%lo0 zoned.test\n\
             not-an-address broken.test\n",
        );
        assert_eq!(
            names["raw.githubusercontent.com"].as_ref(),
            &[ip("185.199.108.133"), ip("185.199.109.133")]
        );
        assert_eq!(
            names["gist.githubusercontent.com"].as_ref(),
            &[ip("185.199.109.133")]
        );
        assert_eq!(
            names["mapped.test"].as_ref(),
            &[ip("10.0.0.1")],
            "unmapped to IPv4"
        );
        assert!(!names.contains_key("zoned.test"));
        assert!(!names.contains_key("broken.test"));
    }

    #[test]
    fn the_system_file_is_read_again_once_it_changed() {
        let directory = std::env::temp_dir().join(format!("egrio-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("hosts");
        std::fs::write(&path, "10.0.0.1 one.test\n").unwrap();
        let file = SystemHostsFile::new(Some(path.clone()));
        assert!(file.names().contains_key("one.test"));
        std::fs::write(&path, "10.0.0.2 two.test longer\n").unwrap();
        // Not looked at again before the recheck interval.
        assert!(file.names().contains_key("one.test"));
        file.state.lock().unwrap().checked = None;
        let names = file.names();
        assert!(names.contains_key("two.test") && !names.contains_key("one.test"));
        std::fs::remove_file(&path).unwrap();
        file.state.lock().unwrap().checked = None;
        assert!(file.names().is_empty(), "a missing file maps nothing");
        let _ = std::fs::remove_dir(&directory);
    }
}

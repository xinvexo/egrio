//! Linux socket ownership from procfs, implementing Core's `FlowScanner`.
//!
//! Sources: proc(5) (`proc_pid_net`, `proc_pid_fd`, `proc_pid_exe`), the
//! kernel's Documentation/networking/proc_net_tcp.txt, and the seq_printf
//! formats in net/ipv4/tcp_ipv4.c, net/ipv4/udp.c, net/ipv6/tcp_ipv6.c and
//! net/ipv6/datagram.c: each endpoint is `%08X:%04X` (IPv4, the raw
//! network-order word) or `%08X%08X%08X%08X:%04X` (IPv6, four raw
//! `s6_addr32` words), ports are host-order, and the socket inode is the
//! tenth column. `/proc/[pid]/fd/*` links read `socket:[inode]`.
//!
//! The view is the reader's network namespace and the processes it may
//! ptrace-read (`PTRACE_MODE_READ_FSCREDS`). Matching follows the macOS
//! scanner: ambiguous, shared or incomplete observations stay unknown.

use egrio_core::{FlowKey, FlowProtocol, FlowScanner, ProcessInfo};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// One socket row of `/proc/net/{tcp,tcp6,udp,udp6}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocketRow {
    pub protocol: FlowProtocol,
    pub local: SocketAddr,
    /// `None` for an unconnected socket (remote port 0).
    pub remote: Option<SocketAddr>,
    pub inode: u64,
}

/// Decodes one `%08X…:%04X` endpoint. The address words are the kernel's
/// in-memory network-order words printed as native integers, so the
/// octets are each word's native-endian bytes.
fn endpoint(text: &str) -> Option<SocketAddr> {
    let (address, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |index: usize| -> Option<[u8; 4]> {
        let hex = address.get(index * 8..index * 8 + 8)?;
        Some(u32::from_str_radix(hex, 16).ok()?.to_ne_bytes())
    };
    let ip = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut octets = [0_u8; 16];
            for index in 0..4 {
                octets[index * 4..index * 4 + 4].copy_from_slice(&word(index)?);
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parses one table; malformed rows are skipped. TIME_WAIT and request
/// sockets report inode 0 and own no descriptor.
pub(crate) fn parse_table(text: &str, protocol: FlowProtocol) -> Vec<SocketRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local = endpoint(fields.get(1)?)?;
            let remote = endpoint(fields.get(2)?)?;
            let inode = fields.get(9)?.parse::<u64>().ok()?;
            (inode != 0).then(|| {
                let (local, remote) = unmap(local, remote);
                SocketRow {
                    protocol,
                    local,
                    remote: (remote.port() != 0).then_some(remote),
                    inode,
                }
            })
        })
        .collect()
}

/// An IPv6 socket talking IPv4 reports IPv4-mapped endpoints. Convert the
/// pair together so a single mapped side never invents a cross-family tuple.
fn unmap(local: SocketAddr, remote: SocketAddr) -> (SocketAddr, SocketAddr) {
    let mapped = |address: SocketAddr| match address.ip() {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), address.port())),
        IpAddr::V4(_) => None,
    };
    let remote_unconnected = remote.port() == 0 && remote.ip().is_unspecified();
    match (mapped(local), mapped(remote)) {
        (Some(local), Some(remote)) => (local, remote),
        (Some(local), None) if remote_unconnected => {
            (local, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        _ => (local, remote),
    }
}

fn row_matches(row: &SocketRow, flow: &FlowKey) -> bool {
    if row.protocol != flow.protocol || row.local.port() != flow.source_port {
        return false;
    }
    let local = row.local.ip();
    let local_matches = match (local, flow.source_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            local.is_unspecified() || local == flow.source_ip
        }
        // A wildcard IPv6 socket may also receive IPv4 (dual stack); it
        // matches so that the flow stays unknown rather than misattributed.
        (IpAddr::V6(_), IpAddr::V4(_)) => local.is_unspecified() && row.remote.is_none(),
        _ => false,
    };
    if !local_matches {
        return false;
    }
    match row.remote {
        Some(remote) => remote == SocketAddr::new(flow.destination_ip, flow.destination_port),
        None => flow.protocol == FlowProtocol::Udp,
    }
}

/// The descriptor holders of the requested inodes, visible to this process.
#[derive(Debug, Default)]
struct Holders {
    by_inode: HashMap<u64, Vec<u32>>,
    complete: bool,
}

fn scan_holders(inodes: &HashSet<u64>, deadline: Instant, stop: &AtomicBool) -> Holders {
    let mut holders = Holders::default();
    let Ok(processes) = std::fs::read_dir("/proc") else {
        return holders;
    };
    for process in processes.flatten() {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            return holders;
        }
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        // Exited or not ptrace-readable: outside the visible scope.
        let Ok(descriptors) = std::fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            if let Some(inode) = socket_inode(&descriptor.path()) {
                if inodes.contains(&inode) {
                    let pids = holders.by_inode.entry(inode).or_default();
                    if !pids.contains(&pid) {
                        pids.push(pid);
                    }
                }
            }
        }
    }
    holders.complete = true;
    holders
}

fn socket_inode(link: &Path) -> Option<u64> {
    let target = std::fs::read_link(link).ok()?;
    target
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The executable of `pid`, revalidated against the descriptor scan so a
/// reused PID cannot lend its identity to the socket.
fn executable(pid: u32, inode: u64) -> Option<PathBuf> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let path = std::fs::read_link(root.join("exe")).ok()?;
    let still_held = std::fs::read_dir(root.join("fd"))
        .ok()?
        .flatten()
        .any(|descriptor| socket_inode(&descriptor.path()) == Some(inode));
    if !still_held {
        return None;
    }
    let path = path.to_str()?;
    // proc_pid_exe(5): an unlinked executable reads with " (deleted)".
    let path = PathBuf::from(path.strip_suffix(" (deleted)").unwrap_or(path));
    path.is_absolute().then_some(path)
}

/// Resolves each flow from the rows of one table snapshot and their holders.
fn resolve(
    flow: &FlowKey,
    rows: &[SocketRow],
    holders: &Holders,
    executable: &mut impl FnMut(u32, u64) -> Option<PathBuf>,
) -> Option<ProcessInfo> {
    if !holders.complete {
        return None;
    }
    let mut matching = rows.iter().filter(|row| row_matches(row, flow));
    let row = matching.next()?;
    // Two sockets on the tuple (reuse, or a v4 and dual-stack v6 socket),
    // or a dual-stack wildcard answering IPv4, cannot be told apart.
    if matching.next().is_some() || (row.local.is_ipv6() && flow.source_ip.is_ipv4()) {
        return None;
    }
    let [pid] = holders.by_inode.get(&row.inode)?.as_slice() else {
        return None;
    };
    let path = executable(*pid, row.inode)?;
    Some(ProcessInfo {
        name: Some(path.file_name()?.to_str()?.to_owned()),
        path: Some(path.to_str()?.to_owned()),
    })
}

/// The host hands this to the Core with its start inputs; the Core's worker
/// calls it for TUN flows and loopback listener clients alike.
#[derive(Debug, Default)]
pub struct LinuxFlowScanner;

impl FlowScanner for LinuxFlowScanner {
    fn scan(
        &self,
        flows: &[FlowKey],
        budget: Duration,
        stop: &AtomicBool,
    ) -> Vec<Option<ProcessInfo>> {
        let deadline = Instant::now() + budget;
        let mut rows = Vec::new();
        for (protocol, tables) in [
            (FlowProtocol::Tcp, ["/proc/net/tcp", "/proc/net/tcp6"]),
            (FlowProtocol::Udp, ["/proc/net/udp", "/proc/net/udp6"]),
        ] {
            if flows.iter().any(|flow| flow.protocol == protocol) {
                for table in tables {
                    // A missing table (e.g. IPv6 disabled) holds no sockets.
                    if let Ok(text) = std::fs::read_to_string(table) {
                        rows.extend(parse_table(&text, protocol));
                    }
                }
            }
        }
        rows.retain(|row| flows.iter().any(|flow| row_matches(row, flow)));
        let inodes: HashSet<u64> = rows.iter().map(|row| row.inode).collect();
        let holders = if inodes.is_empty() {
            Holders {
                complete: true,
                ..Default::default()
            }
        } else {
            scan_holders(&inodes, deadline, stop)
        };
        flows
            .iter()
            .map(|flow| resolve(flow, &rows, &holders, &mut executable))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex4(ip: Ipv4Addr) -> String {
        format!("{:08X}", u32::from_ne_bytes(ip.octets()))
    }

    fn hex6(ip: Ipv6Addr) -> String {
        ip.octets()
            .chunks(4)
            .map(|word| format!("{:08X}", u32::from_ne_bytes(word.try_into().unwrap())))
            .collect()
    }

    fn line(local: String, remote: String, inode: u64) -> String {
        format!("   0: {local} {remote} 01 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0000000000000000 20 4 30 10 -1")
    }

    fn table(lines: &[String]) -> String {
        let mut text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".to_owned();
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    fn flow(protocol: FlowProtocol, source: &str, destination: &str) -> FlowKey {
        let source: SocketAddr = source.parse().unwrap();
        let destination: SocketAddr = destination.parse().unwrap();
        FlowKey {
            protocol,
            source_ip: source.ip(),
            source_port: source.port(),
            destination_ip: destination.ip(),
            destination_port: destination.port(),
        }
    }

    fn holders(entries: &[(u64, &[u32])]) -> Holders {
        Holders {
            by_inode: entries
                .iter()
                .map(|(inode, pids)| (*inode, pids.to_vec()))
                .collect(),
            complete: true,
        }
    }

    fn exe(_: u32, _: u64) -> Option<PathBuf> {
        Some(PathBuf::from("/usr/bin/curl"))
    }

    #[test]
    fn decodes_kernel_endpoint_words_and_skips_descriptorless_rows() {
        let tun = Ipv4Addr::new(10, 255, 255, 1);
        let remote = Ipv4Addr::new(93, 184, 216, 34);
        let text = table(&[
            line(
                format!("{}:A1B2", hex4(tun)),
                format!("{}:01BB", hex4(remote)),
                4242,
            ),
            line(
                format!("{}:0050", hex4(tun)),
                format!("{}:01BB", hex4(remote)),
                0,
            ),
            "garbage".into(),
        ]);
        assert_eq!(
            parse_table(&text, FlowProtocol::Tcp),
            vec![SocketRow {
                protocol: FlowProtocol::Tcp,
                local: SocketAddr::new(tun.into(), 0xA1B2),
                remote: Some(SocketAddr::new(remote.into(), 443)),
                inode: 4242,
            }]
        );
        let v6: Ipv6Addr = "fd00:6572:6769:6f00::2".parse().unwrap();
        let mapped = Ipv4Addr::new(1, 1, 1, 1).to_ipv6_mapped();
        let rows = parse_table(
            &table(&[
                line(
                    format!("{}:1F90", hex6(v6)),
                    format!("{}:0000", hex6(Ipv6Addr::UNSPECIFIED)),
                    7,
                ),
                line(
                    format!("{}:1F91", hex6(tun.to_ipv6_mapped())),
                    format!("{}:0035", hex6(mapped)),
                    8,
                ),
            ]),
            FlowProtocol::Udp,
        );
        assert_eq!(rows[0].local, SocketAddr::new(v6.into(), 8080));
        assert_eq!(rows[0].remote, None);
        assert_eq!(rows[1].local, SocketAddr::new(tun.into(), 8081));
        assert_eq!(rows[1].remote, Some("1.1.1.1:53".parse().unwrap()));
    }

    #[test]
    fn single_visible_owner_is_attributed_and_ambiguity_stays_unknown() {
        let tcp = |local: &str, remote: &str, inode| SocketRow {
            protocol: FlowProtocol::Tcp,
            local: local.parse().unwrap(),
            remote: Some(remote.parse().unwrap()),
            inode,
        };
        let request = flow(FlowProtocol::Tcp, "10.255.255.1:40000", "93.184.216.34:443");
        let rows = [tcp("10.255.255.1:40000", "93.184.216.34:443", 1)];
        let info = resolve(&request, &rows, &holders(&[(1, &[10])]), &mut exe).unwrap();
        assert_eq!(info.name.as_deref(), Some("curl"));
        assert_eq!(info.path.as_deref(), Some("/usr/bin/curl"));
        // Shared descriptor across processes, unknown holder, incomplete scan.
        assert!(resolve(&request, &rows, &holders(&[(1, &[10, 11])]), &mut exe).is_none());
        assert!(resolve(&request, &rows, &holders(&[]), &mut exe).is_none());
        assert!(resolve(&request, &rows, &Holders::default(), &mut exe).is_none());
        // TCP needs the exact remote; another connection on the port is not it.
        let other = [tcp("10.255.255.1:40000", "1.1.1.1:443", 1)];
        assert!(resolve(&request, &other, &holders(&[(1, &[10])]), &mut exe).is_none());
    }

    /// procfs names this test process as the owner of a loopback client
    /// socket, keyed as a listener client is: the client's own address to
    /// the address it dialed. The accepted end of the same connection,
    /// reversed, is not that socket.
    #[cfg(target_os = "linux")]
    #[test]
    fn native_scanner_names_the_owner_of_a_loopback_client() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let key = FlowKey {
            protocol: FlowProtocol::Tcp,
            source_ip: client.local_addr().unwrap().ip(),
            source_port: client.local_addr().unwrap().port(),
            destination_ip: client.peer_addr().unwrap().ip(),
            destination_port: client.peer_addr().unwrap().port(),
        };
        let owners = LinuxFlowScanner.scan(
            std::slice::from_ref(&key),
            Duration::from_secs(1),
            &AtomicBool::new(false),
        );
        let expected = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(
            owners[0].as_ref().and_then(|owner| owner.path.as_deref()),
            expected.to_str()
        );
    }

    #[test]
    fn udp_wildcards_match_but_dual_stack_and_reuse_stay_unknown() {
        let udp = |local: &str, inode| SocketRow {
            protocol: FlowProtocol::Udp,
            local: local.parse().unwrap(),
            remote: None,
            inode,
        };
        let v4 = flow(FlowProtocol::Udp, "10.255.255.1:5353", "8.8.8.8:53");
        let v6 = flow(
            FlowProtocol::Udp,
            "[fd00:6572:6769:6f00::2]:5353",
            "[2001:db8::1]:53",
        );
        let all = holders(&[(1, &[10]), (2, &[10])]);
        assert!(resolve(&v4, &[udp("0.0.0.0:5353", 1)], &all, &mut exe).is_some());
        assert!(resolve(&v6, &[udp("[::]:5353", 2)], &all, &mut exe).is_some());
        assert!(resolve(&v4, &[udp("[::]:5353", 2)], &all, &mut exe).is_none());
        assert!(resolve(
            &v4,
            &[udp("0.0.0.0:5353", 1), udp("10.255.255.1:5353", 2)],
            &all,
            &mut exe
        )
        .is_none());
    }
}

//! Windows flow attribution from the IP Helper owner-PID tables.
//!
//! API basis (Microsoft Learn, `iphlpapi.h` / `processthreadsapi.h` /
//! `winbase.h`): `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` and
//! `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` for `AF_INET`/`AF_INET6`,
//! `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `GetProcessTimes` and
//! `QueryFullProcessImageNameW`. The tables describe current sockets, not an
//! authenticated sender: shared ports and mismatched owners stay unknown, and
//! an image path is reused only while the PID keeps its creation time.
#[cfg(any(windows, test))]
use std::net::{IpAddr, SocketAddr};

#[cfg(any(windows, test))]
use egrio_core::{FlowKey, FlowProtocol, ProcessInfo};

// Pure table logic: used by the IP Helper scan and its host tests.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketRow {
    local: SocketAddr,
    /// `None` for UDP rows, which have no connected peer in the table.
    remote: Option<SocketAddr>,
    pid: u32,
}

// Pure table logic: used by the IP Helper scan and its host tests.
#[cfg(any(windows, test))]
fn process_info_from_path(path: String) -> ProcessInfo {
    let name = path
        .rsplit(['\\', '/'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    ProcessInfo {
        name,
        path: Some(path),
    }
}

/// Folds an IPv4-mapped IPv6 row (a dual-stack socket) onto IPv4, so it
/// matches the IPv4 packets that socket actually sends.
// Pure table logic: used by the IP Helper scan and its host tests.
#[cfg(any(windows, test))]
fn unmap(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => address,
        },
        SocketAddr::V4(_) => address,
    }
}

/// The single owner of the client socket behind `flow`, or `None` when no
/// row or several different owners match.
// Pure table logic: used by the IP Helper scan and its host tests.
#[cfg(any(windows, test))]
fn owner_pid(rows: &[SocketRow], flow: &FlowKey) -> Option<u32> {
    let source = SocketAddr::new(flow.source_ip, flow.source_port);
    let destination = SocketAddr::new(flow.destination_ip, flow.destination_port);
    let unique = |mut candidates: Vec<u32>| {
        candidates.dedup();
        match candidates.as_slice() {
            [pid] if *pid != 0 => Some(*pid),
            _ => None,
        }
    };
    match flow.protocol {
        FlowProtocol::Tcp => unique(
            rows.iter()
                .filter(|row| row.local == source && row.remote == Some(destination))
                .map(|row| row.pid)
                .collect(),
        ),
        FlowProtocol::Udp => {
            let exact: Vec<u32> = rows
                .iter()
                .filter(|row| row.local == source)
                .map(|row| row.pid)
                .collect();
            if !exact.is_empty() {
                return unique(exact);
            }
            unique(
                rows.iter()
                    .filter(|row| {
                        row.local.port() == source.port()
                            && row.local.ip().is_unspecified()
                            && row.local.is_ipv4() == source.is_ipv4()
                    })
                    .map(|row| row.pid)
                    .collect(),
            )
        }
    }
}

#[cfg(windows)]
mod native {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use egrio_core::{FlowKey, FlowProtocol, FlowScanner, ProcessInfo};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{owner_pid, process_info_from_path, unmap, SocketRow};

    /// Attributes captured flows from the desktop process; no privileged
    /// service hop is involved. Same-user processes resolve; processes this
    /// user cannot open stay unknown.
    #[derive(Debug, Default)]
    pub struct WindowsFlowScanner {
        /// PID → (creation time, image). A reused PID has a new creation time.
        images: Mutex<HashMap<u32, (u64, ProcessInfo)>>,
    }

    impl FlowScanner for WindowsFlowScanner {
        fn scan(
            &self,
            flows: &[FlowKey],
            _budget: Duration,
            stop: &AtomicBool,
        ) -> Vec<Option<ProcessInfo>> {
            let needs = |protocol| flows.iter().any(|flow| flow.protocol == protocol);
            let tcp = if needs(FlowProtocol::Tcp) {
                tcp_rows()
            } else {
                Vec::new()
            };
            let udp = if needs(FlowProtocol::Udp) {
                udp_rows()
            } else {
                Vec::new()
            };
            flows
                .iter()
                .map(|flow| {
                    if stop.load(Ordering::Acquire) {
                        return None;
                    }
                    let rows = match flow.protocol {
                        FlowProtocol::Tcp => &tcp,
                        FlowProtocol::Udp => &udp,
                    };
                    self.image(owner_pid(rows, flow)?)
                })
                .collect()
        }
    }

    impl WindowsFlowScanner {
        fn image(&self, pid: u32) -> Option<ProcessInfo> {
            let process = Process::open(pid)?;
            let created = process.creation_time()?;
            let mut images = self.images.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((cached, info)) = images.get(&pid) {
                if *cached == created {
                    return Some(info.clone());
                }
            }
            let info = process_info_from_path(process.image_path()?);
            // Bounded: entries for exited PIDs are replaced on reuse and the
            // map is cleared if it ever grows past any realistic process count.
            if images.len() >= 4096 {
                images.clear();
            }
            images.insert(pid, (created, info.clone()));
            Some(info)
        }
    }

    struct Process(HANDLE);

    impl Process {
        fn open(pid: u32) -> Option<Self> {
            if pid == 0 {
                return None;
            }
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            (!handle.is_null()).then_some(Self(handle))
        }

        fn creation_time(&self) -> Option<u64> {
            let mut times = [FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            }; 4];
            let [created, exited, kernel, user] = &mut times;
            if unsafe { GetProcessTimes(self.0, created, exited, kernel, user) } == 0 {
                return None;
            }
            Some(u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
        }

        fn image_path(&self) -> Option<String> {
            let mut buffer = vec![0_u16; 32_768];
            let mut size = buffer.len() as u32;
            if unsafe { QueryFullProcessImageNameW(self.0, 0, buffer.as_mut_ptr(), &mut size) } == 0
                || size == 0
            {
                return None;
            }
            Some(String::from_utf16_lossy(&buffer[..size as usize]))
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn port(value: u32) -> u16 {
        let bytes = value.to_ne_bytes();
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    fn v4(address: u32, port_value: u32) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(address.to_ne_bytes())),
            port(port_value),
        )
    }

    fn v6(address: [u8; 16], port_value: u32) -> SocketAddr {
        unmap(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(address)),
            port(port_value),
        ))
    }

    fn tcp_rows() -> Vec<SocketRow> {
        let mut rows: Vec<SocketRow> =
            table::<MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID>(|buffer, size| unsafe {
                GetExtendedTcpTable(buffer, size, 0, AF_INET.into(), TCP_TABLE_OWNER_PID_ALL, 0)
            })
            .into_iter()
            .map(|row| SocketRow {
                local: v4(row.dwLocalAddr, row.dwLocalPort),
                remote: Some(v4(row.dwRemoteAddr, row.dwRemotePort)),
                pid: row.dwOwningPid,
            })
            .collect();
        rows.extend(
            table::<MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID>(|buffer, size| unsafe {
                GetExtendedTcpTable(buffer, size, 0, AF_INET6.into(), TCP_TABLE_OWNER_PID_ALL, 0)
            })
            .into_iter()
            .map(|row| {
                let local = v6(row.ucLocalAddr, row.dwLocalPort);
                let remote = v6(row.ucRemoteAddr, row.dwRemotePort);
                SocketRow {
                    local,
                    remote: Some(remote),
                    pid: row.dwOwningPid,
                }
            }),
        );
        rows
    }

    fn udp_rows() -> Vec<SocketRow> {
        let mut rows: Vec<SocketRow> =
            table::<MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID>(|buffer, size| unsafe {
                GetExtendedUdpTable(buffer, size, 0, AF_INET.into(), UDP_TABLE_OWNER_PID, 0)
            })
            .into_iter()
            .map(|row| SocketRow {
                local: v4(row.dwLocalAddr, row.dwLocalPort),
                remote: None,
                pid: row.dwOwningPid,
            })
            .collect();
        rows.extend(
            table::<MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID>(|buffer, size| unsafe {
                GetExtendedUdpTable(buffer, size, 0, AF_INET6.into(), UDP_TABLE_OWNER_PID, 0)
            })
            .into_iter()
            .map(|row| SocketRow {
                local: v6(row.ucLocalAddr, row.dwLocalPort),
                remote: None,
                pid: row.dwOwningPid,
            }),
        );
        rows
    }

    /// Reads one owner-PID table. Any failure yields no rows, which leaves
    /// every flow unknown rather than guessing from a partial table.
    fn table<Row: Copy, Table>(query: impl Fn(*mut c_void, &mut u32) -> u32) -> Vec<Row> {
        let mut size = 0_u32;
        // The table can grow between the size query and the read; retry a
        // few times with the size the API reports.
        for _ in 0..4 {
            let mut buffer = vec![0_u8; size as usize];
            let pointer = if buffer.is_empty() {
                ptr::null_mut()
            } else {
                buffer.as_mut_ptr().cast::<c_void>()
            };
            match query(pointer, &mut size) {
                NO_ERROR if !buffer.is_empty() => return rows::<Row, Table>(&buffer),
                NO_ERROR => return Vec::new(),
                ERROR_INSUFFICIENT_BUFFER => continue,
                _ => return Vec::new(),
            }
        }
        Vec::new()
    }

    fn rows<Row: Copy, Table>(buffer: &[u8]) -> Vec<Row> {
        if buffer.len() < std::mem::size_of::<u32>() {
            return Vec::new();
        }
        let count = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
        let offset = std::mem::size_of::<Table>() - std::mem::size_of::<Row>();
        let Some(end) = count
            .checked_mul(std::mem::size_of::<Row>())
            .and_then(|length| length.checked_add(offset))
        else {
            return Vec::new();
        };
        if end > buffer.len() {
            return Vec::new();
        }
        (0..count)
            .map(|index| unsafe {
                ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .add(offset + index * std::mem::size_of::<Row>())
                        .cast::<Row>(),
                )
            })
            .collect()
    }
}

#[cfg(windows)]
pub use native::WindowsFlowScanner;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn flow(protocol: FlowProtocol, source: SocketAddr, destination: SocketAddr) -> FlowKey {
        FlowKey {
            protocol,
            source_ip: source.ip(),
            source_port: source.port(),
            destination_ip: destination.ip(),
            destination_port: destination.port(),
        }
    }

    fn row(local: &str, remote: Option<&str>, pid: u32) -> SocketRow {
        SocketRow {
            local: local.parse().unwrap(),
            remote: remote.map(|remote| remote.parse().unwrap()),
            pid,
        }
    }

    /// The IP Helper scan names this test process as the owner of a loopback
    /// TCP connection and a connected UDP socket it holds.
    #[cfg(windows)]
    #[test]
    fn native_scanner_names_the_owner_of_local_sockets() {
        use egrio_core::FlowScanner;
        use std::net::{TcpListener, TcpStream, UdpSocket};
        use std::sync::atomic::AtomicBool;

        let expected = std::env::current_exe()
            .expect("test executable path")
            .display()
            .to_string();
        let scanner = WindowsFlowScanner::default();
        let owner = |flow: FlowKey| {
            scanner
                .scan(
                    &[flow],
                    std::time::Duration::from_millis(100),
                    &AtomicBool::new(false),
                )
                .pop()
                .flatten()
                .and_then(|process| process.path)
        };

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("TCP listener");
        let client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("TCP connect");
        let _accepted = listener.accept().expect("TCP accept");
        let tcp = flow(
            FlowProtocol::Tcp,
            client.local_addr().expect("TCP local address"),
            client.peer_addr().expect("TCP peer address"),
        );
        assert_eq!(owner(tcp).as_deref(), Some(expected.as_str()));

        let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP socket");
        udp_socket
            .connect((Ipv4Addr::LOCALHOST, 9))
            .expect("UDP connect");
        let udp = flow(
            FlowProtocol::Udp,
            udp_socket.local_addr().expect("UDP local address"),
            udp_socket.peer_addr().expect("UDP peer address"),
        );
        assert_eq!(owner(udp).as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn process_info_names_the_image_file_for_both_separators() {
        let info = process_info_from_path(r"C:\Program Files\curl\curl.exe".into());
        assert_eq!(info.name.as_deref(), Some("curl.exe"));
        assert_eq!(
            info.path.as_deref(),
            Some(r"C:\Program Files\curl\curl.exe")
        );
        assert_eq!(
            process_info_from_path("/usr/bin/curl".into())
                .name
                .as_deref(),
            Some("curl")
        );
    }

    #[test]
    fn tcp_requires_the_exact_four_tuple_and_a_single_owner() {
        let source = "10.255.255.1:54123".parse().unwrap();
        let fake = "198.18.0.9:443".parse().unwrap();
        let rows = [
            row("10.255.255.1:54123", Some("198.18.0.9:443"), 42),
            row("10.255.255.1:54123", Some("198.18.0.10:443"), 43),
        ];
        assert_eq!(
            owner_pid(&rows, &flow(FlowProtocol::Tcp, source, fake)),
            Some(42)
        );
        let shared = [
            rows[0],
            row("10.255.255.1:54123", Some("198.18.0.9:443"), 44),
        ];
        assert_eq!(
            owner_pid(&shared, &flow(FlowProtocol::Tcp, source, fake)),
            None
        );
        assert_eq!(
            owner_pid(
                &rows,
                &flow(FlowProtocol::Tcp, source, "1.1.1.1:443".parse().unwrap())
            ),
            None
        );
    }

    #[test]
    fn udp_prefers_the_exact_bind_then_a_unique_same_family_wildcard() {
        let source: SocketAddr = "10.255.255.1:5353".parse().unwrap();
        let remote = "8.8.8.8:53".parse().unwrap();
        let exact = [
            row("10.255.255.1:5353", None, 7),
            row("0.0.0.0:5353", None, 8),
        ];
        assert_eq!(
            owner_pid(&exact, &flow(FlowProtocol::Udp, source, remote)),
            Some(7)
        );
        let wildcard = [row("0.0.0.0:5353", None, 8), row("[::]:5353", None, 9)];
        assert_eq!(
            owner_pid(&wildcard, &flow(FlowProtocol::Udp, source, remote)),
            Some(8)
        );
        let reused = [row("0.0.0.0:5353", None, 8), row("0.0.0.0:5353", None, 10)];
        assert_eq!(
            owner_pid(&reused, &flow(FlowProtocol::Udp, source, remote)),
            None
        );
        assert_eq!(
            owner_pid(
                &[row("0.0.0.0:5353", None, 0)],
                &flow(FlowProtocol::Udp, source, remote)
            ),
            None
        );
    }

    #[test]
    fn dual_stack_rows_match_their_ipv4_packets() {
        let mapped = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(10, 255, 255, 1).to_ipv6_mapped()),
            54123,
        );
        assert_eq!(
            unmap(mapped),
            "10.255.255.1:54123".parse::<SocketAddr>().unwrap()
        );
        let native = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1);
        assert_eq!(unmap(native), native);
    }
}

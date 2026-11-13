//! Creating and addressing the utun, as root. A utun is a kernel control
//! socket of `com.apple.net.utun_control` (net/if_utun.h, sys/kern_control.h,
//! sys/sys_domain.h): connecting one with unit 0 creates the next free
//! interface, which lives as long as a descriptor of that socket is open.
//! The addresses and the MTU are set with ifconfig(8).

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use super::{
    MACOS_TUN_IPV4, MACOS_TUN_IPV4_PEER, MACOS_TUN_IPV4_PREFIX, MACOS_TUN_IPV6,
    MACOS_TUN_IPV6_PREFIX,
};

/// sys/sys_domain.h
const SYSPROTO_CONTROL: libc::c_int = 2;
/// net/if_utun.h
const UTUN_CONTROL_NAME: &CStr = c"com.apple.net.utun_control";
const UTUN_OPT_IFNAME: libc::c_int = 2;
/// The socket's buffers: packets the system routes into the tunnel wait in
/// the receive buffer until the Core reads them, and the kernel drops what no
/// longer fits (XNU kern_control.c `ctl_enqueuembuf`); a write larger than
/// the send buffer is refused outright. Both hold many full 64 KiB packets.
const SOCKET_BUFFER: libc::c_int = 4 * 1024 * 1024;
/// net/if_utun.h: "the number of packets that can be waiting to be read from
/// the control socket at a time".
const UTUN_OPT_MAX_PENDING_PACKETS: libc::c_int = 16;
/// XNU's default is one (if_utun.c `utun_ctl_bind`): `utun_start` stops
/// taking packets off the interface's send queue while one waits, so every
/// packet the system routes into the tunnel waits for the Core's previous
/// read. This bounded backlog lets the kernel enqueue a burst while the
/// Core is processing the previous packets.
const MAX_PENDING_PACKETS: libc::c_int = 16;

#[derive(Debug)]
pub(super) struct UtunInterface {
    socket: OwnedFd,
    name: String,
    index: u32,
}

impl UtunInterface {
    /// Creates a utun and gives it the tunnel's addresses and `mtu`.
    pub(super) fn create(mtu: u32) -> Result<Self, String> {
        let socket = open_control_socket().map_err(|error| format!("create a utun: {error}"))?;
        let name = interface_name(&socket).map_err(|error| format!("name the utun: {error}"))?;
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            set_option(&socket, libc::SOL_SOCKET, option, SOCKET_BUFFER)
                .map_err(|error| format!("size the utun socket buffers: {error}"))?;
        }
        set_option(
            &socket,
            SYSPROTO_CONTROL,
            UTUN_OPT_MAX_PENDING_PACKETS,
            MAX_PENDING_PACKETS,
        )
        .map_err(|error| format!("let packets queue on the utun: {error}"))?;
        let peer_mask = std::net::Ipv4Addr::from(u32::MAX << (32 - MACOS_TUN_IPV4_PREFIX));
        ifconfig(&[
            &name,
            "inet",
            &MACOS_TUN_IPV4.to_string(),
            &MACOS_TUN_IPV4_PEER.to_string(),
            "netmask",
            &peer_mask.to_string(),
            "mtu",
            &mtu.to_string(),
            "up",
        ])?;
        ifconfig(&[
            &name,
            "inet6",
            &MACOS_TUN_IPV6.to_string(),
            "prefixlen",
            &MACOS_TUN_IPV6_PREFIX.to_string(),
        ])?;
        let c_name = std::ffi::CString::new(name.clone()).map_err(|error| error.to_string())?;
        // SAFETY: a NUL-terminated interface name.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(format!("{name} has no interface index"));
        }
        Ok(Self {
            socket,
            name,
            index,
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn index(&self) -> u32 {
        self.index
    }

    /// Another descriptor of the utun socket, for the desktop: the interface
    /// lives until every descriptor is closed.
    pub(super) fn duplicate(&self) -> io::Result<OwnedFd> {
        // SAFETY: duplicates a descriptor this value owns.
        let duplicate = unsafe { libc::fcntl(self.socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}

fn open_control_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket creation.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: fcntl on the descriptor just created.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: an all-zero ctl_info is valid; the name fits its field.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (slot, byte) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME.to_bytes()) {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: CTLIOCGINFO fills `info`.
    if unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut info) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: an all-zero sockaddr_ctl is valid before its fields are set.
    let mut address: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    address.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
    address.sc_family = libc::AF_SYSTEM as u8;
    address.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    address.sc_id = info.ctl_id;
    // Unit 0: the next free utun.
    address.sc_unit = 0;
    // SAFETY: `address` is a complete sockaddr_ctl.
    let connected = unsafe {
        libc::connect(
            raw,
            std::ptr::from_ref(&address).cast(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if connected < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn interface_name(socket: &OwnedFd) -> io::Result<String> {
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `length` bytes into `name`.
    let got = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    CStr::from_bytes_until_nul(&name)
        .map(|name| name.to_string_lossy().into_owned())
        .map_err(|_| io::Error::other("utun name is not terminated"))
}

fn set_option(
    socket: &OwnedFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: setsockopt reads one int.
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if set < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ifconfig(arguments: &[&str]) -> Result<(), String> {
    let output = Command::new("/sbin/ifconfig")
        .args(arguments)
        .output()
        .map_err(|error| format!("run ifconfig: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "ifconfig {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

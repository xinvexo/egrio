//! Adding and deleting interface routes through a routing socket (route(4),
//! the layouts of net/route.h), as route(8) does without a process per route:
//! an `rt_msghdr`, then the destination, gateway and netmask addresses in that
//! order, each padded to four bytes, the netmask cut after its last nonzero
//! byte (network_cmds route.tproj/route.c `rtmsg`, `ROUNDUP`, `mask_addr`). An
//! interface route has no `RTF_GATEWAY` and names the interface's link address
//! as its gateway, which route(8) takes from getifaddrs(3) (`getaddr` with
//! `-interface`). The kernel refuses an add or a delete on the write itself,
//! and route(8) reads no reply to either.
//!
//! A reject route scoped to an interface (`-reject -ifscope`) adds
//! `RTF_REJECT` and `RTF_IFSCOPE` with the interface's index in `rtm_index`,
//! which `route_output` takes for the scope of an add or a delete (xnu
//! bsd/net/rtsock.c). Only a lookup scoped to that interface, that of a socket
//! bound with `IP_BOUND_IF` or `IPV6_BOUND_IF`, finds it, and a connect it
//! matches fails at once, while unbound sockets keep the utun's route.

use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use egrio_runtime::IpPrefix;

/// What a route does with its destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// Sends it out of the interface.
    Interface,
    /// Rejects it for sockets bound to the interface.
    RejectScoped,
}

/// Adds a route of `kind` on `interface`; one that is there already counts
/// as added.
pub(super) fn add(destination: IpPrefix, interface: &str, kind: Kind) -> io::Result<()> {
    match send(libc::RTM_ADD, destination, interface, kind) {
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        result => result,
    }
}

/// Deletes a route of `kind` on `interface`.
pub(super) fn delete(destination: IpPrefix, interface: &str, kind: Kind) -> io::Result<()> {
    send(libc::RTM_DELETE, destination, interface, kind)
}

fn send(
    message_type: libc::c_int,
    destination: IpPrefix,
    interface: &str,
    kind: Kind,
) -> io::Result<()> {
    let message = message(message_type, destination, interface, kind)?;
    // SAFETY: plain socket creation.
    let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: writes `message.len()` bytes from the buffer.
    let written =
        unsafe { libc::write(socket.as_raw_fd(), message.as_ptr().cast(), message.len()) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn message(
    message_type: libc::c_int,
    destination: IpPrefix,
    interface: &str,
    kind: Kind,
) -> io::Result<Vec<u8>> {
    let mut body = Vec::with_capacity(128);
    for address in [
        socket_address(destination.address),
        link_address(interface)?,
        netmask(destination),
    ] {
        let padded = round_up(address.len());
        body.extend_from_slice(&address);
        body.resize(body.len() + padded - address.len(), 0);
    }
    let header_length = std::mem::size_of::<libc::rt_msghdr>();
    let length = u16::try_from(header_length + body.len())
        .map_err(|_| io::Error::other("route message too long"))?;
    // SAFETY: an all-zero rt_msghdr is valid before its fields are set.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_msglen = length;
    header.rtm_version = libc::RTM_VERSION as u8;
    header.rtm_type = message_type as u8;
    header.rtm_flags = libc::RTF_UP | libc::RTF_STATIC;
    if kind == Kind::RejectScoped {
        header.rtm_flags |= libc::RTF_REJECT | libc::RTF_IFSCOPE;
        header.rtm_index = interface_index(interface)?;
    }
    header.rtm_addrs = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;
    header.rtm_seq = 1;
    let mut message = Vec::with_capacity(usize::from(length));
    // SAFETY: the header is plain old data of `header_length` bytes.
    message.extend_from_slice(unsafe {
        std::slice::from_raw_parts(std::ptr::from_ref(&header).cast::<u8>(), header_length)
    });
    message.extend_from_slice(&body);
    Ok(message)
}

/// route.c `ROUNDUP`: lengths padded to four bytes, an empty one taking four.
fn round_up(length: usize) -> usize {
    if length == 0 {
        4
    } else {
        1 + ((length - 1) | 3)
    }
}

/// A `sockaddr_in` or `sockaddr_in6`.
fn socket_address(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => {
            let mut bytes = vec![0u8; std::mem::size_of::<libc::sockaddr_in>()];
            bytes[0] = bytes.len() as u8;
            bytes[1] = libc::AF_INET as u8;
            bytes[4..8].copy_from_slice(&address.octets());
            bytes
        }
        IpAddr::V6(address) => {
            let mut bytes = vec![0u8; std::mem::size_of::<libc::sockaddr_in6>()];
            bytes[0] = bytes.len() as u8;
            bytes[1] = libc::AF_INET6 as u8;
            bytes[8..24].copy_from_slice(&address.octets());
            bytes
        }
    }
}

/// The prefix's mask as an address of its family, cut after its last
/// nonzero byte (route.c `mask_addr`).
fn netmask(prefix: IpPrefix) -> Vec<u8> {
    let mask = match prefix.address {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(
            u32::MAX
                .checked_shl(32 - u32::from(prefix.prefix_len))
                .unwrap_or(0),
        )),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(
            u128::MAX
                .checked_shl(128 - u32::from(prefix.prefix_len))
                .unwrap_or(0),
        )),
    };
    let mut bytes = socket_address(mask);
    let length = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    bytes.truncate(length);
    if let Some(first) = bytes.first_mut() {
        *first = length as u8;
    }
    bytes
}

/// The index of `interface`, which a scoped route names.
fn interface_index(interface: &str) -> io::Result<u16> {
    let name = std::ffi::CString::new(interface)
        .map_err(|_| io::Error::other(format!("{interface} is no interface name")))?;
    // SAFETY: a NUL-terminated name.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    u16::try_from(index).map_err(|_| io::Error::other(format!("{interface} has index {index}")))
}

/// A physical interface up now: a broadcast link (Wi-Fi, Ethernet, a
/// bridge), not a loopback or point-to-point one (utun and other tunnels),
/// with the families it has an address beyond the link in. The kernel
/// refuses a scoped route on an interface without an address of the route's
/// family (`ENETUNREACH`), and a socket bound to
/// one finds no route off the link anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PhysicalInterface {
    pub(super) name: String,
    pub(super) ipv4: bool,
    pub(super) ipv6: bool,
}

impl PhysicalInterface {
    /// Whether the interface has an address of `prefix`'s family.
    pub(super) fn carries(&self, prefix: &IpPrefix) -> bool {
        match prefix.address {
            IpAddr::V4(_) => self.ipv4,
            IpAddr::V6(_) => self.ipv6,
        }
    }
}

/// The physical interfaces up now with an address beyond the link.
pub(super) fn physical_interfaces() -> io::Result<Vec<PhysicalInterface>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut interfaces: Vec<PhysicalInterface> = Vec::new();
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        let flags = entry.ifa_flags as libc::c_int;
        let wanted = libc::IFF_UP | libc::IFF_BROADCAST;
        if entry.ifa_addr.is_null()
            || entry.ifa_name.is_null()
            || flags & wanted != wanted
            || flags & (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) != 0
        {
            continue;
        }
        // SAFETY: `ifa_addr` points at a sockaddr of at least its header.
        let (ipv4, ipv6) = match i32::from(unsafe { &*entry.ifa_addr }.sa_family) {
            libc::AF_INET => {
                // SAFETY: an AF_INET address is a whole sockaddr_in.
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                let address = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
                (!address.is_link_local(), false)
            }
            libc::AF_INET6 => {
                // SAFETY: an AF_INET6 address is a whole sockaddr_in6.
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                let address = Ipv6Addr::from(address.sin6_addr.s6_addr);
                (false, !address.is_unicast_link_local())
            }
            _ => continue,
        };
        if !ipv4 && !ipv6 {
            continue;
        }
        // SAFETY: the list's names are NUL-terminated.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        match interfaces
            .iter_mut()
            .find(|interface| interface.name == name)
        {
            Some(interface) => {
                interface.ipv4 |= ipv4;
                interface.ipv6 |= ipv6;
            }
            None => interfaces.push(PhysicalInterface {
                name: name.into_owned(),
                ipv4,
                ipv6,
            }),
        }
    }
    // SAFETY: frees the list getifaddrs returned; nothing refers to it now.
    unsafe { libc::freeifaddrs(list) };
    Ok(interfaces)
}

/// The `sockaddr_dl` getifaddrs(3) lists for `interface`.
fn link_address(interface: &str) -> io::Result<Vec<u8>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut found = None;
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: the list's names are NUL-terminated.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        // SAFETY: `ifa_addr` points at a sockaddr of at least its header.
        let address = unsafe { &*entry.ifa_addr };
        if i32::from(address.sa_family) == libc::AF_LINK && name.to_bytes() == interface.as_bytes()
        {
            // SAFETY: an AF_LINK address spans its own `sa_len` bytes.
            found = Some(
                unsafe {
                    std::slice::from_raw_parts(
                        entry.ifa_addr.cast::<u8>(),
                        usize::from(address.sa_len),
                    )
                }
                .to_vec(),
            );
        }
    }
    // SAFETY: frees the list getifaddrs returned; nothing refers to it now.
    unsafe { libc::freeifaddrs(list) };
    found.ok_or_else(|| io::Error::other(format!("{interface} has no link address")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> IpPrefix {
        text.parse().unwrap()
    }

    #[test]
    fn an_interface_route_names_the_link() {
        let interface =
            message(libc::RTM_ADD, prefix("128.0.0.0/1"), "lo0", Kind::Interface).unwrap();
        // SAFETY: the message starts with a whole rt_msghdr.
        let header = unsafe { &*interface.as_ptr().cast::<libc::rt_msghdr>() };
        assert_eq!(usize::from(header.rtm_msglen), interface.len());
        assert_eq!(header.rtm_flags & libc::RTF_GATEWAY, 0);
        assert_eq!(
            header.rtm_addrs,
            libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK
        );
        let body = &interface[std::mem::size_of::<libc::rt_msghdr>()..];
        assert_eq!(&body[..8], &[16, libc::AF_INET as u8, 0, 0, 128, 0, 0, 0]);
        assert_eq!(
            i32::from(body[17]),
            libc::AF_LINK,
            "the gateway is lo0's link address"
        );
        let link_length = round_up(usize::from(body[16]));
        assert_eq!(
            &body[16 + link_length..],
            &[5, libc::AF_INET as u8, 0, 0, 128, 0, 0, 0]
        );
    }

    #[test]
    fn a_scoped_reject_route_names_its_interface_index() {
        let reject = message(
            libc::RTM_ADD,
            prefix("198.18.0.0/16"),
            "lo0",
            Kind::RejectScoped,
        )
        .unwrap();
        // SAFETY: the message starts with a whole rt_msghdr.
        let header = unsafe { &*reject.as_ptr().cast::<libc::rt_msghdr>() };
        let wanted = libc::RTF_REJECT | libc::RTF_IFSCOPE;
        assert_eq!(header.rtm_flags & wanted, wanted);
        assert_eq!(header.rtm_flags & libc::RTF_GATEWAY, 0);
        // SAFETY: a NUL-terminated name.
        let lo0 = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
        assert_eq!(u32::from(header.rtm_index), lo0, "the scope is lo0's index");
    }

    #[test]
    fn loopback_and_tunnels_are_not_physical() {
        for interface in physical_interfaces().unwrap() {
            assert_ne!(interface.name, "lo0");
            assert!(!interface.name.starts_with("utun"), "{interface:?}");
            assert!(interface.ipv4 || interface.ipv6, "{interface:?}");
        }
    }

    #[test]
    fn masks_end_at_their_last_nonzero_byte() {
        assert_eq!(
            netmask(prefix("1.0.0.0/8")),
            vec![5, libc::AF_INET as u8, 0, 0, 255]
        );
        assert_eq!(netmask(prefix("100::/8")).len(), 9);
        assert_eq!(round_up(0), 4);
        assert_eq!(round_up(5), 8);
        assert_eq!(round_up(28), 28);
    }
}

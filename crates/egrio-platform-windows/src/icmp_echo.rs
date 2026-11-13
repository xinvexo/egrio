//! One ICMP echo from a chosen source address, through the IP Helper API
//! (`IcmpSendEcho2Ex` and `Icmp6SendEcho2`, icmpapi.h). Called with no event
//! and no APC routine the functions are synchronous: they return once a reply
//! arrived or the timeout passed, with the number of replies they stored at
//! the start of the reply buffer. The buffer holds one reply structure, the
//! echoed data, an ICMP error's 8 bytes and an `IO_STATUS_BLOCK`, as the
//! functions ask.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2Ex,
    ICMPV6_ECHO_REPLY_LH, ICMP_ECHO_REPLY, IP_SUCCESS,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

/// An ICMP error's 8 bytes and an `IO_STATUS_BLOCK`, with room to spare.
const REPLY_SLACK: usize = 64;

/// Sends one echo request carrying `payload` from `source` to `target` and
/// waits up to `wait` for its reply. Blocks.
pub(crate) fn echo(
    source: IpAddr,
    target: IpAddr,
    payload: &[u8],
    wait: Duration,
) -> Result<(), String> {
    let size = u16::try_from(payload.len()).map_err(|_| "ICMP echo payload is too large")?;
    let timeout = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX).max(1);
    match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => echo_v4(source, target, payload, size, timeout),
        (IpAddr::V6(source), IpAddr::V6(target)) => echo_v6(source, target, payload, size, timeout),
        _ => Err("ICMP echo source and target are of different families".into()),
    }
}

struct IcmpHandle(HANDLE);

impl IcmpHandle {
    fn open(handle: HANDLE, function: &str) -> Result<Self, String> {
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!("{function}: {}", std::io::Error::last_os_error()));
        }
        Ok(Self(handle))
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from IcmpCreateFile or Icmp6CreateFile and
        // is closed once.
        unsafe { IcmpCloseHandle(self.0) };
    }
}

/// A reply buffer aligned for the reply structures written at its start.
fn reply_buffer(reply: usize, payload: usize) -> Vec<u64> {
    vec![0; (reply + payload + REPLY_SLACK).div_ceil(8)]
}

fn no_reply() -> String {
    // SAFETY: GetLastError has no preconditions.
    let code = unsafe { GetLastError() };
    format!("no ICMP echo reply (IP Helper status {code})")
}

fn echo_v4(
    source: Ipv4Addr,
    target: Ipv4Addr,
    payload: &[u8],
    size: u16,
    timeout: u32,
) -> Result<(), String> {
    // SAFETY: IcmpCreateFile has no preconditions.
    let handle = IcmpHandle::open(unsafe { IcmpCreateFile() }, "IcmpCreateFile")?;
    let mut reply = reply_buffer(std::mem::size_of::<ICMP_ECHO_REPLY>(), payload.len());
    // IPAddr holds the address in network byte order, as in_addr does.
    let destination = u32::from_ne_bytes(target.octets());
    // SAFETY: the handle is open, and the request and reply buffers outlive
    // the synchronous call, which writes at most the reply size given.
    let replies = unsafe {
        IcmpSendEcho2Ex(
            handle.0,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            u32::from_ne_bytes(source.octets()),
            destination,
            payload.as_ptr().cast(),
            size,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            (reply.len() * 8) as u32,
            timeout,
        )
    };
    if replies == 0 {
        return Err(no_reply());
    }
    // SAFETY: the call stored at least one reply at the buffer's start, which
    // is aligned for it.
    let first = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
    if first.Status != IP_SUCCESS || first.Address != destination {
        return Err(format!("ICMP echo answered with status {}", first.Status));
    }
    Ok(())
}

fn echo_v6(
    source: Ipv6Addr,
    target: Ipv6Addr,
    payload: &[u8],
    size: u16,
    timeout: u32,
) -> Result<(), String> {
    // SAFETY: Icmp6CreateFile has no preconditions.
    let handle = IcmpHandle::open(unsafe { Icmp6CreateFile() }, "Icmp6CreateFile")?;
    let mut reply = reply_buffer(std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>(), payload.len());
    let (source, destination) = (sockaddr(source), sockaddr(target));
    // SAFETY: the handle is open, and the addresses, request and reply buffers
    // outlive the synchronous call, which writes at most the reply size given.
    let replies = unsafe {
        Icmp6SendEcho2(
            handle.0,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            &source,
            &destination,
            payload.as_ptr().cast(),
            size,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            (reply.len() * 8) as u32,
            timeout,
        )
    };
    if replies == 0 {
        return Err(no_reply());
    }
    // SAFETY: the call stored at least one reply at the buffer's start, which
    // is aligned for it.
    let first = unsafe { &*reply.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>() };
    let from = first.Address.sin6_addr;
    let from: Vec<u8> = from.iter().flat_map(|word| word.to_ne_bytes()).collect();
    if first.Status != IP_SUCCESS || from != target.octets() {
        let status = first.Status;
        return Err(format!("ICMP echo answered with status {status}"));
    }
    Ok(())
}

fn sockaddr(address: Ipv6Addr) -> SOCKADDR_IN6 {
    let mut sockaddr = SOCKADDR_IN6::default();
    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_addr.u.Byte = address.octets();
    sockaddr
}

//! UDP offloads for the Core's egress sockets (udp(7)): receive offload
//! (`UDP_GRO`, since Linux 5.0) reads the datagrams of one sender that arrive
//! together as one buffer, with a control message (cmsg(3), level `SOL_UDP`,
//! type `UDP_GRO`) holding the size of each datagram but the last; send
//! offload (`UDP_SEGMENT`, since Linux 4.18) sends a buffer as datagrams of
//! the size such a control message names, cut by the kernel or the NIC.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;

/// Turns receive offload on for the UDP socket `fd`; whether the kernel took it.
pub(crate) fn enable(fd: RawFd) -> bool {
    let on: libc::c_int = 1;
    // SAFETY: setsockopt reads one int from `on`.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_UDP,
            libc::UDP_GRO,
            std::ptr::from_ref(&on).cast(),
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    result == 0
}

/// One receive without blocking (the socket is non-blocking): the bytes read,
/// their sender, and the segment size the kernel reports, or the whole read
/// when it glued nothing. A read the kernel had to cut short is refused, as
/// its datagrams can no longer be told apart.
pub(crate) fn recv(fd: RawFd, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr, usize)> {
    // SAFETY: an all-zero sockaddr_storage and msghdr are valid values.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut vector = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // Room for the segment size's control message, aligned for cmsghdr.
    let mut control = [0_u64; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = std::ptr::from_mut(&mut address).cast();
    message.msg_namelen = std::mem::size_of_val(&address) as libc::socklen_t;
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: every pointer in `message` refers to a live local buffer.
    let read = unsafe { libc::recvmsg(fd, &mut message, 0) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a coalesced UDP read did not fit the buffer",
        ));
    }
    let read = read as usize;
    let mut segment = read;
    // SAFETY: the CMSG macros walk the control buffer the kernel filled,
    // within `msg_controllen`.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_UDP && (*header).cmsg_type == libc::UDP_GRO {
                let mut size: libc::c_int = 0;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(header),
                    std::ptr::from_mut(&mut size).cast::<u8>(),
                    std::mem::size_of_val(&size),
                );
                if size > 0 {
                    segment = size as usize;
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    Ok((read, sender(&address)?, segment))
}

/// Sends `payload` from the UDP socket `fd` (non-blocking) to `remote` as
/// datagrams of `segment` bytes each, the last one shorter, in one `sendmsg`:
/// the number of datagrams. The kernel refuses a train it cannot segment
/// (`EINVAL`, `EMSGSIZE` or `EIO`), and the caller then sends the datagrams
/// one by one.
pub(crate) fn send_segmented(
    fd: RawFd,
    payload: &[u8],
    segment: usize,
    remote: SocketAddr,
) -> io::Result<usize> {
    let size = u16::try_from(segment)
        .ok()
        .filter(|size| *size > 0)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let (mut address, address_len) = sockaddr(remote);
    let mut vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // Room for one u16 control message, aligned for cmsghdr.
    let mut control = [0_u64; 4];
    // SAFETY: an all-zero msghdr is a valid value.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = std::ptr::from_mut(&mut address).cast();
    message.msg_namelen = address_len;
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE only computes a size.
    message.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as _;
    // SAFETY: the control buffer holds one cmsghdr with a u16 behind it, as
    // CMSG_SPACE sized it; the CMSG macros stay within `msg_controllen`.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_UDP;
        (*header).cmsg_type = libc::UDP_SEGMENT;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            size.to_ne_bytes().as_ptr(),
            libc::CMSG_DATA(header),
            std::mem::size_of::<u16>(),
        );
    }
    // SAFETY: every pointer in `message` refers to a live local buffer, and
    // the payload is only read.
    let sent = unsafe { libc::sendmsg(fd, &message, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(payload.len().div_ceil(segment))
}

fn sockaddr(remote: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: an all-zero sockaddr_storage is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match remote {
        SocketAddr::V4(remote) => {
            // SAFETY: sockaddr_storage is large and aligned enough for any address.
            let address =
                unsafe { &mut *std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in>() };
            address.sin_family = libc::AF_INET as libc::sa_family_t;
            address.sin_port = remote.port().to_be();
            address.sin_addr.s_addr = u32::from(*remote.ip()).to_be();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(remote) => {
            // SAFETY: sockaddr_storage is large and aligned enough for any address.
            let address =
                unsafe { &mut *std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in6>() };
            address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            address.sin6_port = remote.port().to_be();
            address.sin6_flowinfo = remote.flowinfo().to_be();
            address.sin6_addr.s6_addr = remote.ip().octets();
            address.sin6_scope_id = remote.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn sender(address: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match libc::c_int::from(address.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says the storage holds a sockaddr_in.
            let address = unsafe { &*std::ptr::from_ref(address).cast::<libc::sockaddr_in>() };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
                u16::from_be(address.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the storage holds a sockaddr_in6.
            let address = unsafe { &*std::ptr::from_ref(address).cast::<libc::sockaddr_in6>() };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                u32::from_be(address.sin6_flowinfo),
                address.sin6_scope_id,
            )))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("UDP datagram from address family {family}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    fn a_segmented_send_arrives_as_its_datagrams() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let payload: Vec<u8> = (0..2500_u32).map(|i| i as u8).collect();
        let sent = send_segmented(
            sender.as_raw_fd(),
            &payload,
            1000,
            receiver.local_addr().unwrap(),
        )
        .unwrap();
        assert_eq!(sent, 3);
        let mut buffer = [0_u8; 2048];
        for chunk in payload.chunks(1000) {
            let (read, from) = receiver.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..read], chunk);
            assert_eq!(from, sender.local_addr().unwrap());
        }
    }

    #[test]
    fn a_segment_of_no_bytes_is_refused() {
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let error = send_segmented(
            sender.as_raw_fd(),
            &[1; 10],
            0,
            sender.local_addr().unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

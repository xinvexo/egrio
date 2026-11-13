use egrio_core::{PacketDevice, PacketInterest, PacketReady, PacketSend, ReceivedPacket};

#[cfg(target_os = "linux")]
use std::{
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
};
#[cfg(target_os = "linux")]
use tokio::io::{unix::AsyncFd, Interest};

#[cfg(target_os = "linux")]
use crate::vnet::{self, VNET_HDR_LEN};

/// The most queues a TUN takes (`MAX_TAP_QUEUES`, drivers/net/tun.c).
pub const LINUX_TUN_MAX_QUEUES: usize = 256;

/// One queue of an IFF_TUN | IFF_NO_PI | IFF_VNET_HDR | IFF_MULTI_QUEUE
/// device: either this process's own exclusive, non-persistent device, whose
/// last queue's close removes the interface and its connected routes, or an
/// attachment to a persistent device the Linux service created for this user.
/// Each queue is a descriptor of its own (`TUNSETIFF` with the same name,
/// "Multiqueue tuntap interface" in Documentation/networking/tuntap.rst); the
/// kernel keeps each flow on one of them by a hash of its addresses.
///
/// The descriptor is non-blocking; readiness comes from Tokio's `AsyncFd`
/// (epoll), registered lazily inside the pump's runtime. Each read or write
/// moves one frame: a virtio-net header and one IP packet
/// (`Documentation/networking/tuntap.rst`), or on reads the UDP datagrams the
/// kernel glued into one (see [`crate::vnet`]).
#[derive(Debug)]
pub struct LinuxTunDevice {
    name: String,
    #[cfg(target_os = "linux")]
    io: TunIo,
    #[cfg(target_os = "linux")]
    buffer: Vec<u8>,
    /// The kernel finishes the TCP checksums the Core leaves partial
    /// (`TUN_F_CSUM` accepted).
    #[cfg(target_os = "linux")]
    checksum_offload: bool,
    /// The kernel takes UDP trains (`TUN_F_USO4`/`TUN_F_USO6` accepted, so
    /// it knows `GSO_UDP_L4`).
    #[cfg(target_os = "linux")]
    udp_trains: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum TunIo {
    Unregistered(File),
    Registered(AsyncFd<File>),
    /// Only while switching state inside `ready`.
    Empty,
}

#[cfg(target_os = "linux")]
impl TunIo {
    /// Runs one non-blocking operation. Once registered, a `WouldBlock`
    /// result clears Tokio's readiness so the next `ready` really waits.
    fn operate<R>(
        &self,
        interest: Interest,
        operation: impl FnOnce(&File) -> std::io::Result<R>,
    ) -> std::io::Result<R> {
        match self {
            Self::Unregistered(file) => operation(file),
            Self::Registered(fd) => fd.try_io(interest, operation),
            Self::Empty => Err(std::io::Error::other("Linux TUN descriptor is unavailable")),
        }
    }
}

impl LinuxTunDevice {
    /// Creates this process's own exclusive, non-persistent TUN with
    /// `queues` queues, at least one.
    pub(crate) fn open(name: &str, queues: usize) -> Result<Vec<Self>, String> {
        #[cfg(target_os = "linux")]
        {
            // The first queue creates the device, which `IFF_TUN_EXCL`
            // refuses to share; the kernel then refuses the flag to the
            // queues that join it (drivers/net/tun.c, `tun_set_iff`).
            let mut devices = vec![Self::from_file(
                name,
                tun_file(
                    name,
                    QUEUE_FLAGS | libc::IFF_TUN_EXCL,
                    "create exclusive TUN",
                )?,
            )];
            for _ in 1..queues.clamp(1, LINUX_TUN_MAX_QUEUES) {
                let file = tun_file(name, QUEUE_FLAGS, "add a queue to TUN")?;
                devices.push(Self::from_file(name, file));
            }
            Ok(devices)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, queues);
            Err("/dev/net/tun is only available on Linux".into())
        }
    }

    /// Attaches `queues` queues, at least one, to an existing TUN, such as
    /// the persistent device the Linux service created owned by this user:
    /// the kernel lets the device's owner attach without `CAP_NET_ADMIN`
    /// (drivers/net/tun.c, `tun_permitted`). A missing device is an error:
    /// `TUNSETIFF` would create one for a caller that has `CAP_NET_ADMIN`.
    pub fn attach(name: &str, queues: usize) -> Result<Vec<Self>, String> {
        #[cfg(target_os = "linux")]
        {
            let interface =
                std::ffi::CString::new(name).map_err(|_| format!("invalid TUN name {name:?}"))?;
            if unsafe { libc::if_nametoindex(interface.as_ptr()) } == 0 {
                return Err(format!(
                    "attach to TUN {name}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // The first queue to attach sets the device's flags to these
            // (drivers/net/tun.c, `tun_set_iff`), so the persistent device
            // carries the header whatever it was created with.
            (0..queues.clamp(1, LINUX_TUN_MAX_QUEUES))
                .map(|_| {
                    tun_file(name, QUEUE_FLAGS, "attach to TUN")
                        .map(|file| Self::from_file(name, file))
                })
                .collect()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, queues);
            Err("/dev/net/tun is only available on Linux".into())
        }
    }

    /// Creates a persistent multi-queue TUN owned by `uid` and closes this
    /// process's descriptor (`TUNSETOWNER`, `TUNSETPERSIST`, linux/if_tun.h):
    /// the device stays until it is deleted, and only `uid` or a process with
    /// `CAP_NET_ADMIN` can attach queues to it.
    pub(crate) fn create_for_user(name: &str, uid: u32) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let file = tun_file(
                name,
                libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE | libc::IFF_TUN_EXCL,
                "create TUN",
            )?;
            for (request, argument, action) in [
                (
                    libc::TUNSETOWNER,
                    libc::c_ulong::from(uid),
                    "set the TUN owner",
                ),
                (libc::TUNSETPERSIST, 1, "make the TUN persistent"),
            ] {
                // The kernel reads these arguments as plain integers.
                if unsafe { libc::ioctl(file.as_raw_fd(), request, argument) } < 0 {
                    return Err(format!(
                        "{action} for {name}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, uid);
            Err("/dev/net/tun is only available on Linux".into())
        }
    }

    #[cfg(target_os = "linux")]
    fn from_file(name: &str, file: File) -> Self {
        let offloads = set_offload(&file);
        Self {
            name: name.into(),
            io: TunIo::Unregistered(file),
            buffer: vec![0; VNET_HDR_LEN + 65535],
            checksum_offload: offloads.is_some(),
            udp_trains: offloads.is_some_and(|offloads| offloads & libc::TUN_F_USO4 != 0),
        }
    }

    /// Writes one frame: the virtio-net header and the packet's parts.
    #[cfg(target_os = "linux")]
    fn write_frame(
        &mut self,
        header: &[u8; VNET_HDR_LEN],
        parts: &[&[u8]],
    ) -> Result<PacketSend, String> {
        if parts.len() > MAX_VECTORS {
            return Err(format!("Linux TUN packet in {} parts", parts.len()));
        }
        let length = VNET_HDR_LEN + parts.iter().map(|part| part.len()).sum::<usize>();
        let mut vectors = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; MAX_VECTORS + 1];
        vectors[0] = libc::iovec {
            iov_base: header.as_ptr() as *mut _,
            iov_len: VNET_HDR_LEN,
        };
        for (vector, part) in vectors[1..].iter_mut().zip(parts) {
            *vector = libc::iovec {
                iov_base: part.as_ptr() as *mut _,
                iov_len: part.len(),
            };
        }
        let count = (parts.len() + 1) as libc::c_int;
        match self.io.operate(Interest::WRITABLE, |file| {
            // SAFETY: every vector points at a buffer that outlives the call.
            let written = unsafe { libc::writev(file.as_raw_fd(), vectors.as_ptr(), count) };
            if written < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(written as usize)
            }
        }) {
            Ok(written) if written == length => Ok(PacketSend::Sent),
            Ok(_) => Err("Linux TUN wrote a partial packet".into()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(PacketSend::Full)
            }
            Err(error) => Err(format!("write Linux TUN packet: {error}")),
        }
    }
}

/// Offloads asked of the TUN, most first (`TUNSETOFFLOAD`,
/// uapi/linux/if_tun.h): partial checksums, TCP segments beyond the MTU and
/// glued UDP datagrams. The kernel refuses bits it does not know: USO came in
/// Linux 6.2, and `set_offload` (drivers/net/tun.c) takes it only for both
/// families at once.
#[cfg(target_os = "linux")]
const OFFLOADS: [libc::c_uint; 3] = [
    libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6 | libc::TUN_F_USO4 | libc::TUN_F_USO6,
    libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6,
    libc::TUN_F_CSUM,
];

/// Turns on the most offloads the kernel takes and returns them, each set
/// with checksums. Without any, frames still carry the header, all zero.
#[cfg(target_os = "linux")]
fn set_offload(file: &File) -> Option<libc::c_uint> {
    OFFLOADS.into_iter().find(|offloads| {
        // The kernel reads the argument as a plain integer.
        let result = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                libc::TUNSETOFFLOAD,
                libc::c_ulong::from(*offloads),
            )
        };
        result == 0
    })
}

/// The flags of every queue: a device created multi-queue takes only
/// queues that ask for it (drivers/net/tun.c, `tun_set_iff`).
#[cfg(target_os = "linux")]
const QUEUE_FLAGS: libc::c_int =
    libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR | libc::IFF_MULTI_QUEUE;

/// Opens `/dev/net/tun` non-blocking and binds it to `name` with `flags`
/// (`TUNSETIFF`, Documentation/networking/tuntap.rst).
#[cfg(target_os = "linux")]
fn tun_file(name: &str, flags: libc::c_int, action: &str) -> Result<File, String> {
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open /dev/net/tun: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (target, source) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *target = source as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = flags as libc::c_short;
    // Linux uapi/linux/if_tun.h; the libc request constant is ABI-specific.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
        return Err(format!(
            "{action} {name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

fn validate_packet(payload: &[u8]) -> Result<(), String> {
    validate_parts(&[payload])
}

fn validate_parts(parts: &[&[u8]]) -> Result<(), String> {
    let length: usize = parts.iter().map(|part| part.len()).sum();
    let version = parts
        .iter()
        .find_map(|part| part.first())
        .map(|byte| byte >> 4);
    if length > 65535 || !matches!(version, Some(4 | 6)) {
        return Err("Linux TUN expects one IPv4/IPv6 packet of at most 65535 bytes".into());
    }
    Ok(())
}

/// The parts of one packet the Core hands over: a TCP segment's header and
/// payload slices.
#[cfg(target_os = "linux")]
const MAX_VECTORS: usize = 16;

impl PacketDevice for LinuxTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, String> {
        #[cfg(target_os = "linux")]
        {
            loop {
                let buffer = &mut self.buffer;
                match self
                    .io
                    .operate(Interest::READABLE, |mut file| file.read(buffer))
                {
                    Ok(0) => return Err("Linux TUN descriptor closed".into()),
                    Ok(length) => {
                        // A frame this side cannot read is dropped like a
                        // lost packet; the device itself is fine.
                        if let Ok(received) = vnet::unpack(&self.buffer[..length]) {
                            if validate_packet(&received.bytes).is_ok() {
                                return Ok(Some(received));
                            }
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        return Ok(None)
                    }
                    Err(error) => return Err(format!("read Linux TUN packet: {error}")),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("Linux TUN is only available on Linux".into())
        }
    }

    fn try_send(&mut self, packet: &[u8]) -> Result<PacketSend, String> {
        validate_packet(packet)?;
        #[cfg(target_os = "linux")]
        {
            self.write_frame(&vnet::PLAIN, &[packet])
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("Linux TUN is only available on Linux".into())
        }
    }

    fn completes_tcp_checksums(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.checksum_offload
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Gathers the header and the parts in one `writev`; each write is one
    /// packet (Documentation/networking/tuntap.rst).
    fn try_send_parts(&mut self, parts: &[&[u8]]) -> Result<PacketSend, String> {
        validate_parts(parts)?;
        #[cfg(target_os = "linux")]
        {
            let header = match parts.first().and_then(|part| part.first()) {
                Some(byte) if self.checksum_offload => {
                    vnet::tcp_partial_checksum(if byte >> 4 == 4 { 20 } else { 40 })
                }
                _ => vnet::PLAIN,
            };
            self.write_frame(&header, parts)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("Linux TUN is only available on Linux".into())
        }
    }

    fn sends_udp_trains(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.udp_trains
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// One `GSO_UDP_L4` frame: the kernel cuts it into the datagrams.
    fn try_send_udp_train(
        &mut self,
        header: &[u8],
        payload: &[u8],
        segment: usize,
    ) -> Result<PacketSend, String> {
        validate_parts(&[header, payload])?;
        #[cfg(target_os = "linux")]
        {
            let ip_header_len = header.len().saturating_sub(8);
            if !self.udp_trains || segment == 0 || segment > usize::from(u16::MAX) {
                return Err("Linux TUN cannot take this UDP train".into());
            }
            self.write_frame(&vnet::udp_train(ip_header_len, segment), &[header, payload])
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = segment;
            Err("Linux TUN is only available on Linux".into())
        }
    }

    fn ready(&mut self, interest: PacketInterest) -> PacketReady<'_> {
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            {
                if let TunIo::Unregistered(_) = &self.io {
                    let TunIo::Unregistered(file) = std::mem::replace(&mut self.io, TunIo::Empty)
                    else {
                        unreachable!()
                    };
                    // SAFETY: the File owns its descriptor for the AsyncFd's
                    // whole lifetime and always reports the same fd.
                    let registered = unsafe { AsyncFd::register(file) }
                        .map_err(|error| format!("register Linux TUN with the reactor: {error}"))?;
                    self.io = TunIo::Registered(registered);
                }
                let TunIo::Registered(fd) = &self.io else {
                    return Err("Linux TUN descriptor is unavailable".into());
                };
                let wanted = match (interest.read, interest.write) {
                    (true, true) => Interest::READABLE | Interest::WRITABLE,
                    (false, true) => Interest::WRITABLE,
                    _ => Interest::READABLE,
                };
                fd.ready(wanted)
                    .await
                    .map(drop)
                    .map_err(|error| format!("wait for Linux TUN readiness: {error}"))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = interest;
                Err("Linux TUN is only available on Linux".into())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_boundary_accepts_only_ip_and_limits_allocation() {
        assert!(validate_packet(&[0x45; 20]).is_ok());
        assert!(validate_packet(&[0x60; 40]).is_ok());
        assert!(validate_packet(&[]).is_err());
        assert!(validate_packet(&[0x10; 40]).is_err());
        assert!(validate_packet(&vec![0x45; 65536]).is_err());
    }
}

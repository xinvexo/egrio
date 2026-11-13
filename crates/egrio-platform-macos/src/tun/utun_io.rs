//! Packets on the tunnel's utun socket, which the service handed over. Each
//! read or write is one packet behind a header: the protocol family in
//! network byte order, then the sender's UUID when
//! `UTUN_FLAGS_ENABLE_PROC_UUID` is set (net/if_utun.h; XNU if_utun.c
//! `UTUN_HEADER_SIZE`); the service creates the utun without it.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use egrio_core::PacketSend;
use tokio::io::{unix::AsyncFd, Interest};
use tokio::time::Instant;

/// sys/sys_domain.h
const SYSPROTO_CONTROL: libc::c_int = 2;
/// net/if_utun.h
const UTUN_OPT_FLAGS: libc::c_int = 1;
const UTUN_FLAGS_ENABLE_PROC_UUID: libc::c_int = 0x0004;
const FAMILY_HEADER: usize = 4;
const UUID_HEADER: usize = 16;
/// The utun header plus the parts of one packet the Core hands over: a TCP
/// segment's header and payload slices.
const MAX_VECTORS: usize = 16;

/// A write the kernel refuses for lack of room (ENOSPC, ENOBUFS) signals
/// nothing when room returns, so it is retried after this long; meanwhile
/// the packet waits and the TCP engine is held back instead of losing it.
const FULL_RETRY: Duration = Duration::from_millis(1);

#[derive(Debug)]
pub(super) struct UtunIo {
    io: AsyncFd<OwnedFd>,
    header: usize,
    retry_at: Option<Instant>,
}

impl UtunIo {
    pub(super) fn adopt(fd: OwnedFd) -> Result<Self, String> {
        let raw = fd.as_raw_fd();
        // SAFETY: fcntl on a descriptor this function owns.
        let status = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        // SAFETY: as above.
        if status < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, status | libc::O_NONBLOCK) } < 0 {
            return Err(format!(
                "make the utun non-blocking: {}",
                io::Error::last_os_error()
            ));
        }
        let mut flags: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&flags) as libc::socklen_t;
        // SAFETY: getsockopt writes one int into `flags`.
        let got = unsafe {
            libc::getsockopt(
                raw,
                SYSPROTO_CONTROL,
                UTUN_OPT_FLAGS,
                std::ptr::from_mut(&mut flags).cast(),
                &mut length,
            )
        };
        let header = if got == 0 && flags & UTUN_FLAGS_ENABLE_PROC_UUID != 0 {
            FAMILY_HEADER + UUID_HEADER
        } else {
            FAMILY_HEADER
        };
        // SAFETY: the OwnedFd owns its descriptor for the AsyncFd's whole
        // lifetime and always reports the same fd.
        let io = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }
            .map_err(|error| format!("register the utun: {error}"))?;
        Ok(Self {
            io,
            header,
            retry_at: None,
        })
    }

    /// One packet from the interface, or `None` when none is waiting.
    pub(super) fn try_recv(&self, buffer: &mut [u8]) -> Result<Option<Vec<u8>>, String> {
        loop {
            let read = self.io.try_io(Interest::READABLE, |fd| {
                // SAFETY: reads into `buffer`, which outlives the call.
                let read =
                    unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if read < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(read as usize)
                }
            });
            match read {
                Ok(0) => return Err("utun closed".into()),
                Ok(read) if read <= self.header => {}
                Ok(read) => return Ok(Some(buffer[self.header..read].to_vec())),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("read utun: {error}")),
            }
        }
    }

    /// Writes one packet given as consecutive parts, gathered behind the
    /// utun header in one `writev`, or reports `Full` while the input queue
    /// is full.
    pub(super) fn try_send_parts(&mut self, parts: &[&[u8]]) -> Result<PacketSend, String> {
        if parts.len() >= MAX_VECTORS {
            return Err(format!("utun packet in {} parts", parts.len()));
        }
        if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return Ok(PacketSend::Full);
        }
        self.retry_at = None;
        let version = parts
            .iter()
            .find_map(|part| part.first())
            .map_or(0, |byte| byte >> 4);
        let family = if version == 6 {
            libc::AF_INET6
        } else {
            libc::AF_INET
        } as u32;
        let mut header = [0u8; FAMILY_HEADER + UUID_HEADER];
        header[..FAMILY_HEADER].copy_from_slice(&family.to_be_bytes());
        let mut vectors = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; MAX_VECTORS];
        vectors[0] = libc::iovec {
            iov_base: header.as_mut_ptr().cast(),
            iov_len: self.header,
        };
        for (vector, part) in vectors[1..].iter_mut().zip(parts) {
            *vector = libc::iovec {
                iov_base: part.as_ptr() as *mut _,
                iov_len: part.len(),
            };
        }
        let count = (parts.len() + 1) as libc::c_int;
        loop {
            // SAFETY: every vector points at a buffer that outlives the call.
            if unsafe { libc::writev(self.io.get_ref().as_raw_fd(), vectors.as_ptr(), count) } >= 0
            {
                return Ok(PacketSend::Sent);
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::ENOSPC | libc::ENOBUFS | libc::EAGAIN) => {
                    self.retry_at = Some(Instant::now() + FULL_RETRY);
                    return Ok(PacketSend::Full);
                }
                _ => return Err(format!("write utun: {error}")),
            }
        }
    }

    /// Resolves when a packet may be waiting.
    pub(super) async fn readable(&self) -> Result<(), String> {
        let mut ready = self
            .io
            .readable()
            .await
            .map_err(|error| format!("wait for the utun: {error}"))?;
        ready.retain_ready();
        Ok(())
    }

    /// Resolves when a refused write may be retried; at once if none was.
    pub(super) async fn writable(&self) {
        if let Some(at) = self.retry_at {
            tokio::time::sleep_until(at).await;
        }
    }
}

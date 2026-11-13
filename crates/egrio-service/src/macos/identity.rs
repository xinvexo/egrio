//! Who may control the macOS service: the Egrio app signed by the service's
//! own team, and root, which could make the changes itself. The kernel keeps
//! the audit token of a socket's peer from `connect(2)` (sys/un.h
//! `LOCAL_PEERTOKEN`); Security finds the code running as that process
//! (`SecCodeCopyGuestWithAttributes` with `kSecGuestAttributeAudit`) and
//! checks it against a code requirement (`SecCodeCheckValidity`), so a
//! process that is replaced after it connected is judged as what it is then.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::str::FromStr;

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};

use crate::unix::{PeerCredentials, PeerPolicy};

/// sys/un.h
const LOCAL_PEERTOKEN: libc::c_int = 0x006;
/// bsm/audit.h `audit_token_t`: eight 32-bit words.
const AUDIT_TOKEN_BYTES: usize = 32;
/// Security/CSCommon.h
const SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
extern "C" {
    /// Security/SecCode.h; takes a dynamic code object as well.
    fn SecCodeCopySigningInformation(
        code: *const std::ffi::c_void,
        flags: u32,
        information: *mut core_foundation::dictionary::CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoTeamIdentifier: core_foundation::string::CFStringRef;
}

#[derive(Debug)]
pub struct SignedPeers {
    /// `None` when the service carries no team signature: then only root
    /// may connect.
    requirement: Option<String>,
}

impl SignedPeers {
    /// Requires the Egrio app signed by the team that signed this service.
    pub fn of_this_service() -> Self {
        let requirement = own_team().map(|team| {
            format!(
                "anchor apple generic and identifier \"{}\" and certificate leaf[subject.OU] = \"{team}\"",
                egrio_platform_macos::MACOS_APP_IDENTIFIER
            )
        });
        if requirement.is_none() {
            eprintln!("egrio-service: no team signature; only root may connect");
        }
        Self { requirement }
    }
}

impl PeerPolicy for SignedPeers {
    fn authorize(&self, stream: &UnixStream, peer: &PeerCredentials) -> Result<(), String> {
        if peer.uid == 0 {
            return Ok(());
        }
        let refused = |why: String| {
            Err(format!(
                "process {} may not control the Egrio service: {why}",
                peer.pid
            ))
        };
        let Some(requirement) = &self.requirement else {
            return refused("the service is not signed by a team".into());
        };
        let token = match audit_token(stream) {
            Ok(token) => token,
            Err(error) => return refused(format!("its audit token is unreadable: {error}")),
        };
        let requirement = match SecRequirement::from_str(requirement) {
            Ok(requirement) => requirement,
            Err(error) => return refused(format!("the code requirement is invalid: {error}")),
        };
        let mut attributes = GuestAttributes::new();
        let token = CFData::from_buffer(&token);
        attributes.set_audit_token(token.as_concrete_TypeRef());
        let code = match SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE) {
            Ok(code) => code,
            Err(error) => return refused(format!("its code is unknown: {error}")),
        };
        match code.check_validity(Flags::NONE, &requirement) {
            Ok(()) => Ok(()),
            Err(error) => refused(format!(
                "it is not the Egrio app signed by this team: {error}"
            )),
        }
    }
}

fn audit_token(stream: &UnixStream) -> std::io::Result<[u8; AUDIT_TOKEN_BYTES]> {
    let mut token = [0u8; AUDIT_TOKEN_BYTES];
    let mut length = AUDIT_TOKEN_BYTES as libc::socklen_t;
    // SAFETY: getsockopt writes at most `length` bytes into `token`.
    let got = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if got != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize != AUDIT_TOKEN_BYTES {
        return Err(std::io::Error::other("short audit token"));
    }
    Ok(token)
}

/// The team identifier of this process's signature.
fn own_team() -> Option<String> {
    let code = SecCode::for_self(Flags::NONE).ok()?;
    let mut information = std::ptr::null();
    // SAFETY: a live code object and an out pointer for a dictionary the
    // call creates.
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef().cast(),
            SIGNING_INFORMATION,
            &mut information,
        )
    };
    if status != 0 || information.is_null() {
        return None;
    }
    // SAFETY: the dictionary the call created, owned from here.
    let information: CFDictionary<CFString, core_foundation::base::CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(information) };
    // SAFETY: a constant string of the Security framework.
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoTeamIdentifier) };
    information
        .find(&key)
        .and_then(|team| team.downcast::<CFString>())
        .map(|team| team.to_string())
}

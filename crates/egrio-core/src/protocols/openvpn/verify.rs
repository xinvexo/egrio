//! The server certificate check an OpenVPN client makes (`ssl_verify.c`): a
//! chain to the config's `<ca>` and no host name — OpenVPN never matches the
//! remote's name — then, on the server's own certificate,
//! `remote-cert-tls server` (key usage present, extended key usage TLS Web
//! Server Authentication) and `verify-x509-name` (the subject's common name).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use super::config::X509Name;

#[derive(Debug)]
pub(super) struct ServerVerifier {
    roots: RootCertStore,
    name: Option<X509Name>,
    server_usage: bool,
    provider: Arc<CryptoProvider>,
}

impl ServerVerifier {
    pub(super) fn new(
        ca: &[CertificateDer<'static>],
        name: Option<X509Name>,
        server_usage: bool,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, String> {
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(ca.iter().cloned());
        if added == 0 {
            return Err("<ca> holds no usable certificate".into());
        }
        Ok(Self {
            roots,
            name,
            server_usage,
            provider,
        })
    }
}

fn refuse(reason: &str) -> rustls::Error {
    rustls::Error::General(format!("OpenVPN server certificate: {reason}"))
}

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        let leaf = Leaf::parse(end_entity.as_ref()).ok_or_else(|| refuse("unreadable"))?;
        if self.server_usage && !(leaf.key_usage && leaf.server_auth) {
            return Err(refuse(
                "remote-cert-tls server wants key usage and TLS Web Server Authentication",
            ));
        }
        let matches = match &self.name {
            None => true,
            Some(X509Name::CommonName(name)) => leaf.common_name.as_deref() == Some(name),
            Some(X509Name::CommonNamePrefix(prefix)) => leaf
                .common_name
                .as_deref()
                .is_some_and(|name| name.starts_with(prefix.as_str())),
        };
        if !matches {
            return Err(refuse(&format!(
                "common name {:?} fails verify-x509-name",
                leaf.common_name.unwrap_or_default()
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// What the checks read from the server's certificate (RFC 5280 §4.1).
#[derive(Debug, Default, PartialEq, Eq)]
struct Leaf {
    /// The subject's last common name, as OpenSSL's lookup returns it.
    common_name: Option<String>,
    key_usage: bool,
    server_auth: bool,
}

const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// One DER element: its tag, its contents and what follows it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0_usize, |length, &byte| length << 8 | byte as usize);
        (length, &rest[count..])
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
}

/// The elements of a constructed value.
fn elements(mut input: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let (tag, value, rest) = element(input)?;
        input = rest;
        Some((tag, value))
    })
}

impl Leaf {
    fn parse(der: &[u8]) -> Option<Self> {
        let (_, certificate, _) = element(der)?;
        let (_, tbs, _) = element(certificate)?;
        let mut fields = elements(tbs).peekable();
        // version [0], serial, signature, issuer, validity, subject.
        if fields.peek()?.0 == 0xa0 {
            fields.next();
        }
        let subject = fields.nth(4)?.1;
        let mut leaf = Leaf::default();
        for (_, set) in elements(subject) {
            for (_, attribute) in elements(set) {
                let mut parts = elements(attribute);
                let (_, oid) = parts.next()?;
                let (_, value) = parts.next()?;
                if oid == OID_COMMON_NAME {
                    leaf.common_name = Some(String::from_utf8_lossy(value).into_owned());
                }
            }
        }
        // subjectPublicKeyInfo, then the optional unique ids and [3] extensions.
        for (tag, value) in fields.skip(1) {
            if tag != 0xa3 {
                continue;
            }
            let (_, extensions, _) = element(value)?;
            for (_, extension) in elements(extensions) {
                let mut parts = elements(extension);
                let (_, oid) = parts.next()?;
                let mut contents = parts.next()?;
                if contents.0 == 0x01 {
                    contents = parts.next()?;
                }
                if oid == OID_KEY_USAGE {
                    leaf.key_usage = true;
                } else if oid == OID_EXTENDED_KEY_USAGE {
                    let (_, usages, _) = element(contents.1)?;
                    leaf.server_auth = elements(usages).any(|(_, usage)| usage == OID_SERVER_AUTH);
                }
            }
        }
        Some(leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(
        name: &str,
        usages: &[rcgen::ExtendedKeyUsagePurpose],
        key_usage: bool,
    ) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Example");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.extended_key_usages = usages.to_vec();
        if key_usage {
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        }
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    #[test]
    fn the_leaf_check_reads_common_name_and_usages() {
        let server = certificate(
            "server_sWFnLzeFMEgeiTSj",
            &[rcgen::ExtendedKeyUsagePurpose::ServerAuth],
            true,
        );
        assert_eq!(
            Leaf::parse(&server),
            Some(Leaf {
                common_name: Some("server_sWFnLzeFMEgeiTSj".into()),
                key_usage: true,
                server_auth: true,
            })
        );
        let client = certificate(
            "client",
            &[rcgen::ExtendedKeyUsagePurpose::ClientAuth],
            false,
        );
        assert_eq!(
            Leaf::parse(&client),
            Some(Leaf {
                common_name: Some("client".into()),
                key_usage: false,
                server_auth: false,
            })
        );
        assert_eq!(Leaf::parse(&server[..40]), None);
    }
}

//! The certificate-loading subsystem: turns an
//! operator's externally provided PEM certificate chain and private key into a
//! rustls server config for the encrypted server acceptors. No ACME, no
//! self-signing — the material is supplied out of band; this only parses and
//! validates it.
//!
//! Server-only: it lives behind the `server` feature, so a client build —
//! which never terminates an encrypted inbound — does not link it or its PEM
//! parser.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Builds a rustls server config from PEM cert-chain and private-key bytes,
/// advertising `alpn` (e.g. `[b"h3"]` for the Hysteria2 QUIC endpoint). Pins
/// the aws-lc-rs provider, the client hops' TLS backend (see `tls.rs`).
pub fn server_config_from_pem(
    cert_chain_pem: &[u8],
    private_key_pem: &[u8],
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, String> {
    let certs = rustls_pemfile::certs(&mut &cert_chain_pem[..])
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|error| format!("failed to parse certificate chain: {error}"))?;
    if certs.is_empty() {
        return Err("certificate chain contained no certificates".into());
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &private_key_pem[..])
        .map_err(|error| format!("failed to parse private key: {error}"))?
        .ok_or_else(|| "private-key material contained no key".to_string())?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("failed to select TLS protocol versions: {error}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| format!("failed to build server TLS config: {error}"))?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed cert + key, PEM-encoded, the way an operator would supply.
    pub(crate) fn self_signed_pem() -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .expect("params")
            .self_signed(&key_pair)
            .expect("self-signed cert");
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn loads_a_pem_chain_and_key_with_alpn() {
        let (cert_pem, key_pem) = self_signed_pem();
        let config = server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), &[b"h3"])
            .expect("server config builds");
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn rejects_material_with_no_certificate() {
        let (_cert_pem, key_pem) = self_signed_pem();
        let error = server_config_from_pem(b"not a certificate", key_pem.as_bytes(), &[b"h3"])
            .expect_err("empty chain rejected");
        assert!(error.contains("no certificates"), "{error}");
    }
}

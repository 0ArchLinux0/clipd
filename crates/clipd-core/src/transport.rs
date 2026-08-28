//! Transport: QUIC endpoints.
//!
//! ## Security model (phase 1)
//!
//! QUIC/TLS certificates are self-signed throwaways; **authentication happens
//! at the application layer**: both sides exchange a signed-off identity via
//! the protocol-level `Hello` frame and check it against the pinned peer store.
//! This deliberately trades X.509 plumbing simplicity for explicit app-layer
//! verification. See docs/ARCHITECTURE.md §Security model for the full threat
//! analysis and the phase-2 upgrade path (embed ed25519 pubkey into the cert
//! chain so TLS itself enforces pinning).
//!
//! The certificate verifier accepts ANY server cert (`AcceptAny`). This is safe
//! *only* because app-layer checks pin identity — never expose raw connections
//! outside `session.rs`, which performs verification before trusting any data.

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;

/// Verifier that accepts everything. Fine under app-layer auth only.
#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

fn make_self_signed_cert() -> Result<(CertificateDer<'static>, rustls::pki_types::PrivatePkcs8KeyDer<'static>)> {
    // rcgen's `KeyPair::generate()` defaults to ECDSA-P256, but the custom
    // verifier below only advertises ED25519 — that mismatch surfaces as
    // `NoSignatureSchemesInCommon` during the QUIC handshake (caught by the
    // in-process roundtrip tests). Force ED25519 to match.
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generating ED25519 key pair")?;
    let cert = rcgen::CertificateParams::new(vec!["clipd.local".into()])?
        .self_signed(&key_pair)
        .context("signing self-signed cert")?;
    Ok((
        CertificateDer::from(cert.der().to_vec()),
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    ))
}

/// Bind a QUIC server endpoint on `0.0.0.0:{port}` (port 0 → ephemeral).
pub async fn bind(port: u16) -> Result<Endpoint> {
    let (cert, key) = make_self_signed_cert()?;
    let server_config = quinn::ServerConfig::with_single_cert(vec![cert], key.into())?;
    let ep = Endpoint::server(server_config, format!("0.0.0.0:{port}").parse()?)?;
    Ok(ep)
}

/// Create a client endpoint and connect to `addr`.
///
/// TLS certs are NOT verified here by design — see module docs. Identity is
/// verified at the session layer against pinned peers.
pub async fn connect(addr: &str) -> Result<Connection> {
    let mut ep = Endpoint::client("0.0.0.0:0".parse()?)?;
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    )));

    let conn = ep
        .connect(addr.parse().context("bad peer addr")?, "clipd")
        .context("starting QUIC handshake")?
        .await
        .context("QUIC connect failed")?;
    Ok(conn)
}

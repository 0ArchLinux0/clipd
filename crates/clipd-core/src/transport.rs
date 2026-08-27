//! Transport: direct QUIC connections between paired devices.
//!
//! Phase 0 spike = plaintext-tolerant self-signed certs to prove plumbing.
//! Phase 1 replaces this with pinned peer certs: both sides embed the remote
//! ed25519 public key in their cert chain and verify against the pairing
//! store, so MITM is impossible without stealing an identity.key.

use anyhow::{Context, Result};
use quinn::Endpoint;

fn make_self_signed_cert() -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivatePkcs8KeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["clipd.local".into()])
        .context("generating self-signed cert")?;
    Ok((
        rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec()),
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    ))
}

/// Start a QUIC server on 0.0.0.0:`port`.
pub async fn serve(port: u16) -> Result<Endpoint> {
    let (cert, key) = make_self_signed_cert()?;
    let server_config = quinn::ServerConfig::with_single_cert(vec![cert], key.into())?;
    let ep = Endpoint::server(
        server_config,
        format!("0.0.0.0:{port}").parse()?,
    )?;
    Ok(ep)
}

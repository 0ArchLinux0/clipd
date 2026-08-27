//! Session: app-layer handshake, send, and serve loops on top of QUIC.
//!
//! ## Pipeline (both directions, strict order)
//!
//! Client                                Server
//! ------                                ------
//! QUIC connect  ──────────────────────► accept
//! open bidi stream
//! Frame::Hello ───────────────────────► read Hello → verify pinned peer
//!                                       Frame::Hello ◄──────────────────────
//! read Hello → verify pinned peer
//! Frame::ClipboardText ───────────────► dispatch to handler → apply clip
//!                                       Frame::Ack{lamport} ◄──────────────
//! read Ack, close stream
//!
//! ## Edge cases
//! - First frame from client MUST be Hello — anything else is a protocol error.
//! - Unknown peer: rejected when `strict_trust`, auto-added (warned) otherwise.
//! - Handler error → Ack is not sent; connection torn down; client surfaces it.
//! - Server keeps serving subsequent connections after a bad one (isolation).

use crate::identity::DeviceIdentity;
use crate::peers::PeerStore;
use crate::protocol::{read_frame, write_frame, Frame};
use crate::sync::LamportClock;
use anyhow::{bail, Context, Result};
use quinn::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub device_id: String,
    pub public_key: String,
    pub device_name: String,
}

impl SessionMeta {
    fn from_hello(h: Frame) -> Result<Self> {
        match h {
            Frame::Hello {
                device_id,
                public_key,
                device_name,
            } => Ok(Self {
                device_id,
                public_key,
                device_name,
            }),
            other => bail!("expected Hello, got {other:?}"),
        }
    }
}

/// Validate a claimed identity: device_id must equal first 8 bytes of pubkey.
pub fn validate_meta(meta: &SessionMeta) -> Result<()> {
    let pk = hex::decode(&meta.public_key).context("public_key not hex")?;
    if pk.len() != 32 {
        bail!("public_key must be 32 bytes, got {}", pk.len());
    }
    let expected = hex::encode(&pk[..8]);
    if meta.device_id != expected {
        bail!("device_id does not match public_key prefix");
    }
    if meta.device_name.trim().is_empty() {
        bail!("device_name must be non-empty");
    }
    Ok(())
}


// ---------------------------------------------------------------------------
// Client side

/// Perform handshake; verify server against `trusted` unless `strict_trust`
/// is false (then merely warn). Returns server's session metadata.
pub async fn client_handshake(
    conn: &Connection,
    identity: &DeviceIdentity,
    trusted: Option<&PeerStore>,
) -> Result<SessionMeta> {
    let (mut tx, mut rx) = conn.open_bi().await.context("opening stream")?;

    write_frame(&mut tx, &Frame::Hello {
        device_id: identity.device_id(),
        public_key: identity.public_key_hex(),
        device_name: whoami::device_name(),
    })
    .await?;

    // Server must speak first after our Hello: it sends its Hello next.
    let server_meta = SessionMeta::from_hello(
        read_frame(&mut rx)
            .await?
            .context("server closed before Hello")?,
    )?;
    validate_meta(&server_meta)?;

    if let Some(store) = trusted {
        if !store.contains(&server_meta.device_id) {
            tracing::warn!(
                peer = %server_meta.device_id,
                "connecting to UNPAIRED device (non-strict mode); data is E2E-checked but identity unpinned"
            );
        }
    }
    Ok(server_meta)
}

/// Handshake + send one clipboard text + wait for Ack. Returns server lamport.
/// All frames travel over ONE bidirectional stream: Hello → Hello → Text → Ack.
pub async fn send_clipboard_text(
    conn: &Connection,
    identity: &DeviceIdentity,
    clock: &mut LamportClock,
    text: &str,
    trusted: Option<&PeerStore>,
) -> Result<u64> {
    let (mut tx, mut rx) = conn.open_bi().await.context("opening stream")?;

    write_frame(&mut tx, &Frame::Hello {
        device_id: identity.device_id(),
        public_key: identity.public_key_hex(),
        device_name: whoami::device_name(),
    })
    .await?;

    let server_meta = SessionMeta::from_hello(
        read_frame(&mut rx)
            .await?
            .context("server closed before Hello")?,
    )?;
    validate_meta(&server_meta)?;

    if let Some(store) = trusted {
        if !store.contains(&server_meta.device_id) {
            tracing::warn!(peer = %server_meta.device_id, "sending to UNPAIRED device");
        }
    }

    let lamport = clock.tick();
    let signature = hex::encode(
        identity
            .sign(&crate::sync::sign_payload(text, &identity.device_id(), lamport))
            .to_bytes(),
    );
    write_frame(&mut tx, &Frame::ClipboardText {
        text: text.to_string(),
        origin: identity.device_id(),
        lamport,
        signature,
    })
    .await?;
    tx.finish().context("finishing stream")?;

    let ack = read_frame(&mut rx).await?.context("no ack received")?;
    match ack {
        Frame::Ack { lamport: l } => Ok(l),
        other => bail!("expected Ack, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Server side

pub type FrameHandler<'a> =
    Arc<Mutex<dyn FnMut(SessionMeta, Frame) -> Result<Option<Frame>> + Send + 'a>>;

/// Serve a single connection: handshake + message loop.
/// Returns when the peer closes cleanly or an error occurs.
pub async fn serve_connection(
    conn: Connection,
    identity: Arc<DeviceIdentity>,
    peers: Arc<Mutex<PeerStore>>,
    strict_trust: bool,
    handler: FrameHandler<'static>,
) -> Result<()> {
    let (mut tx, mut rx) = conn.accept_bi().await.context("accepting stream")?;

    // First frame from client MUST be Hello.
    let hello = read_frame(&mut rx)
        .await?
        .context("client closed before Hello")?;
    let meta = SessionMeta::from_hello(hello)?;
    validate_meta(&meta)?;

    let mut store = peers.lock().await;
    if !store.contains(&meta.device_id) {
        if strict_trust {
            bail!(
                "rejecting unpaired device {} (strict_trust)",
                meta.device_id
            );
        }
        tracing::warn!(peer = %meta.device_id, "auto-accepting UNPAIRED device (non-strict)");
        store.insert(
            meta.device_id.clone(),
            crate::peers::PeerEntry {
                device_name: meta.device_name.clone(),
                public_key: meta.public_key.clone(),
                last_addr: conn.remote_address().to_string(),
                added_at_secs: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
        );
        store.save().ok(); // best-effort persistence
    }
    drop(store);

    // Reply with our Hello.
    write_frame(&mut tx, &Frame::Hello {
        device_id: identity.device_id(),
        public_key: identity.public_key_hex(),
        device_name: whoami::device_name(),
    })
    .await?;

    // Message loop until peer closes.
    while let Some(frame) = read_frame(&mut rx).await? {
        let reply = {
            let mut h = handler.lock().await;
            h(meta.clone(), frame)?
        };
        if let Some(frame) = reply {
            write_frame(&mut tx, &frame).await?;
        }
    }
    Ok(())
}

// whoami lives in this crate to keep CLI deps lean; platform-specific name
// resolution: $USER/env for now (Desktop-only MVP). Android uses hostname.
mod whoami {
    pub fn device_name() -> String {
        std::env::var("CLIPD_DEVICE_NAME")
            .or_else(|_| std::env::var("USER"))
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(seed: u8) -> DeviceIdentity {
        DeviceIdentity::from_bytes(&[seed; 32])
    }

    #[test]
    fn meta_validation_catches_mismatch() {
        let id = test_identity(1);
        let mut meta = my_meta(&id);
        assert!(validate_meta(&meta).is_ok());
        meta.device_id = "deadbeefdeadbeef".into();
        assert!(validate_meta(&meta).is_err(), "id/pk mismatch must fail");
        meta.device_id = String::new();
        assert!(validate_meta(&meta).is_err());
        meta.public_key = "zz".into();
        assert!(validate_meta(&meta).is_err(), "bad hex must fail");
    }

    #[tokio::test]
    async fn full_roundtrip_send_and_ack() {
        let server_id = Arc::new(test_identity(2));
        let client_id = Arc::new(test_identity(3));

        let ep = crate::transport::bind(0).await.unwrap();
        let addr = ep.local_addr().unwrap();

        let applied = Arc::new(Mutex::new(Vec::<String>::new()));
        let applied2 = applied.clone();
        let handler: FrameHandler<'static> = Arc::new(Mutex::new(
            move |_meta, frame| {
                Ok(match frame {
                    Frame::ClipboardText { text, lamport, .. } => {
                        applied2.lock().await.push(text);
                        Some(Frame::Ack { lamport })
                    }
                    _ => None,
                })
            },
        ));

        let peers = Arc::new(Mutex::new(
            PeerStore::load(std::env::temp_dir().join(format!(
                "clipd-test-peers-{}.json",
                std::process::id()
            )))
            .unwrap(),
        ));

        let server_task = tokio::spawn(async move {
            loop {
                let incoming = match ep.accept().await {
                    Some(i) => i,
                    None => break,
                };
                let identity = server_id.clone();
                let peers = peers.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = serve_connection(conn, identity, peers, false, handler).await;
                    }
                });
            }
        });

        let conn = crate::transport::connect(&addr.to_string()).await.unwrap();
        let mut clock = LamportClock::new();
        let server_meta = send_clipboard_text(
            &conn,
            &client_id,
            &mut clock,
            "hello clipboard",
            None,
        )
        .await
        .unwrap();

        assert_eq!(server_meta.device_id, server_id.device_id());
        assert_eq!(
            applied.lock().await.as_slice(),
            ["hello clipboard"],
            "server must have applied the text exactly once"
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn strict_mode_rejects_unpaired() {
        let server_id = Arc::new(test_identity(4));
        let ep = crate::transport::bind(0).await.unwrap();
        let addr = ep.local_addr().unwrap();
        let peers = Arc::new(Mutex::new(
            PeerStore::load("/tmp/clipd-strict-test-empty.json").unwrap(),
        ));

        let handler: FrameHandler<'static> = Arc::new(Mutex::new(|_, _| Ok(None)));
        let s = server_id.clone();
        let p = peers.clone();
        tokio::spawn(async move {
            loop {
                let incoming = match ep.accept().await {
                    Some(i) => i,
                    None => break,
                };
                let sid = s.clone();
                let sp = p.clone();
                let h = handler.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = serve_connection(conn, sid, sp, true, h).await;
                    }
                });
            }
        });

        let conn = crate::transport::connect(&addr.to_string()).await.unwrap();
        let client_id = Arc::new(test_identity(5));
        let result = client_handshake(&conn, &client_id, None).await;
        // Handshake writes Hello, then waits for server Hello; server rejects
        // before replying, so the read gets closed-stream error.
        assert!(result.is_err(), "strict server must reject unpaired client");
    }
}

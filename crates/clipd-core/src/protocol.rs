//! Wire protocol: length-prefixed JSON frames over a QUIC stream.
//!
//! Frame layout on the wire:
//! ```text
//! [u32 BE: payload_len][payload_len bytes of UTF-8 JSON]
//! ```
//!
//! Edge cases handled (see docs/ARCHITECTURE.md §Edge cases):
//! - Oversized frames rejected immediately (defends against memory blowup)
//! - Clean EOF at frame boundary → `Ok(None)` (peer closed the stream)
//! - Truncated frame mid-body → error (connection corrupted)

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 16 MiB — text MVP cap; file transfer will use chunking, not this frame type.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    /// Sent as the FIRST message in both directions after QUIC connect.
    Hello {
        /// hex of first 8 bytes of ed25519 public key
        device_id: String,
        /// full hex ed25519 public key (64 chars)
        public_key: String,
        device_name: String,
    },
    ClipboardText {
        text: String,
        origin: String,
        lamport: u64,
        /// hex ed25519 signature over H(domain || origin || lamport || SHA256(text))
        signature: String,
    },
    Ack { lamport: u64 },
}

/// Serialize + write one frame.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<()>
where
    W: AsyncWriteExt + Unpin + Send,
{
    let json = serde_json::to_vec(frame).context("serializing frame")?;
    if json.len() > MAX_FRAME_BYTES {
        bail!("frame too large: {} bytes", json.len());
    }
    writer.write_u32(json.len() as u32).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame. Returns `Ok(None)` on clean EOF exactly at a boundary.
pub async fn read_frame<R>(reader: &mut R) -> Result<Option<Frame>>
where
    R: AsyncReadExt + Unpin + Send,
{
    // Detect EOF at frame boundary: read the first byte non-blocking-ish.
    match reader.read_u8().await {
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(first) => {
            // first byte is MSB of the length prefix; read remaining 3 bytes.
            let mut len_bytes = [first, 0, 0, 0];
            reader.read_exact(&mut len_bytes[1..]).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            if len > MAX_FRAME_BYTES {
                bail!("frame claims {} bytes > limit {}", len, MAX_FRAME_BYTES);
            }
            if len == 0 {
                bail!("zero-length frame is invalid");
            }
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await.context("frame body truncated")?;
            let frame: Frame =
                serde_json::from_slice(&buf).context("deserializing frame")?;
            Ok(Some(frame))
        }
    }
}

// ---------------------------------------------------------------------------
// Blocking variants for tests / CLI tools using std::io.

pub fn write_frame_blocking(writer: &mut impl std::io::Write, frame: &Frame) -> Result<()> {
    let json = serde_json::to_vec(frame)?;
    if json.len() > MAX_FRAME_BYTES {
        bail!("frame too large");
    }
    writer.write_all(&(json.len() as u32).to_be_bytes())?;
    writer.write_all(&json)?;
    Ok(())
}

pub fn read_frame_blocking(reader: &mut impl std::io::Read) -> Result<Option<Frame>> {
    let mut len_bytes = [0u8; 4];
    match reader.read(&mut len_bytes)? {
        0 => return Ok(None), // clean EOF at boundary
        n => {
            // Partial header reads are possible from pipes/buffers.
            let mut got = n;
            while got < 4 {
                got += reader.read(&mut len_bytes[got..])?;
            }
        }
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 {
        bail!("zero-length frame");
    }
    if len > MAX_FRAME_BYTES {
        bail!("oversized frame: {len}");
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(serde_json::from_slice(&buf)?))
}

fn _assert_send<T: DeserializeOwned>() {}
#[allow(dead_code)]
fn _compile_checks() {
    _assert_send::<Frame>();
    fn f<T: Serialize>(_t: &T) {}
    f::<Frame>(&Frame::Ack { lamport: 0 });
}

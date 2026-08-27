//! clipd-core: transport, discovery, crypto, sync engine.
//!
//! Module map (the "main pipeline"):
//!
//! - `identity`  → per-device ed25519 keypair (`identity.key`)
//! - `discovery` → mDNS advertise/scan on the LAN
//! - `transport` → QUIC endpoints (TLS is throwaway; see module docs)
//! - `protocol`  → length-prefixed JSON frames (Hello / ClipboardText / Ack)
//! - `session`   → handshake pipeline + send/serve loops, trust checks
//! - `sync`      → Lamport clock, echo-loop guard, signed receive policy
//! - `peers`     → persistent pin store of paired devices
//! - `sas`       → 6-digit pairing code (short authentication string)

pub mod discovery;
pub mod identity;
pub mod peers;
pub mod protocol;
pub mod sas;
pub mod session;
pub mod sync;
pub mod transport;

pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

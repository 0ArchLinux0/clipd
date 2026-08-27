//! clipd-core: transport, discovery, crypto, sync engine.

pub mod discovery;
pub mod identity;
pub mod transport;

pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

//! Persistent store of paired (trusted) devices.
//!
//! Stored as JSON: { device_id_hex -> PeerEntry }.
//!
//! Edge cases:
//! - Corrupt file → treated as empty store; original file renamed to `.corrupt`
//!   so the data is recoverable by hand instead of silently overwritten later.
//! - Concurrent writers → writes are atomic via temp-file + rename.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    pub device_name: String,
    /// full hex public key
    pub public_key: String,
    /// last known reachable "ip:port"
    pub last_addr: String,
    /// unix seconds when first paired
    pub added_at_secs: u64,
}

#[derive(Debug)]
pub struct PeerStore {
    path: PathBuf,
    peers: BTreeMap<String, PeerEntry>,
}

impl PeerStore {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let peers = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<BTreeMap<String, PeerEntry>>(&bytes) {
                Ok(map) => map,
                Err(e) => {
                    let backup = path.with_extension("json.corrupt");
                    tracing::warn!(
                        error = %e,
                        backup = %backup.display(),
                        "peer store corrupt; starting empty, backing up old file"
                    );
                    let _ = std::fs::rename(&path, &backup);
                    BTreeMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).context("reading peer store"),
        };
        Ok(Self { path, peers })
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.peers)?)?;
        // Atomic on same filesystem: rename is the commit point.
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, device_id: &str) -> Option<&PeerEntry> {
        self.peers.get(device_id)
    }

    pub fn contains(&self, device_id: &str) -> bool {
        self.peers.contains_key(device_id)
    }

    pub fn insert(&mut self, device_id: String, entry: PeerEntry) {
        self.peers.insert(device_id, entry);
    }

    pub fn remove(&mut self, device_id: &str) -> bool {
        self.peers.remove(device_id).is_some()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &PeerEntry)> {
        self.peers.iter()
    }
}

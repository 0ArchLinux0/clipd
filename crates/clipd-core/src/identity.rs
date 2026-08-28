//! Identity: per-device keypair and fingerprint.
//!
//! Each device holds an ed25519 keypair generated on first run and stored in
//! the OS keychain (phase 2). Pairing pins the remote device's public key,
//! so all future sessions authenticate against known peers only.
//!
//! TODO(phase-2): move key storage into OS keychain (Keychain / Credential
//! Manager / Android Keystore) instead of a flat file.

use anyhow::Context;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    /// Generate a fresh identity (first launch).
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Short human-comparable fingerprint shown during pairing
    /// (e.g., "7F 2A 9C"). Derived from the first bytes of the public key.
    pub fn pairing_fingerprint(&self) -> String {
        let vk = self.public();
        let bytes = vk.as_bytes();
        bytes
            .iter()
            .take(6)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Full hex public key (64 chars).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public().as_bytes())
    }

    /// Short hex device id: first 8 bytes of the public key (16 chars).
    pub fn device_id(&self) -> String {
        hex::encode(&self.public().as_bytes()[..8])
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        self.public().verify(msg, sig).is_ok()
    }

    pub fn save_to_dir(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("identity.key"), self.seed()).context("writing identity.key")
    }

    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        let path: PathBuf = dir.join("identity.key");
        if path.exists() {
            let seed: [u8; 32] = std::fs::read(&path)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity.key has wrong length"))?;
            Ok(Self::from_bytes(&seed))
        } else {
            let id = Self::generate();
            id.save_to_dir(dir)?;
            Ok(id)
        }
    }
}

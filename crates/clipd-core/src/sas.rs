//! Pairing code: a Short Authentication String (SAS).
//!
//! Both devices compute `pairing_code(my_pubkey, their_pubkey)` and display it.
//! If the two codes match AND each side verifies the other's fingerprint by eye,
//! an active MITM must have chosen keypairs colliding on both hashes — assumed
//! computationally impossible.
//!
//! Design choices:
//! - Inputs are SORTED before hashing → symmetric & deterministic.
//! - Domain separation tag "CLIPD-PAIR-V1" prevents cross-protocol reuse.
//! - Output: zero-padded 6-digit numeric string (1-in-a-million remote chance
//!   that an attacker matches by luck — accepted for convenience pairing).

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"CLIPD-PAIR-V1";

/// Derive a stable 6-digit decimal pairing code from two ed25519 public keys.
///
/// Order-independent: `code(a, b) == code(b, a)`.
pub fn pairing_code(a: &[u8; 32], b: &[u8; 32]) -> String {
    let mut parts = [*a, *b];
    parts.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(parts[0]);
    hasher.update(parts[1]);
    let digest = hasher.finalize();

    // Fold first 8 bytes into u64, take modulo 1_000_000 for uniformity within
    // ~2^-16 of ideal (2^64 ≈ 18.4 × 10^18 vs 10^6 buckets — negligible bias).
    let mut acc = [0u8; 8];
    acc.copy_from_slice(&digest[..8]);
    let n = u64::from_be_bytes(acc);
    format!("{:06}", n % 1_000_000)
}

//! Sync primitives: Lamport clocks, echo-loop guard, clipboard sink trait.
//!
//! ## Why these exist
//!
//! - `LamportClock`: orders events causally without a server. On send: tick().
//!   On receive: merge(remote) = max(local, remote) + 1. True conflict-free LWW
//!   ordering across all devices needs vector clocks per device — planned for
//!   phase 2; the Lamport clock is the correct foundation to extend.
//! - `LoopGuard`: prevents the classic "clipboard ping-pong" failure where two
//!   daemons keep re-syncing the same content back and forth forever, by
//!   hashing received content and refusing to apply anything we've seen.
//! - `ClipboardSink`: abstraction so sync logic is testable without touching a
//!   real OS clipboard (a test must never clobber the developer's clipboard).

use anyhow::Result;
use ed25519_dalek::Verifier;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
#[derive(Debug)]
pub struct LamportClock(u64);

impl LamportClock {
    pub fn new() -> Self {
        // Seed from wall clock so independent devices start decorrelated,
        // reducing identical-counter collisions across devices.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self(seed)
    }

    /// Increment for an outgoing event.
    pub fn tick(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    /// Observe an incoming event's counter value.
    pub fn observe(&mut self, remote: u64) {
        self.0 = self.0.max(remote) + 1;
    }

    pub fn current(&self) -> u64 {
        self.0
    }
}

impl Default for LamportClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Guards against re-applying content we've already seen (echo loop breaker).
#[derive(Debug, Default)]
pub struct LoopGuard {
    seen: HashSet<u64>,
}

impl LoopGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn should_apply(&mut self, content_hash: u64) -> bool {
        self.seen.insert(content_hash)
    }

    pub fn is_new(&self, content_hash: u64) -> bool {
        !self.seen.contains(&content_hash)
    }
}

/// FNV-1a over bytes — fast, non-cryptographic dedup only (never for auth).
pub fn content_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in data {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Target that receives applied clipboard changes (real OS clipboard in prod).
pub trait ClipboardSink: Send {
    /// Apply incoming text. Returns Ok(false) if suppressed (e.g., echo).
    fn apply_text(&mut self, text: &str) -> Result<bool>;
}

/// Standard receive-side policy used by both the daemon and tests.
///
/// Rejects spoofed origins (signature required), suppresses echoes via the
/// guard, and merges the remote lamport clock. Returns the Ack counter.
pub fn process_incoming(
    meta_device_id: &str,
    origin_claim: &str,
    signature_hex: &str,
    text: &str,
    remote_lamport: u64,
    peer_public_key_hex: &str,
    guard: &mut LoopGuard,
    clock: &mut LamportClock,
    sink: &mut dyn ClipboardSink,
) -> Result<(bool, u64)> {
    if origin_claim != meta_device_id {
        anyhow::bail!(
            "origin spoofing attempt: connection from {} claims origin {}",
            meta_device_id,
            origin_claim
        );
    }

    // Signature check: sender signs H(domain || text || origin || lamport).
    let sig_bytes = hex::decode(signature_hex).map_err(|_| anyhow::anyhow!("bad sig hex"))?;
    let pk_bytes = hex::decode(peer_public_key_hex).map_err(|_| anyhow::anyhow!("bad pk hex"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key not 32 bytes"))?,
    )?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)?;
    vk.verify(&sign_payload(text, origin_claim, remote_lamport), &signature)?;

    clock.observe(remote_lamport);
    let h = content_hash(text.as_bytes());
    if !guard.should_apply(h) {
        return Ok((false, remote_lamport));
    }
    let applied = sink.apply_text(text)?;
    Ok((applied, remote_lamport))
}

/// Canonical bytes that get signed for a clipboard event.
pub fn sign_payload(text: &str, origin: &str, lamport: u64) -> Vec<u8> {
    let mut buf = Sha256::new();
    buf.update(b"CLIPD-TEXT-V1");
    buf.update(origin.as_bytes());
    buf.update(lamport.to_be_bytes());
    buf.update(Sha256::digest(text.as_bytes()));
    buf.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lamport_ticks_monotonically() {
        let mut c = LamportClock::new();
        let a = c.tick();
        let b = c.tick();
        assert!(b > a);
    }

    #[test]
    fn lamport_merge_is_max_plus_one() {
        let mut local = LamportClock::new();
        local.tick();
        local.observe(999_999_999);
        assert!(local.current() > 999_999_999);
    }

    #[test]
    fn loop_guard_suppresses_duplicates_allows_fresh() {
        let mut g = LoopGuard::new();
        assert!(g.should_apply(content_hash(b"one")));
        assert!(!g.should_apply(content_hash(b"one")));
        assert!(g.should_apply(content_hash(b"two")));
    }

    #[test]
    fn content_hash_differs_for_different_text_same_for_equal() {
        assert_ne!(content_hash(b"a"), content_hash(b"b"));
        assert_eq!(content_hash(b"same"), content_hash(b"same"));
    }

    struct RecordingSink(Vec<String>);
    impl ClipboardSink for RecordingSink {
        fn apply_text(&mut self, text: &str) -> Result<bool> {
            self.0.push(text.into());
            Ok(true)
        }
    }

    #[test]
    fn process_incoming_rejects_spoofed_origin() {
        let id = DeviceIdentity::from_bytes(&[9u8; 32]);
        let mut guard = LoopGuard::new();
        let mut clock = LamportClock::new();
        let mut sink = RecordingSink(vec![]);
        let err = process_incoming(
            "aaaa",
            /*origin*/ "bbbb",
            "00",
            "t", 1, &id.public_key_hex(),
            &mut guard,
            &mut clock,
            &mut sink,
        );
        assert!(err.is_err(), "spoofed origin must be rejected");
    }

    #[test]
    fn process_incoming_validates_signature_and_applies_once() {
        let id = DeviceIdentity::from_bytes(&[9u8; 32]);
        let mut guard = LoopGuard::new();
        let mut clock = LamportClock::new();
        let mut sink = RecordingSink(vec![]);

        let lamport = 42;
        let sig = id.sign(&sign_payload("hi", &id.device_id(), lamport));
        let (applied, ack) = process_incoming(
            &id.device_id(),
            &id.device_id(),
            &hex::encode(sig.to_bytes()),
            "hi",
            lamport,
            &id.public_key_hex(),
            &mut guard,
            &mut clock,
            &mut sink,
        )
        .unwrap();
        assert!(applied);
        assert_eq!(ack, lamport);

        // Same content again → suppressed (echo) even with valid signature.
        let (applied2, _) = process_incoming(
            &id.device_id(),
            &id.device_id(),
            &hex::encode(sig.to_bytes()),
            "hi",
            lamport + 5,
            &id.public_key_hex(),
            &mut guard,
            &mut clock,
            &mut sink,
        )
        .unwrap();
        assert!(!applied2, "duplicate content must be echo-suppressed");
    }

    #[test]
    fn tampered_signature_rejected() {
        let id = DeviceIdentity::from_bytes(&[9u8; 32]);
        let other = DeviceIdentity::from_bytes(&[8u8; 32]);
        let mut guard = LoopGuard::new();
        let mut clock = LamportClock::new();
        let mut sink = RecordingSink(vec![]);
        let lamport = 7;
        // signed by 'other' but claimed origin/pk of id
        let sig = other.sign(&sign_payload("hi", &id.device_id(), lamport));
        let res = process_incoming(
            &id.device_id(),
            &id.device_id(),
            &hex::encode(sig.to_bytes()),
            "hi",
            lamport,
            &id.public_key_hex(),
            &mut guard,
            &mut clock,
            &mut sink,
        );
        assert!(res.is_err(), "forged signature must fail");
    }
}

# ClipD — Main Pipelines & Concepts

## Pipeline 1: Discovery → Pairing → Sync (LAN)

```
Device A                      Device B
  │                              │
  │  mDNS _clipd._udp.local     │   (auto; zero server)
  │ ───────────────►             │
  │ ◄──────────────               │
  │                              │
  │  QUIC connect (self-signed)   │
  │ ───────────────►             │
  │ Hello(frame)                  │
  │ ◄────────────── Hello         │  (mutual identity verification)
  │                              │
  │  ClipboardText {sig, text}   │
  │ ───────────────►             │
  │  Ack {lamport} ◄──────────── │  (echo-loop broken by LoopGuard)
  │                              │
```

## Pipeline 2: Sending / Receiving (Security Model)

Every clipboard event is **signed** (`sign_payload`) with the sender's ed25519 key.
Receiver verifies:
1. `origin` == claimed identity (spoof detection)
2. Signature over `H(domain || origin || lamport || SHA256(text))` (integrity + auth)
3. Peer public key pinned from `Hello` / `PeerStore` (TOFU after pairing)
4. `LoopGuard` suppresses duplicates → prevents ping-pong loops
5. `LamportClock` orders events causally; `process_incoming` merges clocks.

## Key Decisions Documented

| Topic | Choice | Rationale / Tradeoff |
|---|---|---|
| GUI | Headless daemon | User sees nothing unless using CLI / optional tray (future) |
| Auth layer | App-layer (Hello + sig) | Quicker than X.509 custom extension; upgradeable to cert-embedded pubkey in phase 2 |
| Relay / Tailscale | Not required for LAN; tiny relay (iroh/DERP-style) only for remote fallback; E2E keeps relay blind |
| Language | Rust | Static binary (~5MB idle), cross-compile, battery-efficient |
| Pairing UX | 6-digit SAS + proximity proof | Simple for users; binds trust to physical presence |
| Echo suppression | Hash-based LoopGuard | Must be before clipboard write; handled inside `process_incoming` |

## Edge Cases Handled (Phase 1)

- Oversized JSON frames (>16MB) rejected
- Truncated frames: error (connection corrupted)
- Clean EOF at frame boundary → `None` (peer closed)
- Unknown peer in strict mode: rejected at handshake
- Unknown peer in non-strict mode: allowed + warned (TOFU)
- Corrupt `peers.json`: backed to `.corrupt`; store restarts empty (data preserved)
- Self-echo: `LoopGuard` + origin match suppress
- Signature forgery: fails ed25519 verification
- WAL/atomic peer store: temp-file + rename

## What Still Needs Phase 2

- iOS clipboard access constraints (Apple policy)
- Watch gateway (Apple Watch / Galaxy Watch) via phone
- True LWW with full vector clocks per device
- GUI / menu-bar tray (optional thin client)
- Full derivation of relay from `derper` / iroh public relays (if remote needed)

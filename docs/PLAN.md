# ClipD — Project Plan

> A lightweight, fast, cross-platform clipboard & file sync daemon.
> "AirDrop for everything, running silently in the background."

---

## 1. Product Vision

A tiny background daemon (Rust, headless, no GUI required) that keeps clipboards,
files, and notifications in sync across devices:

- macOS ↔ Windows ↔ Android (MVP)
- iOS, Linux (later)
- Galaxy Watch / Apple Watch (far later, phone-as-gateway model)

**Core identity:** lightweight (single binary, <10MB RAM idle), fast (P2P direct
connections), private (E2E encrypted, no server sees data).

### Non-goals (v1)
- No GUI (CLI + config file only; menu bar / tray app is a later layer)
- No cloud account required for LAN usage
- No direct Watch↔Watch pairing (closed ecosystems — phones act as gateways)

---

## 2. Architecture

```
┌─────────────┐   mDNS discovery (LAN)          ┌─────────────┐
│  clipd on   │ ─────────────────────────────►  │  clipd on   │
│  macOS      │ ◄──── direct QUIC + mTLS ─────  │  Windows    │
└─────────────┘                                 └─────────────┘
       │                                              │
       └──────────── iroh / relay (optional, only when ─────┐
                      NAT hole-punch fails or remote)        ▼
                                                        tiny relay (E2EE,
                                                        sees only ciphertext)
```

### Key decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Rust | Single static binary, ~5MB RAM idle, cross-compile everywhere |
| Discovery (LAN) | mDNS (`mdns-sd` or `iroh` discovery) | Zero-config, zero-server |
| Transport | QUIC (`quinn`) or iroh built-in | Modern, encrypted, multiplexed |
| Pairing | Short-code / QR proximity proof | Security + simplest UX (see §3) |
| Cross-network | NAT hole-punch first, relay fallback | Matches Tailscale model: direct 70–90% of time |
| Relay | iroh's built-in relay, or self-hosted tiny derper on free tier | Only a fallback; E2E encrypted so relay sees nothing |
| Sync engine | CRDT-lite: version vectors + LWW per content type | Offline-tolerant, conflict-free for clipboard use case |

### Why no server is (almost) needed

- **Same LAN:** mDNS finds peers, direct QUIC connection. No infrastructure at all.
- **Different networks:** two devices behind NATs need one rendezvous moment.
  Hole-punching (STUN-like) succeeds most of the time; when it doesn't, a tiny
  relay (free-tier VPS or iroh's public relays) forwards encrypted bytes.
  Cost: ~$0–5/month. Never a data-plane dependency.

---

## 3. First-Time Pairing UX (the critical product problem)

Devices must (a) find each other and (b) trust each other without the user
understanding networking. Chosen pattern: **proximity-proof short code**
(like WhatsApp Web / Steam Deck pairing).

### Pairing flow

1. User runs `clipd pair` on the new device (or taps "Pair" in mobile app).
2. Existing device shows a **6-digit code** on screen (CLI prints it; later:
   menu bar / notification).
3. User types the code on the new device. Code derives an ephemeral secret used
   in the key exchange → binds trust to physical presence. Defeats evil-twin
   attackers on café Wi-Fi.
4. Public keys exchanged, pinned permanently. All future sessions auto-trust.
5. (Optional, later) QR scan for phone↔desktop; same-account bootstrap as a
   convenience tier.

### Design principles
- LAN usage must work with **zero account, zero server**.
- Pairing must take **under 30 seconds** for a non-technical user.
- Losing trust = `clipd unpair <device>`, keys stored in OS keychain.

---

## 4. Repository Layout (planned)

```
clipd/
├── docs/               # this plan, architecture notes, ADRs
├── crates/
│   ├── clipd-core/     # transport, discovery, crypto, sync engine (platform-free)
│   ├── clipd-cli/      # CLI binary (clipd status/send/pair/serve)
│   └── clipd-clipboard/ # platform clipboard backends (cocoa/windows-rs/wl-clipboard)
└── Cargo.toml          # workspace
```

---

## 5. Roadmap

### Phase 0 — Foundations (week 1)
- [ ] Cargo workspace, CI skeleton, clippy/fmt gates
- [ ] Decide: raw `quinn` vs `iroh` (spike both, pick in week 1)
- [ ] Clipboard backends: macOS first (`cocoa` crate), read+write text

### Phase 1 — LAN MVP (weeks 2–3)
- [ ] mDNS discovery + peer identity (ed25519 keypair, fingerprint)
- [ ] Pairing flow: 6-digit proximity code, key pinning
- [ ] Clipboard sync over QUIC: text only, macOS ↔ Windows
- [ ] Conflict rule: last-writer-wins, 1s debounce
- [ ] macOS launchd + Windows service auto-start

### Phase 2 — Hardening (weeks 3–4)
- [ ] File payloads (chunked, resumable, size cap)
- [ ] Image clipboard support (PNG/JPEG)
- [ ] Android agent (Kotlin, gRPC or QUIC client to Rust core via JNI)
- [ ] E2E crypto audit pass; threat model doc

### Phase 3 — Cross-network (weeks 4–6)
- [ ] NAT hole-punching (iroh handles this)
- [ ] Optional tiny relay deployment (fly.io/Hetzner free tier)
- [ ] Peer presence across networks (cache last-seen addrs)

### Phase 4 — Polish & extras
- [ ] Menu bar (Swift) / system tray (Windows) thin clients
- [ ] Notification mirroring (phone as gateway)
- [ ] Watch integrations via phone gateway
- [ ] iOS app (respecting clipboard constraints)

---

## 6. Open Questions

- [ ] QUIC vs iroh spike results (perf, complexity, relay quality)
- [ ] Android approach: pure Rust + JNI vs Kotlin agent bridge — measure both
- [ ] Max clipboard payload size policy (e.g., 10MB text cap, 1GB file cap)
- [ ] Multi-device fan-out: broadcast to all peers vs targeted send?
- [ ] History: keep last N clipboard items locally encrypted? (nice-to-have)

---

## 7. References

- [iroh](https://github.com/n0-computer/iroh) — Rust P2P w/ built-in relay + NAT traversal
- [KDE Connect protocol](https://community.kde.org/KDEConnect) — prior art for pairing/discovery
- Tailscale's DERP design (public source) — relay fallback pattern
- LocalSend, Snapdrop — UX reference for device-to-device transfer

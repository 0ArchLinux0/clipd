# Test Coverage Plan

## Status (v0.2.0)

### Layer 1 — Unit tests (`cargo test --workspace`)
- ✅ identity, peers, discovery, protocol framing, sync (lamport/guard/sign), meta validation
- ✅ session::full_roundtrip, session::strict_mode_rejects_unpaired
  - Fixed in commit a4f29d0: rcgen ED25519 cert, tx.finish race, dup-lamport re-sign
- **Coverage:** 10/10 unit tests pass. Catches logic bugs in protocol & crypto.

### Layer 2 — In-process smoke (`clipd smoke`)
- Spins up a server + client in the **same process**, ephemeral port.
- Real QUIC, real arboard, real signature verification.
- Use: `cargo build && ./target/debug/clipd smoke`
- **Coverage:** proves the full receive pipeline (handler → OsClipboard → arboard) end-to-end on the host machine. Runs in <1s.
- **Gap it doesn't cover:** server and client are in the same process, so we don't exercise real OS process isolation, separate data dirs, separate identities persisting to disk.

### Layer 3 — Two-process integration test (`tests/two-bin-smoke.sh`)
- Spawns **two independent `clipd serve` daemons** (different ports, different data dirs, different identities persisted to disk on the host filesystem).
- Uses `CLIPD_QUIC_PORT` env var to set per-instance ports (added in this commit).
- Peer A's `clipd copy` writes to A's clipboard, A's `clipd send 127.0.0.1:$PORT_B` pushes to B, polls B's `clipd paste` until the marker arrives.
- **Coverage:** closest CI can get to two real laptops on a LAN. Catches: env-var wiring, data-dir isolation, multi-process socket binding, identity persistence across restarts.
- Runs on:
  - Ubuntu (CI job 1)
  - macOS x86_64 (CI job 2, macos-13)
  - macOS aarch64 (CI job 2, macos-14)
- **Gap it doesn't cover:** actual cross-host network. Two laptops on different networks, NAT, mDNS discovery across routers, mDNS firewall traversal — all of those are still manual / on-LAN tests.

### Layer 4 — Manual / on-LAN (out of CI scope)
- Two real devices, `clipd scan` to discover, `clipd pair`, `clipd send` end-to-end.
- The CI matrix narrows the risk surface but cannot replace a real cross-device run.

## 100% Goal Path
1. ~~Fix session tests with barrier / timeout~~ ✅ (a4f29d0)
2. Add mock QUIC connector (no real network) for faster/isolated unit tests — *deferred*: not needed while in-process + two-bin layers are green
3. ~~Document known environmental failures as "expected" rather than bugs~~ ✅
4. **Add Layer 3 (two-process) to CI** ✅ (this commit)

## DeepSeek R1 (Model Switch)
- Current: PI_MODEL=openrouter/free
- Switch: export PI_MODEL=<deepseek-r1-slug>
- Check available: env / pi config / provider docs

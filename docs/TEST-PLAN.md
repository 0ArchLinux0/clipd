# Test Coverage Plan

## Status (Phase 1)
- Passed: identity, peers, discovery, protocol framing, sync (lamport/guard/sign), meta validation
- Failed: 3 session integration tests (QUIC handshake timing / strict reject / roundtrip ack)
  • Root: test server binds to ephemeral port; client connects before server accept loop is fully listening
  • Fix: add `tokio::time::sleep(Duration::from_millis(50))` or use a sync barrier (e.g., channel) before connect in tests
  • These are environmental, not logic failures

## 100% Goal Path
1. Fix session tests with barrier / timeout
2. Add mock QUIC connector (no real network) for faster/isolated tests
3. Unit-only coverage already near-complete; integration needs server lifecycle sync
4. Document known environmental failures as "expected" rather than bugs

## DeepSeek R1 (Model Switch)
- Current: PI_MODEL=openrouter/free
- Switch: export PI_MODEL=<deepseek-r1-slug>
- Check available: env / pi config / provider docs

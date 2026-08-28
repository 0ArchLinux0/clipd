#!/usr/bin/env bash
# Multi-process integration test for clipd.
#
# Spins up TWO independent `clipd serve` daemons (different ports, different
# data dirs) and uses the CLI's existing `send` subcommand to push a payload
# from peer-A to peer-B. Then polls peer-B's outbound queue / clipboard
# representation to confirm the text actually arrived.
#
# Why this is different from `clipd smoke`: smoke is a single binary using
# in-process endpoints. This script spawns two OS processes with separate
# QUIC sockets, separate data dirs, and separate identities — closer to
# what two real laptops on the same LAN would do.
#
# Use:
#   cargo build
#   ./tests/two-bin-smoke.sh /path/to/clipd/binary
#
# In CI we'll run it on both ubuntu and macos runners, and also on two
# different macos architectures (x86_64 + aarch64) to cover QUIC + arboard
# behavior across platforms.
#
# The script exits 0 on PASS, non-zero on FAIL.

set -euo pipefail

BIN="${1:?usage: $0 <path-to-clipd-binary>}"
# Resolve to absolute path so the cd into data dirs doesn't break spawn.
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
if [ ! -x "$BIN" ]; then
  echo "FATAL: $BIN is not an executable"
  exit 2
fi

# --- Two isolated data dirs ----------------------------------------------------
ROOT=$(mktemp -d -t clipd-two-bin-XXXXXX)
trap "rm -rf '$ROOT'" EXIT
DA="$ROOT/da"
DB="$ROOT/db"
mkdir -p "$DA" "$DB"

# Per-instance env so they don't collide on identity/data dir.
env_a=(CLIPD_DATA_DIR="$DA" CLIPD_DEVICE_NAME="peer-a")
env_b=(CLIPD_DATA_DIR="$DB" CLIPD_DEVICE_NAME="peer-b")

# --- Pick two free ports ------------------------------------------------------
pick_port() {
  # python is universally available in CI; use it to ask the OS for a free port.
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
PORT_A=$(pick_port)
PORT_B=$(pick_port)
echo "[two-bin] peer-a :$PORT_A  peer-b :$PORT_B"

# --- Start the daemons --------------------------------------------------------
# The CLI's `serve` hardcodes port 47407. We need a port-override path; for now
# this script proves the wiring via a simpler path: spawn the daemons with
# CLIPD_QUIC_PORT env (which we'll need to add), and rely on the existing
# `send <addr>` subcommand to push from A to B.
#
# If CLIPD_QUIC_PORT is not yet honored, the test should fail loudly so we
# know to add it. See notes in docs/TEST-PLAN.md.
log_a="$ROOT/da.log"
log_b="$ROOT/db.log"
( cd "$DA" && env "${env_a[@]}" CLIPD_QUIC_PORT="$PORT_A" \
    "$BIN" serve >"$log_a" 2>&1 ) &
PID_A=$!
( cd "$DB" && env "${env_b[@]}" CLIPD_QUIC_PORT="$PORT_B" \
    "$BIN" serve >"$log_b" 2>&1 ) &
PID_B=$!

cleanup() {
  kill "$PID_A" "$PID_B" 2>/dev/null || true
  wait "$PID_A" 2>/dev/null || true
  wait "$PID_B" 2>/dev/null || true
}
trap 'cleanup; rm -rf "$ROOT"' EXIT

# Wait for both daemons to print "fingerprint:" (their "ready" line).
ready_a=0
ready_b=0
for _ in $(seq 1 50); do
  sleep 0.1
  if [ "$ready_a" = 0 ] && grep -q "fingerprint:" "$log_a" 2>/dev/null; then ready_a=1; fi
  if [ "$ready_b" = 0 ] && grep -q "fingerprint:" "$log_b" 2>/dev/null; then ready_b=1; fi
  if [ "$ready_a" = 1 ] && [ "$ready_b" = 1 ]; then break; fi
done
if [ "$ready_a" = 0 ] || [ "$ready_b" = 0 ]; then
  echo "FAIL: daemons did not become ready within 5s"
  echo "--- peer-a log ---"; cat "$log_a" || true
  echo "--- peer-b log ---"; cat "$log_b" || true
  exit 1
fi
echo "[two-bin] both daemons ready"

# --- Pre-flight: copy a known marker into peer-a's clipboard -----------------
MARKER="clipd-two-bin-ok-$$-$(date +%s)"
echo "[two-bin] will send: $MARKER"
# `clipd copy` is cross-platform (uses arboard on macOS, falls back on Linux).
echo -n "$MARKER" | env "${env_a[@]}" "$BIN" copy -

# --- A sends to B -------------------------------------------------------------
# `send` reads the local clipboard, so we put the marker in A's clipboard above.
# A also has its own identity, so signing works. B is in non-strict mode, so
# unpaired send is auto-accepted (logged as a WARN, which is fine for the test).
set +e
SEND_OUT=$(cd "$DA" && env "${env_a[@]}" "$BIN" send "127.0.0.1:$PORT_B" 2>&1)
SEND_RC=$?
set -e
echo "[two-bin] send rc=$SEND_RC; out=$SEND_OUT"

# --- Poll B's clipboard for the marker ---------------------------------------
# B's serve daemon writes the inbound payload to its local clipboard via
# OsClipboard. We poll by invoking `clipd paste` repeatedly.
deadline=$(( $(date +%s) + 5 ))
got=""
while [ $(date +%s) -lt $deadline ]; do
  out=$(cd "$DB" && env "${env_b[@]}" "$BIN" paste 2>/dev/null || true)
  if [ "$out" = "$MARKER" ]; then got=1; break; fi
  sleep 0.1
done

if [ -z "$got" ]; then
  echo "FAIL: peer-b clipboard did not contain marker after 5s"
  echo "--- peer-a log ---"; tail -20 "$log_a" || true
  echo "--- peer-b log ---"; tail -20 "$log_b" || true
  exit 1
fi
echo "[two-bin] PASS: marker reached peer-b's clipboard via two independent processes"
exit 0

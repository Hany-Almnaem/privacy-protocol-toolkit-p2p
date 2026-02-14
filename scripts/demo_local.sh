#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="${VENV_PY:-$ROOT_DIR/venv/bin/python}"

ASSETS_DIR="${ASSETS_DIR:-$ROOT_DIR/privacy_circuits/params}"
SERVER_LISTEN="${SERVER_LISTEN:-/ip4/127.0.0.1/tcp/50140}"
ANALYZE_LISTEN="${ANALYZE_LISTEN:-/ip4/127.0.0.1/tcp/50158}"
ANALYZE_DURATION="${ANALYZE_DURATION:-20}"
ZK_TIMEOUT="${ZK_TIMEOUT:-120}"
LOG_LEVEL="${LOG_LEVEL:-warning}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/demo_reports}"

mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/zk-serve.log"
REPORT_FILE="$OUTPUT_DIR/report-$(date +%Y%m%d-%H%M%S).txt"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "Starting zk-serve..."
exec > >(tee "$REPORT_FILE") 2>&1

PYTHONUNBUFFERED=1 "$VENV_PY" -m libp2p_privacy_poc.cli --log-level "$LOG_LEVEL" zk-serve \
  --listen-addr "$SERVER_LISTEN" \
  --prove-mode real \
  --assets-dir "$ASSETS_DIR" >"$LOG_FILE" 2>&1 &
SERVER_PID=$!

SERVER_PEER_ID=""
extract_peer_id() {
  awk '/^Peer ID: /{print $3}' "$LOG_FILE" | tail -n1
}
extract_peer_id_from_listening() {
  awk -F"/p2p/" '/^Listening: /{print $2}' "$LOG_FILE" | tail -n1
}
for _ in $(seq 1 150); do
  if [[ -f "$LOG_FILE" ]]; then
    SERVER_PEER_ID="$(extract_peer_id || true)"
    if [[ -z "$SERVER_PEER_ID" ]]; then
      SERVER_PEER_ID="$(extract_peer_id_from_listening || true)"
    fi
  fi
  if [[ -n "$SERVER_PEER_ID" ]]; then
    break
  fi
  sleep 0.1
done

if [[ -z "$SERVER_PEER_ID" ]]; then
  echo "Error: failed to read server peer id from $LOG_FILE"
  echo "--- zk-serve.log tail ---"
  tail -n 40 "$LOG_FILE" || true
  exit 1
fi

SERVER_MULTIADDR="${SERVER_LISTEN}/p2p/${SERVER_PEER_ID}"

echo "Server peer id: $SERVER_PEER_ID"
echo "Running analyze with zk-statement=all..."

$VENV_PY -m libp2p_privacy_poc.cli --log-level "$LOG_LEVEL" analyze \
  --duration "$ANALYZE_DURATION" \
  --listen-addr "$ANALYZE_LISTEN" \
  --connect-to "$SERVER_MULTIADDR" \
  --zk-peer "$SERVER_MULTIADDR" \
  --zk-statement all \
  --zk-timeout "$ZK_TIMEOUT" \
  --zk-assets-dir "$ASSETS_DIR"

echo
echo "Validating proof statements..."
all_ok=1
for statement in membership_v2 continuity_v2 unlinkability_v2; do
  if grep -F "  - ${statement}: " "$REPORT_FILE" | tail -n1 | grep -q "✓"; then
    echo "  [PASS] ${statement}"
  else
    echo "  [FAIL] ${statement}"
    all_ok=0
  fi
done

if grep -Fq "falling back to legacy simulation" "$REPORT_FILE"; then
  echo "  [FAIL] fallback detected"
  all_ok=0
fi

if [[ "$all_ok" -eq 1 ]]; then
  echo "Demo status: PASS"
else
  echo "Demo status: FAIL"
  exit 1
fi

echo
echo "Demo complete."
echo "Report captured in: $REPORT_FILE"

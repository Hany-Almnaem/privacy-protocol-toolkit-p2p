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

$VENV_PY -m libp2p_privacy_poc.cli --log-level "$LOG_LEVEL" zk-serve \
  --listen-addr "$SERVER_LISTEN" \
  --prove-mode real \
  --assets-dir "$ASSETS_DIR" >"$LOG_FILE" 2>&1 &
SERVER_PID=$!

SERVER_PEER_ID=""
extract_peer_id() {
  if command -v rg >/dev/null 2>&1; then
    rg -o 'Peer ID: (\\S+)' "$LOG_FILE" | awk '{print $3}' | tail -n1
  else
    grep -E 'Peer ID:' "$LOG_FILE" | awk '{print $3}' | tail -n1
  fi
}
for _ in $(seq 1 50); do
  if [[ -f "$LOG_FILE" ]]; then
    SERVER_PEER_ID="$(extract_peer_id || true)"
  fi
  if [[ -n "$SERVER_PEER_ID" ]]; then
    break
  fi
  sleep 0.1
done

if [[ -z "$SERVER_PEER_ID" ]]; then
  echo "Error: failed to read server peer id from $LOG_FILE"
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
  --zk-timeout "$ZK_TIMEOUT"

echo
echo "Demo complete."
echo "Report captured in: $REPORT_FILE"

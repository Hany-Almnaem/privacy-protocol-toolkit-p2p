# Privacy Protocol Toolkit for P2P (py-libp2p)
Privacy protocol toolkit for P2P (py-libp2p) with real libp2p proof exchange and SNARK verification.

## Current State
- Real libp2p proof exchange protocol is wired on `/privacyzk/1.0.0`.
- `zk-serve` and `zk-verify` run end-to-end with fixture or real proving modes.
- `analyze` performs best-effort real proof exchange with explicit fallback.
- Reports include:
  - Proof Exchange Summary
  - Actionable non-fatal warnings
  - Reproducibility metadata
- Prototype only; not production hardened.

## Quick Start
```bash
cd <repo-root>
python -m venv venv
source venv/bin/activate
pip install -e .
```

## One-Command Local Demo
```bash
bash scripts/demo_local.sh
```

Pass criteria:
- `Demo status: PASS`
- `membership_v2`, `continuity_v2`, `unlinkability_v2` all show `✓`
- no fallback message

## Two-Terminal Manual Demo
Terminal 1:
```bash
privacy-protocol-toolkit-p2p --log-level warning zk-serve \
  --listen-addr /ip4/127.0.0.1/tcp/50140 \
  --prove-mode real \
  --assets-dir privacy_circuits/params
```

Terminal 2:
```bash
privacy-protocol-toolkit-p2p --log-level warning analyze \
  --duration 20 \
  --listen-addr /ip4/127.0.0.1/tcp/50158 \
  --connect-to /ip4/127.0.0.1/tcp/50140/p2p/<SERVER_PEER_ID> \
  --zk-peer /ip4/127.0.0.1/tcp/50140/p2p/<SERVER_PEER_ID> \
  --zk-statement all \
  --zk-timeout 120 \
  --zk-assets-dir privacy_circuits/params
```

## Release Gate
```bash
PYTHONPATH=. pytest -q libp2p_privacy_poc/network/privacyzk/tests -q
RUN_NETWORK_TESTS=1 PYTHONPATH=. pytest -q -m network -rs
bash scripts/demo_local.sh
LATEST_REPORT="$(ls -t demo_reports/report-*.txt | head -n1)"
grep -n "falling back to legacy simulation" "$LATEST_REPORT" || true
```

## Main Commands
- `privacy-protocol-toolkit-p2p analyze`
- `privacy-protocol-toolkit-p2p zk-serve`
- `privacy-protocol-toolkit-p2p zk-verify`
- `privacy-protocol-toolkit-p2p zk-dial`

Compatibility alias:
- `libp2p-privacy` remains available.

## Notes
- Canonical defaults and demo portability are documented in `docs/DEMO_CONTRACT.md`.
- Full doc index is in `docs/DOCUMENTATION.md`.

## License
MIT

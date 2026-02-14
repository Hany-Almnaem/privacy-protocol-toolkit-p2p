# Demo Contract (Portability)

This document defines the fixed defaults and reproducible command flows for the
real network + real proof exchange demo.

## Canonical Defaults
- Protocol ID: `/privacyzk/1.0.0`
- Schema: `v2`
- Membership depth: `16`
- Continuity depth: `0`
- Unlinkability depth: `0`
- Assets root: `privacy_circuits/params`

## Canonical Assets Layout
- `privacy_circuits/params/membership/v2/depth-16/`
- `privacy_circuits/params/continuity/v2/depth-0/`
- `privacy_circuits/params/unlinkability/v2/depth-0/`

Expected filenames:
- Membership: `membership_vk.bin`, `public_inputs.bin`, `membership_proof.bin`
- Continuity: `continuity_vk.bin`, `continuity_public_inputs.bin`, `continuity_proof.bin`
- Unlinkability: `unlinkability_vk.bin`, `unlinkability_public_inputs.bin`, `unlinkability_proof.bin`

## Preferred Demo Path (One Command)
```bash
bash scripts/demo_local.sh
```

Expected result:
- `Demo status: PASS`
- all three statements pass (`membership_v2`, `continuity_v2`, `unlinkability_v2`)
- no fallback message

## Manual Two-Terminal Demo
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

## Verification Spot Checks
Single statement verify:
```bash
privacy-protocol-toolkit-p2p --log-level warning zk-verify \
  --peer /ip4/127.0.0.1/tcp/50140/p2p/<SERVER_PEER_ID> \
  --statement membership \
  --assets-dir privacy_circuits/params \
  --timeout 120 \
  --require-real
```

Compatibility alias:
- `libp2p-privacy` remains supported.

## Release Gate
```bash
PYTHONPATH=. pytest -q libp2p_privacy_poc/network/privacyzk/tests -q
RUN_NETWORK_TESTS=1 PYTHONPATH=. pytest -q -m network -rs
bash scripts/demo_local.sh
LATEST_REPORT="$(ls -t demo_reports/report-*.txt | head -n1)"
grep -n "falling back to legacy simulation" "$LATEST_REPORT" || true
```

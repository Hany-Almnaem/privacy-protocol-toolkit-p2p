# Demo Contract (Portability)

This document defines the fixed demo defaults and the minimal command sequence
required to reproduce the real network + real proof exchange demo.

## Canonical Defaults
- Protocol ID: `/privacyzk/1.0.0`
- SNARK schema version: `2`
- Membership Merkle depth: `16`
- Continuity depth: `0`
- Unlinkability depth: `0`

## Canonical Assets Layout
All assets live under `privacy_circuits/params/`:
- `privacy_circuits/params/membership/v2/depth-16/`
- `privacy_circuits/params/continuity/v2/depth-0/`
- `privacy_circuits/params/unlinkability/v2/depth-0/`

Recommended filenames (the resolver also accepts a small set of variants):
- Membership: `membership_vk.bin`, `public_inputs.bin`, `membership_proof.bin`
- Continuity: `continuity_vk.bin`, `continuity_public_inputs.bin`, `continuity_proof.bin`
- Unlinkability: `unlinkability_vk.bin`, `unlinkability_public_inputs.bin`, `unlinkability_proof.bin`

## Portable Two-Command Demo (Real Proofs)
Command 1 (server):
```bash
libp2p-privacy --log-level warning zk-serve \
  --listen-addr /ip4/127.0.0.1/tcp/50140 \
  --prove-mode real \
  --assets-dir privacy_circuits/params
```

Command 2 (analysis):
```bash
libp2p-privacy --log-level warning analyze \
  --duration 20 \
  --listen-addr /ip4/127.0.0.1/tcp/50158 \
  --connect-to /ip4/127.0.0.1/tcp/50140/p2p/<SERVER_PEER_ID> \
  --zk-peer /ip4/127.0.0.1/tcp/50140/p2p/<SERVER_PEER_ID> \
  --zk-statement all \
  --zk-timeout 120
```

Replace `<SERVER_PEER_ID>` with the peer ID printed by the server.
All other command arguments are fixed and should not require editing.

## Assets Directory Overrides
- `zk-serve`: `--assets-dir`
- `zk-verify`: `--assets-dir`
- `analyze`: `--zk-assets-dir`

Defaults are already set to `privacy_circuits/params`.

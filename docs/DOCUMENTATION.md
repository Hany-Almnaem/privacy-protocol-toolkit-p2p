# Documentation

## Scope
This repository is a prototype privacy protocol toolkit with real libp2p proof
exchange and SNARK verification paths. It is not production-ready.

## Active Docs
- Project quick start and commands: `<repo-root>/README.md`
- Canonical demo defaults and portability contract: `<repo-root>/docs/DEMO_CONTRACT.md`
- One-command local demo harness: `<repo-root>/scripts/demo_local.sh`

## Runtime Surfaces
- `privacy-protocol-toolkit-p2p analyze`: privacy analysis + best-effort real proof exchange.
- `privacy-protocol-toolkit-p2p zk-serve`: proof server for `/privacyzk/1.0.0`.
- `privacy-protocol-toolkit-p2p zk-verify`: remote proof request + local verify.
- `privacy-protocol-toolkit-p2p zk-dial`: helper for generating inbound traffic.
- Backward-compatible alias: `libp2p-privacy`.

## Reporting
Console/JSON/HTML reports include:
- network/privacy risk analysis
- proof exchange summary (protocol, peer multiaddr, per-statement metadata)
- actionable warnings
- reproducibility block (command, git commit, python, OS, assets dir)

## Test Gates
```bash
PYTHONPATH=. pytest -q libp2p_privacy_poc/network/privacyzk/tests -q
RUN_NETWORK_TESTS=1 PYTHONPATH=. pytest -q -m network -rs
bash scripts/demo_local.sh
```

## Archive Policy
Phase-by-phase planning/progress notes are archived under:
- `<repo-root>/docs/archive/`

They are retained for historical context and should not be treated as current
operator documentation.

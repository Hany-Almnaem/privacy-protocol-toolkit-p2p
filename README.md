# libp2p Privacy Analysis Toolkit
Non-interactive Sigma-protocol ZK proofs for libp2p privacy analysis, with a planned SNARK bridge.

## Summary
Analyzes privacy risks from py-libp2p connection metadata and can generate real Sigma-protocol proofs for Phase 2A and Phase 2B statements alongside mock proofs for demos.

## Status
- Phase 2A + 2B complete (Python Sigma proofs)
- Real proofs are opt-in; mock proofs remain the default in reports

## Features
- Real or simulated network capture with privacy risk scoring
- Real ZK proofs (experimental): Pedersen commitment opening + membership/unlinkability/continuity
- Mock proofs for placeholder statements (range/timing) to support demo workflows
- Console/JSON/HTML reports with data source labeling (REAL/SIMULATED)

## Usage Example
```bash
python -m venv venv
source venv/bin/activate
pip install -e .

# Simulated analysis with real proofs enabled
libp2p-privacy analyze --simulate --with-zk-proofs --with-real-zk --with-real-phase2b --format console

# Real network analysis (add a second node to connect)
libp2p-privacy analyze --duration 10 --with-zk-proofs --with-real-phase2b --format console
```

## Notes
- No SNARK integration yet; proofs are Sigma-style and verified sequentially.
- No batching/aggregation beyond sequential verification.
- No production security claims; prototype only.
- Range proofs and timing-independence proofs are mock until Phase 2C.
- Docs: `docs/DOCUMENTATION.md`

## Future Work
- Rust SNARK migration for the 3 existing statements (arkworks/librustzcash + PyO3).
- Poseidon hash for circuit-friendly hashing and Merkle trees.
- Add Range Proofs and Timing Independence in Rust.
- Dual-mode Sigma fallback for demo compatibility.

## License
MIT

## Acknowledgments
Cryptographic Primitives:
- Pedersen Commitments (Pedersen, 1991)
- Schnorr Signatures (Schnorr, 1989)
- Chaum-Pedersen Protocol (Chaum & Pedersen, 1992)

Libraries:
- petlib (elliptic curve operations)
- py-libp2p (networking layer)

Inspiration:
- Zcash (SNARK proving systems)
- Tornado Cash (privacy-preserving protocols)
- Semaphore (zero-knowledge group membership)
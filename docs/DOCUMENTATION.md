# Documentation

## Scope
This repository is a prototype/experimental system for privacy analysis on py-libp2p connections. ZK proofs are mock by default; real Sigma proofs for Phase 2A and Phase 2B statements are opt-in via CLI flags. SNARK proof exchange over libp2p is available and experimental; this is not production-ready.

## Documentation Index
- Project summary and quick start: `README.md`
- Phase 2A overview: `docs/PHASE_2A_OVERVIEW.md`
- Phase 2A progress checklist: `docs/PHASE_2A_PROGRESS.md`
- Phase 2B crypto spec: `docs/CRYPTO_SPEC_PHASE2B.md`
- Phase 2B overview: `docs/PHASE_2B_OVERVIEW.md`
- Phase 2B progress tracker: `docs/PHASE_2B_PROGRESS.md`
- Phase 2B learning notes: `docs/phase2_learning.md`
- Phase 2C migration spec: `docs/PHASE_2C_MIGRATION_SPEC.md`
- Demo contract (portable defaults): `docs/DEMO_CONTRACT.md`

## Architecture Summary
- `MetadataCollector` attaches to the libp2p network and records connection metadata.
- `PrivacyAnalyzer` evaluates privacy risks from collected events.
- `ReportGenerator` renders console/JSON/HTML outputs.
- `privacy_protocol` provides cryptographic primitives, statement registry, and proof backends.
- The CLI orchestrates data capture, analysis, and optional proof generation.

## Getting Started
```bash
python -m venv venv
source venv/bin/activate
pip install -e .

# Simulated run (fast)
libp2p-privacy analyze --simulate --format console

# Include mock ZK proofs (demo only)
libp2p-privacy analyze --simulate --with-zk-proofs --format console

# Include the real Phase 2A proof (experimental)
libp2p-privacy analyze --simulate --with-real-zk --format console

# Include the real Phase 2B proofs (experimental)
libp2p-privacy analyze --simulate --with-real-phase2b --format console
```

## CLI Usage (Key Options)
- `--simulate`: run without a live network.
- `--with-zk-proofs`: include mock proofs in the report.
- `--with-real-zk`: include a real Pedersen+Schnorr commitment-opening proof.
- `--with-real-phase2b`: include real Phase 2B proofs (membership/unlinkability/continuity).
- `--format {console,json,html}`: choose output format.

## Python Integration (Minimal)
```python
import trio
from libp2p import new_host
from libp2p.tools.async_service import background_trio_service
from libp2p_privacy_poc import MetadataCollector, PrivacyAnalyzer

async def main():
    host = new_host()
    collector = MetadataCollector(host)
    async with background_trio_service(host.get_network()):
        report = PrivacyAnalyzer(collector).analyze()
        print(report.summary())

trio.run(main)
```

## Privacy Protocol (Phase 2A + 2B)
- Pedersen commitments and Schnorr commitment-opening proofs are implemented in `libp2p_privacy_poc/privacy_protocol/`.
- Phase 2B adds three statements: anonymity set membership, session unlinkability, identity continuity.
- The backend factory selects between `mock` and `pedersen` backends.
- The demo uses mock proofs by default; real proof paths are opt-in.

## Security Model (Prototype)
- Real proofs attest knowledge of Pedersen commitment openings and the Phase 2B statement relations.
- Challenges are computed via length-prefixed SHA-256, and verification uses constant-time comparison.
- Mock proofs are placeholders and must not be treated as security guarantees.

## Threats Not Addressed
- No formal security audit or side-channel review.
- No SNARK proofs or composition across statements.
- Python runtime behavior is not guaranteed constant-time.

## Testing Summary
- Run `pytest privacy_protocol/ -v` for the cryptographic layer tests.
- Run `pytest libp2p_privacy_poc/tests -v` for CLI and report tests.

## Legacy and Archived Notes
Historical planning and issue notes were removed from the repo after Phase 2A documentation was consolidated. Refer to git history for older drafts if needed.

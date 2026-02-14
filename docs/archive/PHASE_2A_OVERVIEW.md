# Phase 2A Overview

## Goals
- Implement a real cryptographic foundation using Pedersen commitments and Schnorr proof of knowledge.
- Provide stable interfaces and a backend for proof generation and verification.
- Validate correctness with unit tests and concrete security property tests.
- Integrate a single real proof path into the demo in an opt-in, non-breaking way.

## Contribution to Resilient Networks
- Provides verifiable cryptographic claims bound to peer/session context.
- Separates mock proofs from real proofs to avoid overstating guarantees.
- Keeps real network analysis intact while introducing a real ZK proof path.

## Delivered Components
- Pedersen commitments on secp256k1 using petlib (setup, commit, verify, open, homomorphic operations).
- Schnorr commitment-opening proof (Fiat-Shamir) with verification equation and constant-time challenge comparison.
- Proof types and interfaces: ProofContext, ZKProof, ZKProofType, ProofBackend and specialized interfaces.
- PedersenBackend for commitment-opening proof generation and verification.
- Backend factory and feature flags for selection (mock, pedersen).
- Mock adapter compatibility layer for existing demo flows.
- Optional CLI integration for a real proof via `--with-real-zk` and a report section.

## Architecture Snapshot
- `libp2p_privacy_poc/privacy_protocol/` contains configuration, security utilities, types, interfaces, factory, and the Pedersen implementation.
- `libp2p_privacy_poc/privacy_protocol/pedersen/` provides commitments, Schnorr PoK, and the Pedersen backend.
- `libp2p_privacy_poc/privacy_protocol/adapters/` provides a mock backend for compatibility with the legacy mock proof system.
- The main tool uses mock proofs by default; the real proof path is opt-in and additive.

## Proof Semantics (what we can prove today)
- Real proof: knowledge of the opening `(value, blinding)` of a Pedersen commitment.
- The commitment is derived from `peer_id` and the proof is bound to a `ProofContext` (peer_id, session_id, metadata).
- This proof does not claim anonymity set membership, unlinkability, or range properties.

## Integration Points
- `privacy_protocol.factory.get_zk_backend(prefer="pedersen")`
- `PedersenBackend.generate_commitment_opening_proof(ctx)` and `verify_proof(proof)`
- CLI: `libp2p-privacy analyze --with-real-zk` adds a "Real ZK Proofs" section

## Safety Boundaries
- Prototype only; not production-ready and not security-audited.
- Only commitment-opening PoK is real; other proofs remain mock.
- No proof composition, SNARK circuits, or formal verification in Phase 2A.

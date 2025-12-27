# Phase 2B Overview: Composable Privacy Statements (Sigma-Style)

## 1. Overview
Phase 2B delivers three Sigma-style privacy statements implemented in Python.
These statements are designed to be independently verifiable and composable
at the application layer (not in-circuit yet).

**IMPORTANT NOTE:**
Phase 2B implements 3 foundational privacy statements. Additional statements
(Range Proofs, Timing Independence) will be added in Phase 2C alongside
the Rust SNARK migration.

Implemented modules:
- `libp2p_privacy_poc/privacy_protocol/statements.py`
- `libp2p_privacy_poc/privacy_protocol/merkle.py`
- `libp2p_privacy_poc/privacy_protocol/pedersen/membership.py`
- `libp2p_privacy_poc/privacy_protocol/pedersen/unlinkability.py`
- `libp2p_privacy_poc/privacy_protocol/pedersen/continuity.py`

## 2. Statements (detailed)

### 2.1 Anonymity Set Membership
**Statement:** "I know an identity scalar whose commitment is a leaf in the Merkle tree."

**Public Inputs (types and sizes):**
- `statement_type`: `str` ("anon_set_membership_v1")
- `statement_version`: `int` (1)
- `root`: `bytes` (32 bytes, Merkle root)
- `commitment`: `bytes` (33 bytes, SEC1 compressed)
- `ctx_hash`: `bytes` (32 bytes)
- `domain_sep`: `bytes` (domain separator)
- `merkle_path`: `List[Dict[str, Any]]` (list of siblings and positions)

**Witness (secret inputs):**
- `identity_scalar`: `Bn`
- `blinding`: `Bn`
- `merkle_path`: `List[Tuple[bytes, bool]]` (intended witness in circuits)

**Verification steps (Python implementation):**
1. Validate statement metadata via registry.
2. Recompute leaf hash and verify Merkle path to `root`.
3. Verify Schnorr PoK: `z_v*G + z_b*H == A + c*C`.
4. Recompute challenge binding and compare.

**Use case example:** prove membership in an anonymity set without revealing which
leaf corresponds to the prover.

### 2.2 Session Unlinkability
**Statement:** "This session commitment is correctly formed from my identity,
without revealing the identity or linking sessions."

**Public Inputs (types and sizes):**
- `statement_type`: `str` ("session_unlinkability_v1")
- `statement_version`: `int` (1)
- `tag`: `bytes` (32 bytes, session tag)
- `commitment`: `bytes` (33 bytes, SEC1 compressed)
- `ctx_hash`: `bytes` (32 bytes)
- `domain_sep`: `bytes`

**Witness (secret inputs):**
- `identity_scalar`: `Bn`
- `blinding`: `Bn`

**Verification steps (Python implementation):**
1. Validate statement metadata via registry.
2. Recompute session tag from commitment + context hash.
3. Verify Schnorr PoK: `z_v*G + z_b*H == A + c*C`.
4. Recompute challenge binding and compare.

**Use case example:** prove that two sessions are valid without linking them,
using fresh blindings per session.

### 2.3 Identity Continuity
**Statement:** "Two commitments share the same hidden identity scalar."

**Public Inputs (types and sizes):**
- `statement_type`: `str` ("identity_continuity_v1")
- `statement_version`: `int` (1)
- `commitment_1`: `bytes` (33 bytes, SEC1 compressed)
- `commitment_2`: `bytes` (33 bytes, SEC1 compressed)
- `ctx_hash`: `bytes` (32 bytes)
- `domain_sep`: `bytes`

**Witness (secret inputs):**
- `identity_scalar`: `Bn`
- `blinding_1`: `Bn`
- `blinding_2`: `Bn`

**Verification steps (Python implementation):**
1. Validate statement metadata via registry.
2. Extract A1, A2 and responses.
3. Verify equation 1: `z_id*G + z_1*H == A1 + c*C1`.
4. Verify equation 2: `z_id*G + z_2*H == A2 + c*C2`.
5. Recompute challenge binding and compare.

**Use case example:** prove continuity across sessions without revealing the
identity or blinding values.

## 3. Circuit Mappings (Phase 2C Preparation)
Circuits will be implemented in Rust (not Python). The mappings below
describe intended inputs and constraints for Phase 2C circuits.

### 3.1 Anonymity Set Membership (Circuit)
**Public Inputs:** Merkle root (32 bytes), commitment (33 bytes), ctx_hash (32 bytes),
statement metadata fields.  
**Witness:** identity_scalar, blinding, merkle_path (siblings + positions).  
**Constraints:** recompute commitment, recompute Merkle root, verify Schnorr PoK,
bind challenge to context.  
**Estimated Constraints:** ~10K (rough estimate).  
**Rust Crate (planned):** `privacy_snarks::phase2b::membership`

### 3.2 Session Unlinkability (Circuit)
**Public Inputs:** tag (32 bytes), commitment (33 bytes), ctx_hash (32 bytes),
statement metadata fields.  
**Witness:** identity_scalar, blinding.  
**Constraints:** recompute commitment, recompute tag, verify Schnorr PoK,
bind challenge to context.  
**Estimated Constraints:** ~1K (rough estimate).  
**Rust Crate (planned):** `privacy_snarks::phase2b::unlinkability`

### 3.3 Identity Continuity (Circuit)
**Public Inputs:** commitment_1 (33 bytes), commitment_2 (33 bytes), ctx_hash (32 bytes),
statement metadata fields.  
**Witness:** identity_scalar, blinding_1, blinding_2.  
**Constraints:** verify both Schnorr-style equations with shared identity response,
bind challenge to both commitments.  
**Estimated Constraints:** ~500 (rough estimate).  
**Rust Crate (planned):** `privacy_snarks::phase2b::continuity`

### Phase 2C New Statements (Not Implemented Yet)

#### 4. Range Proofs
**Statement:** "My value v is in range [min, max] without revealing v"  
**Status:** Planned for Phase 2C  
**Estimated Constraints:** ~5K

#### 5. Timing Independence Proofs
**Statement:** "My actions are timing-independent"  
**Status:** Planned for Phase 2C  
**Estimated Constraints:** ~2K

Total Phase 2C scope: 5 statements (3 migrated + 2 new).

## 4. API Reference
PedersenBackend methods for Phase 2B statements:

```python
from typing import List, Tuple
from petlib.bn import Bn
from libp2p_privacy_poc.privacy_protocol.types import ProofContext, ZKProof

class PedersenBackend:
    def generate_membership_proof(
        self,
        identity_scalar: Bn,
        blinding: Bn,
        merkle_path: List[Tuple[bytes, bool]],
        root: bytes,
        context: ProofContext,
    ) -> ZKProof:
        ...

    def verify_membership_proof(self, proof: ZKProof) -> bool:
        ...

    def generate_unlinkability_proof(
        self,
        identity_scalar: Bn,
        blinding: Bn,
        context: ProofContext,
    ) -> ZKProof:
        ...

    def verify_unlinkability_proof(self, proof: ZKProof) -> bool:
        ...

    def generate_continuity_proof(
        self,
        identity_scalar: Bn,
        blinding_1: Bn,
        blinding_2: Bn,
        context: ProofContext,
    ) -> ZKProof:
        ...

    def verify_continuity_proof(self, proof: ZKProof) -> bool:
        ...
```

## 5. Example Usage
Examples assume the repo root is on `PYTHONPATH`.

### 5.1 Membership Proof (Merkle tree setup)
```python
from petlib.bn import Bn
from libp2p_privacy_poc.privacy_protocol.pedersen.backend import PedersenBackend
from libp2p_privacy_poc.privacy_protocol.pedersen.membership import g, h
from libp2p_privacy_poc.privacy_protocol.merkle import (
    hash_leaf, build_tree, DOMAIN_SEPARATORS_2B
)
from libp2p_privacy_poc.privacy_protocol.types import ProofContext

backend = PedersenBackend()
identity_scalars = [Bn.from_num(i + 1) for i in range(4)]
blindings = [Bn.from_num(i + 100) for i in range(4)]

commitments = [
    ((id_s * g) + (blind * h)).export()
    for id_s, blind in zip(identity_scalars, blindings)
]
leaves = [
    hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], c)
    for c in commitments
]
root, paths = build_tree(leaves)

ctx = ProofContext(peer_id="peer-1", session_id="session-1", metadata={}, timestamp=0.0)
proof = backend.generate_membership_proof(
    identity_scalar=identity_scalars[0],
    blinding=blindings[0],
    merkle_path=paths[0],
    root=root,
    context=ctx,
)
assert backend.verify_membership_proof(proof)
```

### 5.2 Unlinkable Sessions
```python
from petlib.bn import Bn
from libp2p_privacy_poc.privacy_protocol.pedersen.backend import PedersenBackend
from libp2p_privacy_poc.privacy_protocol.types import ProofContext

backend = PedersenBackend()
identity_scalar = Bn.from_num(42)

ctx_a = ProofContext(peer_id="peer-1", session_id="session-a", metadata={"topic": "a"})
ctx_b = ProofContext(peer_id="peer-1", session_id="session-b", metadata={"topic": "b"})

proof_a = backend.generate_unlinkability_proof(
    identity_scalar=identity_scalar,
    blinding=Bn.from_num(100),
    context=ctx_a,
)
proof_b = backend.generate_unlinkability_proof(
    identity_scalar=identity_scalar,
    blinding=Bn.from_num(200),
    context=ctx_b,
)

assert backend.verify_unlinkability_proof(proof_a)
assert backend.verify_unlinkability_proof(proof_b)
assert proof_a.public_inputs["tag"] != proof_b.public_inputs["tag"]
```

### 5.3 Selective Continuity
```python
from petlib.bn import Bn
from libp2p_privacy_poc.privacy_protocol.pedersen.backend import PedersenBackend
from libp2p_privacy_poc.privacy_protocol.types import ProofContext

backend = PedersenBackend()
identity_scalar = Bn.from_num(7)

ctx = ProofContext(peer_id="peer-1", session_id="continuity", metadata={})
proof = backend.generate_continuity_proof(
    identity_scalar=identity_scalar,
    blinding_1=Bn.from_num(300),
    blinding_2=Bn.from_num(400),
    context=ctx,
)

assert backend.verify_continuity_proof(proof)
```

## 6. Testing
Commands to run statement-specific tests:

```bash
PYTHONPATH=/Users/hanymac/Downloads/libp2p_privacy_poc \
./venv/bin/python -m pytest libp2p_privacy_poc/privacy_protocol/pedersen/tests/test_membership.py -v
```

```bash
PYTHONPATH=/Users/hanymac/Downloads/libp2p_privacy_poc \
./venv/bin/python -m pytest libp2p_privacy_poc/privacy_protocol/pedersen/tests/test_unlinkability.py -v
```

```bash
PYTHONPATH=/Users/hanymac/Downloads/libp2p_privacy_poc \
./venv/bin/python -m pytest libp2p_privacy_poc/privacy_protocol/pedersen/tests/test_continuity.py -v
```

Integration coverage (all three statements):
```bash
PYTHONPATH=/Users/hanymac/Downloads/libp2p_privacy_poc \
./venv/bin/python -m pytest libp2p_privacy_poc/privacy_protocol/pedersen/tests/test_integration_phase2b.py -v
```

## 7. Limitations & Future Work
Current limitations:
- Each property is proven separately (no proof composition).
- Prototype implementation only; no production security claims.
- Python-based Sigma proofs; SNARK circuits not implemented yet.
- Merkle path is currently included in public inputs for Python verification.

### Phase 2C Roadmap

**Rust Migration (Weeks 1-16):**
1. Migrate 3 existing statements to Rust circuits (arkworks primary, librustzcash fallback)
2. Replace SHA-256 with Poseidon hash
3. PyO3 bridge implementation

**New Statements (Weeks 17-20):**
4. Implement Range Proofs in Rust
5. Implement Timing Independence Proofs in Rust

**Integration (Weeks 21-24):**
6. Dual-mode operation (Sigma fallback + SNARK)
7. Performance optimization
8. Production hardening

## 8. References
- Curve: secp256k1 via petlib (`privacy_protocol/pedersen/commitments.py`)
- Hashing: SHA-256 in Phase 2B (`membership.py`, `unlinkability.py`, `continuity.py`)
- Merkle utilities: `privacy_protocol/merkle.py`
- Statement registry and metadata validation: `privacy_protocol/statements.py`
- Integration patterns: `privacy_protocol/pedersen/tests/test_integration_phase2b.py`

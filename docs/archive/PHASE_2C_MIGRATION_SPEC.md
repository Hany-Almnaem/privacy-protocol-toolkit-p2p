# Phase 2C Migration Specification (Rust + PyO3 SNARKs)

## 1. Architecture Overview
Phase 2C moves proving from Python (Sigma proofs) to Rust SNARK circuits.

```
Python Layer (orchestration + networking + statement validation)
  ↓ serialize witness/public inputs (CBOR, versioned)
PyO3 Bridge (FFI boundary)
  ↓ FFI calls with byte buffers
Rust Circuit Layer (SNARK proving for 5 statements total)
```

Responsibilities:
- **Python**: orchestration, context hashing, statement validation, witness packing
- **Rust**: SNARK proving/verification for 5 statements (3 migrated + 2 new)
- **PyO3**: FFI boundary only (no circuit logic in Python)

## 2. Technology Stack Decisions
- **SNARK library**: `arkworks` (primary), `librustzcash` (fallback)
  - Rationale: both are used in production-grade systems (e.g., Zcash, Tornado Cash).
- **Curve**: BN254 (efficient pairings, common in Groth16 deployments)
- **Hash**: Poseidon (SNARK-friendly replacement for SHA-256)
- **Proving system**: Groth16 (start), PLONK (future upgrade)

## 3. Statement Scope

**Phase 2B → Phase 2C Migration (3 statements):**
1. Membership (migrate SHA-256 → Poseidon)
2. Unlinkability (migrate SHA-256 → Poseidon)
3. Continuity (migrate SHA-256 → Poseidon)

**Phase 2C New Implementations (2 statements):**
4. Range Proofs (NEW - implement in Rust)
5. Timing Independence (NEW - implement in Rust)

## 4. Witness Serialization Format
All witness serialization is **deterministic and versioned**:
- Encoding: CBOR (`cbor2.dumps`)
- Canonical encoding recommended (`canonical=True`)
- Scalars: 32-byte big-endian, zero-padded
- Points: SEC1 compressed (33 bytes)
- Endianness: big-endian for all integers and scalar bytes

### Membership (Migration)
```python
# Python side
import cbor2

def serialize_membership_witness(identity_scalar, blinding, merkle_path):
    return cbor2.dumps({
        "schema_version": 1,
        "identity_scalar": identity_scalar.binary().rjust(32, b"\x00"),
        "blinding": blinding.binary().rjust(32, b"\x00"),
        "merkle_path": [
            {"sibling": sibling, "is_left": is_left}
            for sibling, is_left in merkle_path
        ],
    })
```
```rust
// Rust side
use serde::Deserialize;

#[derive(Deserialize)]
pub struct MerkleNode {
    #[serde(with = "serde_bytes")]
    pub sibling: Vec<u8>, // 32 bytes
    pub is_left: bool,
}

#[derive(Deserialize)]
pub struct MembershipWitness {
    pub schema_version: u8,
    #[serde(with = "serde_bytes")]
    pub identity_scalar: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub blinding: Vec<u8>, // 32 bytes
    pub merkle_path: Vec<MerkleNode>,
}
```

### Unlinkability (Migration)
```python
# Python side
import cbor2

def serialize_unlinkability_witness(identity_scalar, blinding):
    return cbor2.dumps({
        "schema_version": 1,
        "identity_scalar": identity_scalar.binary().rjust(32, b"\x00"),
        "blinding": blinding.binary().rjust(32, b"\x00"),
    })
```
```rust
// Rust side
use serde::Deserialize;

#[derive(Deserialize)]
pub struct UnlinkabilityWitness {
    pub schema_version: u8,
    #[serde(with = "serde_bytes")]
    pub identity_scalar: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub blinding: Vec<u8>, // 32 bytes
}
```

### Continuity (Migration)
```python
# Python side
import cbor2

def serialize_continuity_witness(identity_scalar, blinding_1, blinding_2):
    return cbor2.dumps({
        "schema_version": 1,
        "identity_scalar": identity_scalar.binary().rjust(32, b"\x00"),
        "blinding_1": blinding_1.binary().rjust(32, b"\x00"),
        "blinding_2": blinding_2.binary().rjust(32, b"\x00"),
    })
```
```rust
// Rust side
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ContinuityWitness {
    pub schema_version: u8,
    #[serde(with = "serde_bytes")]
    pub identity_scalar: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub blinding_1: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub blinding_2: Vec<u8>, // 32 bytes
}
```

### Range Proofs (NEW)
```python
# Python side
import cbor2

def serialize_range_witness(value, blinding, min_value, max_value):
    return cbor2.dumps({
        "schema_version": 1,
        "value": value.binary().rjust(32, b"\x00"),
        "blinding": blinding.binary().rjust(32, b"\x00"),
        "min_value": min_value.to_bytes(4, "big"),
        "max_value": max_value.to_bytes(4, "big"),
    })
```
```rust
// Rust side (NEW)
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RangeWitness {
    pub schema_version: u8,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub blinding: Vec<u8>, // 32 bytes
    pub min_value: u32,
    pub max_value: u32,
}
```

### Timing Independence (NEW)
```python
# Python side
import cbor2

def serialize_timing_witness(action_commitments, timestamps, randomness):
    return cbor2.dumps({
        "schema_version": 1,
        "action_commitments": [c for c in action_commitments],  # 33 bytes each
        "timestamps": timestamps,  # list[int], CBOR unsigned ints
        "randomness": [r.binary().rjust(32, b"\x00") for r in randomness],
    })
```
```rust
// Rust side (NEW)
use serde::Deserialize;

#[derive(Deserialize)]
pub struct TimingWitness {
    pub schema_version: u8,
    pub action_commitments: Vec<Vec<u8>>, // 33 bytes each
    pub timestamps: Vec<u64>,
    #[serde(with = "serde_bytes")]
    pub randomness: Vec<Vec<u8>>, // 32 bytes each
}
```

## 5. Circuit Specifications
All circuits are implemented in Rust and verify the same semantics as Phase 2B,
with SHA-256 replaced by Poseidon.

### Membership (MIGRATION)
**Public Inputs (Rust):** `root: Fr`, `commitment_x: Fr`, `commitment_y: Fr`, `ctx_hash: Fr`  
**Witness:** `identity_scalar: Fr`, `blinding: Fr`, `merkle_path: Vec<(Fr, bool)>`  
**Constraints:**
- Compute commitment `C = id*G + r*H`
- `leaf = Poseidon(C)` (replaces SHA-256)
- Verify Merkle path: `root == PoseidonPath(leaf, merkle_path)`
- Verify Schnorr equations with Poseidon challenge
**Estimated Constraints:** ~10K  
**Rust Crate (planned):** `privacy_snarks::phase2b::membership`

### Unlinkability (MIGRATION)
**Public Inputs (Rust):** `tag: Fr`, `commitment_x: Fr`, `commitment_y: Fr`, `ctx_hash: Fr`  
**Witness:** `identity_scalar: Fr`, `blinding: Fr`  
**Constraints:**
- Compute commitment `C = id*G + r*H`
- `tag = Poseidon(ctx_hash || C)`
- Verify Schnorr equations with Poseidon challenge
**Estimated Constraints:** ~1K  
**Rust Crate (planned):** `privacy_snarks::phase2b::unlinkability`

### Continuity (MIGRATION)
**Public Inputs (Rust):** `commitment_1: (Fr, Fr)`, `commitment_2: (Fr, Fr)`, `ctx_hash: Fr`  
**Witness:** `identity_scalar: Fr`, `blinding_1: Fr`, `blinding_2: Fr`  
**Constraints:**
- Verify two Schnorr-style equations with shared identity response
- Bind challenge to both commitments via Poseidon
**Estimated Constraints:** ~500  
**Rust Crate (planned):** `privacy_snarks::phase2b::continuity`

## 6. PyO3 Bridge API
```python
from privacy_circuits import (
    MembershipProver,      # Migrated
    UnlinkabilityProver,   # Migrated
    ContinuityProver,      # Migrated
    RangeProver,           # NEW
    TimingProver,          # NEW
)

# Migrated statement
membership = MembershipProver(params_path="params/membership.bin")
proof_bytes = membership.prove(witness_bytes, public_inputs_bytes)

# New statement
range_prover = RangeProver(params_path="params/range.bin")
range_proof = range_prover.prove(value=42, min=0, max=100, blinding=r)
```

Constraints:
- Python only passes serialized bytes (or simple scalars for Range/Timing helpers).
- Rust handles circuit construction, proof generation, and verification.

## 7. Migration Strategy

**Phase 1: Rust Setup (Weeks 1-2)**
- Set up Rust workspace
- PyO3 bridge scaffolding
- Poseidon hash implementation

**Phase 2: Migration (Weeks 3-16)**
- Week 3-6: Membership circuit (SHA-256 → Poseidon)
- Week 7-10: Unlinkability circuit (SHA-256 → Poseidon)
- Week 11-14: Continuity circuit (SHA-256 → Poseidon)
- Week 15-16: Integration testing

**Phase 3: New Statements (Weeks 17-20)**
- Week 17-18: Range Proofs implementation
- Week 19-20: Timing Independence implementation

**Phase 4: Production (Weeks 21-24)**
- Week 21-22: Performance optimization
- Week 23-24: Production hardening

## 8. Backward Compatibility
Dual-mode operation for migrated statements:
```python
class HybridProver:
    def generate_membership_proof(self, use_snark=False):
        if use_snark:
            return self.snark_prover.prove(...)  # Rust circuit
        return self.sigma_prover.prove(...)      # Phase 2B fallback
```

Notes:
- Range Proofs and Timing Independence will ONLY have SNARK mode.
- Python Sigma proofs remain as fallback for the 3 migrated statements.

## 9. Validation Checklist
Before Phase 2C starts:
- [ ] Phase 2B tests pass (105 tests for 3 statements)
- [ ] Witness/public-input separation clear
- [ ] Serialization format documented for 3 statements
- [ ] Rust toolchain installed
- [ ] PyO3 environment tested
- [ ] Range Proof design documented and reviewed (no security claim)
- [ ] Timing Independence design documented and reviewed (no security claim)

**Critical requirements:**
- No Python-native SNARK implementation
- All circuits in Rust (5 total: 3 migrated + 2 new)
- PyO3 for FFI only (not for circuit logic)
- Witness serialization deterministic and versioned
- Range/Timing designs completed before implementation starts

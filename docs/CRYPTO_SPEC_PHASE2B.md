# Phase 2B Cryptographic Specification

## Primitives

### Curve
- **Name:** secp256k1
- **Library:** petlib
- **Point serialization:** SEC1 compressed (33 bytes)
- **Scalar serialization:** big-endian (32 bytes)
- **Group order:** 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

### Hash Functions
- **Primary:** SHA-256
- **Output:** 32 bytes
- **Challenge derivation:** SHA-256
- **Merkle tree:** SHA-256

### Randomness
- **Source:** RandomnessSource (security.py)
- **Scalar generation:** get_random_scalar_mod_order()
- **Nonce strategy:** Random (fork-safe, not deterministic)

## Domain Separators

### Existing (from Phase 2A)
```python
DOMAIN_SEPARATORS = {
    "peer_id_scalar": b"LIBP2P_PRIVACY_PEER_ID_SCALAR_V1",
    "commitment": b"PEDERSEN_COMMITMENT_V1",
    "schnorr_challenge": b"SCHNORR_CHALLENGE_V1",
}
```

### New for Phase 2B
```python
DOMAIN_SEPARATORS_2B = {
    # Merkle tree
    "merkle_leaf": b"MERKLE_LEAF_V1",
    "merkle_node": b"MERKLE_NODE_V1",

    # Statements
    "membership_challenge": b"MEMBERSHIP_CHALLENGE_V1",
    "unlinkability_tag": b"UNLINKABILITY_TAG_V1",
    "continuity_challenge": b"CONTINUITY_CHALLENGE_V1",
}
```

## Serialization Formats

### Point Encoding
```python
def serialize_point(P: EcPt) -> bytes:
    """SEC1 compressed: 0x02/0x03 + x-coordinate (33 bytes)"""
    return P.export()  # petlib default is compressed

def deserialize_point(data: bytes) -> EcPt:
    """Parse SEC1 compressed point"""
    return EcPt.from_binary(data, group)
```

### Scalar Encoding
```python
def serialize_scalar(s: Bn) -> bytes:
    """Big-endian 32 bytes, zero-padded"""
    return s.binary().rjust(32, b'\x00')

def deserialize_scalar(data: bytes) -> Bn:
    """Parse big-endian scalar"""
    return Bn.from_binary(data) % order
```

### CBOR Conventions
- Points: store as bytes (33 bytes compressed)
- Scalars: store as bytes (32 bytes big-endian)
- Merkle paths: list of dicts [{"sibling": bytes, "is_left": bool}, ...]
- Context hashes: raw bytes (32 bytes)

## Identity Scalar Derivation
```python
def derive_identity_scalar(peer_id: str) -> Bn:
    """
    Derive identity scalar from libp2p peer_id.
    peer_id is public, so this does NOT provide anonymity by itself.
    Pedersen blinding is applied elsewhere in the protocol.
    """
    domain = DOMAIN_SEPARATORS["peer_id_scalar"]
    peer_id_bytes = peer_id.encode('utf-8')
    h = hashlib.sha256(domain + peer_id_bytes).digest()
    return Bn.from_binary(h) % order
```

## Context Hash Computation
```python
def compute_ctx_hash(context: ProofContext) -> bytes:
    """
    Existing implementation in backend.py:
    ctx_hash = sha256(context.to_bytes()).digest()

    ProofContext.to_bytes() serializes:
    - peer_id (utf-8)
    - session_id (utf-8)
    - metadata (CBOR)
    - timestamp (float as bytes)
    """
    return hashlib.sha256(context.to_bytes()).digest()
```

## Test Vectors
```python
# Vector 1: Identity Scalar Derivation
peer_id = "12D3KooWTest"
expected_scalar = Bn.from_hex("c39b96302c943d1e0b6ef3e45fa75f0add7601f1acd0fd0413d21f28e8178fa5")

# Vector 2: Merkle Leaf Hash
commitment_bytes = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)  # 33-byte compressed point
leaf_hash = sha256(DOMAIN_SEPARATORS_2B["merkle_leaf"] + commitment_bytes).digest()
expected = bytes.fromhex("0dd947a99cc4778b0d23049a24430d511205d17931b60fc5855686768b449aeb")

# Vector 3: Challenge Computation
# Membership challenge
root_bytes = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
ctx_hash = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)
challenge_input = (
    DOMAIN_SEPARATORS_2B["membership_challenge"] +
    root_bytes +
    commitment_bytes +
    ctx_hash
)
challenge = Bn.from_binary(sha256(challenge_input).digest()) % order
expected_challenge = Bn.from_hex(
    "1f20c1e9ac94f460e1f9f7c1374f9bb86134848ff7b6032f3164dd9b9ba57dbe"
)
```

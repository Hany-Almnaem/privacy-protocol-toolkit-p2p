"""
WARNING: DRAFT - requires crypto review before production use.

Concrete security property tests for Schnorr proof of knowledge.
"""

import pytest
from petlib.bn import Bn
from petlib.ec import EcPt

from ..commitments import (
    setup_curve,
    commit,
    verify_commitment,
)
from ..schnorr import (
    generate_schnorr_pok,
    verify_schnorr_pok,
)
from .. import schnorr as schnorr_module
from ...config import GROUP_ORDER, POINT_SIZE_BYTES


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def params():
    return setup_curve()


# ============================================================================
# HELPERS
# ============================================================================


class FixedRandomnessSource:
    def __init__(self, r_v: int, r_b: int):
        self._values = [r_v, r_b]
        self._index = 0

    def random_scalar(self, order: int) -> int:
        value = self._values[self._index % len(self._values)] % order
        self._index += 1
        return value

    def get_random_scalar_mod_order(self) -> int:
        return self.random_scalar(GROUP_ORDER)


# ============================================================================
# TESTS: SECURITY PROPERTIES
# ============================================================================


def test_hvzk_simulated_transcript_verifies(monkeypatch, params):
    """Simulate a transcript without witness and verify."""
    value = 5
    blinding = 9
    commitment, _ = commit(value, blinding=blinding, params=params)

    C = EcPt.from_binary(commitment, params.group)

    c = 7
    z_v = 11
    z_b = 13

    c_bn = Bn.from_decimal(str(c))
    z_v_bn = Bn.from_decimal(str(z_v))
    z_b_bn = Bn.from_decimal(str(z_b))

    left_side = z_v_bn * params.G + z_b_bn * params.H
    A = left_side - c_bn * C
    A_bytes = A.export()

    assert len(A_bytes) == POINT_SIZE_BYTES

    c_bytes = c.to_bytes(32, "big")
    proof = {
        "A": A_bytes,
        "c": c_bytes,
        "z_v": z_v.to_bytes(32, "big"),
        "z_b": z_b.to_bytes(32, "big"),
    }

    monkeypatch.setattr(
        schnorr_module,
        "_compute_challenge",
        lambda *args, **kwargs: c_bytes,
    )

    ctx = b"hvzk_context"
    assert verify_schnorr_pok(commitment, proof, ctx, params) is True


def test_soundness_proof_bound_to_commitment(params):
    """Proof should not verify against a different commitment."""
    value = 17
    blinding = 19
    commitment_1, _ = commit(value, blinding=blinding, params=params)

    ctx = b"soundness_context"
    proof = generate_schnorr_pok(
        commitment=commitment_1,
        value=value,
        blinding=blinding,
        context=ctx,
        params=params,
    )

    commitment_2, _ = commit(value + 1, blinding=blinding, params=params)
    assert commitment_1 != commitment_2

    assert verify_schnorr_pok(commitment_1, proof, ctx, params) is True
    assert verify_schnorr_pok(commitment_2, proof, ctx, params) is False


def test_special_soundness_witness_extraction(params):
    """Extract witnesses from two transcripts with same A."""
    value = 123
    blinding = 456
    commitment, _ = commit(value, blinding=blinding, params=params)

    r_v = 77
    r_b = 88

    ctx1 = b"extract_context_1"
    ctx2 = b"extract_context_2"

    proof1 = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=ctx1,
        params=params,
        randomness_source=FixedRandomnessSource(r_v, r_b),
    )

    proof2 = generate_schnorr_pok(
        commitment=commitment,
        value=value,
        blinding=blinding,
        context=ctx2,
        params=params,
        randomness_source=FixedRandomnessSource(r_v, r_b),
    )

    assert proof1["A"] == proof2["A"]

    c1 = int.from_bytes(proof1["c"], "big") % GROUP_ORDER
    c2 = int.from_bytes(proof2["c"], "big") % GROUP_ORDER

    if c1 == c2:
        ctx2 = b"extract_context_3"
        proof2 = generate_schnorr_pok(
            commitment=commitment,
            value=value,
            blinding=blinding,
            context=ctx2,
            params=params,
            randomness_source=FixedRandomnessSource(r_v, r_b),
        )
        c2 = int.from_bytes(proof2["c"], "big") % GROUP_ORDER

    assert c1 != c2

    z_v1 = int.from_bytes(proof1["z_v"], "big")
    z_v2 = int.from_bytes(proof2["z_v"], "big")
    z_b1 = int.from_bytes(proof1["z_b"], "big")
    z_b2 = int.from_bytes(proof2["z_b"], "big")

    denom = (c1 - c2) % GROUP_ORDER
    inv_denom = pow(denom, -1, GROUP_ORDER)

    extracted_value = ((z_v1 - z_v2) * inv_denom) % GROUP_ORDER
    extracted_blinding = ((z_b1 - z_b2) * inv_denom) % GROUP_ORDER

    assert verify_commitment(
        commitment,
        extracted_value,
        extracted_blinding,
        params,
    ) is True

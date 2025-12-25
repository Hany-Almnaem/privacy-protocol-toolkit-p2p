from libp2p_privacy_poc.privacy_protocol.test_vectors import phase2b_vectors


def test_compute_expected_vectors():
    vectors = {
        "identity_derivation": {"peer_id": "12D3KooWTest"},
        "merkle_leaf": {
            "commitment_hex": (
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            )
        },
        "membership_challenge": {
            "root_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "commitment_hex": (
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ),
            "ctx_hash_hex": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        },
    }

    expected = phase2b_vectors.compute_expected(vectors)

    assert expected["identity_derivation"]["expected_scalar_hex"] == (
        "c39b96302c943d1e0b6ef3e45fa75f0add7601f1acd0fd0413d21f28e8178fa5"
    )
    assert expected["merkle_leaf"]["expected_leaf_hex"] == (
        "0dd947a99cc4778b0d23049a24430d511205d17931b60fc5855686768b449aeb"
    )
    assert expected["membership_challenge"]["expected_challenge_hex"] == (
        "1f20c1e9ac94f460e1f9f7c1374f9bb86134848ff7b6032f3164dd9b9ba57dbe"
    )


def test_vectors_file_validates():
    data = phase2b_vectors.load_vectors()
    errors = phase2b_vectors.validate_vectors(data)
    assert errors == []

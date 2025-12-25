"""Tests for Merkle tree utilities with deterministic vectors"""

import pytest
from privacy_protocol.merkle import (
    hash_leaf, hash_node, build_tree, verify_path,
    DOMAIN_SEPARATORS_2B
)


class TestMerkleHashing:
    """Test deterministic hash functions"""

    def test_hash_leaf_deterministic(self):
        """Leaf hash is deterministic"""
        domain_sep = DOMAIN_SEPARATORS_2B["merkle_leaf"]
        leaf_data = b"test_commitment_data"

        hash1 = hash_leaf(domain_sep, leaf_data)
        hash2 = hash_leaf(domain_sep, leaf_data)

        assert hash1 == hash2
        assert len(hash1) == 32

    def test_hash_leaf_domain_separation(self):
        """Different domain separators produce different hashes"""
        leaf_data = b"same_data"

        hash1 = hash_leaf(b"DOMAIN_A", leaf_data)
        hash2 = hash_leaf(b"DOMAIN_B", leaf_data)

        assert hash1 != hash2

    def test_hash_node_deterministic(self):
        """Node hash is deterministic"""
        left = b"\x00" * 32
        right = b"\xff" * 32

        hash1 = hash_node(left, right)
        hash2 = hash_node(left, right)

        assert hash1 == hash2
        assert len(hash1) == 32

    def test_hash_node_order_matters(self):
        """Node hash depends on left/right order"""
        left = b"\x00" * 32
        right = b"\xff" * 32

        hash_lr = hash_node(left, right)
        hash_rl = hash_node(right, left)

        assert hash_lr != hash_rl


class TestMerkleTreeBuild:
    """Test tree building"""

    def test_single_leaf_tree(self):
        """Single leaf tree works"""
        leaf = b"\xaa" * 32
        root, paths = build_tree([leaf])

        assert root == leaf
        assert 0 in paths
        assert len(paths[0]) == 0  # No siblings

    def test_two_leaf_tree(self):
        """Two leaf tree builds correctly"""
        leaf1 = b"\xaa" * 32
        leaf2 = b"\xbb" * 32

        root, paths = build_tree([leaf1, leaf2])

        # Verify root computation
        expected_root = hash_node(leaf1, leaf2)
        assert root == expected_root

        # Verify paths
        assert len(paths[0]) == 1  # One sibling
        assert paths[0][0] == (leaf2, False)  # Sibling on right
        assert paths[1][0] == (leaf1, True)   # Sibling on left

    def test_four_leaf_tree(self):
        """Four leaf balanced tree"""
        leaves = [b"\x00" * 32, b"\x11" * 32, b"\x22" * 32, b"\x33" * 32]
        root, paths = build_tree(leaves)

        # Each leaf should have path of length 2 (depth = 2)
        for i in range(4):
            assert len(paths[i]) == 2

        # Verify root computation manually
        node01 = hash_node(leaves[0], leaves[1])
        node23 = hash_node(leaves[2], leaves[3])
        expected_root = hash_node(node01, node23)
        assert root == expected_root

    def test_odd_leaf_count_duplicates_last(self):
        """Odd leaf count duplicates last leaf"""
        leaves = [b"\xaa" * 32, b"\xbb" * 32, b"\xcc" * 32]
        root, paths = build_tree(leaves)

        # Three leaves become four (last duplicated)
        # Tree structure: (aa, bb), (cc, cc)
        node01 = hash_node(leaves[0], leaves[1])
        node22 = hash_node(leaves[2], leaves[2])  # Duplicate
        expected_root = hash_node(node01, node22)
        assert root == expected_root

    def test_fixed_vector_tree(self):
        """Test against fixed vector (for SNARK compatibility)"""
        # Fixed leaves for deterministic test
        leaves = [
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], b"leaf_0"),
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], b"leaf_1"),
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], b"leaf_2"),
            hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], b"leaf_3"),
        ]

        root, paths = build_tree(leaves)

        expected_root = bytes.fromhex(
            "9989187362aec2a62d0282cc81eb0b396a8a6abd50347694ad3ea5db5954a434"
        )
        assert root == expected_root

        assert len(root) == 32
        assert all(len(paths[i]) == 2 for i in range(4))


class TestMerklePathVerification:
    """Test path verification"""

    def test_valid_path_verifies(self):
        """Valid path passes verification"""
        leaves = [b"\xaa" * 32, b"\xbb" * 32, b"\xcc" * 32, b"\xdd" * 32]
        root, paths = build_tree(leaves)

        # Verify all paths
        for i, leaf in enumerate(leaves):
            assert verify_path(leaf, paths[i], root)

    def test_invalid_leaf_fails(self):
        """Wrong leaf fails verification"""
        leaves = [b"\xaa" * 32, b"\xbb" * 32]
        root, paths = build_tree(leaves)

        wrong_leaf = b"\xff" * 32
        assert not verify_path(wrong_leaf, paths[0], root)

    def test_invalid_path_fails(self):
        """Tampered path fails verification"""
        leaves = [b"\xaa" * 32, b"\xbb" * 32]
        root, paths = build_tree(leaves)

        tampered_path = [(b"\xff" * 32, False)]  # Wrong sibling
        assert not verify_path(leaves[0], tampered_path, root)

    def test_invalid_root_fails(self):
        """Wrong root fails verification"""
        leaves = [b"\xaa" * 32, b"\xbb" * 32]
        root, paths = build_tree(leaves)

        wrong_root = b"\xff" * 32
        assert not verify_path(leaves[0], paths[0], wrong_root)


class TestMerkleEdgeCases:
    """Test edge cases and errors"""

    def test_empty_leaves_raises(self):
        """Empty leaf list raises error"""
        with pytest.raises(ValueError, match="zero leaves"):
            build_tree([])

    def test_large_tree(self):
        """Tree with 256 leaves works"""
        leaves = [bytes([i]) * 32 for i in range(256)]
        root, paths = build_tree(leaves)

        assert len(root) == 32
        assert all(len(paths[i]) == 8 for i in range(256))  # depth = 8

        # Spot check: verify first and last leaf
        assert verify_path(leaves[0], paths[0], root)
        assert verify_path(leaves[255], paths[255], root)

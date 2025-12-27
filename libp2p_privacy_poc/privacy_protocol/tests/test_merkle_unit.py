import hashlib

import pytest

try:
    from privacy_protocol import merkle
except ModuleNotFoundError:
    from .. import merkle


def _leaf_bytes(value: int) -> bytes:
    return bytes([value]) * 32


def test_hash_leaf_matches_sha256():
    leaf_data = b"leaf-data"
    domain_sep = merkle.DOMAIN_SEPARATORS_2B["merkle_leaf"]
    expected = hashlib.sha256(domain_sep + leaf_data).digest()
    assert merkle.hash_leaf(domain_sep, leaf_data) == expected


def test_hash_node_matches_sha256():
    left = _leaf_bytes(1)
    right = _leaf_bytes(2)
    domain_sep = merkle.DOMAIN_SEPARATORS_2B["merkle_node"]
    expected = hashlib.sha256(domain_sep + left + right).digest()
    assert merkle.hash_node(left, right) == expected


def test_build_tree_single_leaf():
    leaf = _leaf_bytes(3)
    root, paths = merkle.build_tree([leaf])
    assert root == leaf
    assert paths == {0: []}
    assert merkle.verify_path(leaf, paths[0], root) is True


def test_build_tree_even_leaves():
    leaves = [_leaf_bytes(4), _leaf_bytes(5)]
    root, paths = merkle.build_tree(leaves)
    expected_root = merkle.hash_node(leaves[0], leaves[1])
    assert root == expected_root
    assert paths[0] == [(leaves[1], False)]
    assert paths[1] == [(leaves[0], True)]
    assert merkle.verify_path(leaves[0], paths[0], root) is True
    assert merkle.verify_path(leaves[1], paths[1], root) is True


def test_build_tree_odd_leaves():
    leaves = [_leaf_bytes(6), _leaf_bytes(7), _leaf_bytes(8)]
    root, paths = merkle.build_tree(leaves)
    parent_left = merkle.hash_node(leaves[0], leaves[1])
    parent_right = merkle.hash_node(leaves[2], leaves[2])
    expected_root = merkle.hash_node(parent_left, parent_right)
    assert root == expected_root
    assert merkle.verify_path(leaves[0], paths[0], root) is True
    assert merkle.verify_path(leaves[1], paths[1], root) is True
    assert merkle.verify_path(leaves[2], paths[2], root) is True
    assert len(paths[2]) == 2


def test_build_tree_empty_raises():
    with pytest.raises(ValueError, match="zero leaves"):
        merkle.build_tree([])


def test_verify_path_invalid():
    leaves = [_leaf_bytes(9), _leaf_bytes(10)]
    root, paths = merkle.build_tree(leaves)
    bad_sibling = _leaf_bytes(11)
    bad_path = [(bad_sibling, False)]
    assert merkle.verify_path(leaves[0], bad_path, root) is False

"""
Merkle tree utilities for anonymity set membership.
Uses SHA-256 with domain separation for leaf/node hashing.
"""

import hashlib
from typing import List, Tuple, Dict, Any

# Import domain separators
from .pedersen.backend import DOMAIN_SEPARATORS

# Phase 2B domain separators (add to DOMAIN_SEPARATORS dict)
DOMAIN_SEPARATORS_2B = {
    "merkle_leaf": b"MERKLE_LEAF_V1",
    "merkle_node": b"MERKLE_NODE_V1",
}

DOMAIN_SEPARATORS.update(DOMAIN_SEPARATORS_2B)


def hash_leaf(domain_sep: bytes, leaf_data: bytes) -> bytes:
    """
    Hash a Merkle tree leaf with domain separation.

    Args:
        domain_sep: Domain separator (usually DOMAIN_SEPARATORS_2B["merkle_leaf"])
        leaf_data: Leaf content (e.g., serialized commitment)

    Returns:
        32-byte SHA-256 hash

    Example:
        commitment_bytes = serialize_point(commitment)
        leaf_hash = hash_leaf(DOMAIN_SEPARATORS_2B["merkle_leaf"], commitment_bytes)
    """
    return hashlib.sha256(domain_sep + leaf_data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """
    Hash two Merkle node hashes.

    Args:
        left: Left child hash (32 bytes)
        right: Right child hash (32 bytes)

    Returns:
        32-byte SHA-256 hash

    Note:
        Uses fixed left||right ordering (no sorting).
        Domain separation applied.
    """
    domain_sep = DOMAIN_SEPARATORS_2B["merkle_node"]
    return hashlib.sha256(domain_sep + left + right).digest()


def build_tree(leaves: List[bytes]) -> Tuple[bytes, Dict[int, List[Tuple[bytes, bool]]]]:
    """
    Build a Merkle tree and generate authentication paths.

    Args:
        leaves: List of leaf hashes (each 32 bytes)

    Returns:
        (root_hash, auth_paths)
        - root_hash: 32-byte Merkle root
        - auth_paths: Dict mapping leaf_index -> [(sibling, is_left), ...]

    Algorithm:
        - If odd number of leaves at any level, duplicate the last leaf
        - Build tree bottom-up
        - Track sibling positions for authentication paths

    Example:
        leaves = [hash_leaf(domain, data) for data in leaf_data_list]
        root, paths = build_tree(leaves)
        my_path = paths[my_leaf_index]
    """
    if not leaves:
        raise ValueError("Cannot build tree with zero leaves")

    if len(leaves) == 1:
        # Single leaf, root = leaf
        return leaves[0], {0: []}

    # Initialize authentication paths
    auth_paths: Dict[int, List[Tuple[bytes, bool]]] = {
        i: [] for i in range(len(leaves))
    }

    current_level: List[Tuple[bytes, List[int]]] = [
        (leaf, [i]) for i, leaf in enumerate(leaves)
    ]

    while len(current_level) > 1:
        next_level: List[Tuple[bytes, List[int]]] = []

        for i in range(0, len(current_level), 2):
            left_hash, left_indices = current_level[i]

            if i + 1 < len(current_level):
                # Pair exists
                right_hash, right_indices = current_level[i + 1]
                duplicated = False
            else:
                # Odd number, duplicate last
                right_hash, right_indices = left_hash, left_indices
                duplicated = True

            # Compute parent
            parent = hash_node(left_hash, right_hash)

            # Record authentication path siblings
            # For left child: sibling is right (on right side, is_left=False)
            # For right child: sibling is left (on left side, is_left=True)
            for leaf_idx in left_indices:
                auth_paths[leaf_idx].append((right_hash, False))
            if not duplicated:
                for leaf_idx in right_indices:
                    auth_paths[leaf_idx].append((left_hash, True))

            if duplicated:
                combined_indices = list(left_indices)
            else:
                combined_indices = left_indices + right_indices
            next_level.append((parent, combined_indices))

        current_level = next_level

    root = current_level[0][0]
    return root, auth_paths


def verify_path(
    leaf_hash: bytes,
    path: List[Tuple[bytes, bool]],
    root: bytes
) -> bool:
    """
    Verify a Merkle authentication path.

    Args:
        leaf_hash: Hash of the leaf (32 bytes)
        path: Authentication path [(sibling, is_left), ...]
        root: Expected root hash (32 bytes)

    Returns:
        True if path is valid, False otherwise

    Example:
        if verify_path(my_leaf, my_path, expected_root):
            print("Leaf is in tree")
    """
    current = leaf_hash

    for sibling, is_left in path:
        if is_left:
            # Sibling is on left, current on right
            current = hash_node(sibling, current)
        else:
            # Sibling is on right, current on left
            current = hash_node(current, sibling)

    return current == root

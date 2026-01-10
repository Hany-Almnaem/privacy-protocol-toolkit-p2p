use super::{poseidon_hash_leaf, poseidon_hash_node, poseidon_params};
use ark_bn254::Fr;

#[test]
fn poseidon_merkle_leaf_node_domain_separation() {
    let params = poseidon_params::<Fr>();
    let leaf = Fr::from(42u64);
    let leaf_hash = poseidon_hash_leaf(&params, leaf);
    let node_hash = poseidon_hash_node(&params, leaf, Fr::from(0u64));

    assert_ne!(leaf_hash, node_hash);
}

#[test]
fn poseidon_merkle_node_order_sensitive() {
    let params = poseidon_params::<Fr>();
    let left = Fr::from(1u64);
    let right = Fr::from(2u64);

    let hash_lr = poseidon_hash_node(&params, left, right);
    let hash_rl = poseidon_hash_node(&params, right, left);

    assert_ne!(hash_lr, hash_rl);
}

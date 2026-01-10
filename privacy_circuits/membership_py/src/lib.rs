use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use membership::{
    commitment_hash, fr_to_fixed_bytes, leaf_hash, node_hash, poseidon_hash_leaf,
    poseidon_hash_node, poseidon_params, verify_membership as verify_membership_inner,
    MembershipInstanceBytes, MembershipInstanceV1Bytes, MembershipPublicInputsBytes,
    MembershipPublicInputsV1Bytes, MembershipWitnessBytes, MembershipWitnessV1Bytes,
    MerklePathNodeBytes, MEMBERSHIP_INSTANCE_VERSION_V1, MERKLE_DEPTH,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::fs;
use std::fs::File;
use std::io::BufReader;

#[pyfunction]
fn verify_membership(
    vk_path: &str,
    public_inputs_path: &str,
    proof_path: &str,
) -> PyResult<bool> {
    let vk = read_verifying_key(vk_path)?;
    let public_inputs_bytes = read_public_inputs(public_inputs_path)?;
    let public_inputs = public_inputs_bytes.into_public_inputs().map_err(PyValueError::new_err)?;
    let proof = read_proof(proof_path)?;

    verify_membership_inner(&vk, &public_inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyfunction]
fn verify_membership_bytes(
    vk_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> PyResult<bool> {
    let vk = deserialize_verifying_key(&vk_bytes)?;
    let public_inputs: MembershipPublicInputsBytes =
        bincode::deserialize(&public_inputs_bytes).map_err(|err| PyValueError::new_err(err.to_string()))?;
    let inputs = public_inputs
        .into_public_inputs()
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let proof = deserialize_proof(&proof_bytes)?;

    verify_membership_inner(&vk, &inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyfunction]
fn make_membership_instance_bytes(
    py: Python<'_>,
    identity_scalar: Vec<u8>,
    blinding: Vec<u8>,
    merkle_siblings: Vec<Vec<u8>>,
    merkle_is_left: Vec<bool>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    if merkle_siblings.len() != merkle_is_left.len() {
        return Err(PyValueError::new_err(
            "merkle_siblings and merkle_is_left length mismatch",
        ));
    }
    if merkle_siblings.len() != MERKLE_DEPTH {
        return Err(PyValueError::new_err(format!(
            "merkle_path length mismatch: expected {}, got {}",
            MERKLE_DEPTH,
            merkle_siblings.len()
        )));
    }

    let merkle_path: Vec<MerklePathNodeBytes> = merkle_siblings
        .into_iter()
        .zip(merkle_is_left.into_iter())
        .map(|(sibling, is_left)| MerklePathNodeBytes { sibling, is_left })
        .collect();

    let witness_bytes = MembershipWitnessBytes {
        identity_scalar,
        blinding,
        merkle_path,
    };
    let witness = witness_bytes
        .clone()
        .into_witness()
        .map_err(PyValueError::new_err)?;

    let params = poseidon_params::<Fr>();
    let commitment = commitment_hash(&params, witness.identity_scalar, witness.blinding);
    let mut current = leaf_hash(&params, commitment);
    for (sibling, is_left) in witness.merkle_path.iter() {
        let (left, right) = if *is_left {
            (*sibling, current)
        } else {
            (current, *sibling)
        };
        current = node_hash(&params, left, right);
    }

    let public_inputs = MembershipPublicInputsBytes {
        root: fr_to_fixed_bytes(&current),
        commitment: fr_to_fixed_bytes(&commitment),
    };
    let instance = MembershipInstanceBytes {
        public_inputs: public_inputs.clone(),
        witness: witness_bytes,
    };

    let instance_bytes =
        bincode::serialize(&instance).map_err(|err| PyValueError::new_err(err.to_string()))?;
    let public_inputs_bytes =
        bincode::serialize(&public_inputs).map_err(|err| PyValueError::new_err(err.to_string()))?;

    Ok((
        PyBytes::new(py, &instance_bytes).into(),
        PyBytes::new(py, &public_inputs_bytes).into(),
    ))
}

#[pyfunction]
fn make_membership_instance_v1_bytes(
    py: Python<'_>,
    identity_scalar: Vec<u8>,
    blinding: Vec<u8>,
    merkle_siblings: Vec<Vec<u8>>,
    merkle_is_left: Vec<bool>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    if merkle_siblings.len() != merkle_is_left.len() {
        return Err(PyValueError::new_err(
            "merkle_siblings and merkle_is_left length mismatch",
        ));
    }
    if merkle_siblings.is_empty() {
        return Err(PyValueError::new_err("merkle_path must not be empty"));
    }

    let merkle_path: Vec<MerklePathNodeBytes> = merkle_siblings
        .into_iter()
        .zip(merkle_is_left.into_iter())
        .map(|(sibling, is_left)| MerklePathNodeBytes { sibling, is_left })
        .collect();

    let depth = merkle_path.len() as u32;

    let witness_bytes = MembershipWitnessV1Bytes {
        version: MEMBERSHIP_INSTANCE_VERSION_V1,
        depth,
        identity_scalar,
        blinding,
        merkle_siblings: merkle_path
            .iter()
            .map(|node| node.sibling.clone())
            .collect(),
        merkle_directions: merkle_path.iter().map(|node| node.is_left).collect(),
    };
    let witness = witness_bytes
        .clone()
        .into_witness(depth as usize)
        .map_err(PyValueError::new_err)?;

    let params = poseidon_params::<Fr>();
    let commitment = commitment_hash(&params, witness.identity_scalar, witness.blinding);
    let mut current = poseidon_hash_leaf(&params, commitment);
    for (sibling, is_left) in witness.merkle_path.iter() {
        let (left, right) = if *is_left {
            (*sibling, current)
        } else {
            (current, *sibling)
        };
        current = poseidon_hash_node(&params, left, right);
    }

    let public_inputs = MembershipPublicInputsV1Bytes {
        version: MEMBERSHIP_INSTANCE_VERSION_V1,
        depth,
        root: fr_to_fixed_bytes(&current),
        commitment: fr_to_fixed_bytes(&commitment),
    };
    let instance = MembershipInstanceV1Bytes {
        version: MEMBERSHIP_INSTANCE_VERSION_V1,
        public_inputs: public_inputs.clone(),
        witness: witness_bytes,
    };

    let instance_bytes =
        bincode::serialize(&instance).map_err(|err| PyValueError::new_err(err.to_string()))?;
    let public_inputs_bytes = bincode::serialize(&public_inputs)
        .map_err(|err| PyValueError::new_err(err.to_string()))?;

    Ok((
        PyBytes::new(py, &instance_bytes).into(),
        PyBytes::new(py, &public_inputs_bytes).into(),
    ))
}

#[pyfunction]
fn verify_membership_v1(
    vk_path: &str,
    public_inputs_path: &str,
    proof_path: &str,
) -> PyResult<bool> {
    let vk = read_verifying_key(vk_path)?;
    let public_inputs_bytes = read_public_inputs_v1(public_inputs_path)?;
    let (public_inputs, _depth) = public_inputs_bytes
        .into_public_inputs_with_depth()
        .map_err(PyValueError::new_err)?;
    let proof = read_proof(proof_path)?;

    verify_membership_inner(&vk, &public_inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyfunction]
fn verify_membership_v1_bytes(
    vk_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> PyResult<bool> {
    let vk = deserialize_verifying_key(&vk_bytes)?;
    let public_inputs: MembershipPublicInputsV1Bytes =
        bincode::deserialize(&public_inputs_bytes).map_err(|err| PyValueError::new_err(err.to_string()))?;
    let (inputs, _depth) = public_inputs
        .into_public_inputs_with_depth()
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let proof = deserialize_proof(&proof_bytes)?;

    verify_membership_inner(&vk, &inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pymodule]
fn membership_py(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_membership, m)?)?;
    m.add_function(wrap_pyfunction!(verify_membership_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(make_membership_instance_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(make_membership_instance_v1_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(verify_membership_v1, m)?)?;
    m.add_function(wrap_pyfunction!(verify_membership_v1_bytes, m)?)?;
    Ok(())
}

fn read_verifying_key(path: &str) -> PyResult<VerifyingKey<Bn254>> {
    let file = File::open(path).map_err(PyValueError::new_err)?;
    let mut reader = BufReader::new(file);
    VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

fn read_public_inputs(path: &str) -> PyResult<MembershipPublicInputsBytes> {
    let data = fs::read(path).map_err(PyValueError::new_err)?;
    bincode::deserialize::<MembershipPublicInputsBytes>(&data)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

fn read_public_inputs_v1(path: &str) -> PyResult<MembershipPublicInputsV1Bytes> {
    let data = fs::read(path).map_err(PyValueError::new_err)?;
    bincode::deserialize::<MembershipPublicInputsV1Bytes>(&data)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

fn read_proof(path: &str) -> PyResult<Proof<Bn254>> {
    let file = File::open(path).map_err(PyValueError::new_err)?;
    let mut reader = BufReader::new(file);
    Proof::<Bn254>::deserialize_uncompressed(&mut reader)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

fn deserialize_verifying_key(bytes: &[u8]) -> PyResult<VerifyingKey<Bn254>> {
    let mut reader = std::io::Cursor::new(bytes);
    VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

fn deserialize_proof(bytes: &[u8]) -> PyResult<Proof<Bn254>> {
    let mut reader = std::io::Cursor::new(bytes);
    Proof::<Bn254>::deserialize_uncompressed(&mut reader)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

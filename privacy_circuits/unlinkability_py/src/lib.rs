use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use unlinkability::{
    commitment_hash, domain_sep_v2_fr, fr_from_fixed_bytes, fr_to_fixed_bytes, poseidon_params,
    tag_hash, verify_unlinkability_v2 as verify_unlinkability_v2_inner, UnlinkabilityInstanceV2,
    UnlinkabilityPublicInputsV2, UNLINKABILITY_INSTANCE_VERSION_V2,
    UNLINKABILITY_STATEMENT_TYPE, UNLINKABILITY_STATEMENT_VERSION_V2, UNLINKABILITY_V2_DOMAIN_SEP,
};

#[pyfunction]
fn make_unlinkability_instance_v2_bytes(
    py: Python<'_>,
    id: Vec<u8>,
    blinding: Vec<u8>,
    ctx_hash: Vec<u8>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let id_bytes = fixed_bytes("id", id)?;
    let blinding_bytes = fixed_bytes("blinding", blinding)?;
    let ctx_bytes = fixed_bytes("ctx_hash", ctx_hash)?;

    let id_fr = fr_from_fixed_bytes("id", &id_bytes).map_err(PyValueError::new_err)?;
    let blinding_fr = fr_from_fixed_bytes("blinding", &blinding_bytes).map_err(PyValueError::new_err)?;
    let ctx_fr = fr_from_fixed_bytes("ctx_hash", &ctx_bytes).map_err(PyValueError::new_err)?;

    let params = poseidon_params::<Fr>();
    let commitment = commitment_hash(&params, id_fr, blinding_fr);
    let tag = tag_hash(&params, domain_sep_v2_fr(), ctx_fr, commitment);

    let tag_bytes = fixed_bytes_from_vec("tag", fr_to_fixed_bytes(&tag))?;

    let public_inputs = UnlinkabilityPublicInputsV2 {
        schema_version: UNLINKABILITY_INSTANCE_VERSION_V2,
        statement_type: UNLINKABILITY_STATEMENT_TYPE,
        statement_version: UNLINKABILITY_STATEMENT_VERSION_V2,
        tag: tag_bytes,
        domain_sep: UNLINKABILITY_V2_DOMAIN_SEP,
        ctx_hash: ctx_bytes,
    };
    let instance = UnlinkabilityInstanceV2 {
        schema_version: UNLINKABILITY_INSTANCE_VERSION_V2,
        statement_type: UNLINKABILITY_STATEMENT_TYPE,
        statement_version: UNLINKABILITY_STATEMENT_VERSION_V2,
        id: id_bytes,
        blinding: blinding_bytes,
        tag: public_inputs.tag,
        domain_sep: UNLINKABILITY_V2_DOMAIN_SEP,
        ctx_hash: public_inputs.ctx_hash,
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
fn verify_unlinkability_v2(
    vk_path: &str,
    public_inputs_path: &str,
    proof_path: &str,
) -> PyResult<bool> {
    let vk = read_verifying_key(vk_path)?;
    let public_inputs_bytes = read_public_inputs_v2(public_inputs_path)?;
    let public_inputs = public_inputs_bytes.into_public_inputs().map_err(PyValueError::new_err)?;
    let proof = read_proof(proof_path)?;

    verify_unlinkability_v2_inner(&vk, &public_inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyfunction]
fn verify_unlinkability_v2_bytes(
    vk_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> PyResult<bool> {
    let vk = deserialize_verifying_key(&vk_bytes)?;
    let public_inputs: UnlinkabilityPublicInputsV2 =
        bincode::deserialize(&public_inputs_bytes)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let inputs = public_inputs
        .into_public_inputs()
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let proof = deserialize_proof(&proof_bytes)?;

    verify_unlinkability_v2_inner(&vk, &inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pymodule]
fn unlinkability_py(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(make_unlinkability_instance_v2_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(verify_unlinkability_v2, m)?)?;
    m.add_function(wrap_pyfunction!(verify_unlinkability_v2_bytes, m)?)?;
    Ok(())
}

fn fixed_bytes(label: &str, mut bytes: Vec<u8>) -> PyResult<[u8; 32]> {
    if bytes.is_empty() {
        return Err(PyValueError::new_err(format!("{label} must not be empty")));
    }
    if bytes.len() > 32 {
        return Err(PyValueError::new_err(format!("{label} must be <= 32 bytes")));
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    Ok(bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("invalid length"))?)
}

fn fixed_bytes_from_vec(label: &str, bytes: Vec<u8>) -> PyResult<[u8; 32]> {
    fixed_bytes(label, bytes)
}

fn read_verifying_key(path: &str) -> PyResult<VerifyingKey<Bn254>> {
    let file = File::open(path).map_err(PyValueError::new_err)?;
    let mut reader = BufReader::new(file);
    VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

fn read_public_inputs_v2(path: &str) -> PyResult<UnlinkabilityPublicInputsV2> {
    let data = fs::read(path).map_err(PyValueError::new_err)?;
    bincode::deserialize::<UnlinkabilityPublicInputsV2>(&data)
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

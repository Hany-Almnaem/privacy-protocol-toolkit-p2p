use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use continuity::{
    commitment_hash, commitment_hash_v2, fr_from_fixed_bytes, fr_to_fixed_bytes,
    verify_continuity, verify_continuity_v2 as verify_continuity_v2_inner,
    ContinuityInstanceV1, ContinuityInstanceV2,
    ContinuityPublicInputsV1, ContinuityPublicInputsV2, CONTINUITY_INSTANCE_VERSION_V1,
    CONTINUITY_INSTANCE_VERSION_V2, CONTINUITY_STATEMENT_TYPE,
    CONTINUITY_STATEMENT_VERSION_V2, CONTINUITY_V1_DOMAIN_SEP, CONTINUITY_V2_DOMAIN_SEP,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::fs;
use std::fs::File;
use std::io::BufReader;

#[pyfunction]
fn make_continuity_instance_v1_bytes(
    py: Python<'_>,
    id: Vec<u8>,
    r1: Vec<u8>,
    r2: Vec<u8>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let id_bytes = fixed_bytes("id", id)?;
    let r1_bytes = fixed_bytes("r1", r1)?;
    let r2_bytes = fixed_bytes("r2", r2)?;

    let id_fr = fr_from_fixed_bytes("id", &id_bytes).map_err(PyValueError::new_err)?;
    let r1_fr = fr_from_fixed_bytes("r1", &r1_bytes).map_err(PyValueError::new_err)?;
    let r2_fr = fr_from_fixed_bytes("r2", &r2_bytes).map_err(PyValueError::new_err)?;

    let params = continuity::poseidon_params::<Fr>();
    let c1 = commitment_hash(&params, id_fr, r1_fr);
    let c2 = commitment_hash(&params, id_fr, r2_fr);

    let c1_bytes = fixed_bytes_from_vec("c1_hash", fr_to_fixed_bytes(&c1))?;
    let c2_bytes = fixed_bytes_from_vec("c2_hash", fr_to_fixed_bytes(&c2))?;

    let public_inputs = ContinuityPublicInputsV1 {
        schema_version: CONTINUITY_INSTANCE_VERSION_V1,
        c1_hash: c1_bytes,
        c2_hash: c2_bytes,
        domain_sep: CONTINUITY_V1_DOMAIN_SEP,
    };
    let instance = ContinuityInstanceV1 {
        schema_version: CONTINUITY_INSTANCE_VERSION_V1,
        id: id_bytes,
        r1: r1_bytes,
        r2: r2_bytes,
        c1_hash: public_inputs.c1_hash,
        c2_hash: public_inputs.c2_hash,
        domain_sep: CONTINUITY_V1_DOMAIN_SEP,
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
fn make_continuity_instance_v2_bytes(
    py: Python<'_>,
    id: Vec<u8>,
    r1: Vec<u8>,
    r2: Vec<u8>,
    ctx_hash: Vec<u8>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let id_bytes = fixed_bytes("id", id)?;
    let r1_bytes = fixed_bytes("r1", r1)?;
    let r2_bytes = fixed_bytes("r2", r2)?;
    let ctx_bytes = fixed_bytes("ctx_hash", ctx_hash)?;

    let id_fr = fr_from_fixed_bytes("id", &id_bytes).map_err(PyValueError::new_err)?;
    let r1_fr = fr_from_fixed_bytes("r1", &r1_bytes).map_err(PyValueError::new_err)?;
    let r2_fr = fr_from_fixed_bytes("r2", &r2_bytes).map_err(PyValueError::new_err)?;
    let ctx_fr = fr_from_fixed_bytes("ctx_hash", &ctx_bytes).map_err(PyValueError::new_err)?;

    let params = continuity::poseidon_params::<Fr>();
    let c1 = commitment_hash_v2(&params, id_fr, r1_fr, ctx_fr);
    let c2 = commitment_hash_v2(&params, id_fr, r2_fr, ctx_fr);

    let c1_bytes = fixed_bytes_from_vec("c1_hash", fr_to_fixed_bytes(&c1))?;
    let c2_bytes = fixed_bytes_from_vec("c2_hash", fr_to_fixed_bytes(&c2))?;

    let public_inputs = ContinuityPublicInputsV2 {
        schema_version: CONTINUITY_INSTANCE_VERSION_V2,
        statement_type: CONTINUITY_STATEMENT_TYPE,
        statement_version: CONTINUITY_STATEMENT_VERSION_V2,
        c1_hash: c1_bytes,
        c2_hash: c2_bytes,
        domain_sep: CONTINUITY_V2_DOMAIN_SEP,
        ctx_hash: ctx_bytes,
    };
    let instance = ContinuityInstanceV2 {
        schema_version: CONTINUITY_INSTANCE_VERSION_V2,
        statement_type: CONTINUITY_STATEMENT_TYPE,
        statement_version: CONTINUITY_STATEMENT_VERSION_V2,
        id: id_bytes,
        r1: r1_bytes,
        r2: r2_bytes,
        c1_hash: public_inputs.c1_hash,
        c2_hash: public_inputs.c2_hash,
        domain_sep: CONTINUITY_V2_DOMAIN_SEP,
        ctx_hash: ctx_bytes,
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
fn verify_continuity_v1(
    vk_path: &str,
    public_inputs_path: &str,
    proof_path: &str,
) -> PyResult<bool> {
    let vk = read_verifying_key(vk_path)?;
    let public_inputs_bytes = read_public_inputs_v1(public_inputs_path)?;
    let public_inputs = public_inputs_bytes.into_public_inputs().map_err(PyValueError::new_err)?;
    let proof = read_proof(proof_path)?;

    verify_continuity(&vk, &public_inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyfunction]
fn verify_continuity_v2(
    vk_path: &str,
    public_inputs_path: &str,
    proof_path: &str,
) -> PyResult<bool> {
    let vk = read_verifying_key(vk_path)?;
    let public_inputs_bytes = read_public_inputs_v2(public_inputs_path)?;
    let public_inputs = public_inputs_bytes.into_public_inputs().map_err(PyValueError::new_err)?;
    let proof = read_proof(proof_path)?;

    verify_continuity_v2_inner(&vk, &public_inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyfunction]
fn verify_continuity_v1_bytes(
    vk_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> PyResult<bool> {
    let vk = deserialize_verifying_key(&vk_bytes)?;
    let public_inputs: ContinuityPublicInputsV1 =
        bincode::deserialize(&public_inputs_bytes)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let inputs = public_inputs
        .into_public_inputs()
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let proof = deserialize_proof(&proof_bytes)?;

    verify_continuity(&vk, &inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyfunction]
fn verify_continuity_v2_bytes(
    vk_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> PyResult<bool> {
    let vk = deserialize_verifying_key(&vk_bytes)?;
    let public_inputs: ContinuityPublicInputsV2 =
        bincode::deserialize(&public_inputs_bytes)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let inputs = public_inputs
        .into_public_inputs()
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let proof = deserialize_proof(&proof_bytes)?;

    verify_continuity_v2_inner(&vk, &inputs, &proof)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pymodule]
fn continuity_py(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(make_continuity_instance_v1_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(make_continuity_instance_v2_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(verify_continuity_v1, m)?)?;
    m.add_function(wrap_pyfunction!(verify_continuity_v1_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(verify_continuity_v2, m)?)?;
    m.add_function(wrap_pyfunction!(verify_continuity_v2_bytes, m)?)?;
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

fn read_public_inputs_v1(path: &str) -> PyResult<ContinuityPublicInputsV1> {
    let data = fs::read(path).map_err(PyValueError::new_err)?;
    bincode::deserialize::<ContinuityPublicInputsV1>(&data)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

fn read_public_inputs_v2(path: &str) -> PyResult<ContinuityPublicInputsV2> {
    let data = fs::read(path).map_err(PyValueError::new_err)?;
    bincode::deserialize::<ContinuityPublicInputsV2>(&data)
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

use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::{fr_from_fixed_bytes, fr_to_fixed_bytes};
use membership::{commitment_hash, poseidon_params};

pub const CONTINUITY_INSTANCE_VERSION_V1: u8 = 1;
pub const CONTINUITY_V1_DOMAIN_SEP: [u8; 32] =
    *b"CONTINUITY_SNARK_V1_____________";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuityInstanceV1 {
    pub schema_version: u8,
    pub id: [u8; 32],
    pub r1: [u8; 32],
    pub r2: [u8; 32],
    pub c1_hash: [u8; 32],
    pub c2_hash: [u8; 32],
    pub domain_sep: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuityPublicInputsV1 {
    pub schema_version: u8,
    pub c1_hash: [u8; 32],
    pub c2_hash: [u8; 32],
    pub domain_sep: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ContinuityWitness {
    pub id: Fr,
    pub r1: Fr,
    pub r2: Fr,
}

#[derive(Clone, Debug)]
pub struct ContinuityPublicInputs {
    pub c1_hash: Fr,
    pub c2_hash: Fr,
    pub domain_sep: Fr,
}

#[derive(Clone, Debug)]
pub struct ContinuityInstance {
    pub public_inputs: ContinuityPublicInputs,
    pub witness: ContinuityWitness,
}

pub fn domain_sep_fr() -> Fr {
    Fr::from_be_bytes_mod_order(&CONTINUITY_V1_DOMAIN_SEP)
}

fn ensure_version(label: &str, version: u8) -> Result<(), String> {
    if version != CONTINUITY_INSTANCE_VERSION_V1 {
        return Err(format!(
            "{label}: schema_version mismatch (expected {}, got {})",
            CONTINUITY_INSTANCE_VERSION_V1, version
        ));
    }
    Ok(())
}

fn ensure_domain_sep(label: &str, value: &[u8; 32]) -> Result<(), String> {
    if value != &CONTINUITY_V1_DOMAIN_SEP {
        return Err(format!("{label}: domain_sep mismatch"));
    }
    Ok(())
}

impl ContinuityPublicInputsV1 {
    pub fn into_public_inputs(self) -> Result<ContinuityPublicInputs, String> {
        ensure_version("public_inputs.schema_version", self.schema_version)?;
        ensure_domain_sep("public_inputs.domain_sep", &self.domain_sep)?;

        Ok(ContinuityPublicInputs {
            c1_hash: fr_from_fixed_bytes("c1_hash", &self.c1_hash)?,
            c2_hash: fr_from_fixed_bytes("c2_hash", &self.c2_hash)?,
            domain_sep: fr_from_fixed_bytes("domain_sep", &self.domain_sep)?,
        })
    }
}

impl ContinuityInstanceV1 {
    pub fn into_instance(self) -> Result<ContinuityInstance, String> {
        ensure_version("instance.schema_version", self.schema_version)?;
        ensure_domain_sep("instance.domain_sep", &self.domain_sep)?;

        let id = fr_from_fixed_bytes("id", &self.id)?;
        let r1 = fr_from_fixed_bytes("r1", &self.r1)?;
        let r2 = fr_from_fixed_bytes("r2", &self.r2)?;
        let c1_hash = fr_from_fixed_bytes("c1_hash", &self.c1_hash)?;
        let c2_hash = fr_from_fixed_bytes("c2_hash", &self.c2_hash)?;

        let params = poseidon_params::<Fr>();
        let expected_c1 = commitment_hash(&params, id, r1);
        if expected_c1 != c1_hash {
            return Err("c1_hash does not match commitment hash".to_string());
        }
        let expected_c2 = commitment_hash(&params, id, r2);
        if expected_c2 != c2_hash {
            return Err("c2_hash does not match commitment hash".to_string());
        }

        let public_inputs = ContinuityPublicInputs {
            c1_hash,
            c2_hash,
            domain_sep: fr_from_fixed_bytes("domain_sep", &self.domain_sep)?,
        };
        let witness = ContinuityWitness { id, r1, r2 };

        Ok(ContinuityInstance {
            public_inputs,
            witness,
        })
    }
}

pub fn build_instance_v1(id: Fr, r1: Fr, r2: Fr) -> (ContinuityInstanceV1, ContinuityPublicInputsV1) {
    let params = poseidon_params::<Fr>();
    let c1_hash = commitment_hash(&params, id, r1);
    let c2_hash = commitment_hash(&params, id, r2);

    let public_inputs = ContinuityPublicInputsV1 {
        schema_version: CONTINUITY_INSTANCE_VERSION_V1,
        c1_hash: fr_to_fixed_bytes(&c1_hash).try_into().unwrap(),
        c2_hash: fr_to_fixed_bytes(&c2_hash).try_into().unwrap(),
        domain_sep: CONTINUITY_V1_DOMAIN_SEP,
    };
    let instance = ContinuityInstanceV1 {
        schema_version: CONTINUITY_INSTANCE_VERSION_V1,
        id: fr_to_fixed_bytes(&id).try_into().unwrap(),
        r1: fr_to_fixed_bytes(&r1).try_into().unwrap(),
        r2: fr_to_fixed_bytes(&r2).try_into().unwrap(),
        c1_hash: public_inputs.c1_hash,
        c2_hash: public_inputs.c2_hash,
        domain_sep: CONTINUITY_V1_DOMAIN_SEP,
    };

    (instance, public_inputs)
}

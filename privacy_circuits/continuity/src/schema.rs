use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_sponge::poseidon::PoseidonSponge;
use ark_sponge::CryptographicSponge;
use serde::{Deserialize, Serialize};

use crate::{fr_from_fixed_bytes, fr_to_fixed_bytes};
use membership::{commitment_hash, poseidon_params};

pub const CONTINUITY_INSTANCE_VERSION_V1: u8 = 1;
pub const CONTINUITY_V1_DOMAIN_SEP: [u8; 32] =
    *b"CONTINUITY_SNARK_V1_____________";
pub const CONTINUITY_INSTANCE_VERSION_V2: u16 = 2;
pub const CONTINUITY_STATEMENT_TYPE: u16 = 3;
pub const CONTINUITY_STATEMENT_VERSION_V2: u16 = 2;
pub const CONTINUITY_V2_DOMAIN_SEP: [u8; 32] =
    *b"CONTINUITY_SNARK_V2_____________";
pub const CONTINUITY_V2_DEFAULT_CTX_HASH: [u8; 32] =
    *b"CONTINUITY_CTX_V2_______________";

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuityInstanceV2 {
    pub schema_version: u16,
    pub statement_type: u16,
    pub statement_version: u16,
    pub id: [u8; 32],
    pub r1: [u8; 32],
    pub r2: [u8; 32],
    pub c1_hash: [u8; 32],
    pub c2_hash: [u8; 32],
    pub domain_sep: [u8; 32],
    pub ctx_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuityPublicInputsV2 {
    pub schema_version: u16,
    pub statement_type: u16,
    pub statement_version: u16,
    pub c1_hash: [u8; 32],
    pub c2_hash: [u8; 32],
    pub domain_sep: [u8; 32],
    pub ctx_hash: [u8; 32],
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

#[derive(Clone, Debug)]
pub struct ContinuityWitnessV2 {
    pub id: Fr,
    pub r1: Fr,
    pub r2: Fr,
}

#[derive(Clone, Debug)]
pub struct ContinuityPublicInputsV2Data {
    pub c1_hash: Fr,
    pub c2_hash: Fr,
    pub domain_sep: Fr,
    pub ctx_hash: Fr,
}

#[derive(Clone, Debug)]
pub struct ContinuityInstanceV2Data {
    pub public_inputs: ContinuityPublicInputsV2Data,
    pub witness: ContinuityWitnessV2,
}

pub fn domain_sep_fr() -> Fr {
    Fr::from_be_bytes_mod_order(&CONTINUITY_V1_DOMAIN_SEP)
}

pub fn domain_sep_v2_fr() -> Fr {
    Fr::from_be_bytes_mod_order(&CONTINUITY_V2_DOMAIN_SEP)
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

fn ensure_version_v2(label: &str, version: u16) -> Result<(), String> {
    if version != CONTINUITY_INSTANCE_VERSION_V2 {
        return Err(format!(
            "{label}: schema_version mismatch (expected {}, got {})",
            CONTINUITY_INSTANCE_VERSION_V2, version
        ));
    }
    Ok(())
}

fn ensure_statement_type_version(statement_type: u16, statement_version: u16) -> Result<(), String> {
    if statement_type != CONTINUITY_STATEMENT_TYPE {
        return Err(format!(
            "statement_type mismatch (expected {}, got {})",
            CONTINUITY_STATEMENT_TYPE, statement_type
        ));
    }
    if statement_version != CONTINUITY_STATEMENT_VERSION_V2 {
        return Err(format!(
            "statement_version mismatch (expected {}, got {})",
            CONTINUITY_STATEMENT_VERSION_V2, statement_version
        ));
    }
    Ok(())
}

fn ensure_domain_sep_v2(label: &str, value: &[u8; 32]) -> Result<(), String> {
    if value != &CONTINUITY_V2_DOMAIN_SEP {
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

impl ContinuityPublicInputsV2 {
    pub fn into_public_inputs(self) -> Result<ContinuityPublicInputsV2Data, String> {
        ensure_version_v2("public_inputs.schema_version", self.schema_version)?;
        ensure_statement_type_version(self.statement_type, self.statement_version)?;
        ensure_domain_sep_v2("public_inputs.domain_sep", &self.domain_sep)?;

        Ok(ContinuityPublicInputsV2Data {
            c1_hash: fr_from_fixed_bytes("c1_hash", &self.c1_hash)?,
            c2_hash: fr_from_fixed_bytes("c2_hash", &self.c2_hash)?,
            domain_sep: fr_from_fixed_bytes("domain_sep", &self.domain_sep)?,
            ctx_hash: fr_from_fixed_bytes("ctx_hash", &self.ctx_hash)?,
        })
    }
}

impl ContinuityInstanceV2 {
    pub fn into_instance(self) -> Result<ContinuityInstanceV2Data, String> {
        ensure_version_v2("instance.schema_version", self.schema_version)?;
        ensure_statement_type_version(self.statement_type, self.statement_version)?;
        ensure_domain_sep_v2("instance.domain_sep", &self.domain_sep)?;

        let id = fr_from_fixed_bytes("id", &self.id)?;
        let r1 = fr_from_fixed_bytes("r1", &self.r1)?;
        let r2 = fr_from_fixed_bytes("r2", &self.r2)?;
        let c1_hash = fr_from_fixed_bytes("c1_hash", &self.c1_hash)?;
        let c2_hash = fr_from_fixed_bytes("c2_hash", &self.c2_hash)?;
        let ctx_hash = fr_from_fixed_bytes("ctx_hash", &self.ctx_hash)?;

        let params = poseidon_params::<Fr>();
        let expected_c1 = commitment_hash_v2(&params, id, r1, ctx_hash);
        if expected_c1 != c1_hash {
            return Err("c1_hash does not match commitment hash".to_string());
        }
        let expected_c2 = commitment_hash_v2(&params, id, r2, ctx_hash);
        if expected_c2 != c2_hash {
            return Err("c2_hash does not match commitment hash".to_string());
        }

        let public_inputs = ContinuityPublicInputsV2Data {
            c1_hash,
            c2_hash,
            domain_sep: fr_from_fixed_bytes("domain_sep", &self.domain_sep)?,
            ctx_hash,
        };
        let witness = ContinuityWitnessV2 { id, r1, r2 };

        Ok(ContinuityInstanceV2Data {
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

pub fn build_instance_v2(
    id: Fr,
    r1: Fr,
    r2: Fr,
    ctx_hash: Fr,
) -> (ContinuityInstanceV2, ContinuityPublicInputsV2) {
    let params = poseidon_params::<Fr>();
    let c1_hash = commitment_hash_v2(&params, id, r1, ctx_hash);
    let c2_hash = commitment_hash_v2(&params, id, r2, ctx_hash);

    let public_inputs = ContinuityPublicInputsV2 {
        schema_version: CONTINUITY_INSTANCE_VERSION_V2,
        statement_type: CONTINUITY_STATEMENT_TYPE,
        statement_version: CONTINUITY_STATEMENT_VERSION_V2,
        c1_hash: fr_to_fixed_bytes(&c1_hash).try_into().unwrap(),
        c2_hash: fr_to_fixed_bytes(&c2_hash).try_into().unwrap(),
        domain_sep: CONTINUITY_V2_DOMAIN_SEP,
        ctx_hash: fr_to_fixed_bytes(&ctx_hash).try_into().unwrap(),
    };
    let instance = ContinuityInstanceV2 {
        schema_version: CONTINUITY_INSTANCE_VERSION_V2,
        statement_type: CONTINUITY_STATEMENT_TYPE,
        statement_version: CONTINUITY_STATEMENT_VERSION_V2,
        id: fr_to_fixed_bytes(&id).try_into().unwrap(),
        r1: fr_to_fixed_bytes(&r1).try_into().unwrap(),
        r2: fr_to_fixed_bytes(&r2).try_into().unwrap(),
        c1_hash: public_inputs.c1_hash,
        c2_hash: public_inputs.c2_hash,
        domain_sep: CONTINUITY_V2_DOMAIN_SEP,
        ctx_hash: public_inputs.ctx_hash,
    };

    (instance, public_inputs)
}

fn poseidon_hash_native(
    params: &ark_sponge::poseidon::PoseidonConfig<Fr>,
    inputs: &[Fr],
) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(params);
    sponge.absorb(&inputs);
    sponge.squeeze_field_elements(1)[0]
}

pub fn commitment_hash_v2(
    params: &ark_sponge::poseidon::PoseidonConfig<Fr>,
    id: Fr,
    r: Fr,
    ctx_hash: Fr,
) -> Fr {
    poseidon_hash_native(params, &[Fr::from(1u64), id, r, ctx_hash])
}

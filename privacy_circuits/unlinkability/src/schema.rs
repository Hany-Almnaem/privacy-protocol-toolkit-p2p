use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_sponge::poseidon::PoseidonSponge;
use ark_sponge::CryptographicSponge;
use serde::{Deserialize, Serialize};

use crate::{fr_from_fixed_bytes, fr_to_fixed_bytes};
use membership::{commitment_hash, poseidon_params};

pub const UNLINKABILITY_INSTANCE_VERSION_V2: u16 = 2;
pub const UNLINKABILITY_STATEMENT_TYPE: u16 = 2;
pub const UNLINKABILITY_STATEMENT_VERSION_V2: u16 = 2;
pub const UNLINKABILITY_V2_DOMAIN_SEP: [u8; 32] =
    *b"UNLINKABILITY_SNARK_V2__________";
pub const UNLINKABILITY_V2_DEFAULT_CTX_HASH: [u8; 32] =
    *b"UNLINKABILITY_CTX_V2____________";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnlinkabilityInstanceV2 {
    pub schema_version: u16,
    pub statement_type: u16,
    pub statement_version: u16,
    pub id: [u8; 32],
    pub blinding: [u8; 32],
    pub tag: [u8; 32],
    pub domain_sep: [u8; 32],
    pub ctx_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnlinkabilityPublicInputsV2 {
    pub schema_version: u16,
    pub statement_type: u16,
    pub statement_version: u16,
    pub tag: [u8; 32],
    pub domain_sep: [u8; 32],
    pub ctx_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct UnlinkabilityWitnessV2 {
    pub id: Fr,
    pub blinding: Fr,
}

#[derive(Clone, Debug)]
pub struct UnlinkabilityPublicInputsV2Data {
    pub tag: Fr,
    pub domain_sep: Fr,
    pub ctx_hash: Fr,
}

#[derive(Clone, Debug)]
pub struct UnlinkabilityInstanceV2Data {
    pub public_inputs: UnlinkabilityPublicInputsV2Data,
    pub witness: UnlinkabilityWitnessV2,
}

pub fn domain_sep_v2_fr() -> Fr {
    Fr::from_be_bytes_mod_order(&UNLINKABILITY_V2_DOMAIN_SEP)
}

fn ensure_version_v2(label: &str, version: u16) -> Result<(), String> {
    if version != UNLINKABILITY_INSTANCE_VERSION_V2 {
        return Err(format!(
            "{label}: schema_version mismatch (expected {}, got {})",
            UNLINKABILITY_INSTANCE_VERSION_V2, version
        ));
    }
    Ok(())
}

fn ensure_statement_type_version(statement_type: u16, statement_version: u16) -> Result<(), String> {
    if statement_type != UNLINKABILITY_STATEMENT_TYPE {
        return Err(format!(
            "statement_type mismatch (expected {}, got {})",
            UNLINKABILITY_STATEMENT_TYPE, statement_type
        ));
    }
    if statement_version != UNLINKABILITY_STATEMENT_VERSION_V2 {
        return Err(format!(
            "statement_version mismatch (expected {}, got {})",
            UNLINKABILITY_STATEMENT_VERSION_V2, statement_version
        ));
    }
    Ok(())
}

fn ensure_domain_sep_v2(label: &str, value: &[u8; 32]) -> Result<(), String> {
    if value != &UNLINKABILITY_V2_DOMAIN_SEP {
        return Err(format!("{label}: domain_sep mismatch"));
    }
    Ok(())
}

impl UnlinkabilityPublicInputsV2 {
    pub fn into_public_inputs(self) -> Result<UnlinkabilityPublicInputsV2Data, String> {
        ensure_version_v2("public_inputs.schema_version", self.schema_version)?;
        ensure_statement_type_version(self.statement_type, self.statement_version)?;
        ensure_domain_sep_v2("public_inputs.domain_sep", &self.domain_sep)?;

        Ok(UnlinkabilityPublicInputsV2Data {
            tag: fr_from_fixed_bytes("tag", &self.tag)?,
            domain_sep: fr_from_fixed_bytes("domain_sep", &self.domain_sep)?,
            ctx_hash: fr_from_fixed_bytes("ctx_hash", &self.ctx_hash)?,
        })
    }
}

impl UnlinkabilityInstanceV2 {
    pub fn into_instance(self) -> Result<UnlinkabilityInstanceV2Data, String> {
        ensure_version_v2("instance.schema_version", self.schema_version)?;
        ensure_statement_type_version(self.statement_type, self.statement_version)?;
        ensure_domain_sep_v2("instance.domain_sep", &self.domain_sep)?;

        let id = fr_from_fixed_bytes("id", &self.id)?;
        let blinding = fr_from_fixed_bytes("blinding", &self.blinding)?;
        let tag = fr_from_fixed_bytes("tag", &self.tag)?;
        let ctx_hash = fr_from_fixed_bytes("ctx_hash", &self.ctx_hash)?;

        let params = poseidon_params::<Fr>();
        let commitment = commitment_hash(&params, id, blinding);
        let expected_tag = tag_hash(&params, domain_sep_v2_fr(), ctx_hash, commitment);
        if expected_tag != tag {
            return Err("tag does not match computed value".to_string());
        }

        let public_inputs = UnlinkabilityPublicInputsV2Data {
            tag,
            domain_sep: fr_from_fixed_bytes("domain_sep", &self.domain_sep)?,
            ctx_hash,
        };
        let witness = UnlinkabilityWitnessV2 { id, blinding };

        Ok(UnlinkabilityInstanceV2Data {
            public_inputs,
            witness,
        })
    }
}

pub fn build_instance_v2(
    id: Fr,
    blinding: Fr,
    ctx_hash: Fr,
) -> (UnlinkabilityInstanceV2, UnlinkabilityPublicInputsV2) {
    let params = poseidon_params::<Fr>();
    let commitment = commitment_hash(&params, id, blinding);
    let tag = tag_hash(&params, domain_sep_v2_fr(), ctx_hash, commitment);

    let public_inputs = UnlinkabilityPublicInputsV2 {
        schema_version: UNLINKABILITY_INSTANCE_VERSION_V2,
        statement_type: UNLINKABILITY_STATEMENT_TYPE,
        statement_version: UNLINKABILITY_STATEMENT_VERSION_V2,
        tag: fr_to_fixed_bytes(&tag).try_into().unwrap(),
        domain_sep: UNLINKABILITY_V2_DOMAIN_SEP,
        ctx_hash: fr_to_fixed_bytes(&ctx_hash).try_into().unwrap(),
    };
    let instance = UnlinkabilityInstanceV2 {
        schema_version: UNLINKABILITY_INSTANCE_VERSION_V2,
        statement_type: UNLINKABILITY_STATEMENT_TYPE,
        statement_version: UNLINKABILITY_STATEMENT_VERSION_V2,
        id: fr_to_fixed_bytes(&id).try_into().unwrap(),
        blinding: fr_to_fixed_bytes(&blinding).try_into().unwrap(),
        tag: public_inputs.tag,
        domain_sep: UNLINKABILITY_V2_DOMAIN_SEP,
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

pub fn tag_hash(
    params: &ark_sponge::poseidon::PoseidonConfig<Fr>,
    domain_sep: Fr,
    ctx_hash: Fr,
    commitment: Fr,
) -> Fr {
    poseidon_hash_native(params, &[domain_sep, ctx_hash, commitment])
}

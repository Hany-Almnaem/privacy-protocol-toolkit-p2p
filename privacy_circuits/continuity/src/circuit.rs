use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use membership::poseidon_params;

use crate::schema::{CONTINUITY_V1_DOMAIN_SEP, CONTINUITY_V2_DOMAIN_SEP};

const DOMAIN_COMMITMENT: u64 = 1;

#[derive(Clone, Debug, Default)]
pub struct ContinuityCircuit<F: PrimeField> {
    pub c1_hash: Option<F>,
    pub c2_hash: Option<F>,
    pub domain_sep: Option<F>,
    pub id: Option<F>,
    pub r1: Option<F>,
    pub r2: Option<F>,
}

#[derive(Clone, Debug, Default)]
pub struct ContinuityCircuitV2<F: PrimeField> {
    pub c1_hash: Option<F>,
    pub c2_hash: Option<F>,
    pub domain_sep: Option<F>,
    pub ctx_hash: Option<F>,
    pub id: Option<F>,
    pub r1: Option<F>,
    pub r2: Option<F>,
}

fn poseidon_hash_var<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    params: &ark_sponge::poseidon::PoseidonConfig<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<F>::new(cs, params);
    sponge.absorb(&inputs)?;
    let mut output = sponge.squeeze_field_elements(1)?;
    Ok(output.remove(0))
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ContinuityCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let params = poseidon_params::<F>();

        let c1_hash =
            FpVar::new_input(cs.clone(), || self.c1_hash.ok_or(SynthesisError::AssignmentMissing))?;
        let c2_hash =
            FpVar::new_input(cs.clone(), || self.c2_hash.ok_or(SynthesisError::AssignmentMissing))?;
        let domain_sep = FpVar::new_input(cs.clone(), || {
            self.domain_sep.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let id = FpVar::new_witness(cs.clone(), || self.id.ok_or(SynthesisError::AssignmentMissing))?;
        let r1 =
            FpVar::new_witness(cs.clone(), || self.r1.ok_or(SynthesisError::AssignmentMissing))?;
        let r2 =
            FpVar::new_witness(cs.clone(), || self.r2.ok_or(SynthesisError::AssignmentMissing))?;

        let domain_commitment = FpVar::constant(F::from(DOMAIN_COMMITMENT));
        let expected_c1 =
            poseidon_hash_var(cs.clone(), &params, &[domain_commitment.clone(), id.clone(), r1])?;
        let expected_c2 =
            poseidon_hash_var(cs.clone(), &params, &[domain_commitment, id, r2])?;

        expected_c1.enforce_equal(&c1_hash)?;
        expected_c2.enforce_equal(&c2_hash)?;

        let domain_sep_const = FpVar::constant(F::from_be_bytes_mod_order(
            &CONTINUITY_V1_DOMAIN_SEP,
        ));
        domain_sep.enforce_equal(&domain_sep_const)?;

        Ok(())
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ContinuityCircuitV2<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let params = poseidon_params::<F>();

        let c1_hash =
            FpVar::new_input(cs.clone(), || self.c1_hash.ok_or(SynthesisError::AssignmentMissing))?;
        let c2_hash =
            FpVar::new_input(cs.clone(), || self.c2_hash.ok_or(SynthesisError::AssignmentMissing))?;
        let domain_sep = FpVar::new_input(cs.clone(), || {
            self.domain_sep.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ctx_hash =
            FpVar::new_input(cs.clone(), || self.ctx_hash.ok_or(SynthesisError::AssignmentMissing))?;

        let id =
            FpVar::new_witness(cs.clone(), || self.id.ok_or(SynthesisError::AssignmentMissing))?;
        let r1 =
            FpVar::new_witness(cs.clone(), || self.r1.ok_or(SynthesisError::AssignmentMissing))?;
        let r2 =
            FpVar::new_witness(cs.clone(), || self.r2.ok_or(SynthesisError::AssignmentMissing))?;

        let domain_commitment = FpVar::constant(F::from(DOMAIN_COMMITMENT));
        let expected_c1 = poseidon_hash_var(
            cs.clone(),
            &params,
            &[domain_commitment.clone(), id.clone(), r1, ctx_hash.clone()],
        )?;
        let expected_c2 = poseidon_hash_var(
            cs.clone(),
            &params,
            &[domain_commitment, id, r2, ctx_hash],
        )?;

        expected_c1.enforce_equal(&c1_hash)?;
        expected_c2.enforce_equal(&c2_hash)?;

        let domain_sep_const = FpVar::constant(F::from_be_bytes_mod_order(
            &CONTINUITY_V2_DOMAIN_SEP,
        ));
        domain_sep.enforce_equal(&domain_sep_const)?;

        Ok(())
    }
}

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use membership::poseidon_params;

use crate::schema::UNLINKABILITY_V2_DOMAIN_SEP;

const DOMAIN_COMMITMENT: u64 = 1;

#[derive(Clone, Debug, Default)]
pub struct UnlinkabilityCircuitV2<F: PrimeField> {
    pub tag: Option<F>,
    pub domain_sep: Option<F>,
    pub ctx_hash: Option<F>,
    pub id: Option<F>,
    pub blinding: Option<F>,
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

impl<F: PrimeField> ConstraintSynthesizer<F> for UnlinkabilityCircuitV2<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let params = poseidon_params::<F>();

        let tag =
            FpVar::new_input(cs.clone(), || self.tag.ok_or(SynthesisError::AssignmentMissing))?;
        let domain_sep = FpVar::new_input(cs.clone(), || {
            self.domain_sep.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ctx_hash =
            FpVar::new_input(cs.clone(), || self.ctx_hash.ok_or(SynthesisError::AssignmentMissing))?;

        let id =
            FpVar::new_witness(cs.clone(), || self.id.ok_or(SynthesisError::AssignmentMissing))?;
        let blinding = FpVar::new_witness(cs.clone(), || {
            self.blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let domain_commitment = FpVar::constant(F::from(DOMAIN_COMMITMENT));
        let commitment =
            poseidon_hash_var(cs.clone(), &params, &[domain_commitment, id, blinding])?;

        let computed_tag =
            poseidon_hash_var(cs.clone(), &params, &[domain_sep.clone(), ctx_hash, commitment])?;
        computed_tag.enforce_equal(&tag)?;

        let domain_sep_const = FpVar::constant(F::from_be_bytes_mod_order(
            &UNLINKABILITY_V2_DOMAIN_SEP,
        ));
        domain_sep.enforce_equal(&domain_sep_const)?;

        Ok(())
    }
}

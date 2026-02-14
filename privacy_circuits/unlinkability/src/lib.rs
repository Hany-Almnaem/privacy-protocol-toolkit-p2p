use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::RngCore;

use crate::circuit::UnlinkabilityCircuitV2;
use crate::schema::{UnlinkabilityInstanceV2Data, UnlinkabilityPublicInputsV2Data};

pub mod circuit;
pub mod schema;

pub use membership::{commitment_hash, fr_to_fixed_bytes, poseidon_params};
pub use schema::{
    build_instance_v2, domain_sep_v2_fr, tag_hash, UnlinkabilityInstanceV2,
    UnlinkabilityPublicInputsV2, UNLINKABILITY_INSTANCE_VERSION_V2,
    UNLINKABILITY_STATEMENT_TYPE, UNLINKABILITY_STATEMENT_VERSION_V2,
    UNLINKABILITY_V2_DEFAULT_CTX_HASH, UNLINKABILITY_V2_DOMAIN_SEP,
};

pub fn fr_from_fixed_bytes(label: &str, bytes: &[u8; 32]) -> Result<Fr, String> {
    if bytes.is_empty() {
        return Err(format!("{label}: empty field bytes"));
    }
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

pub fn build_circuit_v2(instance: &UnlinkabilityInstanceV2Data) -> UnlinkabilityCircuitV2<Fr> {
    UnlinkabilityCircuitV2::<Fr> {
        tag: Some(instance.public_inputs.tag),
        domain_sep: Some(instance.public_inputs.domain_sep),
        ctx_hash: Some(instance.public_inputs.ctx_hash),
        id: Some(instance.witness.id),
        blinding: Some(instance.witness.blinding),
    }
}

pub fn setup_unlinkability_v2<R: RngCore>(
    rng: &mut R,
) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let params = poseidon_params::<Fr>();
    let zero = Fr::from(0u64);
    let commitment = commitment_hash(&params, zero, zero);
    let domain_sep = domain_sep_v2_fr();
    let tag = tag_hash(&params, domain_sep, zero, commitment);
    let circuit = UnlinkabilityCircuitV2::<Fr> {
        tag: Some(tag),
        domain_sep: Some(domain_sep),
        ctx_hash: Some(zero),
        id: Some(zero),
        blinding: Some(zero),
    };
    Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)
}

pub fn prove_unlinkability_v2<R: RngCore>(
    pk: &ProvingKey<Bn254>,
    instance: &UnlinkabilityInstanceV2Data,
    rng: &mut R,
) -> Result<Proof<Bn254>, SynthesisError> {
    let circuit = build_circuit_v2(instance);
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, rng)
}

pub fn verify_unlinkability_v2(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &UnlinkabilityPublicInputsV2Data,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let pvk = prepare_verifying_key(vk);
    let inputs = vec![
        public_inputs.tag,
        public_inputs.domain_sep,
        public_inputs.ctx_hash,
    ];
    Groth16::<Bn254>::verify_proof(&pvk, proof, &inputs)
}

#[cfg(test)]
mod tests {
    use super::{
        commitment_hash, build_instance_v2, domain_sep_v2_fr, poseidon_params, tag_hash,
    };
    use crate::circuit::UnlinkabilityCircuitV2;
    use ark_bn254::Fr;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    #[test]
    fn unlinkability_circuit_accepts_valid_witness() {
        let params = poseidon_params::<Fr>();
        let id = Fr::from(2u64);
        let blinding = Fr::from(3u64);
        let ctx_hash = Fr::from(4u64);
        let commitment = commitment_hash(&params, id, blinding);
        let domain_sep = domain_sep_v2_fr();
        let tag = tag_hash(&params, domain_sep, ctx_hash, commitment);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = UnlinkabilityCircuitV2::<Fr> {
            tag: Some(tag),
            domain_sep: Some(domain_sep),
            ctx_hash: Some(ctx_hash),
            id: Some(id),
            blinding: Some(blinding),
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn unlinkability_circuit_rejects_wrong_tag() {
        let params = poseidon_params::<Fr>();
        let id = Fr::from(2u64);
        let blinding = Fr::from(3u64);
        let ctx_hash = Fr::from(4u64);
        let commitment = commitment_hash(&params, id, blinding);
        let domain_sep = domain_sep_v2_fr();
        let tag = tag_hash(&params, domain_sep, ctx_hash, commitment) + Fr::from(1u64);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = UnlinkabilityCircuitV2::<Fr> {
            tag: Some(tag),
            domain_sep: Some(domain_sep),
            ctx_hash: Some(ctx_hash),
            id: Some(id),
            blinding: Some(blinding),
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn unlinkability_circuit_rejects_wrong_domain_sep() {
        let params = poseidon_params::<Fr>();
        let id = Fr::from(2u64);
        let blinding = Fr::from(3u64);
        let ctx_hash = Fr::from(4u64);
        let bad_domain_sep = Fr::from(99u64);
        let commitment = commitment_hash(&params, id, blinding);
        let tag = tag_hash(&params, bad_domain_sep, ctx_hash, commitment);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = UnlinkabilityCircuitV2::<Fr> {
            tag: Some(tag),
            domain_sep: Some(bad_domain_sep),
            ctx_hash: Some(ctx_hash),
            id: Some(id),
            blinding: Some(blinding),
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn unlinkability_instance_v2_rejects_domain_sep_mismatch() {
        let id = Fr::from(2u64);
        let blinding = Fr::from(3u64);
        let ctx_hash = Fr::from(4u64);
        let (mut instance, _) = build_instance_v2(id, blinding, ctx_hash);
        instance.domain_sep = [0u8; 32];

        assert!(instance.into_instance().is_err());
    }

    #[test]
    fn unlinkability_instance_v2_rejects_ctx_hash_mismatch() {
        let id = Fr::from(2u64);
        let blinding = Fr::from(3u64);
        let ctx_hash = Fr::from(4u64);
        let (mut instance, _) = build_instance_v2(id, blinding, ctx_hash);
        instance.ctx_hash = [0u8; 32];

        assert!(instance.into_instance().is_err());
    }

    #[test]
    fn unlinkability_instance_v2_rejects_tag_mismatch() {
        let id = Fr::from(2u64);
        let blinding = Fr::from(3u64);
        let ctx_hash = Fr::from(4u64);
        let (mut instance, _) = build_instance_v2(id, blinding, ctx_hash);
        instance.tag[0] ^= 0x01;

        assert!(instance.into_instance().is_err());
    }
}

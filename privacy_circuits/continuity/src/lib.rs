use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::RngCore;

use crate::circuit::ContinuityCircuit;
use crate::schema::{
    domain_sep_fr, ContinuityInstance, ContinuityPublicInputs,
};

pub mod circuit;
pub mod schema;

pub use membership::{commitment_hash, fr_to_fixed_bytes, poseidon_params};
pub use schema::{
    ContinuityInstanceV1, ContinuityPublicInputsV1, CONTINUITY_INSTANCE_VERSION_V1,
    CONTINUITY_V1_DOMAIN_SEP,
};

pub fn fr_from_fixed_bytes(label: &str, bytes: &[u8; 32]) -> Result<Fr, String> {
    if bytes.is_empty() {
        return Err(format!("{label}: empty field bytes"));
    }
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

pub fn build_circuit(instance: &ContinuityInstance) -> ContinuityCircuit<Fr> {
    ContinuityCircuit::<Fr> {
        c1_hash: Some(instance.public_inputs.c1_hash),
        c2_hash: Some(instance.public_inputs.c2_hash),
        domain_sep: Some(instance.public_inputs.domain_sep),
        id: Some(instance.witness.id),
        r1: Some(instance.witness.r1),
        r2: Some(instance.witness.r2),
    }
}

pub fn setup_continuity<R: RngCore>(
    rng: &mut R,
) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let params = poseidon_params::<Fr>();
    let zero = Fr::from(0u64);
    let commitment = commitment_hash(&params, zero, zero);
    let domain_sep = domain_sep_fr();
    let circuit = ContinuityCircuit::<Fr> {
        c1_hash: Some(commitment),
        c2_hash: Some(commitment),
        domain_sep: Some(domain_sep),
        id: Some(zero),
        r1: Some(zero),
        r2: Some(zero),
    };
    Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)
}

pub fn prove_continuity<R: RngCore>(
    pk: &ProvingKey<Bn254>,
    instance: &ContinuityInstance,
    rng: &mut R,
) -> Result<Proof<Bn254>, SynthesisError> {
    let circuit = build_circuit(instance);
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, rng)
}

pub fn verify_continuity(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &ContinuityPublicInputs,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let pvk = prepare_verifying_key(vk);
    let inputs = vec![
        public_inputs.c1_hash,
        public_inputs.c2_hash,
        public_inputs.domain_sep,
    ];
    Groth16::<Bn254>::verify_proof(&pvk, proof, &inputs)
}

#[cfg(test)]
mod tests {
    use super::{
        commitment_hash, fr_from_fixed_bytes, fr_to_fixed_bytes, poseidon_params,
        ContinuityInstanceV1, ContinuityPublicInputsV1, CONTINUITY_INSTANCE_VERSION_V1,
        CONTINUITY_V1_DOMAIN_SEP,
    };
    use crate::circuit::ContinuityCircuit;
    use crate::schema::{domain_sep_fr, ContinuityInstance};
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn continuity_circuit_accepts_valid_witness() {
        let params = poseidon_params::<Fr>();
        let id = Fr::from(2u64);
        let r1 = Fr::from(3u64);
        let r2 = Fr::from(4u64);
        let c1 = commitment_hash(&params, id, r1);
        let c2 = commitment_hash(&params, id, r2);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = ContinuityCircuit::<Fr> {
            c1_hash: Some(c1),
            c2_hash: Some(c2),
            domain_sep: Some(domain_sep_fr()),
            id: Some(id),
            r1: Some(r1),
            r2: Some(r2),
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn continuity_circuit_rejects_wrong_domain_sep() {
        let params = poseidon_params::<Fr>();
        let id = Fr::from(2u64);
        let r1 = Fr::from(3u64);
        let r2 = Fr::from(4u64);
        let c1 = commitment_hash(&params, id, r1);
        let c2 = commitment_hash(&params, id, r2);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = ContinuityCircuit::<Fr> {
            c1_hash: Some(c1),
            c2_hash: Some(c2),
            domain_sep: Some(Fr::from(123u64)),
            id: Some(id),
            r1: Some(r1),
            r2: Some(r2),
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn continuity_instance_v1_validation_rejects_bad_domain_sep() {
        let mut instance = ContinuityInstanceV1 {
            schema_version: CONTINUITY_INSTANCE_VERSION_V1,
            id: fr_to_fixed_bytes(&Fr::from(1u64)).try_into().unwrap(),
            r1: fr_to_fixed_bytes(&Fr::from(2u64)).try_into().unwrap(),
            r2: fr_to_fixed_bytes(&Fr::from(3u64)).try_into().unwrap(),
            c1_hash: fr_to_fixed_bytes(&Fr::from(4u64)).try_into().unwrap(),
            c2_hash: fr_to_fixed_bytes(&Fr::from(5u64)).try_into().unwrap(),
            domain_sep: [0u8; 32],
        };
        assert!(instance.clone().into_instance().is_err());

        instance.domain_sep = CONTINUITY_V1_DOMAIN_SEP;
        let instance = instance.into_instance();
        assert!(instance.is_err());
    }

    #[test]
    fn continuity_groth16_roundtrip() {
        let params = poseidon_params::<Fr>();
        let id = Fr::from(11u64);
        let r1 = Fr::from(12u64);
        let r2 = Fr::from(13u64);
        let c1 = commitment_hash(&params, id, r1);
        let c2 = commitment_hash(&params, id, r2);
        let domain_sep = domain_sep_fr();

        let circuit = ContinuityCircuit::<Fr> {
            c1_hash: Some(c1),
            c2_hash: Some(c2),
            domain_sep: Some(domain_sep),
            id: Some(id),
            r1: Some(r1),
            r2: Some(r2),
        };

        let mut rng = StdRng::seed_from_u64(42);
        let pk =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .unwrap();
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&pk.vk);
        let inputs = vec![c1, c2, domain_sep];
        assert!(Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs).unwrap());
    }

    #[test]
    fn continuity_schema_roundtrip_public_inputs() {
        let params = poseidon_params::<Fr>();
        let id = Fr::from(21u64);
        let r1 = Fr::from(22u64);
        let r2 = Fr::from(23u64);
        let c1 = commitment_hash(&params, id, r1);
        let c2 = commitment_hash(&params, id, r2);

        let public_inputs = ContinuityPublicInputsV1 {
            schema_version: CONTINUITY_INSTANCE_VERSION_V1,
            c1_hash: fr_to_fixed_bytes(&c1).try_into().unwrap(),
            c2_hash: fr_to_fixed_bytes(&c2).try_into().unwrap(),
            domain_sep: CONTINUITY_V1_DOMAIN_SEP,
        };
        let parsed = public_inputs.into_public_inputs().unwrap();
        assert_eq!(parsed.c1_hash, c1);
        assert_eq!(parsed.c2_hash, c2);
        assert_eq!(parsed.domain_sep, domain_sep_fr());

        let bytes = fr_to_fixed_bytes(&parsed.c1_hash);
        let back = fr_from_fixed_bytes("c1_hash", &bytes.try_into().unwrap()).unwrap();
        assert_eq!(back, parsed.c1_hash);
    }

    #[test]
    fn continuity_instance_v1_to_instance_matches() {
        let params = poseidon_params::<Fr>();
        let id = Fr::from(31u64);
        let r1 = Fr::from(32u64);
        let r2 = Fr::from(33u64);
        let c1 = commitment_hash(&params, id, r1);
        let c2 = commitment_hash(&params, id, r2);
        let instance_bytes = ContinuityInstanceV1 {
            schema_version: CONTINUITY_INSTANCE_VERSION_V1,
            id: fr_to_fixed_bytes(&id).try_into().unwrap(),
            r1: fr_to_fixed_bytes(&r1).try_into().unwrap(),
            r2: fr_to_fixed_bytes(&r2).try_into().unwrap(),
            c1_hash: fr_to_fixed_bytes(&c1).try_into().unwrap(),
            c2_hash: fr_to_fixed_bytes(&c2).try_into().unwrap(),
            domain_sep: CONTINUITY_V1_DOMAIN_SEP,
        };

        let instance: ContinuityInstance = instance_bytes.into_instance().unwrap();
        assert_eq!(instance.witness.id, id);
        assert_eq!(instance.witness.r1, r1);
        assert_eq!(instance.witness.r2, r2);
        assert_eq!(instance.public_inputs.c1_hash, c1);
        assert_eq!(instance.public_inputs.c2_hash, c2);
    }
}

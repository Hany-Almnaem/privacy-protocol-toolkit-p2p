use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_sponge::CryptographicSponge;
use ark_std::rand::RngCore;
use serde::{Deserialize, Serialize};

const POSEIDON_RATE: usize = 3;
const DOMAIN_COMMITMENT: u64 = 1;
const DOMAIN_LEAF: u64 = 2;
const DOMAIN_NODE: u64 = 3;
const FIELD_BYTES: usize = 32;
pub const MERKLE_DEPTH: usize = 1;
pub const MEMBERSHIP_INSTANCE_VERSION_V1: u8 = 1;
pub const MEMBERSHIP_INSTANCE_VERSION_V2: u16 = 2;
pub const MEMBERSHIP_STATEMENT_TYPE: u16 = 1;
pub const MEMBERSHIP_STATEMENT_VERSION_V2: u16 = 2;
pub const MEMBERSHIP_V2_DOMAIN_SEP: [u8; 32] =
    *b"SNARK_MEMBERSHIP_V2_____________";
pub const MEMBERSHIP_V2_DEFAULT_CTX_HASH: [u8; 32] =
    *b"MEMBERSHIP_CTX_V2_______________";

#[cfg(test)]
mod poseidon_merkle_tests;

pub fn poseidon_params<F: PrimeField>() -> PoseidonConfig<F> {
    let full_rounds = 8u64;
    let partial_rounds = 56u64;
    let alpha = 5u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        POSEIDON_RATE,
        full_rounds,
        partial_rounds,
        0,
    );

    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        POSEIDON_RATE,
        1,
    )
}

fn poseidon_hash_var<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    params: &PoseidonConfig<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<F>::new(cs, params);
    sponge.absorb(&inputs)?;
    let mut output = sponge.squeeze_field_elements(1)?;
    Ok(output.remove(0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePathNodeBytes {
    #[serde(with = "serde_bytes")]
    pub sibling: Vec<u8>,
    pub is_left: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipWitnessBytes {
    #[serde(with = "serde_bytes")]
    pub identity_scalar: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blinding: Vec<u8>,
    pub merkle_path: Vec<MerklePathNodeBytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipPublicInputsBytes {
    #[serde(with = "serde_bytes")]
    pub root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub commitment: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipInstanceBytes {
    pub public_inputs: MembershipPublicInputsBytes,
    pub witness: MembershipWitnessBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipWitnessV1Bytes {
    pub version: u8,
    pub depth: u32,
    #[serde(with = "serde_bytes")]
    pub identity_scalar: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blinding: Vec<u8>,
    pub merkle_siblings: Vec<Vec<u8>>,
    pub merkle_directions: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipPublicInputsV1Bytes {
    pub version: u8,
    pub depth: u32,
    #[serde(with = "serde_bytes")]
    pub root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub commitment: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipInstanceV1Bytes {
    pub version: u8,
    pub public_inputs: MembershipPublicInputsV1Bytes,
    pub witness: MembershipWitnessV1Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipWitnessV2Bytes {
    pub schema_version: u16,
    pub depth: u32,
    #[serde(with = "serde_bytes")]
    pub identity_scalar: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blinding: Vec<u8>,
    pub merkle_siblings: Vec<Vec<u8>>,
    pub merkle_directions: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipPublicInputsV2Bytes {
    pub schema_version: u16,
    pub statement_type: u16,
    pub statement_version: u16,
    pub depth: u32,
    pub root: [u8; 32],
    pub commitment: [u8; 32],
    pub domain_sep: [u8; 32],
    pub ctx_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipInstanceV2Bytes {
    pub schema_version: u16,
    pub public_inputs: MembershipPublicInputsV2Bytes,
    pub witness: MembershipWitnessV2Bytes,
}

#[derive(Clone, Debug)]
pub struct MembershipWitness {
    pub identity_scalar: Fr,
    pub blinding: Fr,
    pub merkle_path: Vec<(Fr, bool)>,
}

#[derive(Clone, Debug)]
pub struct MembershipPublicInputs {
    pub root: Fr,
    pub commitment: Fr,
}

#[derive(Clone, Debug)]
pub struct MembershipInstance {
    pub public_inputs: MembershipPublicInputs,
    pub witness: MembershipWitness,
}

#[derive(Clone, Debug)]
pub struct MembershipWitnessV2 {
    pub identity_scalar: Fr,
    pub blinding: Fr,
    pub merkle_path: Vec<(Fr, bool)>,
}

#[derive(Clone, Debug)]
pub struct MembershipPublicInputsV2 {
    pub root: Fr,
    pub commitment: Fr,
    pub domain_sep: Fr,
    pub ctx_hash: Fr,
}

#[derive(Clone, Debug)]
pub struct MembershipInstanceV2 {
    pub public_inputs: MembershipPublicInputsV2,
    pub witness: MembershipWitnessV2,
}

fn fr_from_bytes(label: &str, bytes: &[u8]) -> Result<Fr, String> {
    if bytes.is_empty() {
        return Err(format!("{}: empty field bytes", label));
    }
    if bytes.len() > FIELD_BYTES {
        return Err(format!(
            "{}: expected at most {} bytes, got {}",
            label,
            FIELD_BYTES,
            bytes.len()
        ));
    }
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

fn ensure_version(label: &str, version: u8, expected: u8) -> Result<(), String> {
    if version != expected {
        return Err(format!(
            "{}: version mismatch (expected {}, got {})",
            label, expected, version
        ));
    }
    Ok(())
}

fn ensure_version_u16(label: &str, version: u16, expected: u16) -> Result<(), String> {
    if version != expected {
        return Err(format!(
            "{}: version mismatch (expected {}, got {})",
            label, expected, version
        ));
    }
    Ok(())
}

fn ensure_statement_type_version(
    statement_type: u16,
    statement_version: u16,
) -> Result<(), String> {
    if statement_type != MEMBERSHIP_STATEMENT_TYPE {
        return Err(format!(
            "statement_type mismatch (expected {}, got {})",
            MEMBERSHIP_STATEMENT_TYPE, statement_type
        ));
    }
    if statement_version != MEMBERSHIP_STATEMENT_VERSION_V2 {
        return Err(format!(
            "statement_version mismatch (expected {}, got {})",
            MEMBERSHIP_STATEMENT_VERSION_V2, statement_version
        ));
    }
    Ok(())
}

fn ensure_domain_sep(label: &str, domain_sep: &[u8; 32]) -> Result<(), String> {
    if domain_sep != &MEMBERSHIP_V2_DOMAIN_SEP {
        return Err(format!("{label}: domain_sep mismatch"));
    }
    Ok(())
}

fn membership_v2_domain_sep_fr() -> Fr {
    Fr::from_be_bytes_mod_order(&MEMBERSHIP_V2_DOMAIN_SEP)
}

pub fn fr_to_fixed_bytes(value: &Fr) -> Vec<u8> {
    let mut bytes = value.into_bigint().to_bytes_be();
    if bytes.len() < FIELD_BYTES {
        let mut padded = vec![0u8; FIELD_BYTES - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    bytes
}

fn poseidon_hash_native(params: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(params);
    sponge.absorb(&inputs);
    sponge.squeeze_field_elements(1)[0]
}

pub fn commitment_hash(params: &PoseidonConfig<Fr>, identity: Fr, blinding: Fr) -> Fr {
    poseidon_hash_native(
        params,
        &[Fr::from(DOMAIN_COMMITMENT), identity, blinding],
    )
}

pub fn leaf_hash(params: &PoseidonConfig<Fr>, commitment: Fr) -> Fr {
    poseidon_hash_native(
        params,
        &[Fr::from(DOMAIN_LEAF), commitment, Fr::from(0u64)],
    )
}

pub fn node_hash(params: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    poseidon_hash_native(
        params,
        &[Fr::from(DOMAIN_NODE), left, right],
    )
}

pub fn poseidon_hash_leaf(params: &PoseidonConfig<Fr>, leaf: Fr) -> Fr {
    poseidon_hash_native(params, &[Fr::from(DOMAIN_LEAF), leaf, Fr::from(0u64)])
}

pub fn poseidon_hash_node(params: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    poseidon_hash_native(params, &[Fr::from(DOMAIN_NODE), left, right])
}

pub fn poseidon_hash_leaf_v2(
    params: &PoseidonConfig<Fr>,
    domain_sep: Fr,
    ctx_hash: Fr,
    commitment: Fr,
) -> Fr {
    poseidon_hash_native(params, &[domain_sep, ctx_hash, commitment])
}

impl MembershipPublicInputsBytes {
    pub fn into_public_inputs(self) -> Result<MembershipPublicInputs, String> {
        Ok(MembershipPublicInputs {
            root: fr_from_bytes("root", &self.root)?,
            commitment: fr_from_bytes("commitment", &self.commitment)?,
        })
    }
}

impl MembershipWitnessBytes {
    pub fn into_witness(self) -> Result<MembershipWitness, String> {
        if self.merkle_path.len() != MERKLE_DEPTH {
            return Err(format!(
                "merkle_path length mismatch: expected {}, got {}",
                MERKLE_DEPTH,
                self.merkle_path.len()
            ));
        }
        let mut path = Vec::with_capacity(self.merkle_path.len());
        for (idx, node) in self.merkle_path.into_iter().enumerate() {
            let sibling = fr_from_bytes(&format!("merkle_path[{}].sibling", idx), &node.sibling)?;
            path.push((sibling, node.is_left));
        }

        Ok(MembershipWitness {
            identity_scalar: fr_from_bytes("identity_scalar", &self.identity_scalar)?,
            blinding: fr_from_bytes("blinding", &self.blinding)?,
            merkle_path: path,
        })
    }
}

impl MembershipInstanceBytes {
    pub fn into_instance(self) -> Result<MembershipInstance, String> {
        Ok(MembershipInstance {
            public_inputs: self.public_inputs.into_public_inputs()?,
            witness: self.witness.into_witness()?,
        })
    }
}

impl MembershipPublicInputsV1Bytes {
    pub fn into_public_inputs_with_depth(
        self,
    ) -> Result<(MembershipPublicInputs, usize), String> {
        ensure_version("public_inputs.version", self.version, MEMBERSHIP_INSTANCE_VERSION_V1)?;
        let depth = self.depth as usize;
        if depth == 0 {
            return Err("public_inputs.depth must be > 0".to_string());
        }
        let inputs = MembershipPublicInputs {
            root: fr_from_bytes("root", &self.root)?,
            commitment: fr_from_bytes("commitment", &self.commitment)?,
        };
        Ok((inputs, depth))
    }
}

impl MembershipWitnessV1Bytes {
    pub fn into_witness(self, expected_depth: usize) -> Result<MembershipWitness, String> {
        ensure_version("witness.version", self.version, MEMBERSHIP_INSTANCE_VERSION_V1)?;
        if self.depth as usize != expected_depth {
            return Err(format!(
                "witness.depth mismatch: expected {}, got {}",
                expected_depth, self.depth
            ));
        }
        if self.merkle_siblings.len() != expected_depth {
            return Err(format!(
                "merkle_siblings length mismatch: expected {}, got {}",
                expected_depth,
                self.merkle_siblings.len()
            ));
        }
        if self.merkle_directions.len() != expected_depth {
            return Err(format!(
                "merkle_directions length mismatch: expected {}, got {}",
                expected_depth,
                self.merkle_directions.len()
            ));
        }

        let mut path = Vec::with_capacity(expected_depth);
        for (idx, sibling_bytes) in self.merkle_siblings.into_iter().enumerate() {
            let sibling = fr_from_bytes(&format!("merkle_siblings[{}]", idx), &sibling_bytes)?;
            let is_left = self.merkle_directions[idx];
            path.push((sibling, is_left));
        }

        Ok(MembershipWitness {
            identity_scalar: fr_from_bytes("identity_scalar", &self.identity_scalar)?,
            blinding: fr_from_bytes("blinding", &self.blinding)?,
            merkle_path: path,
        })
    }
}

impl MembershipInstanceV1Bytes {
    pub fn into_instance_with_depth(self) -> Result<(MembershipInstance, usize), String> {
        ensure_version("instance.version", self.version, MEMBERSHIP_INSTANCE_VERSION_V1)?;
        let (public_inputs, expected_depth) =
            self.public_inputs.into_public_inputs_with_depth()?;
        if self.witness.depth as usize != expected_depth {
            return Err(format!(
                "instance.depth mismatch: public_inputs {}, witness {}",
                expected_depth, self.witness.depth
            ));
        }
        let instance = MembershipInstance {
            public_inputs,
            witness: self.witness.into_witness(expected_depth)?,
        };
        Ok((instance, expected_depth))
    }
}

impl MembershipPublicInputsV2Bytes {
    pub fn into_public_inputs_with_depth(
        self,
    ) -> Result<(MembershipPublicInputsV2, usize), String> {
        ensure_version_u16(
            "public_inputs.schema_version",
            self.schema_version,
            MEMBERSHIP_INSTANCE_VERSION_V2,
        )?;
        ensure_statement_type_version(self.statement_type, self.statement_version)?;
        ensure_domain_sep("public_inputs.domain_sep", &self.domain_sep)?;

        let depth = self.depth as usize;
        if depth == 0 {
            return Err("public_inputs.depth must be > 0".to_string());
        }

        let inputs = MembershipPublicInputsV2 {
            root: fr_from_bytes("root", &self.root)?,
            commitment: fr_from_bytes("commitment", &self.commitment)?,
            domain_sep: fr_from_bytes("domain_sep", &self.domain_sep)?,
            ctx_hash: fr_from_bytes("ctx_hash", &self.ctx_hash)?,
        };
        Ok((inputs, depth))
    }
}

impl MembershipWitnessV2Bytes {
    pub fn into_witness(self, expected_depth: usize) -> Result<MembershipWitnessV2, String> {
        ensure_version_u16(
            "witness.schema_version",
            self.schema_version,
            MEMBERSHIP_INSTANCE_VERSION_V2,
        )?;
        if self.depth as usize != expected_depth {
            return Err(format!(
                "witness.depth mismatch: expected {}, got {}",
                expected_depth, self.depth
            ));
        }
        if self.merkle_siblings.len() != expected_depth {
            return Err(format!(
                "merkle_siblings length mismatch: expected {}, got {}",
                expected_depth,
                self.merkle_siblings.len()
            ));
        }
        if self.merkle_directions.len() != expected_depth {
            return Err(format!(
                "merkle_directions length mismatch: expected {}, got {}",
                expected_depth,
                self.merkle_directions.len()
            ));
        }

        let mut path = Vec::with_capacity(expected_depth);
        for (idx, sibling_bytes) in self.merkle_siblings.into_iter().enumerate() {
            let sibling = fr_from_bytes(&format!("merkle_siblings[{}]", idx), &sibling_bytes)?;
            let is_left = self.merkle_directions[idx];
            path.push((sibling, is_left));
        }

        Ok(MembershipWitnessV2 {
            identity_scalar: fr_from_bytes("identity_scalar", &self.identity_scalar)?,
            blinding: fr_from_bytes("blinding", &self.blinding)?,
            merkle_path: path,
        })
    }
}

impl MembershipInstanceV2Bytes {
    pub fn into_instance_with_depth(self) -> Result<(MembershipInstanceV2, usize), String> {
        ensure_version_u16(
            "instance.schema_version",
            self.schema_version,
            MEMBERSHIP_INSTANCE_VERSION_V2,
        )?;
        let (public_inputs, expected_depth) =
            self.public_inputs.into_public_inputs_with_depth()?;
        if self.witness.depth as usize != expected_depth {
            return Err(format!(
                "instance.depth mismatch: public_inputs {}, witness {}",
                expected_depth, self.witness.depth
            ));
        }
        let instance = MembershipInstanceV2 {
            public_inputs,
            witness: self.witness.into_witness(expected_depth)?,
        };
        Ok((instance, expected_depth))
    }
}

pub fn build_circuit(instance: &MembershipInstance) -> MembershipCircuit<Fr> {
    MembershipCircuit::<Fr> {
        root: Some(instance.public_inputs.root),
        commitment: Some(instance.public_inputs.commitment),
        identity_scalar: Some(instance.witness.identity_scalar),
        blinding: Some(instance.witness.blinding),
        expected_depth: instance.witness.merkle_path.len(),
        merkle_path: instance
            .witness
            .merkle_path
            .iter()
            .map(|(sibling, is_left)| (Some(*sibling), Some(*is_left)))
            .collect(),
    }
}

pub fn build_circuit_v2(instance: &MembershipInstanceV2) -> MembershipCircuitV2<Fr> {
    MembershipCircuitV2::<Fr> {
        root: Some(instance.public_inputs.root),
        commitment: Some(instance.public_inputs.commitment),
        domain_sep: Some(instance.public_inputs.domain_sep),
        ctx_hash: Some(instance.public_inputs.ctx_hash),
        identity_scalar: Some(instance.witness.identity_scalar),
        blinding: Some(instance.witness.blinding),
        expected_depth: instance.witness.merkle_path.len(),
        merkle_path: instance
            .witness
            .merkle_path
            .iter()
            .map(|(sibling, is_left)| (Some(*sibling), Some(*is_left)))
            .collect(),
    }
}

pub fn setup_membership<R: RngCore>(
    rng: &mut R,
) -> Result<ProvingKey<Bn254>, SynthesisError> {
    setup_membership_with_depth(rng, MERKLE_DEPTH)
}

pub fn setup_membership_with_depth<R: RngCore>(
    rng: &mut R,
    depth: usize,
) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let zero = Fr::from(0u64);
    let circuit = MembershipCircuit::<Fr> {
        root: Some(zero),
        commitment: Some(zero),
        identity_scalar: Some(zero),
        blinding: Some(zero),
        expected_depth: depth,
        merkle_path: vec![(Some(zero), Some(false)); depth],
    };
    Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)
}

pub fn setup_membership_with_depth_v2<R: RngCore>(
    rng: &mut R,
    depth: usize,
) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let params = poseidon_params::<Fr>();
    let zero = Fr::from(0u64);
    let commitment = commitment_hash(&params, zero, zero);
    let domain_sep = membership_v2_domain_sep_fr();
    let ctx_hash = Fr::from(0u64);
    let circuit = MembershipCircuitV2::<Fr> {
        root: Some(commitment),
        commitment: Some(commitment),
        domain_sep: Some(domain_sep),
        ctx_hash: Some(ctx_hash),
        identity_scalar: Some(zero),
        blinding: Some(zero),
        expected_depth: depth,
        merkle_path: vec![(Some(commitment), Some(false)); depth],
    };
    Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)
}

pub fn prove_membership<R: RngCore>(
    pk: &ProvingKey<Bn254>,
    instance: &MembershipInstance,
    rng: &mut R,
) -> Result<Proof<Bn254>, SynthesisError> {
    let circuit = build_circuit(instance);
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, rng)
}

pub fn prove_membership_v2<R: RngCore>(
    pk: &ProvingKey<Bn254>,
    instance: &MembershipInstanceV2,
    rng: &mut R,
) -> Result<Proof<Bn254>, SynthesisError> {
    let circuit = build_circuit_v2(instance);
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, rng)
}

pub fn verify_membership(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &MembershipPublicInputs,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let pvk = prepare_verifying_key(vk);
    let inputs = vec![public_inputs.root, public_inputs.commitment];
    Groth16::<Bn254>::verify_proof(&pvk, proof, &inputs)
}

pub fn verify_membership_v2(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &MembershipPublicInputsV2,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let pvk = prepare_verifying_key(vk);
    let inputs = vec![
        public_inputs.root,
        public_inputs.commitment,
        public_inputs.domain_sep,
        public_inputs.ctx_hash,
    ];
    Groth16::<Bn254>::verify_proof(&pvk, proof, &inputs)
}
#[derive(Clone, Debug, Default)]
pub struct MembershipCircuit<F: PrimeField> {
    pub root: Option<F>,
    pub commitment: Option<F>,
    pub identity_scalar: Option<F>,
    pub blinding: Option<F>,
    pub expected_depth: usize,
    // Each entry is (sibling, is_left); is_left=true means sibling is on the left.
    pub merkle_path: Vec<(Option<F>, Option<bool>)>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MembershipCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        if self.expected_depth == 0 || self.merkle_path.len() != self.expected_depth {
            return Err(SynthesisError::Unsatisfiable);
        }
        let params = poseidon_params::<F>();

        let root =
            FpVar::new_input(cs.clone(), || self.root.ok_or(SynthesisError::AssignmentMissing))?;
        let commitment_input = FpVar::new_input(cs.clone(), || {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let identity_scalar = FpVar::new_witness(cs.clone(), || {
            self.identity_scalar.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let blinding = FpVar::new_witness(cs.clone(), || {
            self.blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let domain_commitment = FpVar::constant(F::from(DOMAIN_COMMITMENT));
        let domain_leaf = FpVar::constant(F::from(DOMAIN_LEAF));
        let domain_node = FpVar::constant(F::from(DOMAIN_NODE));
        let zero = FpVar::zero();

        let commitment = poseidon_hash_var(
            cs.clone(),
            &params,
            &[domain_commitment, identity_scalar, blinding],
        )?;
        commitment.enforce_equal(&commitment_input)?;

        let mut current =
            poseidon_hash_var(cs.clone(), &params, &[domain_leaf, commitment, zero])?;
        for (sibling_value, is_left_value) in self.merkle_path {
            let sibling = FpVar::new_witness(cs.clone(), || {
                sibling_value.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let is_left = Boolean::new_witness(cs.clone(), || {
                is_left_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let left = is_left.select(&sibling, &current)?;
            let right = is_left.select(&current, &sibling)?;
            current = poseidon_hash_var(cs.clone(), &params, &[domain_node.clone(), left, right])?;
        }

        current.enforce_equal(&root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MembershipCircuitV2<F: PrimeField> {
    pub root: Option<F>,
    pub commitment: Option<F>,
    pub domain_sep: Option<F>,
    pub ctx_hash: Option<F>,
    pub identity_scalar: Option<F>,
    pub blinding: Option<F>,
    pub expected_depth: usize,
    pub merkle_path: Vec<(Option<F>, Option<bool>)>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MembershipCircuitV2<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        if self.expected_depth == 0 || self.merkle_path.len() != self.expected_depth {
            return Err(SynthesisError::Unsatisfiable);
        }
        let params = poseidon_params::<F>();

        let root =
            FpVar::new_input(cs.clone(), || self.root.ok_or(SynthesisError::AssignmentMissing))?;
        let commitment_input = FpVar::new_input(cs.clone(), || {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let domain_sep = FpVar::new_input(cs.clone(), || {
            self.domain_sep.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ctx_hash =
            FpVar::new_input(cs.clone(), || self.ctx_hash.ok_or(SynthesisError::AssignmentMissing))?;

        let identity_scalar = FpVar::new_witness(cs.clone(), || {
            self.identity_scalar.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let blinding = FpVar::new_witness(cs.clone(), || {
            self.blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let domain_commitment = FpVar::constant(F::from(DOMAIN_COMMITMENT));
        let domain_node = FpVar::constant(F::from(DOMAIN_NODE));

        let commitment = poseidon_hash_var(
            cs.clone(),
            &params,
            &[domain_commitment, identity_scalar, blinding],
        )?;
        commitment.enforce_equal(&commitment_input)?;

        let domain_sep_const = FpVar::constant(F::from_be_bytes_mod_order(
            &MEMBERSHIP_V2_DOMAIN_SEP,
        ));
        domain_sep.enforce_equal(&domain_sep_const)?;

        let mut current =
            poseidon_hash_var(cs.clone(), &params, &[domain_sep, ctx_hash, commitment])?;
        for (sibling_value, is_left_value) in self.merkle_path {
            let sibling = FpVar::new_witness(cs.clone(), || {
                sibling_value.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let is_left = Boolean::new_witness(cs.clone(), || {
                is_left_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let left = is_left.select(&sibling, &current)?;
            let right = is_left.select(&current, &sibling)?;
            current = poseidon_hash_var(cs.clone(), &params, &[domain_node.clone(), left, right])?;
        }

        current.enforce_equal(&root)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        commitment_hash, fr_to_fixed_bytes, leaf_hash, node_hash, poseidon_hash_leaf_v2,
        poseidon_params, membership_v2_domain_sep_fr, MembershipCircuit,
        MembershipCircuitV2, MembershipInstanceBytes, MembershipInstanceV1Bytes,
        MembershipPublicInputsBytes, MembershipPublicInputsV1Bytes, MembershipWitnessBytes,
        MembershipWitnessV1Bytes, MerklePathNodeBytes, MEMBERSHIP_INSTANCE_VERSION_V1,
        MERKLE_DEPTH,
    };
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn membership_circuit_accepts_valid_path() {
        let params = poseidon_params::<Fr>();
        let identity = Fr::from(1u64);
        let blinding = Fr::from(2u64);
        let commitment = commitment_hash(&params, identity, blinding);
        let leaf = leaf_hash(&params, commitment);

        let sibling_commitment = commitment_hash(&params, Fr::from(3u64), Fr::from(4u64));
        let sibling = leaf_hash(&params, sibling_commitment);
        let root = node_hash(&params, leaf, sibling);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MembershipCircuit::<Fr> {
            root: Some(root),
            commitment: Some(commitment),
            identity_scalar: Some(identity),
            blinding: Some(blinding),
            expected_depth: MERKLE_DEPTH,
            merkle_path: vec![(Some(sibling), Some(false))],
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn membership_circuit_rejects_wrong_root() {
        let params = poseidon_params::<Fr>();
        let identity = Fr::from(1u64);
        let blinding = Fr::from(2u64);
        let commitment = commitment_hash(&params, identity, blinding);
        let leaf = leaf_hash(&params, commitment);

        let sibling_commitment = commitment_hash(&params, Fr::from(3u64), Fr::from(4u64));
        let sibling = leaf_hash(&params, sibling_commitment);
        let root = node_hash(&params, leaf, sibling);
        let wrong_root = root + Fr::from(1u64);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MembershipCircuit::<Fr> {
            root: Some(wrong_root),
            commitment: Some(commitment),
            identity_scalar: Some(identity),
            blinding: Some(blinding),
            expected_depth: MERKLE_DEPTH,
            merkle_path: vec![(Some(sibling), Some(false))],
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn membership_groth16_roundtrip() {
        let params = poseidon_params::<Fr>();
        let identity = Fr::from(9u64);
        let blinding = Fr::from(10u64);
        let commitment = commitment_hash(&params, identity, blinding);
        let leaf = leaf_hash(&params, commitment);

        let sibling_commitment = commitment_hash(&params, Fr::from(11u64), Fr::from(12u64));
        let sibling = leaf_hash(&params, sibling_commitment);
        let root = node_hash(&params, leaf, sibling);

        let circuit = MembershipCircuit::<Fr> {
            root: Some(root),
            commitment: Some(commitment),
            identity_scalar: Some(identity),
            blinding: Some(blinding),
            expected_depth: MERKLE_DEPTH,
            merkle_path: vec![(Some(sibling), Some(false))],
        };

        let mut rng = StdRng::seed_from_u64(42);
        let pk =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .unwrap();
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&pk.vk);

        let public_inputs = vec![root, commitment];
        assert!(Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap());
    }

    #[test]
    fn membership_instance_bytes_parse_roundtrip() {
        let root = Fr::from(7u64);
        let commitment = Fr::from(8u64);
        let identity = Fr::from(9u64);
        let blinding = Fr::from(10u64);
        let sibling = Fr::from(11u64);

        let instance_bytes = MembershipInstanceBytes {
            public_inputs: MembershipPublicInputsBytes {
                root: fr_to_fixed_bytes(&root),
                commitment: fr_to_fixed_bytes(&commitment),
            },
            witness: MembershipWitnessBytes {
                identity_scalar: fr_to_fixed_bytes(&identity),
                blinding: fr_to_fixed_bytes(&blinding),
                merkle_path: vec![MerklePathNodeBytes {
                    sibling: fr_to_fixed_bytes(&sibling),
                    is_left: false,
                }],
            },
        };

        let instance = instance_bytes.into_instance().unwrap();
        assert_eq!(instance.public_inputs.root, root);
        assert_eq!(instance.public_inputs.commitment, commitment);
        assert_eq!(instance.witness.identity_scalar, identity);
        assert_eq!(instance.witness.blinding, blinding);
        assert_eq!(instance.witness.merkle_path.len(), MERKLE_DEPTH);
    }

    #[test]
    fn membership_v1_witness_length_mismatch_fails() {
        let witness = MembershipWitnessV1Bytes {
            version: MEMBERSHIP_INSTANCE_VERSION_V1,
            depth: 2,
            identity_scalar: fr_to_fixed_bytes(&Fr::from(1u64)),
            blinding: fr_to_fixed_bytes(&Fr::from(2u64)),
            merkle_siblings: vec![fr_to_fixed_bytes(&Fr::from(3u64))],
            merkle_directions: vec![false, true],
        };

        let err = witness.into_witness(2).unwrap_err();
        assert!(err.contains("merkle_siblings length mismatch"));
    }

    #[test]
    fn membership_v1_instance_depth_mismatch_fails() {
        let public_inputs = MembershipPublicInputsV1Bytes {
            version: MEMBERSHIP_INSTANCE_VERSION_V1,
            depth: 1,
            root: fr_to_fixed_bytes(&Fr::from(7u64)),
            commitment: fr_to_fixed_bytes(&Fr::from(8u64)),
        };
        let witness = MembershipWitnessV1Bytes {
            version: MEMBERSHIP_INSTANCE_VERSION_V1,
            depth: 2,
            identity_scalar: fr_to_fixed_bytes(&Fr::from(1u64)),
            blinding: fr_to_fixed_bytes(&Fr::from(2u64)),
            merkle_siblings: vec![
                fr_to_fixed_bytes(&Fr::from(3u64)),
                fr_to_fixed_bytes(&Fr::from(4u64)),
            ],
            merkle_directions: vec![false, true],
        };
        let instance = MembershipInstanceV1Bytes {
            version: MEMBERSHIP_INSTANCE_VERSION_V1,
            public_inputs,
            witness,
        };

        let err = instance.into_instance_with_depth().unwrap_err();
        assert!(err.contains("instance.depth mismatch"));
    }

    #[test]
    fn membership_circuit_depth_two_matches_root() {
        let depth = 2;
        let params = poseidon_params::<Fr>();
        let identity = Fr::from(5u64);
        let blinding = Fr::from(6u64);
        let commitment = commitment_hash(&params, identity, blinding);
        let leaf = leaf_hash(&params, commitment);

        let sibling_1 = node_hash(&params, commitment, Fr::from(7u64));
        let sibling_2 = node_hash(&params, commitment, Fr::from(8u64));

        let mut current = node_hash(&params, leaf, sibling_1);
        current = node_hash(&params, sibling_2, current);
        let root = current;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MembershipCircuit::<Fr> {
            root: Some(root),
            commitment: Some(commitment),
            identity_scalar: Some(identity),
            blinding: Some(blinding),
            expected_depth: depth,
            merkle_path: vec![
                (Some(sibling_1), Some(false)),
                (Some(sibling_2), Some(true)),
            ],
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn membership_v2_domain_sep_tamper_fails() {
        let params = poseidon_params::<Fr>();
        let identity = Fr::from(7u64);
        let blinding = Fr::from(8u64);
        let ctx_hash = Fr::from(9u64);
        let commitment = commitment_hash(&params, identity, blinding);
        let domain_sep = membership_v2_domain_sep_fr();
        let leaf = poseidon_hash_leaf_v2(&params, domain_sep, ctx_hash, commitment);

        let sibling = node_hash(&params, commitment, Fr::from(11u64));
        let root = node_hash(&params, leaf, sibling);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MembershipCircuitV2::<Fr> {
            root: Some(root),
            commitment: Some(commitment),
            domain_sep: Some(domain_sep),
            ctx_hash: Some(ctx_hash),
            identity_scalar: Some(identity),
            blinding: Some(blinding),
            expected_depth: 1,
            merkle_path: vec![(Some(sibling), Some(false))],
        };
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MembershipCircuitV2::<Fr> {
            root: Some(root),
            commitment: Some(commitment),
            domain_sep: Some(Fr::from(123u64)),
            ctx_hash: Some(ctx_hash),
            identity_scalar: Some(identity),
            blinding: Some(blinding),
            expected_depth: 1,
            merkle_path: vec![(Some(sibling), Some(false))],
        };
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn membership_v2_ctx_hash_tamper_fails() {
        let params = poseidon_params::<Fr>();
        let identity = Fr::from(12u64);
        let blinding = Fr::from(13u64);
        let ctx_hash = Fr::from(14u64);
        let commitment = commitment_hash(&params, identity, blinding);
        let domain_sep = membership_v2_domain_sep_fr();
        let leaf = poseidon_hash_leaf_v2(&params, domain_sep, ctx_hash, commitment);

        let sibling = node_hash(&params, commitment, Fr::from(15u64));
        let root = node_hash(&params, leaf, sibling);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MembershipCircuitV2::<Fr> {
            root: Some(root),
            commitment: Some(commitment),
            domain_sep: Some(domain_sep),
            ctx_hash: Some(ctx_hash),
            identity_scalar: Some(identity),
            blinding: Some(blinding),
            expected_depth: 1,
            merkle_path: vec![(Some(sibling), Some(false))],
        };
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MembershipCircuitV2::<Fr> {
            root: Some(root),
            commitment: Some(commitment),
            domain_sep: Some(domain_sep),
            ctx_hash: Some(Fr::from(99u64)),
            identity_scalar: Some(identity),
            blinding: Some(blinding),
            expected_depth: 1,
            merkle_path: vec![(Some(sibling), Some(false))],
        };
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }
}

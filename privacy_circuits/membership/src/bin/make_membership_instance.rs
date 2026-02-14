use ark_bn254::Fr;
use ark_ff::PrimeField;
use membership::{
    commitment_hash, fr_to_fixed_bytes, node_hash, poseidon_hash_leaf,
    poseidon_hash_leaf_v2, poseidon_params, MembershipInstanceBytes,
    MembershipInstanceV1Bytes, MembershipInstanceV2Bytes, MembershipPublicInputsBytes,
    MembershipPublicInputsV1Bytes, MembershipPublicInputsV2Bytes, MembershipWitnessBytes,
    MembershipWitnessV1Bytes, MembershipWitnessV2Bytes, MerklePathNodeBytes,
    MEMBERSHIP_INSTANCE_VERSION_V1, MEMBERSHIP_INSTANCE_VERSION_V2,
    MEMBERSHIP_STATEMENT_TYPE, MEMBERSHIP_STATEMENT_VERSION_V2, MEMBERSHIP_V2_DEFAULT_CTX_HASH,
    MEMBERSHIP_V2_DOMAIN_SEP, MERKLE_DEPTH,
};
use serde::Serialize;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};

const DEFAULT_V1_DEPTH: usize = 16;

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            eprintln!(
                "Usage: make_membership_instance [--schema <v0|v1|v2>] [--depth <n>] [--out-instance <path>] [--out-public-inputs <path>]"
            );
            std::process::exit(1);
        }
    };

    match args.schema {
        Schema::V0 => {
            let (instance_bytes, public_inputs_bytes) = build_legacy_instance();
            write_outputs(&args.instance_out, &args.public_inputs_out, &instance_bytes, &public_inputs_bytes);
        }
        Schema::V1 => {
            let (instance_bytes, public_inputs_bytes) = build_v1_instance(args.depth);
            write_outputs(&args.instance_out, &args.public_inputs_out, &instance_bytes, &public_inputs_bytes);
        }
        Schema::V2 => {
            let (instance_bytes, public_inputs_bytes) = build_v2_instance(args.depth);
            write_outputs(&args.instance_out, &args.public_inputs_out, &instance_bytes, &public_inputs_bytes);
        }
    }
}

#[derive(Clone, Copy)]
enum Schema {
    V0,
    V1,
    V2,
}

struct Args {
    schema: Schema,
    depth: usize,
    instance_out: String,
    public_inputs_out: String,
}

fn parse_args() -> Result<Args, String> {
    let mut schema = Schema::V0;
    let mut depth = DEFAULT_V1_DEPTH;
    let mut instance_out = "instance.bin".to_string();
    let mut public_inputs_out = "public_inputs.bin".to_string();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--schema" => {
                schema = match args.next().as_deref() {
                    Some("v0") => Schema::V0,
                    Some("v1") => Schema::V1,
                    Some("v2") => Schema::V2,
                    _ => return Err("invalid schema (expected v0, v1, or v2)".to_string()),
                };
            }
            "--depth" => {
                depth = args
                    .next()
                    .ok_or_else(|| "missing value for --depth".to_string())?
                    .parse()
                    .map_err(|_| "invalid --depth value".to_string())?;
            }
            "--out-instance" => {
                instance_out = args
                    .next()
                    .ok_or_else(|| "missing value for --out-instance".to_string())?;
            }
            "--out-public-inputs" => {
                public_inputs_out = args
                    .next()
                    .ok_or_else(|| "missing value for --out-public-inputs".to_string())?;
            }
            "--help" | "-h" => return Err("help requested".to_string()),
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if matches!(schema, Schema::V0) {
        depth = MERKLE_DEPTH;
    } else if depth == 0 {
        return Err("depth must be > 0 for schema v1/v2".to_string());
    }

    Ok(Args {
        schema,
        depth,
        instance_out,
        public_inputs_out,
    })
}

fn build_legacy_instance() -> (MembershipInstanceBytes, MembershipPublicInputsBytes) {
    let params = poseidon_params::<Fr>();
    let identity = Fr::from(1u64);
    let blinding = Fr::from(2u64);
    let commitment = commitment_hash(&params, identity, blinding);
    let leaf = poseidon_hash_leaf(&params, commitment);

    let sibling_commitment = commitment_hash(&params, Fr::from(3u64), Fr::from(4u64));
    let sibling = poseidon_hash_leaf(&params, sibling_commitment);
    let root = node_hash(&params, leaf, sibling);

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

    let public_inputs_bytes = MembershipPublicInputsBytes {
        root: fr_to_fixed_bytes(&root),
        commitment: fr_to_fixed_bytes(&commitment),
    };

    (instance_bytes, public_inputs_bytes)
}

fn build_v1_instance(depth: usize) -> (MembershipInstanceV1Bytes, MembershipPublicInputsV1Bytes) {
    let params = poseidon_params::<Fr>();
    let identity = Fr::from(1u64);
    let blinding = Fr::from(2u64);
    let commitment = commitment_hash(&params, identity, blinding);
    let mut current = poseidon_hash_leaf(&params, commitment);

    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);

    for idx in 0..depth {
        let sibling_seed = Fr::from((idx as u64) + 10);
        let sibling = node_hash(&params, commitment, sibling_seed);
        let is_left = idx % 2 == 0;
        let (left, right) = if is_left {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = node_hash(&params, left, right);
        siblings.push(fr_to_fixed_bytes(&sibling));
        directions.push(is_left);
    }

    let public_inputs = MembershipPublicInputsV1Bytes {
        version: MEMBERSHIP_INSTANCE_VERSION_V1,
        depth: depth as u32,
        root: fr_to_fixed_bytes(&current),
        commitment: fr_to_fixed_bytes(&commitment),
    };
    let witness = MembershipWitnessV1Bytes {
        version: MEMBERSHIP_INSTANCE_VERSION_V1,
        depth: depth as u32,
        identity_scalar: fr_to_fixed_bytes(&identity),
        blinding: fr_to_fixed_bytes(&blinding),
        merkle_siblings: siblings,
        merkle_directions: directions,
    };

    let instance = MembershipInstanceV1Bytes {
        version: MEMBERSHIP_INSTANCE_VERSION_V1,
        public_inputs: public_inputs.clone(),
        witness,
    };

    (instance, public_inputs)
}

fn build_v2_instance(depth: usize) -> (MembershipInstanceV2Bytes, MembershipPublicInputsV2Bytes) {
    let params = poseidon_params::<Fr>();
    let identity = Fr::from(1u64);
    let blinding = Fr::from(2u64);
    let commitment = commitment_hash(&params, identity, blinding);
    let domain_sep = Fr::from_be_bytes_mod_order(&MEMBERSHIP_V2_DOMAIN_SEP);
    let ctx_hash = Fr::from_be_bytes_mod_order(&MEMBERSHIP_V2_DEFAULT_CTX_HASH);
    let mut current = poseidon_hash_leaf_v2(&params, domain_sep, ctx_hash, commitment);

    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);

    for idx in 0..depth {
        let sibling_seed = Fr::from((idx as u64) + 20);
        let sibling = node_hash(&params, commitment, sibling_seed);
        let is_left = idx % 2 == 0;
        let (left, right) = if is_left {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = node_hash(&params, left, right);
        siblings.push(fr_to_fixed_bytes(&sibling));
        directions.push(is_left);
    }

    let public_inputs = MembershipPublicInputsV2Bytes {
        schema_version: MEMBERSHIP_INSTANCE_VERSION_V2,
        statement_type: MEMBERSHIP_STATEMENT_TYPE,
        statement_version: MEMBERSHIP_STATEMENT_VERSION_V2,
        depth: depth as u32,
        root: fr_to_fixed_bytes(&current).try_into().unwrap(),
        commitment: fr_to_fixed_bytes(&commitment).try_into().unwrap(),
        domain_sep: MEMBERSHIP_V2_DOMAIN_SEP,
        ctx_hash: MEMBERSHIP_V2_DEFAULT_CTX_HASH,
    };
    let witness = MembershipWitnessV2Bytes {
        schema_version: MEMBERSHIP_INSTANCE_VERSION_V2,
        depth: depth as u32,
        identity_scalar: fr_to_fixed_bytes(&identity),
        blinding: fr_to_fixed_bytes(&blinding),
        merkle_siblings: siblings,
        merkle_directions: directions,
    };

    let instance = MembershipInstanceV2Bytes {
        schema_version: MEMBERSHIP_INSTANCE_VERSION_V2,
        public_inputs: public_inputs.clone(),
        witness,
    };

    (instance, public_inputs)
}

fn write_outputs<T: Serialize, U: Serialize>(
    instance_out: &str,
    public_inputs_out: &str,
    instance: &T,
    public_inputs: &U,
) {
    if let Err(err) = write_bincode(instance_out, instance) {
        eprintln!("failed to write instance: {err}");
        std::process::exit(1);
    }

    if let Err(err) = write_bincode(public_inputs_out, public_inputs) {
        eprintln!("failed to write public inputs: {err}");
        std::process::exit(1);
    }
}

fn write_bincode<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    let file = File::create(path).map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(file);
    bincode::serialize_into(&mut writer, value).map_err(|err| err.to_string())?;
    writer.flush().map_err(|err| err.to_string())
}

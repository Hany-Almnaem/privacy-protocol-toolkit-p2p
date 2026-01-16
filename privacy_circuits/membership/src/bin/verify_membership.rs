use ark_bn254::Bn254;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use membership::{
    verify_membership, verify_membership_v2, MembershipPublicInputsBytes,
    MembershipPublicInputsV1Bytes, MembershipPublicInputsV2Bytes,
};
use std::env;
use std::fs;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let (vk_path, inputs_path, proof_path, schema) = match parse_args() {
        Some(paths) => paths,
        None => {
            eprintln!(
                "Usage: verify_membership --vk <path> --public-inputs <path> --proof <path> [--schema <v0|v1|v2>]"
            );
            std::process::exit(1);
        }
    };

    let vk = match read_verifying_key(&vk_path) {
        Ok(vk) => vk,
        Err(err) => {
            eprintln!("failed to read verifying key: {err}");
            std::process::exit(1);
        }
    };

    let proof = match read_proof(&proof_path) {
        Ok(proof) => proof,
        Err(err) => {
            eprintln!("failed to read proof: {err}");
            std::process::exit(1);
        }
    };

    let verified = match schema {
        Schema::V0 => {
            let inputs_bytes = match read_public_inputs_v0(&inputs_path) {
                Ok(inputs) => inputs,
                Err(err) => {
                    eprintln!("failed to read public inputs: {err}");
                    std::process::exit(1);
                }
            };

            let public_inputs = match inputs_bytes.into_public_inputs() {
                Ok(inputs) => inputs,
                Err(err) => {
                    eprintln!("invalid public inputs: {err}");
                    std::process::exit(1);
                }
            };

            match verify_membership(&vk, &public_inputs, &proof) {
                Ok(result) => result,
                Err(err) => {
                    eprintln!("verification failed: {err}");
                    std::process::exit(1);
                }
            }
        }
        Schema::V1 => {
            let inputs_bytes = match read_public_inputs_v1(&inputs_path) {
                Ok(inputs) => inputs,
                Err(err) => {
                    eprintln!("failed to read public inputs: {err}");
                    std::process::exit(1);
                }
            };

            let (public_inputs, _depth) = match inputs_bytes.into_public_inputs_with_depth() {
                Ok((inputs, depth)) => (inputs, depth),
                Err(err) => {
                    eprintln!("invalid public inputs: {err}");
                    std::process::exit(1);
                }
            };

            match verify_membership(&vk, &public_inputs, &proof) {
                Ok(result) => result,
                Err(err) => {
                    eprintln!("verification failed: {err}");
                    std::process::exit(1);
                }
            }
        }
        Schema::V2 => {
            let inputs_bytes = match read_public_inputs_v2(&inputs_path) {
                Ok(inputs) => inputs,
                Err(err) => {
                    eprintln!("failed to read public inputs: {err}");
                    std::process::exit(1);
                }
            };

            let (public_inputs, _depth) = match inputs_bytes.into_public_inputs_with_depth() {
                Ok((inputs, depth)) => (inputs, depth),
                Err(err) => {
                    eprintln!("invalid public inputs: {err}");
                    std::process::exit(1);
                }
            };

            match verify_membership_v2(&vk, &public_inputs, &proof) {
                Ok(result) => result,
                Err(err) => {
                    eprintln!("verification failed: {err}");
                    std::process::exit(1);
                }
            }
        }
    };

    if verified {
        println!("verified");
        std::process::exit(0);
    }

    eprintln!("verification failed");
    std::process::exit(2);
}

fn parse_args() -> Option<(String, String, String, Schema)> {
    let mut vk_path = None;
    let mut inputs_path = None;
    let mut proof_path = None;
    let mut schema = Schema::V0;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vk" => vk_path = args.next(),
            "--public-inputs" => inputs_path = args.next(),
            "--proof" => proof_path = args.next(),
            "--schema" => {
                schema = match args.next()?.as_str() {
                    "v0" => Schema::V0,
                    "v1" => Schema::V1,
                    "v2" => Schema::V2,
                    _ => return None,
                };
            }
            _ => return None,
        }
    }
    match (vk_path, inputs_path, proof_path) {
        (Some(vk), Some(inputs), Some(proof)) => Some((vk, inputs, proof, schema)),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Schema {
    V0,
    V1,
    V2,
}

fn read_verifying_key(path: &str) -> Result<VerifyingKey<Bn254>, String> {
    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(file);
    VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader).map_err(|err| err.to_string())
}

fn read_public_inputs_v0(path: &str) -> Result<MembershipPublicInputsBytes, String> {
    let data = fs::read(path).map_err(|err| err.to_string())?;
    bincode::deserialize::<MembershipPublicInputsBytes>(&data).map_err(|err| err.to_string())
}

fn read_public_inputs_v1(path: &str) -> Result<MembershipPublicInputsV1Bytes, String> {
    let data = fs::read(path).map_err(|err| err.to_string())?;
    bincode::deserialize::<MembershipPublicInputsV1Bytes>(&data).map_err(|err| err.to_string())
}

fn read_public_inputs_v2(path: &str) -> Result<MembershipPublicInputsV2Bytes, String> {
    let data = fs::read(path).map_err(|err| err.to_string())?;
    bincode::deserialize::<MembershipPublicInputsV2Bytes>(&data).map_err(|err| err.to_string())
}

fn read_proof(path: &str) -> Result<Proof<Bn254>, String> {
    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(file);
    Proof::<Bn254>::deserialize_uncompressed(&mut reader).map_err(|err| err.to_string())
}

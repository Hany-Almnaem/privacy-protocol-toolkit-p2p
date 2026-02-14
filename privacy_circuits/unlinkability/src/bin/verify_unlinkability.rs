use ark_bn254::Bn254;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use std::env;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use unlinkability::{verify_unlinkability_v2, UnlinkabilityPublicInputsV2};

fn main() {
    let (vk_path, inputs_path, proof_path, schema) = match parse_args() {
        Some(paths) => paths,
        None => {
            eprintln!(
                "Usage: verify_unlinkability --vk <path> --public-inputs <path> --proof <path> [--schema <v2>]"
            );
            std::process::exit(1);
        }
    };

    if !matches!(schema, Schema::V2) {
        eprintln!("only schema v2 is supported");
        std::process::exit(1);
    }

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

    let inputs_bytes = match read_public_inputs_v2(&inputs_path) {
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

    let verified = match verify_unlinkability_v2(&vk, &public_inputs, &proof) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("verification failed: {err}");
            std::process::exit(1);
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
    let mut schema = Schema::V2;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vk" => vk_path = args.next(),
            "--public-inputs" => inputs_path = args.next(),
            "--proof" => proof_path = args.next(),
            "--schema" => {
                schema = match args.next()?.as_str() {
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
    V2,
}

fn read_verifying_key(path: &str) -> Result<VerifyingKey<Bn254>, String> {
    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(file);
    VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader).map_err(|err| err.to_string())
}

fn read_public_inputs_v2(path: &str) -> Result<UnlinkabilityPublicInputsV2, String> {
    let data = fs::read(path).map_err(|err| err.to_string())?;
    bincode::deserialize::<UnlinkabilityPublicInputsV2>(&data).map_err(|err| err.to_string())
}

fn read_proof(path: &str) -> Result<Proof<Bn254>, String> {
    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(file);
    Proof::<Bn254>::deserialize_uncompressed(&mut reader).map_err(|err| err.to_string())
}

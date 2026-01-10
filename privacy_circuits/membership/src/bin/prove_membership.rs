use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::OsRng;
use membership::{
    prove_membership, MembershipInstanceBytes, MembershipInstanceV1Bytes,
};
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};

fn main() {
    let (pk_path, instance_path, proof_out, schema) = match parse_args() {
        Some(paths) => paths,
        None => {
            eprintln!(
                "Usage: prove_membership --pk <path> --instance <path> --proof-out <path> [--schema <v0|v1>]"
            );
            std::process::exit(1);
        }
    };

    let pk = match read_proving_key(&pk_path) {
        Ok(pk) => pk,
        Err(err) => {
            eprintln!("failed to read proving key: {err}");
            std::process::exit(1);
        }
    };

    let instance = match schema {
        Schema::V0 => {
            let instance_bytes = match read_instance_v0(&instance_path) {
                Ok(instance) => instance,
                Err(err) => {
                    eprintln!("failed to read instance: {err}");
                    std::process::exit(1);
                }
            };

            match instance_bytes.into_instance() {
                Ok(instance) => instance,
                Err(err) => {
                    eprintln!("invalid instance: {err}");
                    std::process::exit(1);
                }
            }
        }
        Schema::V1 => {
            let instance_bytes = match read_instance_v1(&instance_path) {
                Ok(instance) => instance,
                Err(err) => {
                    eprintln!("failed to read instance: {err}");
                    std::process::exit(1);
                }
            };

            match instance_bytes.into_instance_with_depth() {
                Ok((instance, _depth)) => instance,
                Err(err) => {
                    eprintln!("invalid instance: {err}");
                    std::process::exit(1);
                }
            }
        }
    };

    let mut rng = OsRng;
    let proof = match prove_membership(&pk, &instance, &mut rng) {
        Ok(proof) => proof,
        Err(err) => {
            eprintln!("proof generation failed: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = write_serialized(&proof_out, &proof) {
        eprintln!("failed to write proof: {err}");
        std::process::exit(1);
    }
}

fn parse_args() -> Option<(String, String, String, Schema)> {
    let mut pk_path = None;
    let mut instance_path = None;
    let mut proof_out = None;
    let mut schema = Schema::V0;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pk" => pk_path = args.next(),
            "--instance" => instance_path = args.next(),
            "--proof-out" => proof_out = args.next(),
            "--schema" => {
                schema = match args.next()?.as_str() {
                    "v0" => Schema::V0,
                    "v1" => Schema::V1,
                    _ => return None,
                };
            }
            _ => return None,
        }
    }
    match (pk_path, instance_path, proof_out) {
        (Some(pk), Some(instance), Some(proof)) => Some((pk, instance, proof, schema)),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Schema {
    V0,
    V1,
}

fn read_proving_key(path: &str) -> Result<ProvingKey<Bn254>, String> {
    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(file);
    ProvingKey::<Bn254>::deserialize_uncompressed(&mut reader).map_err(|err| err.to_string())
}

fn read_instance_v0(path: &str) -> Result<MembershipInstanceBytes, String> {
    let data = fs::read(path).map_err(|err| err.to_string())?;
    bincode::deserialize::<MembershipInstanceBytes>(&data).map_err(|err| err.to_string())
}

fn read_instance_v1(path: &str) -> Result<MembershipInstanceV1Bytes, String> {
    let data = fs::read(path).map_err(|err| err.to_string())?;
    bincode::deserialize::<MembershipInstanceV1Bytes>(&data).map_err(|err| err.to_string())
}

fn write_serialized<T: CanonicalSerialize>(path: &str, value: &T) -> Result<(), String> {
    let file = File::create(path).map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(file);
    value
        .serialize_uncompressed(&mut writer)
        .map_err(|err| err.to_string())?;
    writer.flush().map_err(|err| err.to_string())
}

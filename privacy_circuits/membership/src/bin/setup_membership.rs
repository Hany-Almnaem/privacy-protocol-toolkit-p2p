use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::OsRng;
use membership::{setup_membership_with_depth, setup_membership_with_depth_v2, MERKLE_DEPTH};
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};

fn main() {
    let (pk_out, vk_out, depth, schema) = match parse_args() {
        Some(paths) => paths,
        None => {
            eprintln!(
                "Usage: setup_membership --pk-out <path> --vk-out <path> [--depth <n>] [--schema <v0|v1|v2>]"
            );
            std::process::exit(1);
        }
    };

    let mut rng = OsRng;
    let pk = match schema {
        Schema::V2 => setup_membership_with_depth_v2(&mut rng, depth),
        Schema::V0 | Schema::V1 => setup_membership_with_depth(&mut rng, depth),
    };
    let pk = match pk {
        Ok(pk) => pk,
        Err(err) => {
            eprintln!("setup failed: {err}");
            std::process::exit(1);
        }
    };
    let vk = pk.vk.clone();

    if let Err(err) = write_serialized(&pk_out, &pk) {
        eprintln!("failed to write proving key: {err}");
        std::process::exit(1);
    }
    if let Err(err) = write_serialized(&vk_out, &vk) {
        eprintln!("failed to write verifying key: {err}");
        std::process::exit(1);
    }
}

fn parse_args() -> Option<(String, String, usize, Schema)> {
    let mut pk_out = None;
    let mut vk_out = None;
    let mut depth = MERKLE_DEPTH;
    let mut schema = Schema::V0;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pk-out" => pk_out = args.next(),
            "--vk-out" => vk_out = args.next(),
            "--depth" => {
                depth = args.next()?.parse().ok()?;
            }
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
    match (pk_out, vk_out) {
        (Some(pk), Some(vk)) => Some((pk, vk, depth, schema)),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Schema {
    V0,
    V1,
    V2,
}

fn write_serialized<T: CanonicalSerialize>(path: &str, value: &T) -> Result<(), String> {
    let file = File::create(path).map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(file);
    value
        .serialize_uncompressed(&mut writer)
        .map_err(|err| err.to_string())?;
    writer.flush().map_err(|err| err.to_string())
}

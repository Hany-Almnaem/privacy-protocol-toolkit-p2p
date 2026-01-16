use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::OsRng;
use continuity::{setup_continuity, setup_continuity_v2};
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};

fn main() {
    let (pk_out, vk_out, schema) = match parse_args() {
        Some(paths) => paths,
        None => {
            eprintln!(
                "Usage: setup_continuity --out-pk <path> --out-vk <path> [--schema <v1|v2>]"
            );
            std::process::exit(1);
        }
    };

    let mut rng = OsRng;
    let pk = match schema {
        Schema::V1 => setup_continuity(&mut rng),
        Schema::V2 => setup_continuity_v2(&mut rng),
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

fn parse_args() -> Option<(String, String, Schema)> {
    let mut pk_out = None;
    let mut vk_out = None;
    let mut schema = Schema::V1;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-pk" => pk_out = args.next(),
            "--out-vk" => vk_out = args.next(),
            "--schema" => {
                schema = match args.next()?.as_str() {
                    "v1" => Schema::V1,
                    "v2" => Schema::V2,
                    _ => return None,
                };
            }
            _ => return None,
        }
    }
    match (pk_out, vk_out) {
        (Some(pk), Some(vk)) => Some((pk, vk, schema)),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Schema {
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

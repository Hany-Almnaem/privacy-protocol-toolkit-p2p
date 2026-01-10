use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::OsRng;
use continuity::setup_continuity;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};

fn main() {
    let (pk_out, vk_out) = match parse_args() {
        Some(paths) => paths,
        None => {
            eprintln!(
                "Usage: setup_continuity --out-pk <path> --out-vk <path>"
            );
            std::process::exit(1);
        }
    };

    let mut rng = OsRng;
    let pk = match setup_continuity(&mut rng) {
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

fn parse_args() -> Option<(String, String)> {
    let mut pk_out = None;
    let mut vk_out = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-pk" => pk_out = args.next(),
            "--out-vk" => vk_out = args.next(),
            _ => return None,
        }
    }
    match (pk_out, vk_out) {
        (Some(pk), Some(vk)) => Some((pk, vk)),
        _ => None,
    }
}

fn write_serialized<T: CanonicalSerialize>(path: &str, value: &T) -> Result<(), String> {
    let file = File::create(path).map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(file);
    value
        .serialize_uncompressed(&mut writer)
        .map_err(|err| err.to_string())?;
    writer.flush().map_err(|err| err.to_string())
}

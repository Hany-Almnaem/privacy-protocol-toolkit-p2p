use ark_bn254::Fr;
use serde::Serialize;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use unlinkability::schema::build_instance_v2;
use unlinkability::{fr_from_fixed_bytes, UNLINKABILITY_V2_DEFAULT_CTX_HASH};

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            eprintln!(
                "Usage: make_unlinkability_instance [--schema <v2>] [--out-instance <path>] [--out-public-inputs <path>]"
            );
            std::process::exit(1);
        }
    };

    let id = Fr::from(1u64);
    let blinding = Fr::from(2u64);
    let ctx_hash = fr_from_fixed_bytes("ctx_hash", &UNLINKABILITY_V2_DEFAULT_CTX_HASH)
        .expect("default ctx_hash must be valid");

    if !matches!(args.schema, Schema::V2) {
        eprintln!("only schema v2 is supported");
        std::process::exit(1);
    }

    let (instance, public_inputs) = build_instance_v2(id, blinding, ctx_hash);
    write_outputs(
        &args.instance_out,
        &args.public_inputs_out,
        &instance,
        &public_inputs,
    );
}

struct Args {
    schema: Schema,
    instance_out: String,
    public_inputs_out: String,
}

fn parse_args() -> Result<Args, String> {
    let mut schema = Schema::V2;
    let mut instance_out = "unlinkability_instance.bin".to_string();
    let mut public_inputs_out = "unlinkability_public_inputs.bin".to_string();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--schema" => {
                schema = match args.next().as_deref() {
                    Some("v2") => Schema::V2,
                    _ => return Err("invalid schema (expected v2)".to_string()),
                };
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

    Ok(Args {
        schema,
        instance_out,
        public_inputs_out,
    })
}

#[derive(Clone, Copy)]
enum Schema {
    V2,
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

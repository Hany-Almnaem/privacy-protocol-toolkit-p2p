use ark_bn254::Fr;
use continuity::schema::{build_instance_v1, build_instance_v2};
use continuity::fr_from_fixed_bytes;
use continuity::CONTINUITY_V2_DEFAULT_CTX_HASH;
use serde::Serialize;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            eprintln!(
                "Usage: make_continuity_instance [--schema <v1|v2>] [--out-instance <path>] [--out-public-inputs <path>]"
            );
            std::process::exit(1);
        }
    };

    let id = Fr::from(1u64);
    let r1 = Fr::from(2u64);
    let r2 = Fr::from(3u64);

    match args.schema {
        Schema::V1 => {
            let (instance, public_inputs) = build_instance_v1(id, r1, r2);
            write_outputs(
                &args.instance_out,
                &args.public_inputs_out,
                &instance,
                &public_inputs,
            );
        }
        Schema::V2 => {
            let ctx_hash = fr_from_fixed_bytes("ctx_hash", &CONTINUITY_V2_DEFAULT_CTX_HASH)
                .expect("default ctx_hash must be valid");
            let (instance, public_inputs) = build_instance_v2(id, r1, r2, ctx_hash);
            write_outputs(
                &args.instance_out,
                &args.public_inputs_out,
                &instance,
                &public_inputs,
            );
        }
    }
}

struct Args {
    schema: Schema,
    instance_out: String,
    public_inputs_out: String,
}

fn parse_args() -> Result<Args, String> {
    let mut schema = Schema::V1;
    let mut instance_out = "continuity_instance.bin".to_string();
    let mut public_inputs_out = "continuity_public_inputs.bin".to_string();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--schema" => {
                schema = match args.next().as_deref() {
                    Some("v1") => Schema::V1,
                    Some("v2") => Schema::V2,
                    _ => return Err("invalid schema (expected v1 or v2)".to_string()),
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
    V1,
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

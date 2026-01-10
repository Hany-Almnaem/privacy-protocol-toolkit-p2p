use ark_bn254::Fr;
use continuity::schema::build_instance_v1;
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
                "Usage: make_continuity_instance [--schema <v1>] [--out-instance <path>] [--out-public-inputs <path>]"
            );
            std::process::exit(1);
        }
    };

    if args.schema != "v1" {
        eprintln!("unsupported schema: {}", args.schema);
        std::process::exit(1);
    }

    let id = Fr::from(1u64);
    let r1 = Fr::from(2u64);
    let r2 = Fr::from(3u64);
    let (instance, public_inputs) = build_instance_v1(id, r1, r2);

    write_outputs(
        &args.instance_out,
        &args.public_inputs_out,
        &instance,
        &public_inputs,
    );
}

struct Args {
    schema: String,
    instance_out: String,
    public_inputs_out: String,
}

fn parse_args() -> Result<Args, String> {
    let mut schema = "v1".to_string();
    let mut instance_out = "continuity_instance.bin".to_string();
    let mut public_inputs_out = "continuity_public_inputs.bin".to_string();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--schema" => {
                schema = args
                    .next()
                    .ok_or_else(|| "missing value for --schema".to_string())?;
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

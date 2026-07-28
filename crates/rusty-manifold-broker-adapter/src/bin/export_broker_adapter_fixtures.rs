//! Exports deterministic standalone/embedded adapter parity fixtures.

use rusty_manifold_broker_adapter::export_broker_adapter_fixtures;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = output_dir()?;
    export_broker_adapter_fixtures(&out)?;
    println!("wrote {}", out.display());
    Ok(())
}

fn output_dir() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--out"), Some(path), None) => Ok(PathBuf::from(path)),
        _ => Err("usage: export_broker_adapter_fixtures --out <directory>".to_owned()),
    }
}

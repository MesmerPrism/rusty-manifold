//! Deterministic CLI parity for the stream-observation authority.

use rusty_manifold_stream_observation::{
    run_conformance_case, ManifoldStreamObservationConformanceCase,
};
use std::env;
use std::fs;
use std::io::{self, Read};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let input = args.next();
    let output = args.next();
    if args.next().is_some() {
        return Err("usage: stream_observation_conformance [input.json|-] [output.json|-]".into());
    }
    let bytes = if let Some(path) = input.filter(|value| value != "-") {
        fs::read_to_string(path)?
    } else {
        let mut value = String::new();
        io::stdin().read_to_string(&mut value)?;
        value
    };
    let case: ManifoldStreamObservationConformanceCase = serde_json::from_str(&bytes)?;
    let mut encoded = serde_json::to_string_pretty(&run_conformance_case(&case)?)?;
    encoded.push('\n');
    if let Some(path) = output.filter(|value| value != "-") {
        fs::write(path, encoded)?;
    } else {
        print!("{encoded}");
    }
    Ok(())
}

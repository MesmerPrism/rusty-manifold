//! Resolve a broker product specification into a deterministic lock.

use rusty_manifold_broker_product::{resolve_broker_product, ManifoldBrokerProductSpec};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("usage: resolve_broker_product <spec.json> <lock.json>");
        return ExitCode::FAILURE;
    }
    let input = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    let result = fs::read_to_string(&input)
        .map_err(|error| error.to_string())
        .and_then(|text| {
            serde_json::from_str::<ManifoldBrokerProductSpec>(&text)
                .map_err(|error| error.to_string())
        })
        .and_then(|spec| resolve_broker_product(&spec).map_err(|error| format!("{error:?}")))
        .and_then(|lock| serde_json::to_string_pretty(&lock).map_err(|error| error.to_string()))
        .and_then(|json| {
            fs::write(&output, format!("{json}\n")).map_err(|error| error.to_string())
        });
    match result {
        Ok(()) => {
            println!("wrote {}", output.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

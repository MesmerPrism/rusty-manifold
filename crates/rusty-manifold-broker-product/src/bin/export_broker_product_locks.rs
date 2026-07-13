//! Regenerates deterministic broker product locks from committed product specs.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use rusty_manifold_broker_product::{resolve_broker_product, ManifoldBrokerProductSpec};

const PRODUCTS: &[&str] = &[
    "base-standalone",
    "media-session-standalone",
    "media-session-embedded",
    "camera-embedded",
    "direct-p2p-standalone",
    "ble-embedded",
    "legacy-camera-p2p-standalone",
];

fn main() -> Result<(), Box<dyn Error>> {
    let out = output_dir()?;
    fs::create_dir_all(&out)?;
    for name in PRODUCTS {
        let spec_path = out.join(format!("{name}.json"));
        let spec: ManifoldBrokerProductSpec =
            serde_json::from_str(&fs::read_to_string(&spec_path)?)?;
        let lock = resolve_broker_product(&spec)
            .map_err(|error| format!("product lock resolution failed for {name}: {error:?}"))?;
        write_json(&out.join(format!("{name}.lock.json")), &lock)?;
    }
    println!(
        "wrote {} product locks to {}",
        PRODUCTS.len(),
        out.display()
    );
    Ok(())
}

fn output_dir() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--out"), Some(path), None) => Ok(PathBuf::from(path)),
        _ => Err("usage: export_broker_product_locks --out <fixture-directory>".to_owned()),
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), Box<dyn Error>> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

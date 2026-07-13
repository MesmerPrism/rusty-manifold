//! Prints the canonical digest for one typed Manifold media-session descriptor.

use std::{env, fs, process::ExitCode};

use rusty_manifold_media_session::canonical_media_session_sha256;
use rusty_manifold_model::ManifoldMediaSessionDescriptor;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: media_session_digest <descriptor.json>");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("usage: media_session_digest <descriptor.json>");
        return ExitCode::FAILURE;
    }
    let result = fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|json| {
            serde_json::from_str::<ManifoldMediaSessionDescriptor>(&json)
                .map_err(|error| error.to_string())
        })
        .and_then(|descriptor| {
            descriptor
                .validate()
                .map_err(|errors| format!("descriptor validation failed: {errors:?}"))?;
            canonical_media_session_sha256(&descriptor).map_err(|error| error.to_string())
        });
    match result {
        Ok(digest) => {
            println!("{digest}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

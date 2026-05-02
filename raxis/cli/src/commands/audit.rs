// raxis-cli::commands::audit — audit verify.
//
// Normative reference: cli-ceremony.md §4.1 `audit verify`.
//
// Verifies JSONL audit chain integrity. Does NOT connect to the kernel.
// Operates on one segment file per invocation.

use std::io::BufRead;
use std::path::PathBuf;

use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run_verify(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut log_path: Option<PathBuf> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--log-path" => {
                i += 1;
                log_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| CliError::Usage("--log-path requires a path".to_owned()))?,
                ));
            }
            other => return Err(CliError::Usage(format!("unknown audit verify flag: {other:?}"))),
        }
        i += 1;
    }

    let path = log_path.unwrap_or_else(|| {
        flags.data_dir().join("audit").join("segment-000.jsonl")
    });

    let file = std::fs::File::open(&path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let reader = std::io::BufReader::new(file);
    let mut total = 0u64;
    let mut chain_breaks = 0u64;
    let mut prev_sha256: Option<String> = None;
    let mut prev_seq: Option<u64> = None;
    let mut gaps = 0u64;

    for line in reader.lines() {
        let line = line.map_err(|e| CliError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if line.trim().is_empty() {
            continue;
        }

        total += 1;

        // Parse the audit record JSON.
        let record: serde_json::Value = serde_json::from_str(&line).map_err(|e| {
            CliError::Policy(format!("line {total}: JSON parse error: {e}"))
        })?;

        let seq = record["seq"].as_u64().unwrap_or(u64::MAX);

        // Check for sequence gaps.
        if let Some(prev) = prev_seq {
            if seq != prev + 1 {
                eprintln!("Gap at seq={seq}: expected {}", prev + 1);
                gaps += 1;
            }
        }

        // Verify prev_sha256 links correctly.
        let this_prev = record["prev_sha256"].as_str().unwrap_or("").to_owned();
        if let Some(ref expected) = prev_sha256 {
            if &this_prev != expected {
                eprintln!(
                    "Chain break at seq={seq}: expected prev_sha256={expected}, got {this_prev}"
                );
                chain_breaks += 1;
            }
        }

        // Compute SHA-256 of this raw line (with trailing newline as stored).
        let line_with_newline = format!("{line}\n");
        let sha256 = raxis_crypto::token::sha256_hex(line_with_newline.as_bytes());

        prev_sha256 = Some(sha256);
        prev_seq = Some(seq);
    }

    println!("Audit chain verification complete:");
    println!("  Segment:      {}", path.display());
    println!("  Total records: {total}");
    println!("  Gaps:          {gaps}");
    println!("  Chain breaks:  {chain_breaks}");

    if chain_breaks > 0 || gaps > 0 {
        eprintln!("AUDIT CHAIN COMPROMISED: {chain_breaks} breaks, {gaps} gaps");
        std::process::exit(1);
    }

    println!("Chain integrity: OK");
    Ok(())
}

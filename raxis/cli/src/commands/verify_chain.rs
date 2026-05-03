//! `raxis verify-chain` — full audit-chain integrity walk from the
//! CLI process.
//!
//! Normative reference: cli-readonly.md §5.5.13.
//!
//! Walks every `<data_dir>/audit/segment-NNN.jsonl` file in numeric
//! order via [`raxis_audit_tools::ChainReader`], asserting the
//! `prev_sha256` link and `seq` monotonicity invariants per record.
//!
//! # Exit codes (per spec)
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | Chain intact (every record links and seq is monotonic). |
//! | `3`  | Chain shows a break (link mismatch, gap, or malformed record). |
//!
//! `raxis status` calls [`raxis_audit_tools::quick_chain_check`]
//! instead of this command, so this is the slow-path command an
//! operator runs intentionally (e.g. nightly cron).

use std::path::PathBuf;

use raxis_audit_tools::{verify_chain_full, ChainReader, ChainReadError, AUDIT_DIR_NAME};

use crate::errors::CliError;
use crate::GlobalFlags;

/// Run `raxis verify-chain`.
///
/// Like `raxis status`, this command's exit code is *normal output*
/// (3 for a broken chain). We render the report and call
/// `std::process::exit` directly rather than collapsing into the
/// `CliError` channel.
pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let audit_dir = opts
        .audit_dir
        .clone()
        .unwrap_or_else(|| flags.data_dir().join(AUDIT_DIR_NAME));

    if opts.quick {
        // The "first + last" verification handed off to `raxis_audit_tools::
        // quick_chain_check` (the same fast check `raxis status` uses).
        // We emit a one-line OK + exit 0 OR a one-line BROKEN + exit 3.
        match raxis_audit_tools::quick_chain_check(&audit_dir) {
            raxis_audit_tools::ChainQuickCheck::Ok { last_seq, segment_count } => {
                println!(
                    "Audit chain: OK (quick) — segments={segment_count}, last_seq={last_seq}"
                );
                std::process::exit(0);
            }
            raxis_audit_tools::ChainQuickCheck::NoSegments => {
                println!("Audit chain: NO SEGMENTS at {}", audit_dir.display());
                // No segments is "kernel never started" — exit 0 is
                // the spec for `raxis status`; we mirror that here
                // because there's no chain to be broken yet.
                std::process::exit(0);
            }
            raxis_audit_tools::ChainQuickCheck::Broken { error } => {
                eprintln!("Audit chain: BROKEN — {error}");
                std::process::exit(3);
            }
        }
    }

    // Full walk.
    match verify_chain_full(&audit_dir) {
        Ok(stats) => {
            // The spec output sample uses the term "Audit chain
            // verification complete" — keep it stable so operator
            // shell-scripts can grep on it.
            println!("Audit chain verification complete:");
            println!("  Audit dir:     {}", audit_dir.display());
            println!("  Segments:      {}", stats.segment_count);
            println!("  Total records: {}", stats.total_records);
            println!("  Last seq:      {}", stats.last_seq);
            println!("Chain integrity: OK");
            std::process::exit(0);
        }
        Err(e) => {
            // Single-line first so cron-style consumers see the
            // verdict immediately, then a typed detail for humans.
            eprintln!("AUDIT CHAIN COMPROMISED");
            eprintln!("  Audit dir: {}", audit_dir.display());
            eprintln!("  Error:     {e}");
            // Hint the operator to the natural next step. We also
            // surface the segment + line so they can `tail -n` to
            // the failing record.
            if let Some((path, line_no)) = error_location(&e) {
                eprintln!("  Segment:   {}", path.display());
                eprintln!("  Line:      {line_no}");
            }
            std::process::exit(3);
        }
    }
}

#[derive(Debug, Default, Clone)]
struct VerifyChainOpts {
    quick: bool,
    /// `--from` is reserved per spec but not implemented in v1; we
    /// reject it explicitly so an operator who passes it gets a
    /// clear "not yet implemented" instead of a silent no-op.
    /// Tracked at cli-readonly.md §5.5.13 last bullet.
    /// (Kept as a field so a future v2 wiring is a one-line change.)
    #[allow(dead_code)]
    from_seq: Option<u64>,
    /// Override audit dir (defaults to `<data_dir>/audit`). Mirrors
    /// the existing `audit verify --log-path` flag.
    audit_dir: Option<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<VerifyChainOpts, CliError> {
    let mut opts = VerifyChainOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--quick" => opts.quick = true,
            "--from" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    CliError::Usage("--from requires a sequence number".to_owned())
                })?;
                opts.from_seq = Some(v.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("--from expects a non-negative integer; got {v:?}"))
                })?);
                return Err(CliError::Usage(
                    "--from is reserved (cli-readonly.md §5.5.13) but not yet \
                     implemented in v1; remove the flag to verify the full chain"
                        .to_owned(),
                ));
            }
            "--audit-dir" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    CliError::Usage("--audit-dir requires a path".to_owned())
                })?;
                opts.audit_dir = Some(PathBuf::from(v));
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown verify-chain flag: {other:?} (try --quick, --audit-dir, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis verify-chain — walk every audit segment, verify chain integrity\n\
         \n\
         USAGE:\n\
         \tlraxis verify-chain [--quick] [--audit-dir <path>]\n\
         \n\
         FLAGS:\n\
         \t--quick           Only check first + last record (same as `raxis status`).\n\
         \t--audit-dir PATH  Override <data_dir>/audit/.\n\
         \n\
         EXIT CODES:\n\
         \t0   chain intact\n\
         \t3   chain shows a break (link mismatch, gap, malformed record)"
    );
}

/// Pull the (path, line_no) tuple out of any `ChainReadError` variant
/// that carries them; returns `None` for variants without that info.
fn error_location(e: &ChainReadError) -> Option<(&PathBuf, u64)> {
    match e {
        ChainReadError::SegmentIo { path, line_no, .. } => Some((path, *line_no)),
        ChainReadError::MalformedRecord { path, line_no, .. } => Some((path, *line_no)),
        ChainReadError::SequenceGap { path, line_no, .. } => Some((path, *line_no)),
        ChainReadError::ChainBreak { path, .. } => Some((path, 0)),
        _ => None,
    }
}

// Compile-time helper: if the audit-tools API ever changes shape
// (e.g. `ChainReader::open` becomes async), this trivial reference
// makes the rebuild fail loudly. Cheap insurance.
#[allow(dead_code)]
fn _api_anchor() {
    let _: fn(&std::path::Path) -> Result<ChainReader, ChainReadError> = ChainReader::open;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_quick_flag() {
        let opts = parse_args(&["--quick".to_owned()]).unwrap();
        assert!(opts.quick);
    }

    #[test]
    fn parse_args_accepts_audit_dir_override() {
        let opts = parse_args(&[
            "--audit-dir".to_owned(),
            "/var/log/raxis/audit".to_owned(),
        ])
        .unwrap();
        assert_eq!(opts.audit_dir.as_deref(), Some(std::path::Path::new("/var/log/raxis/audit")));
    }

    #[test]
    fn parse_args_rejects_from_until_implemented() {
        // Forward-compat guard: if v2 wires `--from`, this test breaks
        // and reminds the implementer to remove the explicit Err
        // path.
        let err = parse_args(&["--from".to_owned(), "42".to_owned()]).unwrap_err();
        match err {
            CliError::Usage(msg) => {
                assert!(msg.contains("--from"), "got: {msg}");
                assert!(msg.contains("not yet implemented"), "got: {msg}");
            }
            other => panic!("expected Usage; got {other:?}"),
        }
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--garbage".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }
}

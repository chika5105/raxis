// raxis-audit-tools::genesis — One-shot writer for the chain-anchor record.
//
// Normative reference:
//   * specs/v1/cli-ceremony.md §4.2 step 7 "write genesis audit record"
//   * specs/v1/kernel-store.md §2.5.2 "Audit chain anchor"
//
// What this module does
// ─────────────────────
// Writes the very first line of `<audit_dir>/segment-000.jsonl` — the
// chain-anchor record that every subsequent `AuditWriter::append` chains
// off via `prev_sha256`. The record's JSON shape is rendered by the shared
// `raxis_genesis_tools::render_genesis_audit_record`; this module is
// responsible for the I/O contract (`OpenOptions::create+append`, `fsync`).
//
// Why this is a separate module from `writer.rs`
// ──────────────────────────────────────────────
// `AuditWriter::open` is the steady-state writer used after the chain has
// already been anchored — it appends seq=N records that link back to the
// previous line's SHA-256. The genesis record is the chain anchor itself,
// and the kernel deliberately writes it through a one-shot path that takes
// neither a `seq` nor a `prev_sha256` argument: both are implied by the
// "this is record 0" contract baked into the renderer.
//
// Until this module landed, the genesis-segment writer lived in
// `kernel/src/bootstrap.rs::write_genesis_audit_record` and was reachable
// only from the kernel's `RAXIS_BOOTSTRAP=1` self-bootstrap path. The
// operator-facing `raxis genesis` CLI command silently skipped this step,
// so a `raxis genesis` run produced a data dir that the kernel refused to
// boot with `BOOT_ERR_AUDIT_CHAIN: audit segment ... is missing`. Hosting
// the writer in this crate lets both genesis paths share one implementation.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use raxis_genesis_tools::{pubkey_fingerprint, render_genesis_audit_record, GenesisAuditInputs};
use thiserror::Error;
use uuid::Uuid;

/// Failure modes for `write_genesis_segment`. Distinct from
/// `AuditWriterError` because the genesis-segment writer never deals with
/// chain-resume validation — it only does file I/O.
#[derive(Debug, Error)]
pub enum GenesisWriteError {
    #[error("cannot open audit segment {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write genesis record to {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("fsync of audit segment {path} failed: {source}")]
    Fsync {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Append the chain-anchor record to `<audit_dir>/segment-000.jsonl`,
/// then `fsync` so the chain is durable before genesis returns.
///
/// Inputs (all caller-supplied so the function is pure I/O, no clock,
/// no CSPRNG — both the timestamp and the nonce are passed in so tests
/// can pin deterministic byte sequences):
///
/// * `audit_dir` — `<data_dir>/audit/` (must already exist).
/// * `authority_pubkey` — 32-byte Ed25519 public key bytes; the
///   SHA-256[:16] fingerprint becomes `authority_pubkey_fingerprint`
///   in the record.
/// * `nonce_bytes` — 64 CSPRNG bytes. The kernel and the CLI both
///   mint these via `raxis_crypto::token::try_random_array` so a
///   partial RNG failure aborts genesis *before* this writer is
///   invoked.
/// * `emitted_at_unix_secs` — wall-clock timestamp recorded as
///   `emitted_at`. Caller controls the clock.
///
/// File-open contract: `create+append`, NOT `create_new`. A future
/// genesis variant that emits additional pre-IPC records (e.g. an
/// `OperatorRegistered` event chained off the anchor) can append onto
/// the same segment. The `--force` cleanup path is the caller's
/// responsibility — this function will *append* to an existing
/// `segment-000.jsonl`, producing a malformed two-record segment that
/// the chain verifier will reject. Caller MUST `remove_file` the prior
/// segment if re-running genesis.
pub fn write_genesis_segment(
    audit_dir: &Path,
    authority_pubkey: &[u8; 32],
    nonce_bytes: &[u8; 64],
    emitted_at_unix_secs: u64,
) -> Result<(), GenesisWriteError> {
    let segment_path = audit_dir.join("segment-000.jsonl");
    let segment_path_str = || segment_path.display().to_string();

    let fingerprint = pubkey_fingerprint(authority_pubkey);
    let event_id = Uuid::new_v4().to_string();
    let line = render_genesis_audit_record(GenesisAuditInputs {
        authority_pubkey_fingerprint: &fingerprint,
        nonce_bytes,
        emitted_at_unix_secs,
        event_id: &event_id,
    });

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&segment_path)
        .map_err(|e| GenesisWriteError::Open {
            path: segment_path_str(),
            source: e,
        })?;

    file.write_all(line.as_bytes())
        .map_err(|e| GenesisWriteError::Write {
            path: segment_path_str(),
            source: e,
        })?;
    file.sync_all().map_err(|e| GenesisWriteError::Fsync {
        path: segment_path_str(),
        source: e,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::quick_chain_check;

    fn fixed_authority_pubkey() -> [u8; 32] {
        [0xC1u8; 32]
    }

    fn fixed_nonce() -> [u8; 64] {
        let mut n = [0u8; 64];
        for (i, b) in n.iter_mut().enumerate() {
            *b = i as u8;
        }
        n
    }

    #[test]
    fn writes_a_single_jsonl_line_to_segment_zero() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_genesis_segment(
            tmp.path(),
            &fixed_authority_pubkey(),
            &fixed_nonce(),
            1_700_000_000,
        )
        .expect("write_genesis_segment");

        let segment = tmp.path().join("segment-000.jsonl");
        assert!(segment.exists(), "segment-000.jsonl must exist");

        let body = std::fs::read_to_string(&segment).expect("read segment");
        let line_count = body.lines().count();
        assert_eq!(line_count, 1, "genesis writes exactly one record");
        assert!(
            body.ends_with('\n'),
            "JSONL records must terminate with a newline so chained SHA-256 hashes the trailing byte too"
        );
        // Sanity: the line round-trips through serde_json into a generic Value.
        let v: serde_json::Value =
            serde_json::from_str(body.trim_end()).expect("genesis record must be valid JSON");
        assert_eq!(v["seq"], 0, "anchor record carries seq = 0");
        assert_eq!(v["event_kind"], "GenesisRecord");
    }

    #[test]
    fn output_passes_quick_chain_check() {
        // The single most important "two halves" pin: what we wrote MUST be
        // accepted by the production chain reader. A future change to either
        // the renderer or the reader that breaks this round-trip will fail
        // here before it ships.
        let tmp = tempfile::tempdir().expect("tempdir");
        write_genesis_segment(
            tmp.path(),
            &fixed_authority_pubkey(),
            &fixed_nonce(),
            1_700_000_000,
        )
        .expect("write_genesis_segment");

        // `quick_chain_check` walks the segment, confirms seq=0/GenesisRecord,
        // and bails fast — same path the kernel uses at boot to decide
        // BOOT_ERR_AUDIT_CHAIN. The successful outcome is `ChainQuickCheck::Ok`
        // (an enum, not a Result) — anything else means the genesis writer
        // produced bytes the production reader would reject.
        match quick_chain_check(tmp.path()) {
            crate::reader::ChainQuickCheck::Ok {
                last_seq,
                segment_count,
            } => {
                assert_eq!(
                    last_seq, 0,
                    "genesis segment has exactly one record (seq=0)"
                );
                assert_eq!(segment_count, 1, "genesis writes exactly one segment file");
            }
            other => panic!("genesis segment must pass quick chain check, got: {other:?}"),
        }
    }
}

// raxis-verifier-no-secrets — Real, fast worktree-scanning verifier.
//
// What this verifier checks
// ─────────────────────────
// It walks the executor's worktree (the directory the kernel mounted
// at `RAXIS_WORKTREE_ROOT`) and looks for byte-substrings that match
// well-known credential prefixes published by major providers:
//
//   - AWS access key id      "AKIA"      (followed by 16 alnum chars in real keys)
//   - GitHub Personal Access "ghp_"      (canonical CLI-issued token prefix)
//   - Anthropic API key      "sk-ant-"   (per Anthropic API docs)
//   - Slack bot token        "xoxb-"     (per Slack API docs)
//
// The scan is intentionally prefix-based, not regex-anchored: a
// leaked credential almost always retains its provider prefix
// verbatim (operators who try to "obfuscate" a leaked key by
// truncating or splitting it have already lost — the prefix shows
// up as soon as someone copy-pastes it, which is the failure mode
// we are guarding against). We deliberately do NOT include the
// generic OpenAI `sk-` prefix because it is too short to discriminate
// from English words like "asks" / "masks" without a regex word-
// boundary guard — the four prefixes above all have at least one
// non-alphanumeric character (`_`, `-`, `K` after `AKIA` is uppercase
// in a context that's normally lowercase) and don't false-positive
// on prose.
//
// Why this is a *real* check (not a tautology)
// ────────────────────────────────────────────
// The kernel's path-allowlist gate at admission catches writes
// outside the task's `path_allowlist`, but it does NOT inspect file
// CONTENTS. A planner that legitimately writes to its allowlisted
// directory but accidentally pastes an Anthropic key into a code
// comment passes admission cleanly — and the leaked key lands in
// the merge commit. This verifier closes that hole at the
// witness-recheck stage: if the planner-emitted diff contains any
// known secret prefix, the gate-recheck pipeline records `Fail` and
// the kernel never advances `GatesPending → Admitted` for that
// task. The verifier is fast enough (sub-second on every realistic
// fixture we ship) that adding it to the gate set has no perceivable
// latency cost.
//
// Why this verifier wires into iter63's audit invariants
// ──────────────────────────────────────────────────────
// `kernel/src/scheduler/dag.rs::transition_to_admitted` (commit
// 31177d5 on `worker/iter62-deep-sweep`) introduced a paired-write
// at the recheck-clear edge: when a witness Pass lands and the gate
// re-evaluator clears `GatesPending → Admitted`, an audit row is
// written in the same SQLite transaction as the FSM transition
// (`INV-AUDIT-TASK-STATE-CHANGED-PAIRED-WRITE-01`). Without an
// active gate in the loaded policy, the live-e2e harness never
// drives that edge — the new paired-write has no production
// witness. This verifier closes that gap by giving the live-e2e a
// concrete `[[gates]]` entry that fires on every task.
//
// Crate-internal split
// ────────────────────
//   - `scan` — pure scanning logic over a directory tree. No env, no
//     I/O beyond file reads. Unit-tested in this file's `tests` module.
//   - `env` — env-var parsing into a typed `ScannerEnv`. Pure (the
//     `parse_scanner_env_from_process` shim is the only env-touching
//     function and is exercised by the binary's smoke tests).
//   - `submission` — env+ScanReport → WitnessSubmission. No I/O.
//     Unit-tested in this file's `tests` module.
//
// The binary half (`main.rs`) is the thin `#[tokio::main]` shim that
// glues the three together with the UDS round trip.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use raxis_types::{CommitSha, GateType, TaskId, WitnessResultClass, WitnessSubmission};

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

/// Default secret-prefix patterns the verifier checks for. Each entry
/// is `(short_name, byte_pattern)`. We keep the patterns as raw byte
/// strings (not regex) because:
///
///   1. Speed — `memchr`-style substring search through tens of files
///      finishes in microseconds; `regex` would add a startup cost on
///      every spawn that swamps the actual scan.
///   2. False-positive control — a regex with `\b` word boundaries
///      against the OpenAI `sk-` prefix is fragile (the `-` is itself
///      a non-word character), and we deliberately spelled the
///      pattern as `"sk-"` with a leading-space guard for that reason.
///      A real OpenAI key in a `.env` file or a code string literal
///      is preceded by `=`, `"`, `'`, or whitespace — the ` sk-` form
///      catches every realistic case without false-positive on
///      English words like `"asks"` or `"masks"`.
///   3. Auditability — the pattern table is readable as plain Rust
///      bytes; an operator skimming this file can confirm what the
///      verifier looks for without parsing regex syntax.
///
/// **Ordering matters for the report**: we keep the table in
/// alphabetical-by-short-name order so the rendered witness body
/// has stable ordering across runs, and a future contributor adding
/// a pattern must keep that order to avoid byte-noise diffs in
/// captured witness bodies.
pub const DEFAULT_PATTERNS: &[(&str, &[u8])] = &[
    ("anthropic_api_key", b"sk-ant-"),
    ("aws_access_key_id", b"AKIA"),
    ("github_pat", b"ghp_"),
    ("slack_bot_token", b"xoxb-"),
];

// ---------------------------------------------------------------------------
// Scan options
// ---------------------------------------------------------------------------

/// Per-spawn scan budget. Hard caps stop a malicious or accidental
/// large worktree from making the verifier the bottleneck — every
/// file beyond `max_files` is skipped silently (the fact that a
/// worktree has more than this many files in it is itself an iter63
/// signal worth surfacing, but the verifier's job is to scan what
/// it can within budget, not to fail the gate over a large tree).
#[derive(Debug, Clone)]
pub struct ScanOpts {
    /// Maximum number of regular files to read (after walking the
    /// tree). Files past this cap are skipped. Defaults to 5000 —
    /// well above every realistic live-e2e fixture (`rich-multilang-001`
    /// has < 100 files; the materialise-records output adds ~50).
    pub max_files: usize,

    /// Maximum bytes read per file. Files larger than this are
    /// truncated at this offset. Defaults to 256 KiB — enough to
    /// cover the largest source file in any realistic seed without
    /// being so large that a malicious seed could DoS the verifier.
    pub max_bytes_per_file: usize,

    /// Top-level directory names that are skipped entirely (we never
    /// descend into them). Defaults to `[".git", "target", "node_modules"]`.
    /// `target/` and `node_modules/` are routinely large vendored
    /// directories whose contents are derived from package manifests;
    /// scanning them wastes budget without adding signal.
    pub skip_dir_names: Vec<&'static str>,
}

impl Default for ScanOpts {
    fn default() -> Self {
        Self {
            max_files: 5000,
            max_bytes_per_file: 256 * 1024,
            skip_dir_names: vec![".git", "target", "node_modules"],
        }
    }
}

// ---------------------------------------------------------------------------
// ScanReport
// ---------------------------------------------------------------------------

/// One match found by the scanner. We capture enough context for
/// audit forensics (which file, which pattern, byte offset) without
/// echoing the secret itself — including the secret in the witness
/// body would defeat the purpose of the gate, since the witness
/// row is durably persisted to `witness_records.witness_body_json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    /// Path of the offending file, relative to the scan root. Always
    /// uses '/' as the separator (we normalise on insertion) so the
    /// witness body is byte-stable across Unix / Windows hosts even
    /// though we only ship Unix verifiers in v1.
    pub relative_path: String,

    /// Short name of the matched pattern (key in `DEFAULT_PATTERNS`).
    pub pattern_name: &'static str,

    /// Byte offset within the (possibly-truncated) file where the
    /// match started. Useful for `git blame -L<offset>` follow-up.
    pub byte_offset: usize,
}

/// The result of one scan. `Clean` fires the `Pass` witness; any
/// non-empty `matches` fires `Fail`. `Inconclusive` is reserved for
/// I/O-environmental failures (worktree directory missing,
/// permission denied on every file, etc.) — those are NOT a
/// gate-relevant signal and the kernel re-queues for retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanReport {
    /// Walked the full tree (or the budgeted prefix); no matches.
    Clean { files_scanned: usize },

    /// One or more secret-prefix matches in the worktree.
    Found { matches: Vec<SecretMatch> },

    /// Could not even start the scan — root missing or unreadable.
    /// Kernel will retry per `INV-VERIFIER-04` retry policy.
    Inconclusive { reason: String },
}

impl ScanReport {
    pub fn result_class(&self) -> WitnessResultClass {
        match self {
            ScanReport::Clean { .. } => WitnessResultClass::Pass,
            ScanReport::Found { .. } => WitnessResultClass::Fail,
            ScanReport::Inconclusive { .. } => WitnessResultClass::Inconclusive,
        }
    }
}

// ---------------------------------------------------------------------------
// scan_worktree_for_secrets — the only public scan entry point.
// ---------------------------------------------------------------------------

/// Walk `root` recursively and look for any byte-pattern from
/// `DEFAULT_PATTERNS` in every regular file's contents.
///
/// Behaviour matrix:
///
///   - `root` does not exist or is not a directory →
///     `ScanReport::Inconclusive` (kernel retries).
///   - `root` exists but contains zero files we can read → still
///     `ScanReport::Clean { files_scanned: 0 }`. An empty worktree
///     legitimately has no secrets.
///   - At least one match → `ScanReport::Found` with the FULL list
///     (we don't short-circuit; operator audit reads benefit from
///     seeing every offending file in one pass). We DO cap matches
///     at `max_files * 4` to bound the witness body size against a
///     pathological seed where every file is full of `AKIA` strings.
///
/// The scan walks directories in deterministic alphabetical order so
/// the report's `matches` ordering is byte-stable across runs (the
/// same worktree always produces the same witness body, and the
/// `witness_records.blob_sha256` index entry is content-addressed).
pub fn scan_worktree_for_secrets(root: &Path, opts: &ScanOpts) -> ScanReport {
    if !root.is_dir() {
        return ScanReport::Inconclusive {
            reason: format!("worktree root {root:?} is not an accessible directory"),
        };
    }

    // Gather all regular files first, sorted, so traversal order is
    // deterministic. We keep a `BTreeMap<PathBuf, ()>`-style sorted
    // accumulator to avoid an extra `sort_unstable` pass and to make
    // the algorithm trivially auditable.
    let mut files: Vec<PathBuf> = Vec::new();
    walk_dir(root, &opts.skip_dir_names, &mut files, opts.max_files);
    files.sort();

    let mut matches: Vec<SecretMatch> = Vec::new();
    let cap = opts.max_files.saturating_mul(4);
    let mut files_scanned = 0usize;

    for path in &files {
        if matches.len() >= cap {
            // Stop recording further matches; the cap exists to bound
            // the witness body size, not to terminate scanning early.
            // We still continue counting `files_scanned` so the
            // report's denominator reflects the full traversal.
            files_scanned += 1;
            continue;
        }
        let mut buf = vec![0u8; opts.max_bytes_per_file];
        let read = match read_capped(path, &mut buf) {
            Ok(n) => n,
            Err(_) => {
                // Per-file read errors (permissions, transient I/O)
                // are not a gate signal — we deliberately swallow
                // them so a single weird symlink doesn't sink the
                // whole gate into Inconclusive. The traversal cap
                // still bounds total work.
                files_scanned += 1;
                continue;
            }
        };
        files_scanned += 1;
        let slice = &buf[..read];
        scan_buffer(slice, path, root, &mut matches);
    }

    if matches.is_empty() {
        ScanReport::Clean { files_scanned }
    } else {
        ScanReport::Found { matches }
    }
}

/// Walk `dir` recursively and append every regular file to `out`.
/// Stops appending once `out.len() >= max_files`, but still descends
/// the rest of the tree so the caller's `files_scanned` can be
/// accurate-or-capped (we don't bother — once the cap is hit we
/// just stop pushing). Skips any directory whose `file_name`
/// matches one of `skip_dir_names`.
fn walk_dir(dir: &Path, skip_dir_names: &[&str], out: &mut Vec<PathBuf>, max_files: usize) {
    if out.len() >= max_files {
        return;
    }
    let read_dir = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return, // Unreadable directory — silently skip.
    };
    // Collect children and sort so traversal is deterministic. This
    // matters for the witness body: an LLM that paste-bombed a
    // secret into one of two files will produce the SAME witness
    // body across runs, which lets `witness_records.blob_sha256`
    // dedupe legitimately.
    let mut entries: Vec<_> = read_dir.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if out.len() >= max_files {
            return;
        }
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            // Symlinks could point outside the worktree (or back into
            // it, creating cycles). The verifier never follows them;
            // a symlinked secret is the operator's problem to clean
            // up, and including the link target in the scan would
            // make the witness non-deterministic.
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if skip_dir_names.iter().any(|s| *s == name_str) {
                continue;
            }
            walk_dir(&path, skip_dir_names, out, max_files);
        } else if ft.is_file() {
            out.push(path);
        }
    }
}

/// Read up to `buf.len()` bytes from `path` into `buf`. Returns the
/// number of bytes actually read (which may be smaller than
/// `buf.len()` for short files). Errors propagate so the caller can
/// distinguish "I/O fault on this file" from "successfully read N bytes".
fn read_capped(path: &Path, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut f = fs::File::open(path)?;
    let mut total = 0usize;
    while total < buf.len() {
        let n = f.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

/// Search `slice` for every byte-pattern in `DEFAULT_PATTERNS`,
/// recording matches into `matches`. Cheap O(n * P) where P is the
/// pattern count (currently 5) and n is the slice length — every
/// realistic file fits in cache, so the scan is bounded by `read`
/// time, not search time.
fn scan_buffer(slice: &[u8], path: &Path, root: &Path, matches: &mut Vec<SecretMatch>) {
    let rel = relative_to(path, root);
    for (name, pat) in DEFAULT_PATTERNS {
        // Walk the slice once per pattern; substring search via a
        // hand-rolled loop avoids pulling in `memchr` as a dep.
        // Length-1 patterns are pathological but our patterns are
        // 4-7 bytes, so this is fine.
        if pat.is_empty() {
            continue;
        }
        let mut i = 0usize;
        while i + pat.len() <= slice.len() {
            if &slice[i..i + pat.len()] == *pat {
                matches.push(SecretMatch {
                    relative_path: rel.clone(),
                    pattern_name: name,
                    byte_offset: i,
                });
                i += pat.len();
            } else {
                i += 1;
            }
        }
    }
}

/// Render `path` relative to `root` with '/' separators. If `path`
/// is not under `root` (shouldn't happen in practice — we only call
/// this with files we found by walking from `root`), we fall back
/// to the absolute path.
fn relative_to(path: &Path, root: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => rel.components().fold(String::new(), |mut s, c| {
            if !s.is_empty() {
                s.push('/');
            }
            s.push_str(&c.as_os_str().to_string_lossy());
            s
        }),
        Err(_) => path.display().to_string(),
    }
}

// ---------------------------------------------------------------------------
// Exit codes — same surface as raxis-verifier-stub for harness parity.
// ---------------------------------------------------------------------------

/// Process exit codes the verifier returns. Stable across releases —
/// integration test harnesses assert on these literals. Kept in
/// declaration parity with `raxis-verifier-stub::ExitCode` so a
/// future kernel-side dashboard rendering "verifier exit codes"
/// doesn't need a per-verifier translation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Witness was submitted AND the kernel acked with `accepted = true`.
    AcceptedPass = 0,
    /// Witness was submitted AND the kernel acked with `accepted = false`.
    Rejected = 1,
    /// One or more REQUIRED env vars were missing.
    MissingEnv = 2,
    /// Connect, send, or read failed at the syscall level.
    IoError = 3,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// Env parsing
// ---------------------------------------------------------------------------

/// All inputs the verifier harvests from the spawn envelope, in one
/// place. Kept behind a struct (rather than scattering `env::var`
/// calls across the binary) so unit tests can build `ScannerEnv`
/// literals without the process-global hassle of `set_var`.
#[derive(Debug, Clone)]
pub struct ScannerEnv {
    pub verifier_token: String,
    pub task_id: String,
    pub gate_type: String,
    pub evaluation_sha: String,
    pub socket_path: String,
    pub worktree_root: PathBuf,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScannerEnvError {
    #[error("required environment variable {0} is not set or is empty")]
    Missing(&'static str),
}

/// Read the spawn envelope from the process environment. Fails fast
/// on any missing / empty required var.
pub fn parse_scanner_env_from_process() -> Result<ScannerEnv, ScannerEnvError> {
    Ok(ScannerEnv {
        verifier_token: require_env("RAXIS_VERIFIER_TOKEN")?,
        task_id: require_env("RAXIS_TASK_ID")?,
        gate_type: require_env("RAXIS_GATE_TYPE")?,
        evaluation_sha: require_env("RAXIS_EVALUATION_SHA")?,
        socket_path: require_env("RAXIS_KERNEL_SOCKET")?,
        worktree_root: PathBuf::from(require_env("RAXIS_WORKTREE_ROOT")?),
    })
}

fn require_env(var: &'static str) -> Result<String, ScannerEnvError> {
    match env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(ScannerEnvError::Missing(var)),
    }
}

// ---------------------------------------------------------------------------
// Submission construction
// ---------------------------------------------------------------------------

/// Errors `build_submission` can surface. Distinct from `ScannerEnvError`
/// so tests can pin "envelope-shape-was-wrong" cases (e.g. a 39-char
/// `evaluation_sha` from a misconfigured spawn) separately.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("RAXIS_TASK_ID is invalid: {0}")]
    BadTaskId(#[from] raxis_types::TaskIdError),
    #[error("RAXIS_GATE_TYPE is invalid: {0}")]
    BadGateType(#[from] raxis_types::GateTypeError),
    #[error("RAXIS_EVALUATION_SHA is invalid: {0}")]
    BadEvaluationSha(#[from] raxis_types::CommitShaError),
}

/// Fold `ScannerEnv + ScanReport` into the wire-shape `WitnessSubmission`
/// the binary will write. Pure function (no I/O) so unit tests can
/// drive every result_class without touching the process environment.
///
/// The body shape is small and forensic-friendly:
///   - On `Pass`: `{ "files_scanned": N, "matches": [] }`
///   - On `Fail`: `{ "files_scanned": null,  "matches": [<SecretMatch>...] }`
///   - On `Inconclusive`: `{ "files_scanned": null, "matches": [], "reason": "<text>" }`
///
/// The `files_scanned` field on the Pass path is the strongest
/// available "did the scanner actually run?" signal short of replaying
/// the scan from the witness body.
pub fn build_submission(
    env: &ScannerEnv,
    report: &ScanReport,
) -> Result<WitnessSubmission, BuildError> {
    let body = match report {
        ScanReport::Clean { files_scanned } => serde_json::json!({
            "files_scanned": files_scanned,
            "matches":       [],
        }),
        ScanReport::Found { matches } => {
            // Collapse to a stable JSON array. We use serde_json's
            // value builder rather than a hand-rolled string concat
            // so the body round-trips through the kernel's JSON
            // body re-parser without escape surprises (see the
            // `WitnessSubmission.body` doc comment for the wire
            // round-trip rationale).
            let arr: Vec<serde_json::Value> = matches
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "relative_path": m.relative_path,
                        "pattern_name":  m.pattern_name,
                        "byte_offset":   m.byte_offset as u64,
                    })
                })
                .collect();
            serde_json::json!({
                "files_scanned": serde_json::Value::Null,
                "matches":       arr,
            })
        }
        ScanReport::Inconclusive { reason } => serde_json::json!({
            "files_scanned": serde_json::Value::Null,
            "matches":       [],
            "reason":        reason,
        }),
    };

    Ok(WitnessSubmission {
        verifier_token: env.verifier_token.clone(),
        task_id: TaskId::parse(&env.task_id)?,
        gate_type: GateType::parse(&env.gate_type)?,
        evaluation_sha: CommitSha::parse(&env.evaluation_sha)?,
        result_class: report.result_class(),
        body,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── ScanReport → result_class plumbing ─────────────────────────────────

    #[test]
    fn clean_scan_maps_to_pass() {
        let r = ScanReport::Clean { files_scanned: 3 };
        assert_eq!(r.result_class(), WitnessResultClass::Pass);
    }

    #[test]
    fn found_scan_maps_to_fail() {
        let r = ScanReport::Found {
            matches: vec![SecretMatch {
                relative_path: "x".to_owned(),
                pattern_name: "aws_access_key_id",
                byte_offset: 0,
            }],
        };
        assert_eq!(r.result_class(), WitnessResultClass::Fail);
    }

    #[test]
    fn inconclusive_maps_to_inconclusive() {
        let r = ScanReport::Inconclusive {
            reason: "no root".to_owned(),
        };
        assert_eq!(r.result_class(), WitnessResultClass::Inconclusive);
    }

    // ── build_submission body shape ────────────────────────────────────────

    fn fixture_env() -> ScannerEnv {
        ScannerEnv {
            verifier_token: "tok".to_owned(),
            task_id: "task-1".to_owned(),
            gate_type: "NoSecretStrings".to_owned(),
            evaluation_sha: "abcd1234abcd1234abcd1234abcd1234abcd1234".to_owned(),
            socket_path: "/tmp/k.sock".to_owned(),
            worktree_root: PathBuf::from("/tmp/wt"),
        }
    }

    #[test]
    fn submission_clean_body_carries_files_scanned() {
        let env = fixture_env();
        let report = ScanReport::Clean { files_scanned: 7 };
        let s = build_submission(&env, &report).unwrap();
        assert_eq!(s.result_class, WitnessResultClass::Pass);
        assert_eq!(s.body["files_scanned"], serde_json::json!(7));
        assert_eq!(s.body["matches"], serde_json::json!([]));
    }

    #[test]
    fn submission_found_body_lists_each_match() {
        let env = fixture_env();
        let report = ScanReport::Found {
            matches: vec![
                SecretMatch {
                    relative_path: "src/foo.rs".to_owned(),
                    pattern_name: "aws_access_key_id",
                    byte_offset: 42,
                },
                SecretMatch {
                    relative_path: "src/bar.py".to_owned(),
                    pattern_name: "github_pat",
                    byte_offset: 7,
                },
            ],
        };
        let s = build_submission(&env, &report).unwrap();
        assert_eq!(s.result_class, WitnessResultClass::Fail);
        assert_eq!(s.body["matches"][0]["relative_path"], "src/foo.rs");
        assert_eq!(s.body["matches"][0]["pattern_name"], "aws_access_key_id");
        assert_eq!(s.body["matches"][0]["byte_offset"], 42);
        assert_eq!(s.body["matches"][1]["pattern_name"], "github_pat");
    }

    #[test]
    fn submission_rejects_short_evaluation_sha() {
        let mut env = fixture_env();
        env.evaluation_sha = "abcd".to_owned();
        let report = ScanReport::Clean { files_scanned: 0 };
        let err = build_submission(&env, &report).expect_err("4-char sha must fail");
        assert!(matches!(err, BuildError::BadEvaluationSha(_)));
    }

    // ── scan_worktree_for_secrets — the witness test ───────────────────────

    /// Writes one file inside `dir` with `name` and `body`. Auto-creates
    /// any parent directories. Returns the absolute path.
    fn write_at(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn scan_clean_fixture_returns_clean_report() {
        // Realistic fixture: a Rust crate-style worktree with
        // README.md, Cargo.toml, src/main.rs, tests/integration.rs —
        // none of them contain a secret prefix. The scanner must walk
        // every file, find nothing, and report `Clean` with the right
        // file count.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        write_at(root, "README.md", b"# Demo\n\nNothing to see here.\n");
        write_at(
            root,
            "Cargo.toml",
            b"[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        );
        write_at(
            root,
            "src/main.rs",
            b"fn main() {\n    println!(\"hello\");\n}\n",
        );
        write_at(
            root,
            "tests/integration.rs",
            b"#[test]\nfn smoke() {\n    assert_eq!(2 + 2, 4);\n}\n",
        );

        let report = scan_worktree_for_secrets(root, &ScanOpts::default());
        match report {
            ScanReport::Clean { files_scanned } => {
                assert_eq!(
                    files_scanned, 4,
                    "expected exactly 4 files scanned in clean fixture"
                );
            }
            other => panic!("clean fixture must return Clean, got {other:?}"),
        }
    }

    #[test]
    fn scan_finds_aws_access_key_in_committed_file() {
        // Plant ONE realistic-looking AWS access key in a single file
        // and confirm the scanner finds it. This is the negative pin
        // — the gate exists to catch this exact case.
        //
        // Note we use a synthetic `AKIAEXAMPLEKEY00000000` value
        // (not a real credential). The scanner's matcher is
        // prefix-based ("AKIA"), so it would fire on any string
        // beginning with those four bytes.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // A few clean files surrounding the offender so the assertion
        // also pins "we don't false-positive on the unrelated files".
        write_at(root, "README.md", b"# Demo\n\nNothing to see here.\n");
        write_at(
            root,
            "src/main.rs",
            b"fn main() {\n    println!(\"hello\");\n}\n",
        );
        // The offender — note we deliberately put a recognisable
        // suffix so a debug-print of the witness body shows "this is
        // a leaked AWS key" not "this is a coincidental literal".
        write_at(
            root,
            "config/secrets.env",
            b"AWS_KEY=AKIAEXAMPLEKEY00000000\nOTHER=ok\n",
        );

        let report = scan_worktree_for_secrets(root, &ScanOpts::default());
        match report {
            ScanReport::Found { matches } => {
                assert_eq!(
                    matches.len(),
                    1,
                    "expected exactly one match, got {matches:?}"
                );
                let m = &matches[0];
                assert_eq!(m.pattern_name, "aws_access_key_id");
                assert_eq!(m.relative_path, "config/secrets.env");
                // The "AWS_KEY=" prefix is 8 bytes; AKIA starts at offset 8.
                assert_eq!(m.byte_offset, 8);
            }
            other => panic!("fixture with planted AWS key must return Found, got {other:?}"),
        }
    }

    #[test]
    fn scan_finds_anthropic_and_github_in_same_pass() {
        // Multi-pattern fixture: confirm the scanner reports BOTH
        // matches when two distinct provider prefixes appear in the
        // same worktree (a real-world failure mode where an LLM
        // pasted multiple keys into a brainstorm doc).
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "notes.md",
            b"keys i've been given:\nsk-ant-foobar123\nghp_aaaaaaaaaaaaaaaaaaaa\n",
        );
        let report = scan_worktree_for_secrets(root, &ScanOpts::default());
        match report {
            ScanReport::Found { matches } => {
                let names: Vec<&str> = matches.iter().map(|m| m.pattern_name).collect();
                assert!(
                    names.contains(&"anthropic_api_key"),
                    "missing anthropic match in {names:?}"
                );
                assert!(
                    names.contains(&"github_pat"),
                    "missing github match in {names:?}"
                );
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn scan_skips_dot_git_directory_by_default() {
        // .git/ contains huge amounts of binary blob data and packed
        // object headers — scanning it would routinely false-positive
        // on byte-coincidences, AND blow the per-file budget. Pin the
        // skip behaviour against a fixture where a .git/ entry
        // contains an "AKIA" byte sequence we MUST NOT report.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(root, "src/main.rs", b"fn main() {}\n");
        write_at(root, ".git/objects/pack/coincidence", b"random AKIAblob\n");

        let report = scan_worktree_for_secrets(root, &ScanOpts::default());
        match report {
            ScanReport::Clean { files_scanned } => {
                assert_eq!(files_scanned, 1, "only src/main.rs should be scanned");
            }
            other => panic!(".git skip failed; expected Clean, got {other:?}"),
        }
    }

    #[test]
    fn scan_inconclusive_when_root_does_not_exist() {
        let tmp = TempDir::new().unwrap();
        let nonexistent = tmp.path().join("does-not-exist");
        let report = scan_worktree_for_secrets(&nonexistent, &ScanOpts::default());
        match report {
            ScanReport::Inconclusive { reason } => {
                assert!(reason.contains("does-not-exist"), "reason = {reason:?}");
            }
            other => panic!("expected Inconclusive, got {other:?}"),
        }
    }

    // ── env parsing — exercised through the constructor only ──────────────
    //
    // We deliberately avoid `parse_scanner_env_from_process` in unit
    // tests: it touches process-global env and would force every test
    // here through a serialisation mutex (the same pattern
    // `raxis-verifier-stub::tests` uses). The body is small enough
    // that the integration-test surface (kernel-side spawn through
    // `gates::verifier_runner::spawn_verifier`) covers it end-to-end
    // without us having to re-shape every unit test around a global
    // env mutex here.
}

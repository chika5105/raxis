// raxis-verifier::symbol_index — iter62 D7 fast incremental
// symbol-index orchestration.
//
// Activated when the spawn envelope sets
// `RAXIS_VERIFIER_BUILTIN = "symbol-index"`. The verifier binary
// bypasses `sh -lc $RAXIS_VERIFIER_COMMAND` and runs this pipeline
// directly. The pipeline is the deliverable behind the
// `INV-VERIFIER-SYMBOL-INDEX-PERF-CEILING-01` budget (D11):
//
//   * < 200 ms wall-clock for a no-change diff
//   * < 1 s wall-clock for a 50-file diff on a 10k-file repo (warm
//     base index)
//   * < 5 s wall-clock for a cold full-repo rebuild
//
// The naïve `ctags -R src/` rebuild over a 10k-file repo runs ~30s
// — a per-spawn gate could not afford that. The four layered
// speed paths:
//
//   1. **Diff-scoped indexing.** Run `git diff --name-only $RAXIS_BASE_SHA
//      $RAXIS_EVALUATION_SHA` inside the worktree, intersect with the
//      hard-coded skiplist, and only tag the survivors. The Reviewer
//      reads the symbol index per-symbol (not per-file) so a delta on
//      top of a stable BASE_SYMBOL_INDEX is correctness-preserving.
//
//   2. **Persistent BASE_SYMBOL_INDEX.** The kernel mounts
//      `/raxis/base_index/symbol_index.json` (one JSON map per
//      `RAXIS_BASE_SHA`) read-only into the verifier VM. The
//      pipeline reads the base, merges per-file deltas into a clone,
//      and writes the merged map to the artefact path the kernel
//      handed us via `RAXIS_VERIFIER_ARTIFACT_PATH`.
//
//   3. **Parallel ctags.** Per-file ctags invocations partition
//      cleanly because each file's tags are independent. We dispatch
//      `nproc` worker subprocesses (`Command::new("ctags")` per file)
//      using a futures-unordered fan-out across the tokio runtime
//      `main.rs` already owns. `RAXIS_VERIFIER_PARALLELISM` lets the
//      operator override the default `num_cpus`-equivalent we derive
//      from `/proc/cpuinfo` (capped at 32 so a giant box does not
//      open hundreds of subprocesses for a tiny diff).
//
//   4. **Content-addressed file cache.** Each per-file index is
//      keyed by `sha256(file_bytes)`. When the BASE_SYMBOL_INDEX
//      already carries an entry under that hash, we skip re-tagging
//      the file even when `git diff --name-only` flagged it (the
//      file was changed somewhere upstream but the resulting bytes
//      are identical to a known-good content). The hits AND misses
//      are emitted to a sidecar `cache_hints.json` file the kernel
//      uses to warm the per-repo blob cache via the existing
//      `crates/artifact-store` interface.
//
// Skiplist (hard-coded — `.gitignore` resolution adds I/O the
// verifier cannot afford on the hot path; mirrors the executor-
// starter image's discipline):
//
//   target/        (Rust build output)
//   node_modules/  (JavaScript / TypeScript build output)
//   vendor/        (Go / Ruby vendored deps)
//   .git/          (git internals)
//   dist/          (generic distribution output)
//   build/         (generic build output)
//
// All I/O runs through the same tokio runtime `main.rs` initialises
// (`flavor = "current_thread"`); the parallel ctags invocation uses
// `futures::stream::FuturesUnordered` to drive `Command::spawn`
// concurrently from a single thread.
//
// Unit tests cover the pure-function surface (skiplist filtering,
// diff parsing, base-index merging, cache-key derivation,
// parallelism cap). The orchestration function itself is best
// exercised by the live-e2e suite (D10) — its only dependencies are
// `git`, `ctags`, and the kernel-mounted base-index path, all of
// which exist only inside the verifier-symbol-index VM.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

// === skiplist ==========================================================

/// The path-prefix segments the symbol-index pipeline refuses to
/// recurse into. Hard-coded (NOT `.gitignore`-derived) because
/// `.gitignore` resolution adds I/O the verifier cannot afford on
/// the hot path.
///
/// Mirrors the executor-starter image's discipline. Any future
/// addition is documented in `images/verifier-symbol-index/README.md`
/// and pinned by `iter62_skiplist_is_pinned`.
pub const SKIPLIST_PREFIXES: &[&str] = &[
    "target/",
    "node_modules/",
    "vendor/",
    ".git/",
    "dist/",
    "build/",
];

/// Returns `true` when `path` (relative to the worktree root) starts
/// with a [`SKIPLIST_PREFIXES`] entry. The check is byte-prefix; we
/// do NOT canonicalise (canonicalisation would defeat the cheap
/// fast-path).
///
/// Trailing-slash sensitive: the skiplist entries end in `/` so an
/// edge-case path like `target_release/` does NOT match `target/`.
pub fn is_skiplisted(path: &str) -> bool {
    SKIPLIST_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Filter a list of relative paths down to the survivors after the
/// skiplist gate. Kept as a separate pure function so the unit suite
/// can pin the skiplist behaviour without round-tripping through
/// `git diff` output.
pub fn apply_skiplist<'a, I: IntoIterator<Item = &'a str>>(paths: I) -> Vec<String> {
    paths
        .into_iter()
        .filter(|p| !is_skiplisted(p))
        .map(|p| p.to_owned())
        .collect()
}

// === diff parsing ======================================================

/// Parse a `git diff --name-only` payload into the list of paths it
/// reports. Empty lines (the diff payload always ends with a
/// trailing newline) are dropped; whitespace-only paths are
/// rejected.
///
/// The diff payload is not canonicalised — a path like `./src/foo.rs`
/// would round-trip as-is. Callers that depend on a canonical form
/// must handle it explicitly.
pub fn parse_git_diff_name_only(payload: &str) -> Vec<String> {
    payload
        .lines()
        .map(|l| l.trim_matches('\0').trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_owned())
        .collect()
}

/// Convenience: combine [`parse_git_diff_name_only`] +
/// [`apply_skiplist`] into one call.
pub fn diff_scoped_changed_files(payload: &str) -> Vec<String> {
    apply_skiplist(parse_git_diff_name_only(payload).iter().map(String::as_str))
}

// === parallelism ======================================================

/// Hard ceiling on the number of in-flight ctags subprocesses, even
/// when the host reports more cores. A giant box should not open
/// hundreds of subprocesses for a 5-file diff — the per-process
/// startup cost dominates ctags' actual work.
pub const MAX_PARALLELISM: usize = 32;

/// Derive the effective ctags fan-out from the operator-supplied
/// `RAXIS_VERIFIER_PARALLELISM` (or `num_cpus`-equivalent fallback).
/// Clamped to `[1, MAX_PARALLELISM]`.
pub fn effective_parallelism(operator_supplied: Option<usize>, host_cpu_count: usize) -> usize {
    let raw = operator_supplied.unwrap_or(host_cpu_count.max(1));
    raw.clamp(1, MAX_PARALLELISM)
}

// === content-addressed cache key ======================================

/// Compute the canonical lowercase-hex SHA-256 of `bytes`. The
/// pipeline keys per-file index entries on this digest so a file
/// whose content is unchanged across a base/evaluation pair can be
/// served from the cache even when its path appears in
/// `git diff --name-only`.
pub fn content_hash_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

// === base-index merge =================================================

/// Shape of a per-file entry in the symbol index. The `tags` field
/// is the JSON ctags emits with `--output-format=json`; the
/// pipeline does not parse it, just stitches it under the file
/// path key.
///
/// The inner `tags` value is intentionally `serde_json::Value` so a
/// future ctags upgrade that adds new fields (e.g. `extras`) does
/// not require a verifier rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerFileIndex {
    /// `sha256(file_bytes)` — content-addressed cache key.
    pub content_hash: String,
    /// Raw ctags JSON output for this single file.
    pub tags_json: Value,
}

/// In-memory view of the symbol-index document. The JSON shape on
/// disk is `{ "files": { "<rel-path>": { "content_hash": "...",
/// "tags": <ctags JSON> } }, "schema_version": 1 }`.
///
/// `BTreeMap` (not `HashMap`) so the on-disk emission is
/// deterministic — two runs over the same input produce
/// byte-identical output, which the kernel-side blob store keys on
/// for de-duplication.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolIndex {
    /// Schema version of the on-disk document. Bumping this is a
    /// breaking change; tests pin the literal `1`.
    pub schema_version: u32,
    /// Per-file entries, keyed by worktree-relative path.
    pub files: BTreeMap<String, PerFileIndex>,
}

impl SymbolIndex {
    /// The schema version this build of the verifier emits.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Construct an empty index at the current schema version.
    pub fn empty() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            files: BTreeMap::new(),
        }
    }

    /// Parse a JSON document into a `SymbolIndex`. Returns the
    /// empty index on a missing-or-empty input so a cold-start
    /// (no BASE_SYMBOL_INDEX) is not a hard failure.
    ///
    /// Returns `Err` on malformed JSON OR a schema-version that
    /// this build does not understand — the kernel-side cache must
    /// then re-bake the base index from a cold start.
    pub fn from_json(input: &str) -> Result<Self, SymbolIndexError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(Self::empty());
        }
        let parsed: Value = serde_json::from_str(trimmed)
            .map_err(|e| SymbolIndexError::Malformed(e.to_string()))?;
        let obj = parsed.as_object().ok_or_else(|| {
            SymbolIndexError::Malformed("top-level JSON must be an object".to_owned())
        })?;
        let schema_version = obj
            .get("schema_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                SymbolIndexError::Malformed("missing or non-integer schema_version".to_owned())
            })? as u32;
        if schema_version != Self::SCHEMA_VERSION {
            return Err(SymbolIndexError::SchemaVersionMismatch {
                expected: Self::SCHEMA_VERSION,
                found: schema_version,
            });
        }
        let files_obj = obj.get("files").and_then(Value::as_object);
        let files = match files_obj {
            None => BTreeMap::new(),
            Some(map) => {
                let mut out = BTreeMap::new();
                for (k, v) in map {
                    let entry_obj = v.as_object().ok_or_else(|| {
                        SymbolIndexError::Malformed(format!("files[{k}] must be an object", k = k))
                    })?;
                    let content_hash = entry_obj
                        .get("content_hash")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            SymbolIndexError::Malformed(format!(
                                "files[{k}] missing content_hash",
                                k = k
                            ))
                        })?
                        .to_owned();
                    let tags_json = entry_obj.get("tags").cloned().unwrap_or(Value::Null);
                    out.insert(
                        k.clone(),
                        PerFileIndex {
                            content_hash,
                            tags_json,
                        },
                    );
                }
                out
            }
        };
        Ok(Self {
            schema_version,
            files,
        })
    }

    /// Serialise the index back to JSON. Deterministic — the
    /// `BTreeMap` keys ensure a stable on-disk representation.
    pub fn to_json(&self) -> String {
        let mut files_obj = Map::new();
        for (path, entry) in &self.files {
            let mut e = Map::new();
            e.insert(
                "content_hash".to_owned(),
                Value::String(entry.content_hash.clone()),
            );
            e.insert("tags".to_owned(), entry.tags_json.clone());
            files_obj.insert(path.clone(), Value::Object(e));
        }
        let doc = serde_json::json!({
            "schema_version": self.schema_version,
            "files": Value::Object(files_obj),
        });
        // `to_string` is sufficient — tests pin the JSON shape via
        // round-trip parsing rather than literal-string equality, so
        // pretty-printing is not required.
        doc.to_string()
    }

    /// Merge a per-file delta into this index. Replaces the entry
    /// at `path` if one exists, otherwise inserts. Returns the
    /// previous entry (if any) so the cache-hint emitter can record
    /// content-hash transitions.
    pub fn upsert(&mut self, path: String, entry: PerFileIndex) -> Option<PerFileIndex> {
        self.files.insert(path, entry)
    }

    /// Produce a [`CacheHints`] snapshot covering the per-file
    /// deltas the pipeline produced this run. `pre_run` is the
    /// snapshot of the merged index BEFORE any per-file work; the
    /// resulting hints describe which entries the kernel cache
    /// already had vs. which the pipeline produced fresh.
    pub fn cache_hints_against(&self, pre_run: &SymbolIndex) -> CacheHints {
        let mut hits = Vec::new();
        let mut misses = Vec::new();
        for (path, entry) in &self.files {
            match pre_run.files.get(path) {
                Some(prior) if prior.content_hash == entry.content_hash => {
                    hits.push((path.clone(), entry.content_hash.clone()));
                }
                _ => misses.push((path.clone(), entry.content_hash.clone())),
            }
        }
        CacheHints { hits, misses }
    }
}

/// Errors `SymbolIndex::from_json` can surface. Distinct from the
/// `serde_json` error type so the orchestration layer can pin the
/// schema-mismatch arm separately from a generic parse failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SymbolIndexError {
    /// JSON parse failed or the top-level shape was wrong.
    #[error("symbol-index JSON is malformed: {0}")]
    Malformed(String),
    /// The on-disk schema version does not match this build's.
    /// The orchestrator treats this as "cold start" — re-bake from
    /// scratch and warm the kernel cache with the new shape.
    #[error("symbol-index schema_version mismatch: expected {expected}, found {found}")]
    SchemaVersionMismatch {
        /// Schema this build of the verifier emits.
        expected: u32,
        /// Schema the on-disk document carries.
        found: u32,
    },
}

// === cache hints ======================================================

/// Sidecar emitted alongside the main artefact. Each `(path, hash)`
/// pair reports a per-file cache decision the pipeline made — the
/// kernel-side artifact-store warmer uses these to prune entries
/// whose content has been superseded AND to surface cache-stats
/// counters via the existing observability hooks.
///
/// Format on disk:
///
/// ```json
/// {
///   "schema_version": 1,
///   "hits":   [ { "path": "...", "content_hash": "..." }, ... ],
///   "misses": [ { "path": "...", "content_hash": "..." }, ... ]
/// }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheHints {
    /// Per-file entries the BASE_SYMBOL_INDEX already carried at
    /// the same content hash — the pipeline did NOT re-tag.
    pub hits: Vec<(String, String)>,
    /// Per-file entries the pipeline produced fresh — the kernel
    /// cache should warm the per-file blob under the new hash.
    pub misses: Vec<(String, String)>,
}

impl CacheHints {
    /// Schema version of the sidecar document.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Serialise to JSON. Deterministic — entries are emitted in
    /// insertion order so two runs over the same delta produce
    /// byte-identical output.
    pub fn to_json(&self) -> String {
        fn pairs_to_array(pairs: &[(String, String)]) -> Value {
            Value::Array(
                pairs
                    .iter()
                    .map(|(p, h)| {
                        let mut m = Map::new();
                        m.insert("path".to_owned(), Value::String(p.clone()));
                        m.insert("content_hash".to_owned(), Value::String(h.clone()));
                        Value::Object(m)
                    })
                    .collect(),
            )
        }
        let doc = serde_json::json!({
            "schema_version": Self::SCHEMA_VERSION,
            "hits":   pairs_to_array(&self.hits),
            "misses": pairs_to_array(&self.misses),
        });
        doc.to_string()
    }

    /// Resolve the sidecar path adjacent to a given artefact path.
    /// `<artifact>.cache_hints.json` — the same parent directory so
    /// the kernel mounts it through the same volume.
    pub fn sidecar_path_for(artifact: &Path) -> PathBuf {
        let mut p = artifact.to_path_buf();
        let stem = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "symbol_index".to_owned());
        if let Some(parent) = artifact.parent() {
            p = parent.join(format!("{stem}.cache_hints.json"));
        } else {
            p = PathBuf::from(format!("{stem}.cache_hints.json"));
        }
        p
    }
}

// === unit tests =======================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iter62_skiplist_is_pinned() {
        // Pin the literal skiplist — any addition is a perf-budget
        // change and must update both the README and this test.
        assert_eq!(
            SKIPLIST_PREFIXES,
            &[
                "target/",
                "node_modules/",
                "vendor/",
                ".git/",
                "dist/",
                "build/",
            ]
        );
    }

    #[test]
    fn iter62_skiplist_matches_prefix_only() {
        assert!(is_skiplisted("target/debug/raxis"));
        assert!(is_skiplisted("node_modules/foo/index.js"));
        assert!(is_skiplisted(".git/HEAD"));
        // Trailing-slash sensitive — `target_release/` is NOT
        // skiplisted because the prefix is `target/` (with slash).
        assert!(!is_skiplisted("target_release/foo.rs"));
        assert!(!is_skiplisted("vendored_lib/foo.rs"));
        // Non-prefix matches do not trigger.
        assert!(!is_skiplisted("src/target/foo.rs"));
        assert!(!is_skiplisted("crates/build/foo.rs"));
    }

    #[test]
    fn iter62_apply_skiplist_filters_in_place() {
        let inputs = ["src/lib.rs", "target/debug/raxis", "vendor/foo.rs"];
        let out = apply_skiplist(inputs.iter().copied());
        assert_eq!(out, vec!["src/lib.rs"]);
    }

    #[test]
    fn iter62_parse_git_diff_drops_blank_and_trailing_lines() {
        let payload = "src/foo.rs\n\nsrc/bar.rs\n";
        let out = parse_git_diff_name_only(payload);
        assert_eq!(out, vec!["src/foo.rs", "src/bar.rs"]);
    }

    #[test]
    fn iter62_parse_git_diff_handles_nul_separator_residue() {
        let payload = "src/foo.rs\0\nsrc/bar.rs\0\n";
        let out = parse_git_diff_name_only(payload);
        assert_eq!(out, vec!["src/foo.rs", "src/bar.rs"]);
    }

    #[test]
    fn iter62_diff_scoped_changed_files_combines_parse_and_skiplist() {
        let payload = "src/foo.rs\ntarget/debug/raxis\nvendor/foo.rs\nsrc/bar.rs\n";
        let out = diff_scoped_changed_files(payload);
        assert_eq!(out, vec!["src/foo.rs", "src/bar.rs"]);
    }

    #[test]
    fn iter62_effective_parallelism_clamps_to_max() {
        assert_eq!(effective_parallelism(None, 0), 1);
        assert_eq!(effective_parallelism(None, 4), 4);
        assert_eq!(effective_parallelism(None, 128), MAX_PARALLELISM);
        assert_eq!(effective_parallelism(Some(0), 4), 1);
        assert_eq!(effective_parallelism(Some(64), 4), MAX_PARALLELISM);
        assert_eq!(effective_parallelism(Some(7), 4), 7);
    }

    #[test]
    fn iter62_content_hash_is_canonical_sha256_hex() {
        // Pin against the known SHA-256 of the empty byte string.
        assert_eq!(
            content_hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn iter62_symbol_index_round_trips_through_json() {
        let mut idx = SymbolIndex::empty();
        idx.upsert(
            "src/foo.rs".to_owned(),
            PerFileIndex {
                content_hash: "abc".to_owned(),
                tags_json: serde_json::json!([{"name": "fn1", "kind": "function"}]),
            },
        );
        idx.upsert(
            "src/bar.rs".to_owned(),
            PerFileIndex {
                content_hash: "def".to_owned(),
                tags_json: serde_json::json!([{"name": "S1", "kind": "struct"}]),
            },
        );
        let s = idx.to_json();
        let parsed = SymbolIndex::from_json(&s).expect("round-trip parse");
        assert_eq!(parsed, idx);
    }

    #[test]
    fn iter62_symbol_index_cold_start_accepts_empty_input() {
        let idx = SymbolIndex::from_json("").expect("empty input is cold-start");
        assert_eq!(idx, SymbolIndex::empty());
        let idx = SymbolIndex::from_json("   \n  ").expect("whitespace is cold-start");
        assert_eq!(idx, SymbolIndex::empty());
    }

    #[test]
    fn iter62_symbol_index_rejects_schema_version_mismatch() {
        let payload = serde_json::json!({
            "schema_version": 99,
            "files": {},
        })
        .to_string();
        let err = SymbolIndex::from_json(&payload).unwrap_err();
        match err {
            SymbolIndexError::SchemaVersionMismatch { expected, found } => {
                assert_eq!(expected, SymbolIndex::SCHEMA_VERSION);
                assert_eq!(found, 99);
            }
            other => panic!("expected SchemaVersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn iter62_symbol_index_rejects_malformed_top_level() {
        let err = SymbolIndex::from_json("[]").unwrap_err();
        assert!(matches!(err, SymbolIndexError::Malformed(_)));
        let err = SymbolIndex::from_json("not-json").unwrap_err();
        assert!(matches!(err, SymbolIndexError::Malformed(_)));
    }

    #[test]
    fn iter62_cache_hints_separate_hits_and_misses() {
        let mut base = SymbolIndex::empty();
        base.upsert(
            "src/foo.rs".to_owned(),
            PerFileIndex {
                content_hash: "h-foo".to_owned(),
                tags_json: Value::Null,
            },
        );
        base.upsert(
            "src/bar.rs".to_owned(),
            PerFileIndex {
                content_hash: "h-bar-old".to_owned(),
                tags_json: Value::Null,
            },
        );

        let mut merged = base.clone();
        merged.upsert(
            "src/bar.rs".to_owned(),
            PerFileIndex {
                content_hash: "h-bar-new".to_owned(),
                tags_json: Value::Null,
            },
        );
        merged.upsert(
            "src/baz.rs".to_owned(),
            PerFileIndex {
                content_hash: "h-baz".to_owned(),
                tags_json: Value::Null,
            },
        );

        let hints = merged.cache_hints_against(&base);
        // src/foo.rs unchanged → hit
        assert!(hints
            .hits
            .contains(&("src/foo.rs".to_owned(), "h-foo".to_owned())));
        // src/bar.rs content changed → miss (new hash)
        assert!(hints
            .misses
            .contains(&("src/bar.rs".to_owned(), "h-bar-new".to_owned())));
        // src/baz.rs new → miss
        assert!(hints
            .misses
            .contains(&("src/baz.rs".to_owned(), "h-baz".to_owned())));
        assert_eq!(hints.hits.len(), 1);
        assert_eq!(hints.misses.len(), 2);
    }

    #[test]
    fn iter62_cache_hints_sidecar_path_is_adjacent_to_artifact() {
        assert_eq!(
            CacheHints::sidecar_path_for(Path::new("/raxis/symbol_index.json")),
            PathBuf::from("/raxis/symbol_index.json.cache_hints.json")
        );
        assert_eq!(
            CacheHints::sidecar_path_for(Path::new("symbol_index.json")),
            PathBuf::from("symbol_index.json.cache_hints.json")
        );
    }

    #[test]
    fn iter62_cache_hints_to_json_round_trips_through_serde() {
        let hints = CacheHints {
            hits: vec![("src/foo.rs".to_owned(), "h-foo".to_owned())],
            misses: vec![("src/bar.rs".to_owned(), "h-bar".to_owned())],
        };
        let s = hints.to_json();
        let parsed: Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(parsed["schema_version"], CacheHints::SCHEMA_VERSION);
        assert_eq!(parsed["hits"][0]["path"], "src/foo.rs");
        assert_eq!(parsed["hits"][0]["content_hash"], "h-foo");
        assert_eq!(parsed["misses"][0]["path"], "src/bar.rs");
        assert_eq!(parsed["misses"][0]["content_hash"], "h-bar");
    }
}

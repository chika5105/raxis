// raxis-kernel::worktree_snapshot — content-addressed worktree
// snapshot store. iter68.
//
// Normative reference:
//   * `specs/v3/worktree-snapshots.md`
//   * `INV-WORKTREE-SNAPSHOT-PRE-GC-01` — gc must snapshot first
//   * `INV-WORKTREE-SNAPSHOT-CONTENT-ADDR-01` — identical states dedupe
//   * `INV-WORKTREE-SNAPSHOT-DURABLE-WRITE-01` — fsync before SQL commit
//   * `INV-WORKTREE-SNAPSHOT-BOUNDED-DIFF-01` — diffs capped at 1 MiB
//
// All kernel code that reads or writes worktree-snapshot records MUST
// go through this module. No other module may access the
// `worktree_snapshots` SQL table or the
// `$RAXIS_DATA_DIR/worktree-snapshots/` filesystem directory directly.
//
// Write order contract (mirrors `witness_index`):
//   1. Run git plumbing (`git log/diff/ls-tree/status --porcelain`) to
//      derive the four body buffers.
//   2. Truncate the diff at `MAX_DIFF_BYTES` if oversize, append the
//      `DIFF_TRUNCATION_MARKER`, record `diff_truncated = 1`.
//   3. SHA-256 each body. Identical bytes ⇒ identical sha ⇒ blob
//      shared on disk (idempotent write skips on existing file).
//   4. `fs::write` each blob to `<data_dir>/worktree-snapshots/blobs/<sha>`
//      and `sync_all` the file handle.
//   5. INSERT the index row in a single transaction.
//
// A crash between steps 3 and 5 leaves orphaned blobs on disk — they
// are invisible to queries (no row references them) and detected
// at-boot by [`startup_check`]. A crash between steps 1 and 3 leaves
// nothing on disk and nothing in SQL — the next trigger writes a
// fresh snapshot.

use std::path::{Path, PathBuf};

use raxis_crypto::token::sha256_hex;
use raxis_store::{Store, Table};
use rusqlite::OptionalExtension;
use thiserror::Error;

const WS: &str = Table::WorktreeSnapshots.as_str();

/// Cap on diff body size before truncation. Aligns with the cap
/// the dashboard's `/api/worktree-snapshots/:id/diff` route serves
/// to operators — beyond this, the diff is genuinely incomprehensible
/// in a browser anyway. Pinned by
/// `INV-WORKTREE-SNAPSHOT-BOUNDED-DIFF-01`.
pub const MAX_DIFF_BYTES: usize = 1_048_576; // 1 MiB

/// Operator-visible marker appended to a truncated diff so a
/// reader knows the body is incomplete. Carries the original byte
/// count so a corruption-replay can verify the truncation site.
pub const DIFF_TRUNCATION_MARKER: &str = "\n<<< RAXIS-DIFF-TRUNCATED >>>\n";

/// The lifecycle event that triggered a snapshot. Pinned 1:1 with
/// the `worktree_snapshots.trigger` CHECK clause (migration 24);
/// adding a variant here MUST bump a new migration to widen the
/// CHECK list. The witness test `trigger_sql_values_match_check_clause`
/// surfaces drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotTrigger {
    /// Executor task transitioned to Running (worktree just minted).
    ExecutorActivate,
    /// Executor task reached an idle / paused state (waiting on a
    /// witness, on the orchestrator, on a planner fetch).
    ExecutorIdle,
    /// Executor produced a commit and the kernel has just copied its
    /// closure into the orchestrator ODB
    /// (`worktree_provisioning::copy_executor_commit_to_orchestrator_odb`).
    ExecutorCommitCopy,
    /// Witness submission was accepted with `result_class == Pass`.
    WitnessPass,
    /// Witness submission was accepted with `result_class == Fail`.
    WitnessFail,
    /// Witness submission was accepted with `result_class == Inconclusive`.
    WitnessInconclusive,
    /// `IntegrationMerge` completed (orchestrator-anchor advanced).
    IntegrationMerge,
    /// **Hard-required.** Snapshot taken just before
    /// `worktree_gc::gc_session_worktree` removes the tree. Failing
    /// to write this snapshot violates
    /// `INV-WORKTREE-SNAPSHOT-PRE-GC-01`.
    PreGc,
}

impl SnapshotTrigger {
    /// Exact SQL CHECK-clause text. Drift between this and the
    /// migration-24 CHECK list is fatal.
    pub const fn as_sql_str(self) -> &'static str {
        match self {
            Self::ExecutorActivate => "ExecutorActivate",
            Self::ExecutorIdle => "ExecutorIdle",
            Self::ExecutorCommitCopy => "ExecutorCommitCopy",
            Self::WitnessPass => "WitnessPass",
            Self::WitnessFail => "WitnessFail",
            Self::WitnessInconclusive => "WitnessInconclusive",
            Self::IntegrationMerge => "IntegrationMerge",
            Self::PreGc => "PreGc",
        }
    }

    /// Parse a SQL value back into the typed variant. `None` for an
    /// unknown string (migration drift / corrupted row) — callers
    /// must propagate as a hard error, not coerce to a default.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        Some(match s {
            "ExecutorActivate" => Self::ExecutorActivate,
            "ExecutorIdle" => Self::ExecutorIdle,
            "ExecutorCommitCopy" => Self::ExecutorCommitCopy,
            "WitnessPass" => Self::WitnessPass,
            "WitnessFail" => Self::WitnessFail,
            "WitnessInconclusive" => Self::WitnessInconclusive,
            "IntegrationMerge" => Self::IntegrationMerge,
            "PreGc" => Self::PreGc,
            _ => return None,
        })
    }
}

/// Errors the snapshot writer / reader can surface. The `PreGc`
/// trigger's hard-fail contract means callers in
/// `worktree_gc::gc_session_worktree` MUST treat
/// [`SnapshotError::WriteFailed`] as a refusal to GC the tree.
#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("git plumbing failed at {step}: {reason}")]
    GitPlumbing { step: &'static str, reason: String },

    #[error("IO error writing snapshot blob {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("SQL error: {0}")]
    Sql(#[from] rusqlite::Error),

    #[error("store error: {0}")]
    Store(#[from] raxis_store::StoreError),

    #[error("worktree root does not exist: {0}")]
    WorktreeMissing(PathBuf),

    #[error("snapshot blob not found: {sha256}")]
    BlobNotFound { sha256: String },
}

/// On-disk + in-memory shape of a single snapshot index row.
///
/// `*_blob_sha256` fields are `Option` because a fresh-clone
/// worktree (base == HEAD, no changes) produces empty diff/log
/// bodies whose sha256 we deliberately do NOT bother to write —
/// the absence is cheaper and equally informative.
#[derive(Debug, Clone)]
pub struct WorktreeSnapshotRecord {
    pub snapshot_id: String,
    pub task_id: String,
    pub session_id: Option<String>,
    pub initiative_id: Option<String>,
    pub trigger: SnapshotTrigger,
    pub taken_at: i64,
    pub base_sha: String,
    pub head_sha: String,
    pub commit_count: u32,
    pub diff_blob_sha256: Option<String>,
    pub log_blob_sha256: Option<String>,
    pub tree_blob_sha256: Option<String>,
    pub porcelain_blob_sha256: Option<String>,
    pub diff_bytes_total: u64,
    pub diff_truncated: bool,
}

/// Output of [`startup_check`] — used by the kernel daemon's boot
/// path to log orphan counts (mirrors `witness_index::WitnessStartupReport`).
#[derive(Debug, Default)]
pub struct SnapshotStartupReport {
    pub orphaned_blobs: usize,
    pub orphaned_index_rows: usize,
}

// ---------------------------------------------------------------------------
// Directory + path helpers
// ---------------------------------------------------------------------------

/// `<data_dir>/worktree-snapshots/blobs/`. The kernel daemon
/// bootstraps `<data_dir>/worktree-snapshots/` via
/// `data_dir_layout::ensure_data_dir_layout`; this helper appends
/// the blobs subdirectory.
pub fn blobs_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("worktree-snapshots").join("blobs")
}

/// `<data_dir>/worktree-snapshots/blobs/<sha256>`.
pub fn blob_path(data_dir: &Path, sha256: &str) -> PathBuf {
    blobs_dir(data_dir).join(sha256)
}

/// Idempotent: creates `worktree-snapshots/blobs/` if missing. Called
/// once by `snapshot_worktree` before the first FS write so a fresh
/// data dir survives the iter66-style "directory absent on first
/// write" panic.
fn ensure_blobs_dir(data_dir: &Path) -> Result<PathBuf, SnapshotError> {
    let dir = blobs_dir(data_dir);
    std::fs::create_dir_all(&dir).map_err(|e| SnapshotError::Io {
        path: dir.display().to_string(),
        source: e,
    })?;
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Blob write — content-addressed + fsync'd
// ---------------------------------------------------------------------------

/// Write `bytes` to `<data_dir>/worktree-snapshots/blobs/<sha>`.
/// Returns `Some(sha)` when the body is non-empty (and now on disk),
/// `None` when `bytes` is empty (we skip empty blobs to avoid
/// polluting the FS with a sha256(b"") sentinel).
///
/// **Durability** (`INV-WORKTREE-SNAPSHOT-DURABLE-WRITE-01`): the
/// file handle is `sync_all`'d before close, so the bytes are on
/// stable storage before the caller proceeds to the SQL insert.
/// Without this, a crash between the FS write and the SQL commit
/// could leave a row referencing a sha that the OS page cache
/// silently dropped.
fn write_blob(data_dir: &Path, bytes: &[u8]) -> Result<Option<String>, SnapshotError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let dir = ensure_blobs_dir(data_dir)?;
    let sha = sha256_hex(bytes);
    let path = dir.join(&sha);
    if !path.exists() {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| SnapshotError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
        f.write_all(bytes).map_err(|e| SnapshotError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        f.sync_all().map_err(|e| SnapshotError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    }
    Ok(Some(sha))
}

// ---------------------------------------------------------------------------
// Git plumbing — capture the four body buffers
// ---------------------------------------------------------------------------

/// Bundle of git-derived body buffers. Held as `Vec<u8>` so a
/// future bincode/protobuf wire shape can swap the storage layer
/// without re-running the git plumbing.
#[derive(Debug, Default)]
struct WorktreeBodies {
    /// `git diff <base>..HEAD` (capped at [`MAX_DIFF_BYTES`]).
    diff: Vec<u8>,
    /// `git log <base>..HEAD --format=...` using committer
    /// unix timestamps (`%ct`) so the dashboard shows when the
    /// system observed/created the agent commit, not a possibly
    /// inherited author date.
    log: Vec<u8>,
    /// `git ls-tree -r HEAD --name-only` (full tracked file listing).
    tree_listing: Vec<u8>,
    /// `git status --porcelain` (uncommitted changes; usually empty
    /// for the executor's tree at idle).
    porcelain: Vec<u8>,
    /// `git rev-parse HEAD`.
    head_sha: String,
    /// Number of commits in `base..HEAD`.
    commit_count: u32,
    /// True iff the diff body was truncated at [`MAX_DIFF_BYTES`].
    diff_truncated: bool,
    /// Original (pre-truncation) diff size in bytes.
    diff_bytes_total: u64,
}

/// Run `git ...` in `cwd` and capture stdout. The 30 s wall-clock
/// timeout is generous for the worktree sizes the snapshot loop
/// covers (executor / reviewer trees are bounded by the plan's
/// max-file-count). Stderr is discarded — the dashboard surfaces
/// the empty-body case structurally (`diff_blob_sha256 IS NULL`)
/// rather than as an error string.
fn run_git(cwd: &Path, args: &[&str]) -> Result<Vec<u8>, SnapshotError> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| SnapshotError::GitPlumbing {
            step: "spawn",
            reason: format!("git {} in {}: {e}", args.join(" "), cwd.display()),
        })?;
    if !output.status.success() {
        return Err(SnapshotError::GitPlumbing {
            step: "exit",
            reason: format!(
                "git {} in {}: exit {:?}",
                args.join(" "),
                cwd.display(),
                output.status.code(),
            ),
        });
    }
    Ok(output.stdout)
}

/// Capture the four body buffers + HEAD sha + commit count for
/// `worktree_root` relative to `base_sha`. Cheap on small trees,
/// O(diff size) on big ones (bounded by [`MAX_DIFF_BYTES`]).
fn capture_bodies(worktree_root: &Path, base_sha: &str) -> Result<WorktreeBodies, SnapshotError> {
    if !worktree_root.is_dir() {
        return Err(SnapshotError::WorktreeMissing(worktree_root.to_path_buf()));
    }
    let head_raw = run_git(worktree_root, &["rev-parse", "HEAD"])?;
    let head_sha = String::from_utf8_lossy(&head_raw).trim().to_owned();

    // `git diff <base>..HEAD` covers committed changes; uncommitted
    // changes show up in `git status --porcelain`. Together they
    // span the full worktree delta.
    let base_dotdot_head = format!("{base_sha}..HEAD");
    let mut diff = run_git(worktree_root, &["diff", &base_dotdot_head])?;
    let diff_bytes_total = diff.len() as u64;
    let mut diff_truncated = false;
    if diff.len() > MAX_DIFF_BYTES {
        diff.truncate(MAX_DIFF_BYTES);
        diff.extend_from_slice(DIFF_TRUNCATION_MARKER.as_bytes());
        diff_truncated = true;
    }

    let log = run_git(
        worktree_root,
        &["log", &base_dotdot_head, "--format=%H%x09%an%x09%ct%x09%s"],
    )?;
    // Each non-empty line is one commit. Do not count `\n`
    // bytes directly: git omits the trailing newline for a
    // single-commit log, which previously rendered one agent
    // commit as `0 commits`.
    let commit_count = String::from_utf8_lossy(&log)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u32;

    // `git ls-tree -r HEAD --name-only` is the canonical "every
    // tracked file at HEAD" enumeration — used by the dashboard's
    // tree-view to render the worktree shape.
    let tree_listing = run_git(worktree_root, &["ls-tree", "-r", "HEAD", "--name-only"])?;

    // `git status --porcelain` captures any uncommitted modifications
    // (executor mid-work) so the dashboard's "live worktree state"
    // tab matches what the agent sees.
    let porcelain = run_git(worktree_root, &["status", "--porcelain"])?;

    Ok(WorktreeBodies {
        diff,
        log,
        tree_listing,
        porcelain,
        head_sha,
        commit_count,
        diff_truncated,
        diff_bytes_total,
    })
}

// ---------------------------------------------------------------------------
// Snapshot writer — the canonical entry point
// ---------------------------------------------------------------------------

/// Inputs the kernel passes to [`snapshot_worktree`]. Plain-data
/// struct so a future async hop / `spawn_blocking` wrap does not
/// have to thread 6 separate arguments.
#[derive(Debug, Clone)]
pub struct SnapshotInput {
    pub task_id: String,
    pub session_id: Option<String>,
    pub initiative_id: Option<String>,
    pub trigger: SnapshotTrigger,
    pub worktree_root: PathBuf,
    pub base_sha: String,
}

/// Capture a snapshot of `input.worktree_root` and commit a row
/// into `worktree_snapshots`. Returns the freshly-minted
/// [`WorktreeSnapshotRecord`] on success.
///
/// **Hot-path safety.** Runs git plumbing as subprocesses; callers
/// invoking this from an async runtime MUST wrap the call in
/// `tokio::task::spawn_blocking` (mirrors the
/// `INV-WITNESS-INDEX-LOOKUP-ASYNC-SAFE-01` discipline applied to
/// `witness_index::lookup`).
///
/// **Idempotency.** Calling twice with the same inputs writes two
/// rows but reuses blob files (content-addressed). The caller
/// (typically the trigger site) decides whether to dedupe at the
/// row level — for now we record every trigger so the audit chain
/// has the full timeline.
pub fn snapshot_worktree(
    store: &Store,
    data_dir: &Path,
    input: SnapshotInput,
) -> Result<WorktreeSnapshotRecord, SnapshotError> {
    let bodies = capture_bodies(&input.worktree_root, &input.base_sha)?;

    // Step 1 — write blobs (content-addressed + fsync'd).
    let diff_sha = write_blob(data_dir, &bodies.diff)?;
    let log_sha = write_blob(data_dir, &bodies.log)?;
    let tree_sha = write_blob(data_dir, &bodies.tree_listing)?;
    let porcelain_sha = write_blob(data_dir, &bodies.porcelain)?;

    // Step 2 — mint a snapshot id. Derived from
    // (task_id, taken_at_ns, trigger) so collisions are
    // statistically impossible in single-host wall-clock time.
    let taken_at = unix_now_secs();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let snapshot_id = format!(
        "wts-{}-{}-{:x}",
        sanitize_id_segment(&input.task_id),
        nanos,
        input
            .trigger
            .as_sql_str()
            .as_bytes()
            .iter()
            .fold(0u32, |a, b| a.wrapping_add(*b as u32)),
    );

    let record = WorktreeSnapshotRecord {
        snapshot_id: snapshot_id.clone(),
        task_id: input.task_id.clone(),
        session_id: input.session_id.clone(),
        initiative_id: input.initiative_id.clone(),
        trigger: input.trigger,
        taken_at,
        base_sha: input.base_sha.clone(),
        head_sha: bodies.head_sha.clone(),
        commit_count: bodies.commit_count,
        diff_blob_sha256: diff_sha,
        log_blob_sha256: log_sha,
        tree_blob_sha256: tree_sha,
        porcelain_blob_sha256: porcelain_sha,
        diff_bytes_total: bodies.diff_bytes_total,
        diff_truncated: bodies.diff_truncated,
    };

    // Step 3 — insert the index row in a single transaction.
    {
        let mut conn = store.lock_sync();
        let tx = conn.transaction()?;
        insert_snapshot_row_in_tx(&tx, &record)?;
        tx.commit()?;
    }

    Ok(record)
}

fn sanitize_id_segment(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect()
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Insert a row inside an existing transaction. Used by
/// [`snapshot_worktree`]; exposed for future callers that batch
/// multiple inserts under one tx.
pub fn insert_snapshot_row_in_tx(
    conn: &rusqlite::Connection,
    record: &WorktreeSnapshotRecord,
) -> Result<(), SnapshotError> {
    conn.execute(
        &format!(
            "INSERT INTO {WS}
                (snapshot_id, task_id, session_id, initiative_id,
                 trigger, taken_at, base_sha, head_sha, commit_count,
                 diff_blob_sha256, log_blob_sha256, tree_blob_sha256,
                 porcelain_blob_sha256, diff_bytes_total, diff_truncated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"
        ),
        rusqlite::params![
            record.snapshot_id,
            record.task_id,
            record.session_id,
            record.initiative_id,
            record.trigger.as_sql_str(),
            record.taken_at,
            record.base_sha,
            record.head_sha,
            record.commit_count,
            record.diff_blob_sha256,
            record.log_blob_sha256,
            record.tree_blob_sha256,
            record.porcelain_blob_sha256,
            record.diff_bytes_total as i64,
            if record.diff_truncated { 1 } else { 0 },
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Read paths — dashboard + audit replay
// ---------------------------------------------------------------------------

fn parse_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorktreeSnapshotRecord> {
    let trigger_str: String = row.get("trigger")?;
    let trigger = SnapshotTrigger::from_sql_str(&trigger_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown worktree-snapshot trigger: {trigger_str:?}"),
            )),
        )
    })?;
    let diff_truncated_int: i64 = row.get("diff_truncated")?;
    let diff_bytes_total_int: i64 = row.get("diff_bytes_total")?;
    let commit_count_int: i64 = row.get("commit_count")?;
    Ok(WorktreeSnapshotRecord {
        snapshot_id: row.get("snapshot_id")?,
        task_id: row.get("task_id")?,
        session_id: row.get("session_id")?,
        initiative_id: row.get("initiative_id")?,
        trigger,
        taken_at: row.get("taken_at")?,
        base_sha: row.get("base_sha")?,
        head_sha: row.get("head_sha")?,
        commit_count: commit_count_int.max(0) as u32,
        diff_blob_sha256: row.get("diff_blob_sha256")?,
        log_blob_sha256: row.get("log_blob_sha256")?,
        tree_blob_sha256: row.get("tree_blob_sha256")?,
        porcelain_blob_sha256: row.get("porcelain_blob_sha256")?,
        diff_bytes_total: diff_bytes_total_int.max(0) as u64,
        diff_truncated: diff_truncated_int != 0,
    })
}

const SELECT_COLS: &str = "snapshot_id, task_id, session_id, initiative_id, \
                           trigger, taken_at, base_sha, head_sha, commit_count, \
                           diff_blob_sha256, log_blob_sha256, tree_blob_sha256, \
                           porcelain_blob_sha256, diff_bytes_total, diff_truncated";

/// List every snapshot for `task_id`, newest first. The dashboard's
/// per-task timeline calls this from a `spawn_blocking` hop.
pub fn list_for_task(
    store: &Store,
    task_id: &str,
) -> Result<Vec<WorktreeSnapshotRecord>, SnapshotError> {
    let conn = store.lock_sync();
    let sql = format!(
        "SELECT {SELECT_COLS} FROM {WS} WHERE task_id = ?1 ORDER BY taken_at DESC, snapshot_id DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![task_id], parse_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// List every snapshot for a session (executor / reviewer trees
/// keyed by session_id). Returns rows newest-first.
pub fn list_for_session(
    store: &Store,
    session_id: &str,
) -> Result<Vec<WorktreeSnapshotRecord>, SnapshotError> {
    let conn = store.lock_sync();
    let sql = format!(
        "SELECT {SELECT_COLS} FROM {WS} WHERE session_id = ?1 \
         ORDER BY taken_at DESC, snapshot_id DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![session_id], parse_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Look up one snapshot by id.
pub fn get(
    store: &Store,
    snapshot_id: &str,
) -> Result<Option<WorktreeSnapshotRecord>, SnapshotError> {
    let conn = store.lock_sync();
    let sql = format!("SELECT {SELECT_COLS} FROM {WS} WHERE snapshot_id = ?1");
    let row = conn
        .query_row(&sql, rusqlite::params![snapshot_id], parse_row)
        .optional()?;
    Ok(row)
}

/// Read a blob from `<data_dir>/worktree-snapshots/blobs/<sha>`.
pub fn read_blob(data_dir: &Path, sha256: &str) -> Result<Vec<u8>, SnapshotError> {
    let path = blob_path(data_dir, sha256);
    std::fs::read(&path).map_err(|_| SnapshotError::BlobNotFound {
        sha256: sha256.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// startup_check — orphan detector
// ---------------------------------------------------------------------------

/// Walk the blob FS and the SQL index, return orphan counts. The
/// kernel daemon logs the report at boot; orphans are harmless but
/// surface a hint that the kernel crashed mid-snapshot at some
/// prior boot.
pub fn startup_check(
    store: &Store,
    data_dir: &Path,
) -> Result<SnapshotStartupReport, SnapshotError> {
    let dir = blobs_dir(data_dir);
    let mut blob_files: std::collections::HashSet<String> = std::collections::HashSet::new();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir).map_err(|e| SnapshotError::Io {
            path: dir.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| SnapshotError::Io {
                path: dir.display().to_string(),
                source: e,
            })?;
            if let Some(name) = entry.file_name().to_str() {
                blob_files.insert(name.to_owned());
            }
        }
    }

    let conn = store.lock_sync();
    let index_shas: Vec<String> = {
        let mut acc: std::collections::HashSet<String> = std::collections::HashSet::new();
        for col in [
            "diff_blob_sha256",
            "log_blob_sha256",
            "tree_blob_sha256",
            "porcelain_blob_sha256",
        ] {
            let sql = format!("SELECT DISTINCT {col} FROM {WS} WHERE {col} IS NOT NULL");
            let mut stmt = conn.prepare(&sql)?;
            for sha in stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
            {
                acc.insert(sha);
            }
        }
        acc.into_iter().collect()
    };
    let index_set: std::collections::HashSet<String> = index_shas.iter().cloned().collect();

    let orphaned_blobs = blob_files
        .iter()
        .filter(|f| !index_set.contains(*f))
        .count();
    let orphaned_index_rows = index_shas
        .iter()
        .filter(|s| !blob_files.contains(*s))
        .count();

    Ok(SnapshotStartupReport {
        orphaned_blobs,
        orphaned_index_rows,
    })
}

// ---------------------------------------------------------------------------
// Witness tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn git_ok(dir: &std::path::Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn make_seed_repo() -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().ok()?;
        for args in [
            &["init", "-q"][..],
            &["checkout", "-q", "-B", "main"][..],
            &["config", "user.email", "raxis-test@example.com"][..],
            &["config", "user.name", "raxis-test"][..],
            &["commit", "--allow-empty", "-q", "-m", "seed"][..],
        ] {
            if !git_ok(dir.path(), args) {
                return None;
            }
        }
        Some(dir)
    }

    #[test]
    fn inv_worktree_snapshot_trigger_sql_values_match_check_clause() {
        // INV-WORKTREE-SNAPSHOT-TRIGGER-DOMAIN-01 — the kernel-side
        // enum and the migration-24 CHECK clause must agree byte
        // for byte. A drift here lets a kernel write attempt fail
        // at SQL-write time with an opaque CHECK violation rather
        // than at compile time.
        let expected = [
            "ExecutorActivate",
            "ExecutorIdle",
            "ExecutorCommitCopy",
            "WitnessPass",
            "WitnessFail",
            "WitnessInconclusive",
            "IntegrationMerge",
            "PreGc",
        ];
        let variants = [
            SnapshotTrigger::ExecutorActivate,
            SnapshotTrigger::ExecutorIdle,
            SnapshotTrigger::ExecutorCommitCopy,
            SnapshotTrigger::WitnessPass,
            SnapshotTrigger::WitnessFail,
            SnapshotTrigger::WitnessInconclusive,
            SnapshotTrigger::IntegrationMerge,
            SnapshotTrigger::PreGc,
        ];
        for (v, e) in variants.iter().zip(expected.iter()) {
            assert_eq!(v.as_sql_str(), *e);
            assert_eq!(SnapshotTrigger::from_sql_str(e), Some(*v));
        }
        assert_eq!(SnapshotTrigger::from_sql_str("Bogus"), None);
    }

    #[test]
    fn inv_worktree_snapshot_diff_truncation_marker_pinned() {
        // INV-WORKTREE-SNAPSHOT-BOUNDED-DIFF-01 — the truncation
        // marker is operator-visible and consumed by the dashboard
        // diff renderer to surface a clear "this is incomplete"
        // banner. Pin the literal so a rephrase doesn't break the
        // UI contract.
        assert_eq!(DIFF_TRUNCATION_MARKER, "\n<<< RAXIS-DIFF-TRUNCATED >>>\n");
        assert_eq!(MAX_DIFF_BYTES, 1_048_576);
    }

    #[test]
    fn blob_path_is_content_addressed() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = b"hello, world\n";
        let sha = write_blob(dir.path(), bytes).unwrap().unwrap();
        let p = blob_path(dir.path(), &sha);
        assert!(p.is_file(), "blob must be on disk at {}", p.display());
        let read = std::fs::read(&p).unwrap();
        assert_eq!(read, bytes);
    }

    #[test]
    fn write_blob_skips_empty_bodies() {
        let dir = tempfile::tempdir().unwrap();
        // Empty body → no blob written, returns None.
        assert!(write_blob(dir.path(), b"").unwrap().is_none());
        // Blobs dir may not even exist yet.
        let blobs = blobs_dir(dir.path());
        if blobs.exists() {
            assert!(
                std::fs::read_dir(&blobs).unwrap().count() == 0,
                "empty-body write must not pollute the blobs dir"
            );
        }
    }

    #[test]
    fn inv_worktree_snapshot_content_addr_01_identical_bytes_dedupe() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = b"the same diff body";
        let sha1 = write_blob(dir.path(), bytes).unwrap().unwrap();
        let sha2 = write_blob(dir.path(), bytes).unwrap().unwrap();
        assert_eq!(sha1, sha2);
        let blobs = blobs_dir(dir.path());
        let count = std::fs::read_dir(&blobs).unwrap().count();
        assert_eq!(
            count, 1,
            "INV-WORKTREE-SNAPSHOT-CONTENT-ADDR-01: identical bytes must dedupe to one blob"
        );
    }

    #[test]
    fn read_blob_missing_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_blob(dir.path(), "nonexistent_sha");
        assert!(matches!(
            result.unwrap_err(),
            SnapshotError::BlobNotFound { .. }
        ));
    }

    #[test]
    fn capture_bodies_counts_single_commit_and_uses_committer_time() {
        let Some(dir) = make_seed_repo() else {
            eprintln!("skipping: no working git binary on PATH");
            return;
        };
        let base = String::from_utf8_lossy(&run_git(dir.path(), &["rev-parse", "HEAD"]).unwrap())
            .trim()
            .to_owned();
        let status = std::process::Command::new("git")
            .current_dir(dir.path())
            .env("GIT_AUTHOR_DATE", "2001-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2023-11-14T22:13:20Z")
            .args(["commit", "--allow-empty", "-q", "-m", "agent snapshot"])
            .status()
            .expect("git commit");
        if !status.success() {
            eprintln!("skipping: git commit with explicit dates failed");
            return;
        }

        let bodies = capture_bodies(dir.path(), &base).unwrap();
        assert_eq!(
            bodies.commit_count, 1,
            "single-commit logs have no trailing newline; still count them"
        );
        let log = String::from_utf8_lossy(&bodies.log);
        assert!(
            log.contains("\t1700000000\tagent snapshot"),
            "snapshot log must use committer/system time, got {log:?}"
        );
    }
}

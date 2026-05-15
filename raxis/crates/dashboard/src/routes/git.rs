//! Git worktree endpoints.
//!
//! Spec §4.3 — `GET /api/git/worktrees`,
//! `GET /api/git/worktrees/:name`,
//! `GET /api/git/worktrees/:name/log`,
//! `GET /api/git/worktrees/:name/diff`,
//! `GET /api/git/worktrees/:name/diff/:range` (where `:range`
//! is `<sha1>..<sha2>`).
//!
//! Repo browsing (added in the dashboard-backend-robustness
//! pass): `GET /api/git/worktrees/:name/tree?path=…` and
//! `GET /api/git/worktrees/:name/file?path=…`. Both honour the
//! same `policy.allowed_worktree_roots()` containment the diff
//! endpoints already enforce, plus a route-layer
//! `validate_relative_path` that refuses traversal / NUL /
//! `.git` / absolute paths before the data layer ever sees them.
//!
//! Authorization: `read` role suffices for every endpoint —
//! these are read-only views over operator-blessed worktrees,
//! and the kernel-side data layer enforces that only paths
//! under `policy.allowed_worktree_roots()` are ever surfaced.
//!
//! Audit discipline: every endpoint in this file is a pure
//! read-only browse of operator-blessed source material. The
//! `OperatorWorktreeAccessed` / `OperatorDiffViewed` /
//! `OperatorFileContentFetched` emissions were retired in
//! `worker/audit-noise-sweep-r2` per the signal-vs-noise policy
//! in `specs/v2/dashboard-operator-action-audit-coverage.md` —
//! the worktrees are operator-blessed, no kernel state changes
//! on a read, and a per-click chain row only ever proved
//! "someone browsed". The kernel's existing
//! `PathReadAccessed` events still record CLI-side reads, and
//! the per-worktree access-control containment still holds —
//! `policy.allowed_worktree_roots()` rejects anything outside
//! the operator's blessed surface BEFORE the data-layer call.
//!
//! Hard input validation:
//!   * `:name` MUST match `[A-Za-z0-9._-]{1,128}` (route layer
//!     rejects anything else with `FAIL_BAD_REQUEST`).
//!   * `:range` MUST parse as `<sha1>..<sha2>` where both SHAs
//!     are 40-char lowercase hex.
//!   * `?path=` (tree + file) MUST pass `validate_relative_path`
//!     (no `..`, no leading `/`, no NUL, no `.git`).
//!
//! These checks shut the door on path traversal and arbitrary
//! command injection through the URL.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::{
    WorktreeDetail, WorktreeDiff, WorktreeFile, WorktreeListEntry, WorktreeLogEntry, WorktreeTree,
};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// Maximum length of the `:name` path segment.
const MAX_NAME_LEN: usize = 128;

/// `GET /api/git/worktrees`.
///
/// The data-layer call walks the operator's
/// `allowed_worktree_roots()` policy bundle plus a read-only
/// SQL view; the operation is bounded but still touches disk,
/// so `INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01` requires we
/// run it under `tokio::task::spawn_blocking` rather than on
/// the async worker.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<Vec<WorktreeListEntry>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let data = std::sync::Arc::clone(&state.data);
    let rows = tokio::task::spawn_blocking(move || data.list_worktrees())
        .await
        .map_err(|e| ApiError::Internal {
            log_only: format!("list_worktrees join error: {e}"),
        })??;
    Ok(Json(rows))
}

/// `GET /api/git/worktrees/:name`.
///
/// Wrapped in `spawn_blocking` per
/// `INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01`
/// (`specs/v2/dashboard-hardening.md §1.9`): even with the
/// parallel-probe optimisation inside `get_worktree`, the four
/// `git` subprocesses each block on `Child::try_wait` and would
/// otherwise pin a tokio runtime worker for tens of ms,
/// starving every other dashboard request.
pub async fn detail<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(name): Path<String>,
) -> ApiResult<Json<WorktreeDetail>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    validate_name(&name)?;
    let data = std::sync::Arc::clone(&state.data);
    let detail = tokio::task::spawn_blocking(move || data.get_worktree(&name))
        .await
        .map_err(|e| ApiError::Internal {
            log_only: format!("get_worktree join error: {e}"),
        })??;
    Ok(Json(detail))
}

/// Query string for `GET /api/git/worktrees/:name/log`.
#[derive(Debug, Deserialize)]
pub struct LogQuery {
    /// Page size; clamped to `[1, 200]`. Default 50.
    #[serde(default = "default_log_limit")]
    pub limit: u32,
}

fn default_log_limit() -> u32 {
    50
}

/// `GET /api/git/worktrees/:name/log`.
pub async fn log<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(name): Path<String>,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<Vec<WorktreeLogEntry>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    validate_name(&name)?;
    let limit = q.limit.clamp(1, 200);
    let data = std::sync::Arc::clone(&state.data);
    let log = tokio::task::spawn_blocking(move || data.worktree_log(&name, limit))
        .await
        .map_err(|e| ApiError::Internal {
            log_only: format!("worktree_log join error: {e}"),
        })??;
    Ok(Json(log))
}

/// `GET /api/git/worktrees/:name/diff` — diff between the
/// worktree's recorded base SHA and current HEAD.
pub async fn diff_default<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(name): Path<String>,
) -> ApiResult<Json<WorktreeDiff>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    validate_name(&name)?;
    let data = std::sync::Arc::clone(&state.data);
    let diff = tokio::task::spawn_blocking(move || data.worktree_diff_default(&name))
        .await
        .map_err(|e| ApiError::Internal {
            log_only: format!("worktree_diff_default join error: {e}"),
        })??;
    Ok(Json(diff))
}

/// `GET /api/git/worktrees/:name/diff/:range` — diff between
/// two arbitrary commit SHAs in the worktree.
pub async fn diff_range<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path((name, range)): Path<(String, String)>,
) -> ApiResult<Json<WorktreeDiff>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    validate_name(&name)?;
    let (from, to) = parse_range(&range)?;
    let data = std::sync::Arc::clone(&state.data);
    let diff = tokio::task::spawn_blocking(move || data.worktree_diff_range(&name, &from, &to))
        .await
        .map_err(|e| ApiError::Internal {
            log_only: format!("worktree_diff_range join error: {e}"),
        })??;
    Ok(Json(diff))
}

/// Query string for the new tree + file endpoints.
///
/// Keeping the path in a query parameter (rather than a URL
/// path segment) lets us defer URL-decoding to axum's
/// `Query` extractor and avoids a wildcard-route footgun
/// (axum's `:rest` would happily eat `..` segments without
/// our `validate_relative_path` ever seeing them).
#[derive(Debug, Deserialize, Default)]
pub struct PathQuery {
    /// Optional sub-path relative to the worktree root,
    /// forward-slash separated, no leading slash.
    /// `None` ⇒ worktree root for the tree endpoint.
    /// REQUIRED for the file endpoint (handler returns
    /// `BadRequest` when missing).
    #[serde(default)]
    pub path: Option<String>,
}

/// `GET /api/git/worktrees/:name/tree?path=…` — list one
/// directory under the worktree.
pub async fn tree<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(name): Path<String>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<WorktreeTree>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    validate_name(&name)?;
    let sub_path = match q.path.as_deref() {
        Some(p) if !p.is_empty() => Some(validate_relative_path(p)?.to_owned()),
        _ => None,
    };
    let data = std::sync::Arc::clone(&state.data);
    let tree = tokio::task::spawn_blocking(move || data.worktree_tree(&name, sub_path.as_deref()))
        .await
        .map_err(|e| ApiError::Internal {
            log_only: format!("worktree_tree join error: {e}"),
        })??;
    Ok(Json(tree))
}

/// `GET /api/git/worktrees/:name/file?path=…` — read one
/// regular file under the worktree.
pub async fn file<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(name): Path<String>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<WorktreeFile>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    validate_name(&name)?;
    let raw = q.path.as_deref().unwrap_or("");
    if raw.is_empty() {
        return Err(ApiError::BadRequest {
            detail: "path query parameter is required".into(),
        });
    }
    let file_path = validate_relative_path(raw)?.to_owned();
    let data = std::sync::Arc::clone(&state.data);
    let file = tokio::task::spawn_blocking(move || data.worktree_file(&name, &file_path))
        .await
        .map_err(|e| ApiError::Internal {
            log_only: format!("worktree_file join error: {e}"),
        })??;
    Ok(Json(file))
}

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

/// Reject anything outside `[A-Za-z0-9._-]{1,128}`.
fn validate_name(name: &str) -> ApiResult<&str> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(ApiError::BadRequest {
            detail: "worktree name length out of range".into(),
        });
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(ApiError::BadRequest {
            detail: "worktree name contains forbidden characters".into(),
        });
    }
    Ok(name)
}

/// Maximum total length of a worktree-relative path (sum of
/// every component + separators). Generous enough for any
/// real source tree but tight enough that path-walking can
/// not be amplified by a megabyte-long URL.
const MAX_REL_PATH_LEN: usize = 4096;

/// Validate a forward-slash separated, root-relative path
/// before handing it to a sandbox-aware data-layer call.
///
/// What this rejects (route-layer; the data layer applies a
/// second canonicalization-based check as defence-in-depth):
///   * empty string
///   * leading `/` (absolute path)
///   * a `..` component anywhere (parent traversal)
///   * a `.` component (no-op but keeps the surface tight)
///   * an empty component (double slashes)
///   * any backslash (Windows-style separator; we only run
///     on Unix and a backslash inside a unix component is a
///     legal-but-suspicious character we'd rather refuse)
///   * any NUL byte
///   * any `.git` component (repo internals are never surfaced)
///   * total length above [`MAX_REL_PATH_LEN`]
fn validate_relative_path(p: &str) -> ApiResult<&str> {
    if p.is_empty() {
        return Err(ApiError::BadRequest {
            detail: "path must not be empty".into(),
        });
    }
    if p.len() > MAX_REL_PATH_LEN {
        return Err(ApiError::BadRequest {
            detail: "path too long".into(),
        });
    }
    if p.starts_with('/') {
        return Err(ApiError::BadRequest {
            detail: "absolute paths are not allowed".into(),
        });
    }
    if p.bytes().any(|b| b == 0 || b == b'\\') {
        return Err(ApiError::BadRequest {
            detail: "path contains forbidden characters".into(),
        });
    }
    for component in p.split('/') {
        if component.is_empty() {
            return Err(ApiError::BadRequest {
                detail: "path contains empty component".into(),
            });
        }
        if component == "." || component == ".." {
            return Err(ApiError::BadRequest {
                detail: "path contains traversal segment".into(),
            });
        }
        if component == ".git" {
            return Err(ApiError::BadRequest {
                detail: ".git is not browsable".into(),
            });
        }
    }
    Ok(p)
}

/// Parse `<sha1>..<sha2>` where both SHAs are 40-char
/// lowercase hex. Rejects anything else.
fn parse_range(range: &str) -> ApiResult<(String, String)> {
    let mut parts = range.split("..");
    let from = parts.next().unwrap_or("");
    let to = parts.next().unwrap_or("");
    if parts.next().is_some() || from.len() != 40 || to.len() != 40 {
        return Err(ApiError::BadRequest {
            detail: "diff range must be <sha1>..<sha2> with 40-hex shas".into(),
        });
    }
    if !is_hex(from) || !is_hex(to) {
        return Err(ApiError::BadRequest {
            detail: "diff range shas must be lowercase hex".into(),
        });
    }
    Ok((from.to_owned(), to.to_owned()))
}

fn is_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn require_read(op: &AuthorizedOperator) -> ApiResult<()> {
    if !op.has_role(DashboardRole::Read)
        && !op.has_role(DashboardRole::WritePolicy)
        && !op.has_role(DashboardRole::Admin)
    {
        return Err(ApiError::Forbidden {
            required: "read".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validator_accepts_typical_slugs() {
        assert!(validate_name("main-0").is_ok());
        assert!(validate_name("session-abc12345").is_ok());
        assert!(validate_name("a.b.c").is_ok());
        assert!(validate_name("snake_case_2").is_ok());
    }

    #[test]
    fn name_validator_rejects_traversal_and_specials() {
        assert!(validate_name("").is_err());
        assert!(validate_name("../etc/passwd").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name("a b").is_err());
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn range_parser_round_trips_valid_input() {
        let from = "a".repeat(40);
        let to = "b".repeat(40);
        let raw = format!("{from}..{to}");
        let (got_from, got_to) = parse_range(&raw).unwrap();
        assert_eq!(got_from, from);
        assert_eq!(got_to, to);
    }

    #[test]
    fn range_parser_rejects_short_sha_or_extra_separator() {
        assert!(parse_range("short..short").is_err());
        let valid = "a".repeat(40);
        assert!(parse_range(&format!("{valid}..{valid}..{valid}")).is_err());
        assert!(parse_range(&format!("{valid}-{valid}")).is_err());
    }

    #[test]
    fn range_parser_rejects_uppercase_or_non_hex() {
        let upper = "A".repeat(40);
        let lower = "a".repeat(40);
        assert!(parse_range(&format!("{upper}..{lower}")).is_err());
        let bogus = "z".repeat(40);
        assert!(parse_range(&format!("{lower}..{bogus}")).is_err());
    }

    #[test]
    fn relative_path_accepts_typical_paths() {
        assert!(validate_relative_path("README.md").is_ok());
        assert!(validate_relative_path("src/lib.rs").is_ok());
        assert!(validate_relative_path("a/b/c/d.txt").is_ok());
    }

    #[test]
    fn relative_path_rejects_traversal_and_specials() {
        assert!(validate_relative_path("").is_err());
        assert!(validate_relative_path("/etc/passwd").is_err());
        assert!(validate_relative_path("../etc/passwd").is_err());
        assert!(validate_relative_path("a/../b").is_err());
        assert!(validate_relative_path("a/./b").is_err());
        assert!(validate_relative_path("a//b").is_err());
        assert!(validate_relative_path("a\\b").is_err());
        assert!(validate_relative_path("a\0b").is_err());
        assert!(validate_relative_path(".git/config").is_err());
        assert!(validate_relative_path("foo/.git/HEAD").is_err());
        assert!(validate_relative_path(&"a/".repeat(MAX_REL_PATH_LEN)).is_err());
    }
}

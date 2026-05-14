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
//! Hard input validation:
//!   * `:name` MUST match `[A-Za-z0-9._-]{1,128}` (route layer
//!     rejects anything else with `FAIL_BAD_REQUEST`).
//!   * `:range` MUST parse as `<sha1>..<sha2>` where both SHAs
//!     are 40-char lowercase hex.
//!   * `?path=` (tree + file) MUST pass `validate_relative_path`
//!     (no `..`, no leading `/`, no NUL, no `.git`).
//! These checks shut the door on path traversal and arbitrary
//! command injection through the URL.

use axum::extract::{Path, Query, State};
use axum::Json;
use raxis_audit_tools::AuditEventKind;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::{
    operator_outcome, WorktreeDetail, WorktreeDiff, WorktreeFile,
    WorktreeListEntry, WorktreeLogEntry, WorktreeTree,
};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// Maximum length of the `:name` path segment.
const MAX_NAME_LEN: usize = 128;

/// `GET /api/git/worktrees`.
///
/// Audit discipline: this listing endpoint is a pure read-only
/// browse. The `OperatorViewedWorktreeList` emission was
/// retired in `worker/audit-tightening` per the signal-vs-noise
/// policy in `specs/v2/dashboard-operator-action-audit-coverage.md`.
/// The per-worktree detail / log / tree / file paths below
/// continue to audit via `OperatorWorktreeAccessed` /
/// `OperatorDiffViewed` / `OperatorFileContentFetched` because
/// they surface operator-blessed source material whose access
/// the security review specifically needs to reconstruct.
pub async fn list<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<Vec<WorktreeListEntry>>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let rows = state.data.list_worktrees()?;
    Ok(Json(rows))
}

/// `GET /api/git/worktrees/:name`.
pub async fn detail<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Path(name): Path<String>,
) -> ApiResult<Json<WorktreeDetail>>
where
    D: crate::data::DashboardData,
{
    audited_worktree_access(&*state.data, &op, &name, "detail", |validated| {
        state.data.get_worktree(validated).map(Json)
    })
}

/// Query string for `GET /api/git/worktrees/:name/log`.
#[derive(Debug, Deserialize)]
pub struct LogQuery {
    /// Page size; clamped to `[1, 200]`. Default 50.
    #[serde(default = "default_log_limit")]
    pub limit: u32,
}

fn default_log_limit() -> u32 { 50 }

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
    let limit = q.limit.clamp(1, 200);
    audited_worktree_access(&*state.data, &op, &name, "log", |validated| {
        state.data.worktree_log(validated, limit).map(Json)
    })
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
    audited_diff(&*state.data, &op, &name, None, None, |validated| {
        state.data.worktree_diff_default(validated).map(Json)
    })
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
    // Permission first so we don't audit `from`/`to` we never
    // parsed. `from`/`to` are added once validation succeeds.
    if let Err(e) = require_read(&op) {
        emit_diff_audit(
            &*state.data,
            &op,
            &name,
            None,
            None,
            operator_outcome::outcome_from_api_error(&e),
        );
        return Err(e);
    }
    let validated_name = match validate_name(&name) {
        Ok(n) => n.to_owned(),
        Err(e) => {
            emit_diff_audit(
                &*state.data,
                &op,
                &name,
                None,
                None,
                operator_outcome::outcome_from_api_error(&e),
            );
            return Err(e);
        }
    };
    let (from, to) = match parse_range(&range) {
        Ok(p) => p,
        Err(e) => {
            emit_diff_audit(
                &*state.data,
                &op,
                &validated_name,
                None,
                None,
                operator_outcome::outcome_from_api_error(&e),
            );
            return Err(e);
        }
    };
    match state.data.worktree_diff_range(&validated_name, &from, &to) {
        Ok(d) => {
            state
                .data
                .emit_operator_audit(AuditEventKind::OperatorDiffViewed {
                    operator_fingerprint: op.fingerprint.clone(),
                    worktree_id:          validated_name,
                    base_ref:             Some(from),
                    head_ref:             Some(to),
                    outcome:              operator_outcome::ACCEPTED.into(),
                })?;
            Ok(Json(d))
        }
        Err(err) => {
            emit_diff_audit(
                &*state.data,
                &op,
                &validated_name,
                Some(&from),
                Some(&to),
                operator_outcome::outcome_from_api_error(&err),
            );
            Err(err)
        }
    }
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
    if let Err(e) = require_read(&op) {
        emit_worktree_access_audit(
            &*state.data,
            &op,
            &name,
            "tree",
            operator_outcome::outcome_from_api_error(&e),
        );
        return Err(e);
    }
    let validated = match validate_name(&name) {
        Ok(n) => n.to_owned(),
        Err(e) => {
            emit_worktree_access_audit(
                &*state.data,
                &op,
                &name,
                "tree",
                operator_outcome::outcome_from_api_error(&e),
            );
            return Err(e);
        }
    };
    let sub_path = match q.path.as_deref() {
        Some(p) if !p.is_empty() => match validate_relative_path(p) {
            Ok(p) => Some(p),
            Err(e) => {
                emit_worktree_access_audit(
                    &*state.data,
                    &op,
                    &validated,
                    "tree",
                    operator_outcome::outcome_from_api_error(&e),
                );
                return Err(e);
            }
        },
        _ => None,
    };
    match state.data.worktree_tree(&validated, sub_path) {
        Ok(t) => {
            state
                .data
                .emit_operator_audit(AuditEventKind::OperatorWorktreeAccessed {
                    operator_fingerprint: op.fingerprint.clone(),
                    worktree_id:          validated,
                    surface:              "tree".into(),
                    outcome:              operator_outcome::ACCEPTED.into(),
                })?;
            Ok(Json(t))
        }
        Err(e) => {
            emit_worktree_access_audit(
                &*state.data,
                &op,
                &validated,
                "tree",
                operator_outcome::outcome_from_api_error(&e),
            );
            Err(e)
        }
    }
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
    let raw_path = q.path.clone().unwrap_or_default();
    if let Err(e) = require_read(&op) {
        emit_file_audit(
            &*state.data,
            &op,
            &name,
            &raw_path,
            operator_outcome::outcome_from_api_error(&e),
        );
        return Err(e);
    }
    let validated_name = match validate_name(&name) {
        Ok(n) => n.to_owned(),
        Err(e) => {
            emit_file_audit(
                &*state.data,
                &op,
                &name,
                &raw_path,
                operator_outcome::outcome_from_api_error(&e),
            );
            return Err(e);
        }
    };
    let raw = q.path.as_deref().unwrap_or("");
    if raw.is_empty() {
        let err = ApiError::BadRequest {
            detail: "path query parameter is required".into(),
        };
        emit_file_audit(
            &*state.data,
            &op,
            &validated_name,
            "",
            operator_outcome::outcome_from_api_error(&err),
        );
        return Err(err);
    }
    let file_path = match validate_relative_path(raw) {
        Ok(p) => p.to_owned(),
        Err(e) => {
            emit_file_audit(
                &*state.data,
                &op,
                &validated_name,
                raw,
                operator_outcome::outcome_from_api_error(&e),
            );
            return Err(e);
        }
    };
    match state.data.worktree_file(&validated_name, &file_path) {
        Ok(f) => {
            state
                .data
                .emit_operator_audit(AuditEventKind::OperatorFileContentFetched {
                    operator_fingerprint: op.fingerprint.clone(),
                    worktree_id:          validated_name,
                    path:                 file_path,
                    outcome:              operator_outcome::ACCEPTED.into(),
                })?;
            Ok(Json(f))
        }
        Err(e) => {
            emit_file_audit(
                &*state.data,
                &op,
                &validated_name,
                &file_path,
                operator_outcome::outcome_from_api_error(&e),
            );
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Operator-audit helpers (INV-AUDIT-OPERATOR-ACTION-01)
// ---------------------------------------------------------------------------

/// Wraps a privileged worktree-access handler that does the
/// usual `require_read → validate_name → data-layer call`
/// pattern: emits `OperatorWorktreeAccessed` on the success
/// path (`outcome = "Accepted"`) and on each failure branch
/// with the rejection class set from the underlying `ApiError`.
///
/// The inner closure runs only when both `require_read` and
/// `validate_name` succeed, and it receives the canonicalised
/// `&str` slug. Audit emission failures bubble up as
/// `InternalError` (the success path) so the operator surface
/// never silently drops an audit row.
fn audited_worktree_access<D, R, F>(
    data: &D,
    op: &AuthorizedOperator,
    raw_name: &str,
    surface: &'static str,
    f: F,
) -> ApiResult<R>
where
    D: crate::data::DashboardData + ?Sized,
    F: FnOnce(&str) -> ApiResult<R>,
{
    if let Err(e) = require_read(op) {
        emit_worktree_access_audit(
            data,
            op,
            raw_name,
            surface,
            operator_outcome::outcome_from_api_error(&e),
        );
        return Err(e);
    }
    let validated = match validate_name(raw_name) {
        Ok(n) => n,
        Err(e) => {
            emit_worktree_access_audit(
                data,
                op,
                raw_name,
                surface,
                operator_outcome::outcome_from_api_error(&e),
            );
            return Err(e);
        }
    };
    match f(validated) {
        Ok(out) => {
            data.emit_operator_audit(AuditEventKind::OperatorWorktreeAccessed {
                operator_fingerprint: op.fingerprint.clone(),
                worktree_id:          validated.to_owned(),
                surface:              surface.to_owned(),
                outcome:              operator_outcome::ACCEPTED.into(),
            })?;
            Ok(out)
        }
        Err(e) => {
            emit_worktree_access_audit(
                data,
                op,
                validated,
                surface,
                operator_outcome::outcome_from_api_error(&e),
            );
            Err(e)
        }
    }
}

fn audited_diff<D, R, F>(
    data: &D,
    op: &AuthorizedOperator,
    raw_name: &str,
    base_ref: Option<String>,
    head_ref: Option<String>,
    f: F,
) -> ApiResult<R>
where
    D: crate::data::DashboardData + ?Sized,
    F: FnOnce(&str) -> ApiResult<R>,
{
    if let Err(e) = require_read(op) {
        emit_diff_audit(
            data,
            op,
            raw_name,
            base_ref.as_deref(),
            head_ref.as_deref(),
            operator_outcome::outcome_from_api_error(&e),
        );
        return Err(e);
    }
    let validated = match validate_name(raw_name) {
        Ok(n) => n,
        Err(e) => {
            emit_diff_audit(
                data,
                op,
                raw_name,
                base_ref.as_deref(),
                head_ref.as_deref(),
                operator_outcome::outcome_from_api_error(&e),
            );
            return Err(e);
        }
    };
    match f(validated) {
        Ok(out) => {
            data.emit_operator_audit(AuditEventKind::OperatorDiffViewed {
                operator_fingerprint: op.fingerprint.clone(),
                worktree_id:          validated.to_owned(),
                base_ref:             base_ref.clone(),
                head_ref:             head_ref.clone(),
                outcome:              operator_outcome::ACCEPTED.into(),
            })?;
            Ok(out)
        }
        Err(e) => {
            emit_diff_audit(
                data,
                op,
                validated,
                base_ref.as_deref(),
                head_ref.as_deref(),
                operator_outcome::outcome_from_api_error(&e),
            );
            Err(e)
        }
    }
}

fn emit_worktree_access_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    worktree_id: &str,
    surface: &str,
    outcome: &'static str,
) where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorWorktreeAccessed {
        operator_fingerprint: op.fingerprint.clone(),
        worktree_id:          worktree_id.to_owned(),
        surface:              surface.to_owned(),
        outcome:              outcome.into(),
    });
}

fn emit_diff_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    worktree_id: &str,
    base_ref: Option<&str>,
    head_ref: Option<&str>,
    outcome: &'static str,
) where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorDiffViewed {
        operator_fingerprint: op.fingerprint.clone(),
        worktree_id:          worktree_id.to_owned(),
        base_ref:             base_ref.map(|s| s.to_owned()),
        head_ref:             head_ref.map(|s| s.to_owned()),
        outcome:              outcome.into(),
    });
}

fn emit_file_audit<D>(
    data: &D,
    op: &AuthorizedOperator,
    worktree_id: &str,
    path: &str,
    outcome: &'static str,
) where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorFileContentFetched {
        operator_fingerprint: op.fingerprint.clone(),
        worktree_id:          worktree_id.to_owned(),
        path:                 path.to_owned(),
        outcome:              outcome.into(),
    });
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
    s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn require_read(op: &AuthorizedOperator) -> ApiResult<()> {
    if !op.has_role(DashboardRole::Read)
        && !op.has_role(DashboardRole::WritePolicy)
        && !op.has_role(DashboardRole::Admin)
    {
        return Err(ApiError::Forbidden { required: "read".into() });
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

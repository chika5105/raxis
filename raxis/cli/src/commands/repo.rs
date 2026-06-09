// raxis-cli::commands::repo — managed repository lifecycle ergonomics.
//
// A managed repository is not "any directory Git can open"; it is an
// explicitly adopted source mirror recorded in kernel.db. These commands own
// adoption, fetch/sync/publish state, and exact-root repair so the dashboard
// and kernel review surfaces can trust repository rows.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use raxis_store::managed_repositories as repo_store;
use serde::Serialize;

use crate::errors::CliError;
use crate::GlobalFlags;

const DEFAULT_REPOSITORY_ID: &str = "main";
const MAX_REPOSITORY_ID_LEN: usize = 64;
const DEFAULT_TARGET_REF: &str = "refs/heads/main";

pub fn run_adopt(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut force = false;
    let mut json = false;
    let mut positional = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--force" => force = true,
            "--json" => json = true,
            "-h" | "--help" => {
                print_adopt_help();
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(CliError::Usage(format!(
                    "repo adopt: unknown flag {other:?}"
                )));
            }
            _ => positional.push(arg.clone()),
        }
    }
    if positional.len() != 2 {
        return Err(CliError::Usage(
            "repo adopt requires <repository_id> <path-or-git-url>".to_owned(),
        ));
    }

    let repository_id = normalize_repository_id(Some(&positional[0]))?;
    let source = positional[1].clone();
    let dest = managed_repository_path(flags.data_dir(), &repository_id);

    if dest.exists() {
        if !force {
            return Err(CliError::Usage(format!(
                "managed repository `{repository_id}` already exists at {}; \
                 pass --force to replace it",
                dest.display(),
            )));
        }
        std::fs::remove_dir_all(&dest).map_err(|e| CliError::Io {
            path: dest.display().to_string(),
            source: e,
        })?;
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CliError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }

    let status = Command::new("git")
        .arg("clone")
        .arg("--")
        .arg(&source)
        .arg(&dest)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| CliError::Io {
            path: "git".to_owned(),
            source: e,
        })?;
    if !status.success() {
        return Err(CliError::Usage(format!(
            "git clone failed for source {source:?} into {} (exit {status})",
            dest.display(),
        )));
    }

    let status = repo_status(&repository_id, &dest, Some(source.as_str()), None, false);
    record_status(flags, &status, true)?;
    render_statuses(&[status], json)
}

pub fn run_status(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_status_help();
        return Ok(());
    }
    let opts = parse_status_args(args)?;
    let mut statuses = load_statuses(flags, opts.repository_id.as_deref(), opts.remote)?;
    if opts.remote {
        for status in &mut statuses {
            fetch_one(status);
            *status = repo_status(
                &status.id,
                &status.path,
                status.source_url.as_deref(),
                status.publish_state.as_deref(),
                true,
            );
            record_status(flags, status, false)?;
        }
    }
    render_statuses(&statuses, opts.json)
}

pub fn run_fetch(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: raxis repo fetch [repository_id] [--json]");
        return Ok(());
    }
    let opts = parse_one_repo_args("repo fetch", args)?;
    let mut status = load_required_status(flags, &opts.repository_id)?;
    fetch_one(&mut status);
    status = repo_status(
        &status.id,
        &status.path,
        status.source_url.as_deref(),
        status.publish_state.as_deref(),
        true,
    );
    record_status(flags, &status, false)?;
    render_statuses(&[status], opts.json)
}

pub fn run_sync(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: raxis repo sync [repository_id] [--json]");
        return Ok(());
    }
    let opts = parse_one_repo_args("repo sync", args)?;
    let mut status = load_required_status(flags, &opts.repository_id)?;
    fetch_one(&mut status);
    status = repo_status(
        &status.id,
        &status.path,
        status.source_url.as_deref(),
        status.publish_state.as_deref(),
        true,
    );

    match status.lifecycle_state.as_str() {
        repo_store::STATE_BEHIND => {
            let tracking = status.tracking_ref.clone().ok_or_else(|| {
                CliError::Usage(format!(
                    "repo sync {}: behind state has no tracking_ref",
                    status.id
                ))
            })?;
            git_status(&status.path, &["merge", "--ff-only", &tracking]).map_err(|reason| {
                CliError::Usage(format!(
                    "repo sync {} failed to fast-forward from {tracking}: {reason}",
                    status.id
                ))
            })?;
            status = repo_status(
                &status.id,
                &status.path,
                status.source_url.as_deref(),
                Some(repo_store::PUBLISH_PUBLISHED),
                false,
            );
        }
        repo_store::STATE_CLEAN | repo_store::STATE_LOCAL_ONLY => {}
        repo_store::STATE_AHEAD => {
            return Err(CliError::Usage(format!(
                "repo sync {} refused: managed repo is ahead of remote; use `raxis repo publish {}`",
                status.id, status.id
            )));
        }
        repo_store::STATE_DIRTY
        | repo_store::STATE_DIVERGED
        | repo_store::STATE_REMOTE_UNREACHABLE => {
            return Err(CliError::Usage(format!(
                "repo sync {} refused: lifecycle_state={} ({})",
                status.id,
                status.lifecycle_state,
                status.error.as_deref().unwrap_or("resolve before syncing")
            )));
        }
        _ => {}
    }

    record_status(flags, &status, false)?;
    render_statuses(&[status], opts.json)
}

pub fn run_publish(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_publish_help();
        return Ok(());
    }
    let opts = parse_publish_args(args)?;
    let mut status = load_required_status(flags, &opts.repository_id)?;
    let remote = opts
        .remote
        .or_else(|| status.default_remote.clone())
        .unwrap_or_else(|| "origin".to_owned());
    let target_ref = opts
        .target_ref
        .or_else(|| Some(status.default_target_ref.clone()))
        .unwrap_or_else(|| DEFAULT_TARGET_REF.to_owned());
    let refspec = format!("HEAD:{target_ref}");

    {
        let store = open_store(flags)?;
        let conn = store.lock_sync();
        let _ = repo_store::record_publish_pending(&conn, &status.id, status.head_sha.as_deref())
            .map_err(sql_usage)?;
    }

    match git_status(&status.path, &["push", &remote, &refspec]) {
        Ok(()) => {
            status = repo_status(
                &status.id,
                &status.path,
                status.source_url.as_deref(),
                Some(repo_store::PUBLISH_PUBLISHED),
                false,
            );
            let store = open_store(flags)?;
            let conn = store.lock_sync();
            repo_store::record_publish_success(&conn, &status.id, status.head_sha.as_deref())
                .map_err(sql_usage)?;
            render_statuses(&[status], opts.json)
        }
        Err(reason) => {
            let store = open_store(flags)?;
            let conn = store.lock_sync();
            repo_store::record_publish_failure(
                &conn,
                &status.id,
                status.head_sha.as_deref(),
                &reason,
            )
            .map_err(sql_usage)?;
            Err(CliError::Usage(format!(
                "repo publish {} failed: {reason}",
                status.id
            )))
        }
    }
}

pub fn run_repair(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: raxis repo repair [--json]");
        return Ok(());
    }
    let opts = parse_repair_args(args)?;
    let repositories_root = flags.data_dir().join("repositories");
    let mut statuses = Vec::new();
    if repositories_root.exists() {
        for entry in std::fs::read_dir(&repositories_root).map_err(|e| CliError::Io {
            path: repositories_root.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| CliError::Io {
                path: repositories_root.display().to_string(),
                source: e,
            })?;
            if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            if validate_repository_id(&id).is_err() {
                continue;
            }
            let status = repo_status(&id, &entry.path(), None, None, false);
            if status.is_exact_git_root {
                record_status(flags, &status, true)?;
            }
            statuses.push(status);
        }
    }
    statuses.sort_by(|a, b| a.id.cmp(&b.id));
    render_statuses(&statuses, opts.json)
}

#[derive(Debug, Serialize, Clone)]
struct RepoStatus {
    id: String,
    path: PathBuf,
    source_url: Option<String>,
    default_remote: Option<String>,
    default_target_ref: String,
    tracking_ref: Option<String>,
    exists: bool,
    is_exact_git_root: bool,
    lifecycle_state: String,
    publish_state: Option<String>,
    branch: Option<String>,
    head_sha: Option<String>,
    remote_sha: Option<String>,
    ahead_count: Option<i64>,
    behind_count: Option<i64>,
    dirty: bool,
    fetched: bool,
    error: Option<String>,
}

fn repo_status(
    id: &str,
    path: &Path,
    source_url: Option<&str>,
    publish_state: Option<&str>,
    fetched: bool,
) -> RepoStatus {
    if !path.exists() {
        return status_error(
            id,
            path,
            source_url,
            publish_state,
            fetched,
            repo_store::STATE_MISSING,
            "managed repository path does not exist",
        );
    }
    if !is_exact_repo_root(path) {
        return status_error(
            id,
            path,
            source_url,
            publish_state,
            fetched,
            repo_store::STATE_NOT_A_GIT_ROOT,
            "path is not an exact git root; refusing parent-walk resolution",
        );
    }

    let branch = git_stdout(path, &["branch", "--show-current"]).filter(|s| !s.is_empty());
    let head_sha = git_stdout(path, &["rev-parse", "HEAD"]);
    let dirty = git_stdout(path, &["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let tracking_ref = upstream_ref(path);
    let (remote_sha, ahead_count, behind_count, remote_error) = match tracking_ref.as_deref() {
        Some(tracking) => {
            let remote_sha = git_stdout(path, &["rev-parse", tracking]);
            let counts = git_stdout(
                path,
                &[
                    "rev-list",
                    "--left-right",
                    "--count",
                    &format!("HEAD...{tracking}"),
                ],
            )
            .and_then(|s| parse_ahead_behind(&s));
            match (remote_sha, counts) {
                (Some(remote_sha), Some((ahead, behind))) => {
                    (Some(remote_sha), Some(ahead), Some(behind), None)
                }
                _ => (
                    None,
                    None,
                    None,
                    Some("tracking ref is unavailable".to_owned()),
                ),
            }
        }
        None => (None, None, None, None),
    };

    let lifecycle_state = if remote_error.is_some() && fetched {
        repo_store::STATE_REMOTE_UNREACHABLE
    } else if dirty {
        repo_store::STATE_DIRTY
    } else if tracking_ref.is_none() {
        repo_store::STATE_LOCAL_ONLY
    } else {
        match (ahead_count.unwrap_or(0), behind_count.unwrap_or(0)) {
            (0, 0) => repo_store::STATE_CLEAN,
            (a, 0) if a > 0 => repo_store::STATE_AHEAD,
            (0, b) if b > 0 => repo_store::STATE_BEHIND,
            (a, b) if a > 0 && b > 0 => repo_store::STATE_DIVERGED,
            _ => repo_store::STATE_UNKNOWN,
        }
    };
    let publish_state = publish_state
        .map(str::to_owned)
        .or_else(|| match lifecycle_state {
            repo_store::STATE_LOCAL_ONLY => Some(repo_store::PUBLISH_LOCAL_ONLY.to_owned()),
            repo_store::STATE_CLEAN if tracking_ref.is_some() => {
                Some(repo_store::PUBLISH_PUBLISHED.to_owned())
            }
            repo_store::STATE_AHEAD | repo_store::STATE_DIRTY | repo_store::STATE_DIVERGED => {
                Some(repo_store::PUBLISH_PENDING.to_owned())
            }
            _ => Some(repo_store::PUBLISH_UNKNOWN.to_owned()),
        });
    let default_remote = tracking_ref
        .as_deref()
        .and_then(|t| t.strip_prefix("refs/remotes/"))
        .and_then(|rest| rest.split('/').next())
        .map(str::to_owned)
        .or_else(|| {
            git_stdout(path, &["remote"]).and_then(|s| s.lines().next().map(str::to_owned))
        });
    let default_target_ref = branch
        .as_deref()
        .map(|b| format!("refs/heads/{b}"))
        .unwrap_or_else(|| DEFAULT_TARGET_REF.to_owned());

    RepoStatus {
        id: id.to_owned(),
        path: path.to_path_buf(),
        source_url: source_url
            .map(str::to_owned)
            .or_else(|| first_remote_url(path)),
        default_remote,
        default_target_ref,
        tracking_ref,
        exists: true,
        is_exact_git_root: true,
        lifecycle_state: lifecycle_state.to_owned(),
        publish_state,
        branch,
        head_sha,
        remote_sha,
        ahead_count,
        behind_count,
        dirty,
        fetched,
        error: remote_error,
    }
}

fn status_error(
    id: &str,
    path: &Path,
    source_url: Option<&str>,
    publish_state: Option<&str>,
    fetched: bool,
    lifecycle_state: &str,
    error: &str,
) -> RepoStatus {
    RepoStatus {
        id: id.to_owned(),
        path: path.to_path_buf(),
        source_url: source_url.map(str::to_owned),
        default_remote: None,
        default_target_ref: DEFAULT_TARGET_REF.to_owned(),
        tracking_ref: None,
        exists: path.exists(),
        is_exact_git_root: false,
        lifecycle_state: lifecycle_state.to_owned(),
        publish_state: publish_state.map(str::to_owned),
        branch: None,
        head_sha: None,
        remote_sha: None,
        ahead_count: None,
        behind_count: None,
        dirty: false,
        fetched,
        error: Some(error.to_owned()),
    }
}

fn load_statuses(
    flags: &GlobalFlags,
    requested_id: Option<&str>,
    fetched: bool,
) -> Result<Vec<RepoStatus>, CliError> {
    let store = open_store(flags)?;
    let conn = store.lock_sync();
    let rows = if let Some(id) = requested_id {
        match repo_store::by_id(&conn, id).map_err(sql_usage)? {
            Some(row) => vec![row],
            None => {
                let path = managed_repository_path(flags.data_dir(), id);
                let status = repo_status(id, &path, None, None, fetched);
                return Ok(vec![status]);
            }
        }
    } else {
        repo_store::list(&conn).map_err(sql_usage)?
    };
    Ok(rows
        .into_iter()
        .map(|row| {
            repo_status(
                &row.repository_id,
                Path::new(&row.managed_path),
                row.source_url.as_deref(),
                Some(&row.publish_state),
                fetched,
            )
        })
        .collect())
}

fn load_required_status(flags: &GlobalFlags, repository_id: &str) -> Result<RepoStatus, CliError> {
    let statuses = load_statuses(flags, Some(repository_id), false)?;
    let Some(status) = statuses.into_iter().next() else {
        return Err(CliError::Usage(format!(
            "repo {repository_id:?} is not adopted; run `raxis repo adopt {repository_id} <path-or-git-url>`"
        )));
    };
    if !status.is_exact_git_root {
        return Err(CliError::Usage(format!(
            "repo {} is not usable: {}",
            status.id,
            status.error.as_deref().unwrap_or("not an exact git root")
        )));
    }
    Ok(status)
}

fn record_status(flags: &GlobalFlags, status: &RepoStatus, upsert: bool) -> Result<(), CliError> {
    let store = open_store(flags)?;
    let conn = store.lock_sync();
    if upsert {
        repo_store::upsert(
            &conn,
            &repo_store::UpsertManagedRepository {
                repository_id: &status.id,
                managed_path: &status.path,
                source_url: status.source_url.as_deref(),
                default_remote: status.default_remote.as_deref(),
                default_target_ref: &status.default_target_ref,
                tracking_ref: status.tracking_ref.as_deref(),
                lifecycle_state: &status.lifecycle_state,
                publish_state: status
                    .publish_state
                    .as_deref()
                    .unwrap_or(repo_store::PUBLISH_UNKNOWN),
                head_sha: status.head_sha.as_deref(),
                remote_sha: status.remote_sha.as_deref(),
                ahead_count: status.ahead_count,
                behind_count: status.behind_count,
                dirty: status.dirty,
                last_error: status.error.as_deref(),
            },
        )
        .map_err(sql_usage)?;
    } else {
        repo_store::record_status(
            &conn,
            &repo_store::RepositoryStatusUpdate {
                repository_id: &status.id,
                lifecycle_state: &status.lifecycle_state,
                publish_state: status.publish_state.as_deref(),
                head_sha: status.head_sha.as_deref(),
                remote_sha: status.remote_sha.as_deref(),
                ahead_count: status.ahead_count,
                behind_count: status.behind_count,
                dirty: status.dirty,
                fetched: status.fetched,
                last_error: status.error.as_deref(),
            },
        )
        .map_err(sql_usage)?;
    }
    Ok(())
}

fn render_statuses(statuses: &[RepoStatus], json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string_pretty(statuses)?);
        return Ok(());
    }
    if statuses.is_empty() {
        println!("No adopted repositories recorded.");
        println!(
            "Adopt one with: raxis repo adopt {} <path-or-git-url>",
            DEFAULT_REPOSITORY_ID
        );
        return Ok(());
    }

    for status in statuses {
        println!(
            "{}  {}  publish={}  {}",
            status.id,
            status.lifecycle_state,
            status.publish_state.as_deref().unwrap_or("-"),
            status.path.display()
        );
        if let Some(source_url) = status.source_url.as_deref() {
            println!("    source:   {source_url}");
        }
        if let Some(branch) = status.branch.as_deref() {
            println!("    branch:   {branch}");
        }
        if let Some(head) = status.head_sha.as_deref() {
            println!("    head:     {head}");
        }
        if let Some(tracking) = status.tracking_ref.as_deref() {
            println!("    tracking: {tracking}");
        }
        if status.ahead_count.is_some() || status.behind_count.is_some() {
            println!(
                "    remote:   ahead {} · behind {}",
                status.ahead_count.unwrap_or(0),
                status.behind_count.unwrap_or(0)
            );
        }
        if let Some(error) = status.error.as_deref() {
            println!("    error:    {error}");
        }
    }
    Ok(())
}

fn fetch_one(status: &mut RepoStatus) {
    let Some(remote) = status.default_remote.as_deref().or(Some("origin")) else {
        return;
    };
    if let Err(reason) = git_status(&status.path, &["fetch", "--prune", remote]) {
        status.lifecycle_state = repo_store::STATE_REMOTE_UNREACHABLE.to_owned();
        status.error = Some(reason);
    }
}

fn upstream_ref(path: &Path) -> Option<String> {
    let raw = git_stdout(
        path,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    )?;
    if raw.is_empty() {
        None
    } else if raw.starts_with("refs/") {
        Some(raw)
    } else {
        Some(format!("refs/remotes/{raw}"))
    }
}

fn first_remote_url(path: &Path) -> Option<String> {
    let remote = git_stdout(path, &["remote"]).and_then(|s| s.lines().next().map(str::to_owned))?;
    git_stdout(path, &["remote", "get-url", &remote])
}

fn parse_ahead_behind(raw: &str) -> Option<(i64, i64)> {
    let mut parts = raw.split_whitespace();
    let ahead = parts.next()?.parse().ok()?;
    let behind = parts.next()?.parse().ok()?;
    Some((ahead, behind))
}

fn git_stdout(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_status(cwd: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Err(if stderr.is_empty() { stdout } else { stderr })
}

fn is_exact_repo_root(path: &Path) -> bool {
    let Some(top) = git_stdout(path, &["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let Ok(actual) = PathBuf::from(top).canonicalize() else {
        return false;
    };
    let Ok(expected) = path.canonicalize() else {
        return false;
    };
    actual == expected
}

fn open_store(flags: &GlobalFlags) -> Result<raxis_store::Store, CliError> {
    let db_path = flags.data_dir().join(raxis_store::KERNEL_DB_FILE);
    raxis_store::Store::open(&db_path).map_err(|e| {
        CliError::Usage(format!(
            "cannot open kernel.db at {}: {e}",
            db_path.display()
        ))
    })
}

fn sql_usage(e: rusqlite::Error) -> CliError {
    CliError::Usage(format!("repository metadata sqlite error: {e}"))
}

#[derive(Debug)]
struct StatusOpts {
    repository_id: Option<String>,
    remote: bool,
    json: bool,
}

fn parse_status_args(args: &[String]) -> Result<StatusOpts, CliError> {
    let mut json = false;
    let mut remote = false;
    let mut repository_id: Option<String> = None;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--remote" => remote = true,
            other if other.starts_with('-') => {
                return Err(CliError::Usage(format!(
                    "repo status: unknown flag {other:?}"
                )));
            }
            _ => {
                if repository_id.is_some() {
                    return Err(CliError::Usage(
                        "repo status accepts at most one <repository_id>".to_owned(),
                    ));
                }
                repository_id = Some(normalize_repository_id(Some(arg))?);
            }
        }
    }
    Ok(StatusOpts {
        repository_id,
        remote,
        json,
    })
}

#[derive(Debug)]
struct OneRepoOpts {
    repository_id: String,
    json: bool,
}

fn parse_one_repo_args(command: &str, args: &[String]) -> Result<OneRepoOpts, CliError> {
    let mut json = false;
    let mut repository_id: Option<String> = None;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other if other.starts_with('-') => {
                return Err(CliError::Usage(format!(
                    "{command}: unknown flag {other:?}"
                )));
            }
            _ => {
                if repository_id.is_some() {
                    return Err(CliError::Usage(format!(
                        "{command} accepts at most one <repository_id>"
                    )));
                }
                repository_id = Some(normalize_repository_id(Some(arg))?);
            }
        }
    }
    Ok(OneRepoOpts {
        repository_id: repository_id.unwrap_or_else(|| DEFAULT_REPOSITORY_ID.to_owned()),
        json,
    })
}

#[derive(Debug)]
struct PublishOpts {
    repository_id: String,
    remote: Option<String>,
    target_ref: Option<String>,
    json: bool,
}

fn parse_publish_args(args: &[String]) -> Result<PublishOpts, CliError> {
    let mut json = false;
    let mut remote: Option<String> = None;
    let mut target_ref: Option<String> = None;
    let mut repository_id: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--remote" => {
                remote = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::Usage("repo publish --remote requires a value".to_owned())
                        })?
                        .clone(),
                );
            }
            "--ref" => {
                target_ref = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::Usage("repo publish --ref requires a value".to_owned())
                        })?
                        .clone(),
                );
            }
            other if other.starts_with('-') => {
                return Err(CliError::Usage(format!(
                    "repo publish: unknown flag {other:?}"
                )));
            }
            _ => {
                if repository_id.is_some() {
                    return Err(CliError::Usage(
                        "repo publish accepts at most one <repository_id>".to_owned(),
                    ));
                }
                repository_id = Some(normalize_repository_id(Some(arg))?);
            }
        }
    }
    Ok(PublishOpts {
        repository_id: repository_id.unwrap_or_else(|| DEFAULT_REPOSITORY_ID.to_owned()),
        remote,
        target_ref,
        json,
    })
}

#[derive(Debug)]
struct RepairOpts {
    json: bool,
}

fn parse_repair_args(args: &[String]) -> Result<RepairOpts, CliError> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other => {
                return Err(CliError::Usage(format!(
                    "repo repair: unknown argument {other:?}"
                )));
            }
        }
    }
    Ok(RepairOpts { json })
}

fn normalize_repository_id(raw: Option<&str>) -> Result<String, CliError> {
    let id = raw.unwrap_or(DEFAULT_REPOSITORY_ID).trim();
    validate_repository_id(id).map_err(|reason| {
        CliError::Usage(format!(
            "invalid repository id {id:?}: {reason}; valid example: `api`"
        ))
    })?;
    Ok(id.to_owned())
}

fn validate_repository_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("repository id is empty".to_owned());
    }
    if id.len() > MAX_REPOSITORY_ID_LEN {
        return Err(format!(
            "repository id is {} bytes, exceeds cap {}",
            id.len(),
            MAX_REPOSITORY_ID_LEN,
        ));
    }
    let mut chars = id.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err("repository id must start with an ASCII letter or digit".to_owned());
    }
    if id == "." || id == ".." || id.contains('/') || id.contains('\\') {
        return Err("repository id must be a single path-safe segment".to_owned());
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return Err(
            "repository id may contain only ASCII letters, digits, '.', '-' and '_'".to_owned(),
        );
    }
    Ok(())
}

fn managed_repository_path(data_dir: &Path, repository_id: &str) -> PathBuf {
    data_dir.join("repositories").join(repository_id)
}

fn print_adopt_help() {
    println!("usage: raxis repo adopt <repository_id> <path-or-git-url> [--force] [--json]");
}

fn print_status_help() {
    println!("usage: raxis repo status [repository_id] [--remote] [--json]");
}

fn print_publish_help() {
    println!("usage: raxis repo publish [repository_id] [--remote origin] [--ref refs/heads/main] [--json]");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_id_validation_allows_safe_names() {
        for id in ["main", "api", "web-app", "service_v2", "repo.1"] {
            validate_repository_id(id).unwrap();
        }
    }

    #[test]
    fn repository_id_validation_rejects_paths() {
        for id in ["", ".hidden", "../api", "api/foo", "api foo"] {
            assert!(validate_repository_id(id).is_err(), "{id:?} must reject");
        }
    }

    #[test]
    fn upstream_ref_normalizes_remote_branch() {
        assert_eq!(parse_ahead_behind("2\t3"), Some((2, 3)));
        assert_eq!(parse_ahead_behind("0 0"), Some((0, 0)));
    }
}

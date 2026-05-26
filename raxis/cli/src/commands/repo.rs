// raxis-cli::commands::repo — managed repository ergonomics.
//
// Raxis 0.2 lets one data directory own multiple managed source
// repositories under `<data_dir>/repositories/<id>`. These commands are
// local-only helpers: they do not open operator.sock and they do not mutate
// kernel.db. The kernel still treats the managed clone as the authority.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;

use crate::errors::CliError;
use crate::GlobalFlags;

const DEFAULT_REPOSITORY_ID: &str = "main";
const MAX_REPOSITORY_ID_LEN: usize = 64;

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

    let status = repo_status(&repository_id, &dest);
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!(
            "Adopted repository `{}` at {}",
            status.id,
            status.path.display()
        );
        if let Some(head) = status.head.as_deref() {
            println!("  head: {head}");
        }
        if let Some(branch) = status.branch.as_deref() {
            println!("  branch: {branch}");
        }
    }
    Ok(())
}

pub fn run_status(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut json = false;
    let mut repository_id: Option<String> = None;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                print_status_help();
                return Ok(());
            }
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

    let repositories_root = flags.data_dir().join("repositories");
    let statuses = if let Some(id) = repository_id {
        vec![repo_status(
            &id,
            &managed_repository_path(flags.data_dir(), &id),
        )]
    } else if repositories_root.exists() {
        let mut out = Vec::new();
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
            if validate_repository_id(&id).is_ok() {
                out.push(repo_status(&id, &entry.path()));
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    } else {
        Vec::new()
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&statuses)?);
        return Ok(());
    }

    if statuses.is_empty() {
        println!(
            "No managed repositories found under {}",
            repositories_root.display()
        );
        println!(
            "Adopt one with: raxis repo adopt {} <path-or-git-url>",
            DEFAULT_REPOSITORY_ID
        );
        return Ok(());
    }

    for status in statuses {
        let state = if status.is_git_repo { "git" } else { "missing" };
        println!("{}  {}  {}", status.id, state, status.path.display());
        if let Some(branch) = status.branch.as_deref() {
            println!("    branch: {branch}");
        }
        if let Some(head) = status.head.as_deref() {
            println!("    head:   {head}");
        }
        if let Some(error) = status.error.as_deref() {
            println!("    error:  {error}");
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct RepoStatus {
    id: String,
    path: PathBuf,
    exists: bool,
    is_git_repo: bool,
    branch: Option<String>,
    head: Option<String>,
    dirty: Option<bool>,
    error: Option<String>,
}

fn repo_status(id: &str, path: &Path) -> RepoStatus {
    if !path.exists() {
        return RepoStatus {
            id: id.to_owned(),
            path: path.to_path_buf(),
            exists: false,
            is_git_repo: false,
            branch: None,
            head: None,
            dirty: None,
            error: Some("managed repository path does not exist".to_owned()),
        };
    }
    let inside = git_stdout(path, &["rev-parse", "--is-inside-work-tree"]);
    if !matches!(inside.as_deref(), Some("true")) {
        return RepoStatus {
            id: id.to_owned(),
            path: path.to_path_buf(),
            exists: true,
            is_git_repo: false,
            branch: None,
            head: None,
            dirty: None,
            error: Some("path exists but is not a git work tree".to_owned()),
        };
    }
    let branch = git_stdout(path, &["branch", "--show-current"]).filter(|s| !s.is_empty());
    let head = git_stdout(path, &["rev-parse", "HEAD"]);
    let dirty = git_stdout(path, &["status", "--porcelain"]).map(|s| !s.is_empty());
    RepoStatus {
        id: id.to_owned(),
        path: path.to_path_buf(),
        exists: true,
        is_git_repo: true,
        branch,
        head,
        dirty,
        error: None,
    }
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
    println!("usage: raxis repo status [repository_id] [--json]");
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
}

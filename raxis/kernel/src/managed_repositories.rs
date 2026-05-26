//! Managed repository path helpers.
//!
//! Raxis 0.2 introduces more than one operator-managed source repository per
//! data directory. The storage convention is intentionally boring:
//!
//! ```text
//! <data_dir>/repositories/<repository_id>
//! ```
//!
//! `main` remains the default repository id for every existing plan. New plans
//! can select another repository with `[workspace] repository = "api"`.

use std::path::{Path, PathBuf};

pub const DEFAULT_REPOSITORY_ID: &str = "main";
pub const MAX_REPOSITORY_ID_LEN: usize = 64;

pub fn validate_repository_id(id: &str) -> Result<(), String> {
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
    let Some(first) = chars.next() else {
        return Err("repository id is empty".to_owned());
    };
    if !first.is_ascii_alphanumeric() {
        return Err("repository id must start with an ASCII letter or digit".to_owned());
    }
    if id == "." || id == ".." || id.contains('/') || id.contains('\\') {
        return Err("repository id must be a single path-safe segment".to_owned());
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(
            "repository id may contain only ASCII letters, digits, '.', '-' and '_'".to_owned(),
        );
    }
    Ok(())
}

pub fn normalize_repository_id(raw: Option<&str>) -> Result<String, String> {
    let id = raw.unwrap_or(DEFAULT_REPOSITORY_ID).trim();
    validate_repository_id(id)?;
    Ok(id.to_owned())
}

pub fn managed_repository_path(data_dir: &Path, repository_id: &str) -> PathBuf {
    data_dir.join("repositories").join(repository_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_repository_is_main() {
        assert_eq!(normalize_repository_id(None).unwrap(), "main");
    }

    #[test]
    fn repository_ids_are_single_safe_segments() {
        for id in ["api", "web-app", "service_v2", "repo.1"] {
            validate_repository_id(id).unwrap();
        }
        for id in ["", ".hidden", "../main", "foo/bar", "foo bar"] {
            assert!(validate_repository_id(id).is_err(), "{id:?} must reject");
        }
    }
}

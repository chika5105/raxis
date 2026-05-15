//! Tiny `.env` reader for the live-e2e harness.
//!
//! Why not pull in `dotenvy`: the rest of the workspace deliberately
//! avoids `dotenvy`-style auto-loading because it makes secrets a
//! cwd-implicit input. This binary is dev-only and explicit; a 30
//! line parser is sufficient and avoids polluting the dependency
//! graph.
//!
//! Supported syntax (a strict subset of `.env`):
//!
//!   - One `KEY=VALUE` per line.
//!   - `#` introduces a comment.
//!   - Blank lines are skipped.
//!   - Surrounding whitespace on `KEY` and `VALUE` is trimmed.
//!   - `VALUE` may be wrapped in single or double quotes; the
//!     quotes are stripped without unescaping.
//!
//! No variable expansion, no `export ` prefix support, no shell
//! quoting. The intent is to read a hand-written file with a few
//! API keys.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

pub type EnvMap = BTreeMap<String, String>;

pub fn load(path: &Path) -> Result<EnvMap> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = EnvMap::new();
    for (lineno, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=').ok_or_else(|| {
            anyhow!(
                "{}:{}: expected KEY=VALUE, got {line:?}",
                path.display(),
                lineno + 1,
            )
        })?;
        let k = k.trim().to_owned();
        let mut v = v.trim().to_owned();
        if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            v = v[1..v.len() - 1].to_owned();
        }
        out.insert(k, v);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_simple_pairs() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "# a comment").unwrap();
        writeln!(f, "FOO=bar").unwrap();
        writeln!(f, "BAZ = qux").unwrap();
        writeln!(f, "QUOTED=\"hello world\"").unwrap();
        writeln!(f, "SINGLE='ok'").unwrap();
        let m = load(f.path()).unwrap();
        assert_eq!(m.get("FOO").unwrap(), "bar");
        assert_eq!(m.get("BAZ").unwrap(), "qux");
        assert_eq!(m.get("QUOTED").unwrap(), "hello world");
        assert_eq!(m.get("SINGLE").unwrap(), "ok");
    }

    #[test]
    fn rejects_malformed() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "no_equals_sign").unwrap();
        assert!(load(f.path()).is_err());
    }
}

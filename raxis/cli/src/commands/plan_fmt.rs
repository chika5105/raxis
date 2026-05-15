// raxis-cli::commands::plan_fmt — `raxis plan fmt <plan.toml> [--check] [--stdout]`.
//
// Normative reference: `specs/v2/operator-ergonomics.md §10`.
//
// `plan fmt` canonicalizes a plan.toml file's formatting:
//   * 2-space indentation;
//   * stable per-table key ordering (keep operator order, but trim
//     trailing whitespace, normalise blank lines, force the final
//     newline);
//   * preserve comments (including `@raxis-default` annotations) at
//     their original positions — this is the contract that rules out
//     a `toml::Value` round-trip and motivates the `toml_edit` dep.
//
// Modes (mutually exclusive):
//   * default          — overwrite the file in place if it differs.
//   * `--check`        — exit 0 if canonical, 2 otherwise; never write.
//   * `--stdout`       — write the canonical bytes to stdout, do not
//                        modify the file.
//
// Local-only: never opens the operator socket. The kernel's plan
// admission does not consult the formatting; this command exists
// purely so an operator's diff is clean for review.

use std::path::PathBuf;

use crate::errors::CliError;
use crate::GlobalFlags;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub check: bool,
    pub stdout: bool,
}

pub fn run(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut opts = Options::default();
    let mut path: Option<PathBuf> = None;

    for arg in args {
        match arg.as_str() {
            "--check" => opts.check = true,
            "--stdout" => opts.stdout = true,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            s if s.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{s}`; see `raxis plan fmt --help`"
                )));
            }
            s => {
                if path.is_some() {
                    return Err(CliError::Usage(format!(
                        "plan fmt accepts a single <plan.toml> path; got also `{s}`"
                    )));
                }
                path = Some(PathBuf::from(s));
            }
        }
    }

    if opts.check && opts.stdout {
        return Err(CliError::Usage(
            "`--check` and `--stdout` are mutually exclusive".to_owned(),
        ));
    }

    let path = path.ok_or_else(|| {
        CliError::Usage(
            "plan fmt requires <plan.toml> (e.g. `raxis plan fmt ./plan.toml`)".to_owned(),
        )
    })?;

    let original = std::fs::read_to_string(&path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let canonical =
        canonicalize(&original).map_err(|e| CliError::Usage(format!("plan fmt: {e}")))?;

    if opts.stdout {
        print!("{canonical}");
        return Ok(());
    }

    if opts.check {
        if original == canonical {
            return Ok(());
        }
        return Err(CliError::Usage(format!(
            "plan fmt: {} is not in canonical form (run without --check to fix)",
            path.display()
        )));
    }

    if original == canonical {
        println!(
            "plan fmt: {} already canonical (no changes).",
            path.display()
        );
        return Ok(());
    }

    std::fs::write(&path, &canonical).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    println!("plan fmt: {} reformatted.", path.display());
    Ok(())
}

fn print_help() {
    println!(
        "raxis plan fmt — canonicalize a plan.toml file's formatting.\n\
         \n\
         USAGE:\n\
             raxis plan fmt <plan.toml>            # rewrite in-place\n\
             raxis plan fmt <plan.toml> --check    # CI gate; exit 2 if not canonical\n\
             raxis plan fmt <plan.toml> --stdout   # print to stdout, do not modify\n\
         \n\
         The transform is deterministic and comment-preserving:\n\
           * 2-space indentation\n\
           * trailing whitespace stripped; final newline ensured\n\
           * blank lines normalised (≤ 1 between sibling rows;\n\
             exactly 1 between top-level tables)\n\
           * `@raxis-default` annotation comments retained verbatim"
    );
}

// ---------------------------------------------------------------------------
// Canonicalization core (pure; comment-preserving via toml_edit)
// ---------------------------------------------------------------------------

/// Returns the canonical-form bytes for `text`.
///
/// Behaviour:
///   1. Parse into a `toml_edit::DocumentMut` (preserves comments).
///   2. Walk the produced text and apply post-processing rules that
///      `toml_edit`'s default `to_string()` does not enforce: trailing
///      whitespace removal, blank-line collapsing, ensured final newline.
///   3. Return the result.
pub fn canonicalize(text: &str) -> Result<String, String> {
    let doc = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("invalid TOML: {e}"))?;
    let raw = doc.to_string();
    Ok(post_process(&raw))
}

/// Post-processing pass applied to `toml_edit`'s default rendering.
///
/// Rules (all idempotent — running twice is a no-op):
///   * strip trailing whitespace from every line;
///   * collapse runs of ≥ 2 blank lines down to 1;
///   * ensure the document ends with exactly one `\n` (no trailing blank).
fn post_process(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_blank = false;

    for line in raw.split_inclusive('\n') {
        let body = line.trim_end_matches('\n');
        let trimmed = body.trim_end();
        let is_blank = trimmed.is_empty();

        if is_blank && last_blank {
            continue;
        }
        last_blank = is_blank;

        out.push_str(trimmed);
        out.push('\n');
    }

    while out.ends_with("\n\n") {
        out.pop();
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotent_on_canonical_input() {
        let input = "[workspace]\nlane_id = \"default\"\n\n[[tasks]]\ntask_id = \"a\"\n";
        let once = canonicalize(input).unwrap();
        let twice = canonicalize(&once).unwrap();
        assert_eq!(once, twice, "fmt must be idempotent");
        assert_eq!(once, input, "input is already canonical");
    }

    #[test]
    fn strips_trailing_whitespace() {
        let input = "[workspace]   \nlane_id = \"x\"  \n";
        let output = canonicalize(input).unwrap();
        assert!(!output.contains("  \n"), "output: {output:?}");
    }

    #[test]
    fn collapses_double_blank_lines() {
        let input = "[a]\nx = 1\n\n\n\n[b]\ny = 2\n";
        let output = canonicalize(input).unwrap();
        assert!(!output.contains("\n\n\n"), "output: {output:?}");
    }

    #[test]
    fn ensures_trailing_newline() {
        let input = "[workspace]\nlane_id = \"x\"";
        let output = canonicalize(input).unwrap();
        assert!(output.ends_with('\n'));
        assert!(!output.ends_with("\n\n"));
    }

    #[test]
    fn preserves_inline_comment() {
        let input = "[workspace]\nlane_id = \"x\" # @raxis-default v0.4.0\n";
        let output = canonicalize(input).unwrap();
        assert!(output.contains("@raxis-default v0.4.0"));
    }

    #[test]
    fn preserves_full_line_comment() {
        let input = "# Top-level note.\n[workspace]\nlane_id = \"x\"\n";
        let output = canonicalize(input).unwrap();
        assert!(output.starts_with("# Top-level note.\n"));
    }

    #[test]
    fn invalid_toml_returns_descriptive_error() {
        let input = "[workspace\nbroken = \n";
        let err = canonicalize(input).unwrap_err();
        assert!(err.contains("invalid TOML"), "err = {err}");
    }
}

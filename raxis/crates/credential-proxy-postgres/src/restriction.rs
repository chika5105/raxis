//! Restriction enforcement for the Postgres proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §4.1` "SQL restriction
//! modes". The MVP supports `allow_only_select` only. The richer
//! surface — `forbidden_schemas`, `forbidden_tables`, `max_result_rows`,
//! `statement_timeout_ms` — is documented in the spec and lands when
//! the extended-query path lands.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// If true, only `SELECT` and explicitly-allowed read operations
    /// pass; everything else is rejected with a Postgres
    /// `ErrorResponse` and recorded as `DatabaseQueryBlocked`.
    #[serde(default)]
    pub allow_only_select: bool,
}

impl Restrictions {
    /// Convenience constructor for tests.
    pub const fn select_only() -> Self {
        Self { allow_only_select: true }
    }

    /// Returns `true` if the given operation must be blocked under
    /// this restriction set.
    pub fn is_blocked(&self, op: &OperationKind) -> bool {
        if !self.allow_only_select {
            return false;
        }
        !matches!(op, OperationKind::Select)
    }
}

/// First-token classification of a SQL string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationKind {
    /// `SELECT`, `WITH ... SELECT`, `SHOW`, `EXPLAIN ... SELECT`.
    Select,
    /// `INSERT`.
    Insert,
    /// `UPDATE`.
    Update,
    /// `DELETE`.
    Delete,
    /// Anything else (`CREATE`, `DROP`, `ALTER`, `BEGIN`, ...). The
    /// payload is the uppercased first token.
    Other(String),
}

/// Classify the first SQL operation in `sql`.
///
/// We deliberately use a tiny, fast, dependency-free tokenizer. We
/// strip leading whitespace and SQL line comments (`-- ... \n`) and
/// block comments (`/* ... */`) before reading the first identifier.
pub fn classify_first_operation(sql: &str) -> OperationKind {
    let s = strip_leading_whitespace_and_comments(sql.as_bytes());
    let first_word: String = s.iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_')
        .map(|&b| b.to_ascii_uppercase() as char)
        .collect();

    match first_word.as_str() {
        "SELECT"      => OperationKind::Select,
        "WITH"        => classify_after_cte(&s[first_word.len()..]),
        "SHOW"        => OperationKind::Select,
        "VALUES"      => OperationKind::Select,
        "TABLE"       => OperationKind::Select,
        "EXPLAIN"     => classify_after_explain(&s[first_word.len()..]),
        "INSERT"      => OperationKind::Insert,
        "UPDATE"      => OperationKind::Update,
        "DELETE"      => OperationKind::Delete,
        ""            => OperationKind::Other(String::new()),
        other         => OperationKind::Other(other.to_owned()),
    }
}

fn strip_leading_whitespace_and_comments(mut s: &[u8]) -> &[u8] {
    loop {
        // Whitespace.
        let trimmed = strip_ascii_whitespace(s);
        if trimmed.starts_with(b"--") {
            // Line comment until \n.
            let nl = trimmed.iter().position(|&b| b == b'\n').unwrap_or(trimmed.len());
            s = &trimmed[nl..];
            continue;
        }
        if trimmed.starts_with(b"/*") {
            // Block comment until "*/".
            let mut i = 2;
            while i + 1 < trimmed.len() {
                if trimmed[i] == b'*' && trimmed[i + 1] == b'/' {
                    s = &trimmed[i + 2..];
                    break;
                }
                i += 1;
            }
            // Unterminated block comment: bail with the rest.
            if i + 1 >= trimmed.len() {
                return &trimmed[trimmed.len()..];
            }
            continue;
        }
        return trimmed;
    }
}

fn strip_ascii_whitespace(s: &[u8]) -> &[u8] {
    let start = s.iter().take_while(|&&b| b.is_ascii_whitespace()).count();
    &s[start..]
}

fn classify_after_cte(after_with: &[u8]) -> OperationKind {
    // `WITH foo AS (...) SELECT|INSERT|UPDATE|DELETE ...`
    //
    // Strategy: peel off CTE binding(s) (each is a paren-balanced
    // expression). After the last balanced top-level group whose
    // companion text is `<name> AS (...)`, classify the remainder.
    //
    // Implementation: walk left-to-right tracking paren depth; once
    // depth returns to 0 *and* we've passed a closing `)`, peek
    // forward past whitespace to see if a comma indicates another
    // CTE binding follows. When we exhaust the bindings, classify
    // the trailing tokens.
    let s = std::str::from_utf8(after_with).unwrap_or("");
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace and comments.
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        if i >= bytes.len() { break; }

        // Skip the CTE alias and `AS`. Any sequence of
        // alpha+numeric+underscore counts as the alias.
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        // Optional column list after the alias — `(c1, c2)`.
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        if i < bytes.len() && bytes[i] == b'(' {
            i = skip_balanced_parens(bytes, i);
        }

        // Optional MATERIALIZED / NOT MATERIALIZED.
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        // `AS` keyword.
        if i + 2 <= bytes.len()
            && (&bytes[i..i + 2] == b"AS" || &bytes[i..i + 2] == b"as")
            && (i + 2 == bytes.len() || !(bytes[i + 2].is_ascii_alphanumeric() || bytes[i + 2] == b'_'))
        {
            i += 2;
        }
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        // Optional `[NOT] MATERIALIZED`.
        for kw in ["NOT MATERIALIZED", "MATERIALIZED", "not materialized", "materialized"] {
            if i + kw.len() <= bytes.len() && &bytes[i..i + kw.len()] == kw.as_bytes() {
                i += kw.len();
                break;
            }
        }
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();

        // CTE body — the parenthesised statement.
        if i < bytes.len() && bytes[i] == b'(' {
            i = skip_balanced_parens(bytes, i);
        } else {
            // Malformed CTE — bail.
            return OperationKind::Other("WITH".to_owned());
        }

        // After the CTE body: comma → another CTE; else this is the
        // final statement.
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
            continue;
        }
        // Reached the trailing statement — recurse.
        let trailing = std::str::from_utf8(&bytes[i..]).unwrap_or("");
        return classify_first_operation(trailing);
    }
    OperationKind::Other("WITH".to_owned())
}

/// Returns the index just past a balanced paren expression starting
/// at `bytes[start] == b'('`. If unbalanced, returns `bytes.len()`.
fn skip_balanced_parens(bytes: &[u8], start: usize) -> usize {
    debug_assert!(bytes.get(start) == Some(&b'('));
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            // Single-quoted string literal.
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

fn classify_after_explain(after_explain: &[u8]) -> OperationKind {
    // `EXPLAIN [ANALYZE] [VERBOSE] [(...)]  <stmt>` — strip leading
    // modifiers and recurse on the trailing statement.
    let mut bytes = strip_ascii_whitespace(after_explain);
    // Optional parenthesized options: `EXPLAIN (analyze, verbose) ...`.
    if let Some(b'(') = bytes.first().copied() {
        let end = skip_balanced_parens(bytes, 0);
        bytes = &bytes[end..];
    }
    // Optional `ANALYZE`, `VERBOSE`, `BUFFERS`, etc. Peel as many as we
    // can recognise.
    loop {
        let trimmed = strip_ascii_whitespace(bytes);
        let next_word: String = trimmed.iter()
            .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_')
            .map(|&b| b.to_ascii_uppercase() as char)
            .collect();
        if matches!(next_word.as_str(),
            "ANALYZE" | "VERBOSE" | "BUFFERS" | "TIMING" | "COSTS" | "FORMAT") {
            bytes = &trimmed[next_word.len()..];
            continue;
        }
        bytes = trimmed;
        break;
    }
    classify_first_operation(std::str::from_utf8(bytes).unwrap_or(""))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_classified() {
        assert_eq!(classify_first_operation("SELECT 1"), OperationKind::Select);
        assert_eq!(classify_first_operation("  select 1"), OperationKind::Select);
        assert_eq!(classify_first_operation("\t\nSELECT 1"), OperationKind::Select);
    }

    #[test]
    fn insert_update_delete() {
        assert_eq!(classify_first_operation("INSERT INTO t VALUES (1)"), OperationKind::Insert);
        assert_eq!(classify_first_operation("UPDATE t SET x=1"), OperationKind::Update);
        assert_eq!(classify_first_operation("DELETE FROM t"), OperationKind::Delete);
    }

    #[test]
    fn other_classification() {
        assert_eq!(
            classify_first_operation("DROP TABLE t"),
            OperationKind::Other("DROP".to_owned()),
        );
        assert_eq!(
            classify_first_operation("CREATE TABLE t (x INT)"),
            OperationKind::Other("CREATE".to_owned()),
        );
    }

    #[test]
    fn line_comments_skipped() {
        assert_eq!(
            classify_first_operation("-- audit comment\nSELECT 1"),
            OperationKind::Select,
        );
    }

    #[test]
    fn block_comments_skipped() {
        assert_eq!(
            classify_first_operation("/* hello */ SELECT 1"),
            OperationKind::Select,
        );
        assert_eq!(
            classify_first_operation("/* multi\nline */ INSERT INTO t VALUES (1)"),
            OperationKind::Insert,
        );
    }

    #[test]
    fn cte_classified_by_inner_op() {
        assert_eq!(
            classify_first_operation("WITH foo AS (SELECT 1) SELECT * FROM foo"),
            OperationKind::Select,
        );
        assert_eq!(
            classify_first_operation("WITH foo AS (SELECT 1) INSERT INTO t VALUES (1)"),
            OperationKind::Insert,
        );
    }

    #[test]
    fn explain_classified_by_inner_op() {
        assert_eq!(
            classify_first_operation("EXPLAIN SELECT 1"),
            OperationKind::Select,
        );
        assert_eq!(
            classify_first_operation("EXPLAIN INSERT INTO t VALUES (1)"),
            OperationKind::Insert,
        );
    }

    #[test]
    fn select_only_blocks_dml() {
        let r = Restrictions::select_only();
        assert!(!r.is_blocked(&OperationKind::Select));
        assert!( r.is_blocked(&OperationKind::Insert));
        assert!( r.is_blocked(&OperationKind::Update));
        assert!( r.is_blocked(&OperationKind::Delete));
        assert!( r.is_blocked(&OperationKind::Other("DROP".into())));
    }

    #[test]
    fn unrestricted_blocks_nothing() {
        let r = Restrictions::default();
        assert!(!r.is_blocked(&OperationKind::Insert));
        assert!(!r.is_blocked(&OperationKind::Other("CREATE".into())));
    }
}

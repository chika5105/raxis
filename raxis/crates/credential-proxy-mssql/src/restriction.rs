//! Restriction enforcement for the MSSQL proxy.
//!
//! Mirrors the Postgres proxy's restriction surface verbatim — the
//! `allow_only_select` flag is the only V2 MVP knob. Reference:
//! `specs/v2/credential-proxy.md §4.3` (MSSQL).

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// If true, only `SELECT` and explicitly-allowed read operations
    /// pass; everything else is rejected with a TDS `ERROR` token
    /// carrying SQLSTATE `42501`-equivalent.
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
        if !self.allow_only_select { return false; }
        !matches!(op, OperationKind::Select)
    }
}

/// First-token classification of a SQL string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationKind {
    /// `SELECT`, `WITH ... SELECT`, etc.
    Select,
    /// `INSERT`.
    Insert,
    /// `UPDATE`.
    Update,
    /// `DELETE`.
    Delete,
    /// Anything else; payload is the uppercased first token.
    Other(String),
}

/// Classify the first SQL operation in `sql`. Strips leading
/// whitespace, line comments (`-- ... \n`), and block comments
/// (`/* ... */`).
pub fn classify_first_operation(sql: &str) -> OperationKind {
    let s = strip_leading_whitespace_and_comments(sql.as_bytes());
    let first_word: String = s.iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_')
        .map(|&b| b.to_ascii_uppercase() as char)
        .collect();

    match first_word.as_str() {
        "SELECT"  => OperationKind::Select,
        "WITH"    => classify_after_cte(&s[first_word.len()..]),
        "EXEC" | "EXECUTE" => classify_after_explain(&s[first_word.len()..]),
        "INSERT"  => OperationKind::Insert,
        "UPDATE"  => OperationKind::Update,
        "DELETE"  => OperationKind::Delete,
        ""        => OperationKind::Other(String::new()),
        other     => OperationKind::Other(other.to_owned()),
    }
}

fn strip_leading_whitespace_and_comments(mut s: &[u8]) -> &[u8] {
    loop {
        let trimmed = strip_ascii_whitespace(s);
        if trimmed.starts_with(b"--") {
            let nl = trimmed.iter().position(|&b| b == b'\n').unwrap_or(trimmed.len());
            s = &trimmed[nl..];
            continue;
        }
        if trimmed.starts_with(b"/*") {
            let mut i = 2;
            while i + 1 < trimmed.len() {
                if trimmed[i] == b'*' && trimmed[i + 1] == b'/' {
                    s = &trimmed[i + 2..];
                    break;
                }
                i += 1;
            }
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
    let s = std::str::from_utf8(after_with).unwrap_or("");
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        if i >= bytes.len() { break; }
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        if i < bytes.len() && bytes[i] == b'(' {
            i = skip_balanced_parens(bytes, i);
        }
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        if i + 2 <= bytes.len()
            && (&bytes[i..i + 2] == b"AS" || &bytes[i..i + 2] == b"as")
            && (i + 2 == bytes.len() || !(bytes[i + 2].is_ascii_alphanumeric() || bytes[i + 2] == b'_'))
        {
            i += 2;
        }
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        if i < bytes.len() && bytes[i] == b'(' {
            i = skip_balanced_parens(bytes, i);
        } else {
            return OperationKind::Other("WITH".to_owned());
        }
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
            continue;
        }
        let trailing = std::str::from_utf8(&bytes[i..]).unwrap_or("");
        return classify_first_operation(trailing);
    }
    OperationKind::Other("WITH".to_owned())
}

fn skip_balanced_parens(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 { return i + 1; }
            }
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

fn classify_after_explain(after: &[u8]) -> OperationKind {
    let bytes = strip_ascii_whitespace(after);
    classify_first_operation(std::str::from_utf8(bytes).unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_classified() {
        assert_eq!(classify_first_operation("SELECT 1"), OperationKind::Select);
    }

    #[test]
    fn insert_update_delete() {
        assert_eq!(classify_first_operation("INSERT INTO t VALUES (1)"), OperationKind::Insert);
        assert_eq!(classify_first_operation("UPDATE t SET x=1"), OperationKind::Update);
        assert_eq!(classify_first_operation("DELETE FROM t"), OperationKind::Delete);
    }

    #[test]
    fn select_only_blocks_dml() {
        let r = Restrictions::select_only();
        assert!(!r.is_blocked(&OperationKind::Select));
        assert!( r.is_blocked(&OperationKind::Insert));
        assert!( r.is_blocked(&OperationKind::Other("DROP".into())));
    }
}

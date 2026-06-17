//! Shared SQL restriction types for database credential proxies.
//!
//! Dialect-specific parsers stay in their proxy crates. This crate
//! only carries the policy verdict types and table-name matching
//! rules they had duplicated verbatim.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Closed enum of restriction-rejection reasons. Strings in the
/// audit chain match `as_str()` verbatim per
/// `proxy-table-allowlists.md §8.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictionReason {
    /// Verb-class filter (`allow_only_select`) blocked.
    AllowOnlySelect,
    /// Walker resolved tables; one or more was not in `allowed_tables`.
    TableNotInAllowedList,
    /// Walker resolved tables; one or more was in `forbidden_tables`.
    TableInForbiddenList,
    /// Walker could not resolve a multi-statement batch.
    AmbiguousSqlMultiStatement,
    /// Walker could not resolve dynamic SQL.
    AmbiguousSqlDynamic,
    /// Walker could not resolve malformed SQL.
    AmbiguousSqlMalformed,
}

impl RestrictionReason {
    /// Stable grep key for the audit chain.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnlySelect => "allow_only_select",
            Self::TableNotInAllowedList => "table_not_in_allowed_list",
            Self::TableInForbiddenList => "table_in_forbidden_list",
            Self::AmbiguousSqlMultiStatement => "ambiguous_sql_multi_statement",
            Self::AmbiguousSqlDynamic => "ambiguous_sql_dynamic",
            Self::AmbiguousSqlMalformed => "ambiguous_sql_malformed",
        }
    }
}

/// Outcome of a SQL restriction check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestrictionDecision {
    /// Forward upstream; record the walker's resolved table list
    /// in audit.
    Admit {
        /// Walker-resolved relation list.
        tables_referenced: Vec<String>,
    },
    /// Reject with a wire-format error; record reason in audit.
    Block {
        /// Closed-enum reason; serialised verbatim into audit.
        reason: RestrictionReason,
        /// Walker output, included for audit even when ambiguous
        /// (in which case it is empty).
        tables_referenced: Vec<String>,
    },
    /// `enforce = false`: forward upstream but record the would-have
    /// blocked reason in audit.
    AuditOnly {
        /// Reason the walker would have blocked under `enforce = true`.
        reason: RestrictionReason,
        /// Walker output; may be empty if ambiguous.
        tables_referenced: Vec<String>,
    },
}

/// Walker output: either a confidently extracted relation list, or
/// an ambiguity signal that fails closed when allowlists exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationList {
    /// Confidently resolved set of qualified relations.
    Resolved(Vec<QualifiedName>),
    /// Walker could not prove the set with high confidence.
    Ambiguous {
        /// Specific ambiguity class.
        reason: AmbiguityReason,
    },
}

/// Why a SQL relation walker bailed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbiguityReason {
    /// `;`-separated batch with more than one non-trailing statement.
    MultiStatementBatch,
    /// Dynamic SQL (`EXEC`, `PREPARE`, `CALL`, and dialect peers).
    DynamicSql,
    /// Unbalanced parens, unterminated strings, or empty input.
    Malformed,
}

/// Schema-qualified relation reference produced by a SQL walker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedName {
    /// Optional schema/database qualifier. `None` means the SQL
    /// referenced the relation by bare name.
    pub schema: Option<String>,
    /// Table component, case preserved per
    /// `proxy-table-allowlists.md §3 D3`.
    pub table: String,
}

impl std::fmt::Display for QualifiedName {
    /// Canonical `<schema>.<table>` or bare `<table>` form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.schema {
            Some(s) => write!(f, "{}.{}", s.to_ascii_lowercase(), self.table),
            None => f.write_str(&self.table),
        }
    }
}

/// Returns true when `t` matches any operator-declared
/// `allowed_tables` / `forbidden_tables` entry.
pub fn matches_any(t: &QualifiedName, list: &[String]) -> bool {
    list.iter().any(|entry| {
        let e = parse_entry(entry);
        match (&e.schema, &t.schema) {
            (Some(es), Some(ts)) => es.eq_ignore_ascii_case(ts) && e.table == t.table,
            // Operator declared a qualified name but the walker saw
            // only a bare name; do not match because we cannot prove
            // the schema.
            (Some(_), None) => false,
            // Operator declared a bare name; match on table only.
            (None, _) => e.table == t.table,
        }
    })
}

fn parse_entry(entry: &str) -> QualifiedName {
    if let Some(idx) = entry.rfind('.') {
        QualifiedName {
            schema: Some(entry[..idx].to_ascii_lowercase()),
            table: entry[idx + 1..].to_owned(),
        }
    } else {
        QualifiedName {
            schema: None,
            table: entry.to_owned(),
        }
    }
}

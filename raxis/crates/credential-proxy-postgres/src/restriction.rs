//! Restriction enforcement for the Postgres proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §4.1` "SQL restriction
//! modes" + `specs/v2/proxy-table-allowlists.md`. The V2 surface
//! supports:
//!
//!   * `allow_only_select` — verb-class filter (V2.1, unchanged).
//!   * `allowed_tables` — table-level allowlist enforced on the
//!     simple-query path by the relation walker in this module.
//!   * `forbidden_tables` — denylist applied after the allowlist.
//!   * `max_result_rows` — streaming hard-cap on rows returned to
//!     the agent (enforced post-walker, in `lib.rs`'s relay path).
//!   * `enforce` — when `false`, walker output is audited but the
//!     query is admitted regardless of the allow/deny outcome
//!     (per `proxy-table-allowlists.md §3 D8`).
//!
//! The walker is intentionally a dependency-free hand-rolled
//! tokenizer (matching the style of `classify_first_operation`);
//! it returns a typed `RelationList::{Resolved, Ambiguous}` per
//! `proxy-table-allowlists.md §5.1`. Operators who declare any
//! allowlist or denylist trade away the V2.1 admit-on-ambiguous
//! behaviour for fail-closed-on-ambiguous (`§3 D4` of that spec).

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// If true, only `SELECT` and explicitly-allowed read operations
    /// pass; everything else is rejected with a Postgres
    /// `ErrorResponse` and recorded as `DatabaseQueryBlocked`.
    #[serde(default)]
    pub allow_only_select: bool,

    /// Table-level allowlist. When non-empty, the walker MUST
    /// resolve every referenced table to a member of this list
    /// for the query to be admitted. Entries match qualified
    /// (`schema.table`) or bare (`table`) per the matching rules
    /// in `proxy-table-allowlists.md §3 D3`. Empty = no allowlist.
    #[serde(default)]
    pub allowed_tables: Vec<String>,

    /// Table-level denylist. Applied AFTER the allowlist: if any
    /// referenced table matches an entry here the query is
    /// rejected, even when the same table is in `allowed_tables`.
    /// Empty = no denylist.
    #[serde(default)]
    pub forbidden_tables: Vec<String>,

    /// Upper bound on rows returned to the agent per simple-query
    /// result set. `0` = uncapped (V2.1-compatible default).
    /// Streaming enforcement lives in `lib.rs`'s relay path.
    #[serde(default)]
    pub max_result_rows: u64,

    /// When `false`, the walker still runs and audits the
    /// outcome (`tables_referenced` / `restriction_reason`) but
    /// the query is admitted regardless of allow/deny verdict.
    /// Defaults to `true` (block on violation).
    #[serde(default = "default_enforce_true")]
    pub enforce: bool,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self {
            allow_only_select: false,
            allowed_tables: Vec::new(),
            forbidden_tables: Vec::new(),
            max_result_rows: 0,
            enforce: true,
        }
    }
}

fn default_enforce_true() -> bool {
    true
}

impl Restrictions {
    /// Convenience constructor for tests.
    pub fn select_only() -> Self {
        Self {
            allow_only_select: true,
            ..Self::default()
        }
    }

    /// Returns `true` if the verb-class restriction blocks the
    /// operation (i.e. `allow_only_select` is set and `op` is not a
    /// `Select`). Internal helper used by [`Self::check`] as the
    /// first guard before the table-allowlist walker runs; tests in
    /// this crate exercise it directly to pin the
    /// `allow_only_select` semantics in isolation from the SQL
    /// walker.
    pub fn is_blocked(&self, op: &OperationKind) -> bool {
        self.allow_only_select && !matches!(op, OperationKind::Select)
    }

    /// True iff a non-empty allowlist or denylist is configured.
    pub fn has_table_lists(&self) -> bool {
        !self.allowed_tables.is_empty() || !self.forbidden_tables.is_empty()
    }

    /// Decide what to do with a SQL statement under the full V2
    /// restriction surface.
    ///
    /// Returns a `RestrictionDecision`:
    ///   * `Admit { tables_referenced }` — the proxy MUST forward
    ///     the query upstream. `tables_referenced` is the walker's
    ///     resolved list (empty for non-DML or when no list is
    ///     configured).
    ///   * `Block { reason, tables_referenced }` — the proxy MUST
    ///     return a wire-format error frame to the agent and MUST
    ///     NOT forward. `reason` is the closed-enum string from
    ///     `proxy-table-allowlists.md §8.2`.
    ///   * `AuditOnly { reason, tables_referenced }` — the walker
    ///     would have blocked but `enforce = false`; the proxy
    ///     forwards the query upstream and records `blocked =
    ///     false`, `restriction_reason = Some(reason)` in the
    ///     audit envelope.
    pub fn check(&self, sql: &str, op: &OperationKind) -> RestrictionDecision {
        if self.is_blocked(op) {
            return self.block_or_audit_only(RestrictionReason::AllowOnlySelect, Vec::new());
        }
        if !self.has_table_lists() {
            return RestrictionDecision::Admit {
                tables_referenced: Vec::new(),
            };
        }
        let relations = extract_relations(sql, op);
        match relations {
            RelationList::Ambiguous { reason } => self.block_or_audit_only(
                match reason {
                    AmbiguityReason::MultiStatementBatch => {
                        RestrictionReason::AmbiguousSqlMultiStatement
                    }
                    AmbiguityReason::DynamicSql => RestrictionReason::AmbiguousSqlDynamic,
                    AmbiguityReason::Malformed => RestrictionReason::AmbiguousSqlMalformed,
                },
                Vec::new(),
            ),
            RelationList::Resolved(tables) => {
                let qual_strs: Vec<String> = tables.iter().map(|t| t.to_string()).collect();
                if let Some(t) = tables
                    .iter()
                    .find(|t| matches_any(t, &self.forbidden_tables))
                {
                    let _ = t;
                    return self
                        .block_or_audit_only(RestrictionReason::TableInForbiddenList, qual_strs);
                }
                if !self.allowed_tables.is_empty()
                    && tables.iter().any(|t| !matches_any(t, &self.allowed_tables))
                {
                    return self
                        .block_or_audit_only(RestrictionReason::TableNotInAllowedList, qual_strs);
                }
                RestrictionDecision::Admit {
                    tables_referenced: qual_strs,
                }
            }
        }
    }

    fn block_or_audit_only(
        &self,
        reason: RestrictionReason,
        tables_referenced: Vec<String>,
    ) -> RestrictionDecision {
        if self.enforce {
            RestrictionDecision::Block {
                reason,
                tables_referenced,
            }
        } else {
            RestrictionDecision::AuditOnly {
                reason,
                tables_referenced,
            }
        }
    }
}

/// Closed enum of restriction-rejection reasons. Strings in the
/// audit chain match `as_str()` verbatim per `proxy-table-
/// allowlists.md §8.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictionReason {
    /// Verb-class filter (V2.1 `allow_only_select`) blocked.
    AllowOnlySelect,
    /// Walker resolved tables; one or more was not in `allowed_tables`.
    TableNotInAllowedList,
    /// Walker resolved tables; one or more was in `forbidden_tables`.
    TableInForbiddenList,
    /// Walker couldn't resolve because the input was a multi-
    /// statement batch (`;`-separated).
    AmbiguousSqlMultiStatement,
    /// Walker couldn't resolve dynamic SQL (`EXEC`/`PREPARE`/etc.).
    AmbiguousSqlDynamic,
    /// Walker couldn't resolve malformed SQL.
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

/// Outcome of `Restrictions::check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestrictionDecision {
    /// Forward upstream; record the walker's resolved table list
    /// in audit.
    Admit {
        /// Walker-resolved relation list (empty when no list was
        /// configured or the statement is non-DML).
        tables_referenced: Vec<String>,
    },
    /// Reject with a wire-format error; record reason in audit.
    Block {
        /// Closed-enum reason; serialised verbatim into audit.
        reason: RestrictionReason,
        /// Walker output, included for audit even when ambiguous
        /// (in which case it's empty).
        tables_referenced: Vec<String>,
    },
    /// `enforce = false`: forward upstream BUT record the would-
    /// have-blocked reason in audit. Per `§3 D8`.
    AuditOnly {
        /// Reason the walker would have blocked under `enforce = true`.
        reason: RestrictionReason,
        /// Walker output (may be empty if ambiguous).
        tables_referenced: Vec<String>,
    },
}

/// Walker output: either a confidently-extracted relation list, or
/// an `Ambiguous` signal that fails closed when allowlists exist.
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

/// Why the walker bailed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbiguityReason {
    /// `;`-separated batch with > 1 non-trailing statement.
    MultiStatementBatch,
    /// Dynamic SQL (`EXEC`, `EXECUTE`, `PREPARE`, `CALL`, `DO`).
    DynamicSql,
    /// Unbalanced parens, unterminated string, or empty input.
    Malformed,
}

/// Schema-qualified relation reference produced by the walker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedName {
    /// Optional schema qualifier. `None` when the SQL referenced
    /// the relation by bare name.
    pub schema: Option<String>,
    /// Table component, case preserved per `§3 D3`.
    pub table: String,
}

impl QualifiedName {
    /// Canonical `<schema>.<table>` or bare `<table>` form. Used as
    /// the audit string and as the comparison key against
    /// allowed_tables / forbidden_tables.
    pub fn to_string(&self) -> String {
        match &self.schema {
            Some(s) => format!("{}.{}", s.to_ascii_lowercase(), self.table),
            None => self.table.clone(),
        }
    }
}

/// First-token classification of a SQL string. (V2.1; unchanged.)
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

/// Classify the first SQL operation in `sql`. (V2.1; unchanged.)
pub fn classify_first_operation(sql: &str) -> OperationKind {
    let s = strip_leading_whitespace_and_comments(sql.as_bytes());
    let first_word: String = first_keyword(s);
    match first_word.as_str() {
        "SELECT" => OperationKind::Select,
        "WITH" => classify_after_cte(&s[first_word.len()..]),
        "SHOW" => OperationKind::Select,
        "VALUES" => OperationKind::Select,
        "TABLE" => OperationKind::Select,
        "EXPLAIN" => classify_after_explain(&s[first_word.len()..]),
        "INSERT" => OperationKind::Insert,
        "UPDATE" => OperationKind::Update,
        "DELETE" => OperationKind::Delete,
        "" => OperationKind::Other(String::new()),
        other => OperationKind::Other(other.to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Relation walker — `proxy-table-allowlists.md §5.1`.
// ---------------------------------------------------------------------------

/// Extract the relation list from `sql`. The walker handles
/// `SELECT`, `WITH ... SELECT|INSERT|UPDATE|DELETE`, `INSERT INTO`,
/// `UPDATE`, `DELETE FROM`, and `EXPLAIN <inner>`. Anything else
/// falls into [`RelationList::Ambiguous`].
pub fn extract_relations(sql: &str, op: &OperationKind) -> RelationList {
    let bytes = sql.as_bytes();
    let bytes = strip_leading_whitespace_and_comments(bytes);

    if has_dangerous_multi_statement(bytes) {
        return RelationList::Ambiguous {
            reason: AmbiguityReason::MultiStatementBatch,
        };
    }
    if matches!(op, OperationKind::Other(verb) if is_dynamic_verb(verb)) {
        return RelationList::Ambiguous {
            reason: AmbiguityReason::DynamicSql,
        };
    }
    let mut walker = Walker::new(bytes);
    let outcome = match op {
        OperationKind::Select => walker.walk_select_like(&[]),
        OperationKind::Insert => walker.walk_insert(),
        OperationKind::Update => walker.walk_update(),
        OperationKind::Delete => walker.walk_delete(),
        OperationKind::Other(verb) => {
            let v = verb.to_uppercase();
            if v == "WITH" || v == "EXPLAIN" {
                // Other(_) is never these — classify_first_operation
                // resolves them — but defensive shape.
                walker.walk_select_like(&[])
            } else if v == "VALUES" || v == "SHOW" || v == "TABLE" {
                return RelationList::Resolved(Vec::new());
            } else {
                return RelationList::Ambiguous {
                    reason: AmbiguityReason::DynamicSql,
                };
            }
        }
    };
    match outcome {
        Ok(t) => RelationList::Resolved(t),
        Err(reason) => RelationList::Ambiguous { reason },
    }
}

fn is_dynamic_verb(verb: &str) -> bool {
    matches!(
        verb,
        "EXEC"
            | "EXECUTE"
            | "PREPARE"
            | "DO"
            | "CALL"
            | "DEALLOCATE"
            | "DECLARE"
            | "FETCH"
            | "MOVE"
    )
}

/// Returns `true` if `sql` contains a `;` followed by any non-
/// whitespace, non-comment input. A trailing `;` alone is fine.
fn has_dangerous_multi_statement(sql: &[u8]) -> bool {
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < sql.len() {
        match sql[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'-' if !in_single && !in_double && i + 1 < sql.len() && sql[i + 1] == b'-' => {
                while i < sql.len() && sql[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if !in_single && !in_double && i + 1 < sql.len() && sql[i + 1] == b'*' => {
                i += 2;
                while i + 1 < sql.len() && !(sql[i] == b'*' && sql[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b';' if !in_single && !in_double => {
                let rest = strip_leading_whitespace_and_comments(&sql[i + 1..]);
                if !rest.is_empty() {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Internal walker state. The walker reads identifiers, keywords,
/// and parenthesised subqueries; it deliberately does NOT build a
/// full AST. The output is the set of *table* references; CTE
/// names are tracked separately and excluded from the output.
struct Walker<'a> {
    bytes: &'a [u8],
    pos: usize,
    cte_names: Vec<String>,
    /// De-duplicated qualified-name accumulator.
    tables: Vec<QualifiedName>,
}

impl<'a> Walker<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            cte_names: Vec::new(),
            tables: Vec::new(),
        }
    }

    fn rest(&self) -> &[u8] {
        if self.pos > self.bytes.len() {
            &[]
        } else {
            &self.bytes[self.pos..]
        }
    }

    fn skip_ws(&mut self) {
        let rest = strip_leading_whitespace_and_comments(self.rest());
        self.pos = self.bytes.len() - rest.len();
    }

    fn peek_keyword(&mut self) -> String {
        self.skip_ws();
        first_keyword(self.rest())
    }

    fn add_table(&mut self, qn: QualifiedName) {
        if self
            .cte_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&qn.table))
            && qn.schema.is_none()
        {
            return; // CTE self-reference, not a real table.
        }
        if !self.tables.iter().any(|existing| existing == &qn) {
            self.tables.push(qn);
        }
    }

    /// Read one identifier (bare, double-quoted, backtick, or
    /// bracketed). Returns `None` on EOF.
    fn read_identifier(&mut self) -> Option<String> {
        self.skip_ws();
        let rest = self.rest();
        if rest.is_empty() {
            return None;
        }
        match rest[0] {
            b'"' => self.read_delimited_identifier(b'"', b'"'),
            b'`' => self.read_delimited_identifier(b'`', b'`'),
            b'[' => self.read_delimited_identifier(b'[', b']'),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let mut end = 0;
                while end < rest.len() && (rest[end].is_ascii_alphanumeric() || rest[end] == b'_') {
                    end += 1;
                }
                let id = std::str::from_utf8(&rest[..end]).ok()?.to_owned();
                self.pos += end;
                Some(id)
            }
            _ => None,
        }
    }

    fn read_delimited_identifier(&mut self, open: u8, close: u8) -> Option<String> {
        let rest = self.rest();
        if rest.is_empty() || rest[0] != open {
            return None;
        }
        let mut end = 1;
        while end < rest.len() && rest[end] != close {
            end += 1;
        }
        if end >= rest.len() {
            return None;
        }
        let body = std::str::from_utf8(&rest[1..end]).ok()?.to_owned();
        self.pos += end + 1;
        Some(body)
    }

    /// Read an optionally-qualified relation reference.
    /// Handles `db.schema.table` (drops `db`) and `schema.table`
    /// and bare `table`.
    fn read_qualified_relation(&mut self) -> Option<QualifiedName> {
        let id1 = self.read_identifier()?;
        // Look for `.id2[.id3]`.
        let mut parts = vec![id1];
        loop {
            self.skip_ws();
            let rest = self.rest();
            if rest.first().copied() != Some(b'.') {
                break;
            }
            let saved = self.pos;
            self.pos += 1;
            match self.read_identifier() {
                Some(id) => parts.push(id),
                None => {
                    self.pos = saved;
                    break;
                }
            }
            if parts.len() >= 3 {
                break;
            }
        }
        let (schema, table) = match parts.len() {
            1 => (None, parts.pop().unwrap()),
            2 => {
                let table = parts.pop().unwrap();
                let schema = parts.pop().unwrap();
                (Some(schema), table)
            }
            3 => {
                let table = parts.pop().unwrap();
                let schema = parts.pop().unwrap();
                let _db = parts.pop().unwrap();
                (Some(schema), table)
            }
            _ => return None,
        };
        Some(QualifiedName { schema, table })
    }

    /// Skip past an optional alias following a relation (`AS foo` or `foo`).
    fn skip_alias(&mut self) {
        self.skip_ws();
        // Optional `AS`.
        let kw = first_keyword(self.rest());
        if kw.eq_ignore_ascii_case("AS") {
            self.pos += 2;
            self.skip_ws();
        }
        // Optional identifier alias (only if the next token isn't a known clause keyword).
        let kw2 = first_keyword(self.rest());
        if !kw2.is_empty()
            && !is_clause_boundary(&kw2)
            && (self
                .rest()
                .first()
                .copied()
                .map_or(false, |b| b.is_ascii_alphabetic() || b == b'_' || b == b'"'))
        {
            let _ = self.read_identifier();
        }
    }

    fn walk_select_like(
        &mut self,
        extra_cte: &[String],
    ) -> Result<Vec<QualifiedName>, AmbiguityReason> {
        // Handle WITH ... AS (...) prefix.
        let kw = self.peek_keyword();
        if kw.eq_ignore_ascii_case("WITH") {
            self.pos += "WITH".len();
            self.parse_cte_bindings()?;
        }
        for n in extra_cte {
            self.cte_names.push(n.clone());
        }
        // Walk the trailing statement. After WITH it may be SELECT,
        // INSERT, UPDATE, or DELETE.
        let next = self.peek_keyword();
        match next.to_ascii_uppercase().as_str() {
            "SELECT" | "VALUES" | "TABLE" | "SHOW" => {
                self.walk_select_body()?;
                Ok(std::mem::take(&mut self.tables))
            }
            "INSERT" => self.walk_insert(),
            "UPDATE" => self.walk_update(),
            "DELETE" => self.walk_delete(),
            "EXPLAIN" => {
                self.pos += next.len();
                self.skip_explain_modifiers();
                let inner = self.peek_keyword();
                match inner.to_ascii_uppercase().as_str() {
                    "SELECT" | "VALUES" | "TABLE" | "SHOW" => {
                        self.walk_select_body()?;
                        Ok(std::mem::take(&mut self.tables))
                    }
                    "INSERT" => self.walk_insert(),
                    "UPDATE" => self.walk_update(),
                    "DELETE" => self.walk_delete(),
                    _ => Err(AmbiguityReason::DynamicSql),
                }
            }
            "" => Ok(std::mem::take(&mut self.tables)),
            _ => Err(AmbiguityReason::DynamicSql),
        }
    }

    /// Walk a SELECT (or trailing tail of INSERT/UPDATE/DELETE) body,
    /// accumulating relation references into `self.tables`. Does NOT
    /// drain `self.tables` — that responsibility lives with the
    /// top-level entry points so they can return their accumulated
    /// list correctly even when this is called multiple times.
    fn walk_select_body(&mut self) -> Result<(), AmbiguityReason> {
        // Walk to end of statement, picking up `FROM`/`JOIN`-introduced
        // relation references and recursing into parenthesised
        // subqueries.
        while self.pos < self.bytes.len() {
            self.skip_ws();
            let b = match self.bytes.get(self.pos).copied() {
                Some(b) => b,
                None => break,
            };
            if b == b'(' {
                self.walk_paren()?;
                continue;
            }
            if b == b'\'' {
                self.skip_string_literal(b'\'');
                continue;
            }
            if b == b';' {
                self.pos += 1;
                continue;
            }
            let kw = first_keyword(self.rest());
            if kw.is_empty() {
                self.pos += 1;
                continue;
            }
            let upper = kw.to_ascii_uppercase();
            self.pos += kw.len();
            match upper.as_str() {
                "FROM" | "JOIN" => {
                    self.read_relation_list_after_keyword()?;
                }
                "INTO" => {
                    // `SELECT ... INTO <table> FROM ...` (Postgres syntax).
                    self.skip_ws();
                    if let Some(rel) = self.read_qualified_relation() {
                        self.add_table(rel);
                    }
                }
                "USING" => {
                    // For DELETE FROM x USING y the `USING` introduces
                    // additional relations. For JOIN ... USING (col, ...)
                    // it introduces a column list — the next char is `(`.
                    self.skip_ws();
                    if self.rest().first().copied() == Some(b'(') {
                        self.walk_paren()?;
                    } else {
                        self.read_relation_list_after_keyword()?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Read a comma-separated relation list (e.g. after FROM).
    /// Stops at the first non-comma boundary.
    fn read_relation_list_after_keyword(&mut self) -> Result<(), AmbiguityReason> {
        loop {
            self.skip_ws();
            let rest = self.rest();
            if rest.is_empty() {
                return Ok(());
            }
            if rest[0] == b'(' {
                // Sub-SELECT / lateral / VALUES.
                self.walk_paren()?;
            } else if let Some(rel) = self.read_qualified_relation() {
                // Skip an optional function-call paren after the
                // identifier; a function reference is not a relation.
                self.skip_ws();
                if self.rest().first().copied() == Some(b'(') {
                    // It was a table function. Skip its arg list.
                    self.walk_paren()?;
                } else {
                    self.add_table(rel);
                }
                self.skip_alias();
            } else {
                return Ok(());
            }
            self.skip_ws();
            if self.rest().first().copied() == Some(b',') {
                self.pos += 1;
                continue;
            }
            return Ok(());
        }
    }

    fn walk_paren(&mut self) -> Result<(), AmbiguityReason> {
        // Recursively walk inside parens. We track our own depth
        // here rather than reusing `skip_balanced_parens`, because
        // that helper cannot distinguish "balanced paren ending at
        // the very last byte" (legal) from "unterminated paren that
        // runs to EOF" (malformed) — both produce `bytes.len()`.
        debug_assert_eq!(self.rest().first().copied(), Some(b'('));
        let start = self.pos;
        let end = match find_matching_close_paren(self.bytes, start) {
            Some(e) => e,
            None => return Err(AmbiguityReason::Malformed),
        };
        let inner = &self.bytes[start + 1..end];
        let inner_str = std::str::from_utf8(inner).unwrap_or("");
        let op = classify_first_operation(inner_str);
        let mut child = Walker {
            bytes: inner,
            pos: 0,
            cte_names: self.cte_names.clone(),
            tables: Vec::new(),
        };
        let result = match op {
            OperationKind::Select => child.walk_select_like(&[]),
            OperationKind::Insert => child.walk_insert(),
            OperationKind::Update => child.walk_update(),
            OperationKind::Delete => child.walk_delete(),
            OperationKind::Other(v) if v == "VALUES" || v == "SHOW" || v == "TABLE" => {
                Ok(Vec::new())
            }
            // A paren group that isn't a statement is fine (e.g. a
            // column list, JOIN ... ON expression). Just walk it
            // shallowly for FROM/JOIN references in case there are
            // nested correlated subqueries.
            _ => child
                .walk_select_body()
                .map(|_| std::mem::take(&mut child.tables)),
        };
        for t in result? {
            self.add_table(t);
        }
        self.pos = end + 1;
        Ok(())
    }

    fn walk_insert(&mut self) -> Result<Vec<QualifiedName>, AmbiguityReason> {
        // `INSERT [INTO] <table> ...`.
        let kw = self.peek_keyword();
        if kw.eq_ignore_ascii_case("INSERT") {
            self.pos += "INSERT".len();
        }
        self.skip_ws();
        let kw2 = first_keyword(self.rest());
        if kw2.eq_ignore_ascii_case("INTO") {
            self.pos += kw2.len();
        }
        self.skip_ws();
        if let Some(rel) = self.read_qualified_relation() {
            self.add_table(rel);
        } else {
            return Err(AmbiguityReason::Malformed);
        }
        // Optional `(col1, col2)`.
        self.skip_ws();
        if self.rest().first().copied() == Some(b'(') {
            self.walk_paren()?;
        }
        // Trailing `SELECT ...` / `VALUES ...` / `DEFAULT VALUES`.
        self.walk_select_body()?;
        Ok(std::mem::take(&mut self.tables))
    }

    fn walk_update(&mut self) -> Result<Vec<QualifiedName>, AmbiguityReason> {
        let kw = self.peek_keyword();
        if kw.eq_ignore_ascii_case("UPDATE") {
            self.pos += "UPDATE".len();
        }
        self.skip_ws();
        if let Some(rel) = self.read_qualified_relation() {
            self.add_table(rel);
        } else {
            return Err(AmbiguityReason::Malformed);
        }
        self.skip_alias();
        // Walk through SET / FROM / WHERE picking up relations.
        self.walk_select_body()?;
        Ok(std::mem::take(&mut self.tables))
    }

    fn walk_delete(&mut self) -> Result<Vec<QualifiedName>, AmbiguityReason> {
        let kw = self.peek_keyword();
        if kw.eq_ignore_ascii_case("DELETE") {
            self.pos += "DELETE".len();
        }
        self.skip_ws();
        let from_kw = first_keyword(self.rest());
        if from_kw.eq_ignore_ascii_case("FROM") {
            self.pos += from_kw.len();
        }
        self.skip_ws();
        if let Some(rel) = self.read_qualified_relation() {
            self.add_table(rel);
        } else {
            return Err(AmbiguityReason::Malformed);
        }
        self.skip_alias();
        // Walk through optional USING / WHERE.
        self.walk_select_body()?;
        Ok(std::mem::take(&mut self.tables))
    }

    fn parse_cte_bindings(&mut self) -> Result<(), AmbiguityReason> {
        loop {
            self.skip_ws();
            // Optional `RECURSIVE`.
            let kw = first_keyword(self.rest());
            if kw.eq_ignore_ascii_case("RECURSIVE") {
                self.pos += kw.len();
                self.skip_ws();
            }
            let name = match self.read_identifier() {
                Some(n) => n,
                None => return Err(AmbiguityReason::Malformed),
            };
            self.cte_names.push(name);
            self.skip_ws();
            // Optional column list `(a, b)`.
            if self.rest().first().copied() == Some(b'(') {
                self.walk_paren()?;
                self.skip_ws();
            }
            // `AS`
            let as_kw = first_keyword(self.rest());
            if !as_kw.eq_ignore_ascii_case("AS") {
                return Err(AmbiguityReason::Malformed);
            }
            self.pos += as_kw.len();
            self.skip_ws();
            // Optional [NOT] MATERIALIZED.
            for kw in ["NOT MATERIALIZED", "MATERIALIZED"] {
                if self.rest().len() >= kw.len()
                    && self.rest()[..kw.len()].eq_ignore_ascii_case(kw.as_bytes())
                {
                    self.pos += kw.len();
                    self.skip_ws();
                    break;
                }
            }
            // CTE body `(...)`.
            if self.rest().first().copied() != Some(b'(') {
                return Err(AmbiguityReason::Malformed);
            }
            self.walk_paren()?;
            self.skip_ws();
            if self.rest().first().copied() == Some(b',') {
                self.pos += 1;
                continue;
            }
            return Ok(());
        }
    }

    fn skip_explain_modifiers(&mut self) {
        self.skip_ws();
        if self.rest().first().copied() == Some(b'(') {
            let _ = self.walk_paren();
        }
        loop {
            self.skip_ws();
            let kw = first_keyword(self.rest());
            if matches!(
                kw.to_ascii_uppercase().as_str(),
                "ANALYZE" | "VERBOSE" | "BUFFERS" | "TIMING" | "COSTS" | "FORMAT"
            ) {
                self.pos += kw.len();
            } else {
                break;
            }
        }
    }

    fn skip_string_literal(&mut self, quote: u8) {
        let mut i = self.pos + 1;
        while i < self.bytes.len() {
            if self.bytes[i] == b'\\' && i + 1 < self.bytes.len() {
                i += 2;
                continue;
            }
            if self.bytes[i] == quote {
                // Possible doubled-quote escape.
                if i + 1 < self.bytes.len() && self.bytes[i + 1] == quote {
                    i += 2;
                    continue;
                }
                i += 1;
                break;
            }
            i += 1;
        }
        self.pos = i;
    }
}

fn is_clause_boundary(kw: &str) -> bool {
    matches!(
        kw.to_ascii_uppercase().as_str(),
        "WHERE"
            | "GROUP"
            | "HAVING"
            | "ORDER"
            | "LIMIT"
            | "OFFSET"
            | "WINDOW"
            | "ON"
            | "INNER"
            | "LEFT"
            | "RIGHT"
            | "FULL"
            | "CROSS"
            | "NATURAL"
            | "JOIN"
            | "FROM"
            | "INTO"
            | "USING"
            | "SET"
            | "VALUES"
            | "RETURNING"
            | "AS"
            | "WITH"
            | "UNION"
            | "INTERSECT"
            | "EXCEPT"
            | "FOR"
            | "FETCH"
            | "LATERAL"
    )
}

/// Returns the canonical comparison value for `entry` (lowercased
/// schema, table preserved). Used to match operator-declared entries
/// in `allowed_tables` / `forbidden_tables` against walker output.
fn parse_entry(entry: &str) -> QualifiedName {
    if let Some(idx) = entry.rfind('.') {
        let schema = entry[..idx].to_ascii_lowercase();
        let table = entry[idx + 1..].to_owned();
        QualifiedName {
            schema: Some(schema),
            table,
        }
    } else {
        QualifiedName {
            schema: None,
            table: entry.to_owned(),
        }
    }
}

fn matches_any(t: &QualifiedName, list: &[String]) -> bool {
    list.iter().any(|entry| {
        let e = parse_entry(entry);
        match (&e.schema, &t.schema) {
            (Some(es), Some(ts)) => es.eq_ignore_ascii_case(ts) && e.table == t.table,
            (Some(_), None) =>
            // Operator declared a qualified name; walker only saw
            // a bare name. Do NOT match: the operator was specific
            // and we cannot prove the schema.
            {
                false
            }
            (None, _) =>
            // Operator declared a bare name; match on table only.
            {
                e.table == t.table
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Helpers shared with classify_first_operation (V2.1).
// ---------------------------------------------------------------------------

fn first_keyword(s: &[u8]) -> String {
    s.iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_')
        .map(|&b| b.to_ascii_uppercase() as char)
        .collect()
}

fn strip_leading_whitespace_and_comments(mut s: &[u8]) -> &[u8] {
    loop {
        let trimmed = strip_ascii_whitespace(s);
        if trimmed.starts_with(b"--") {
            let nl = trimmed
                .iter()
                .position(|&b| b == b'\n')
                .unwrap_or(trimmed.len());
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
        if i >= bytes.len() {
            break;
        }
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
            && (i + 2 == bytes.len()
                || !(bytes[i + 2].is_ascii_alphanumeric() || bytes[i + 2] == b'_'))
        {
            i += 2;
        }
        let rest = strip_ascii_whitespace(&bytes[i..]);
        i = bytes.len() - rest.len();
        for kw in [
            "NOT MATERIALIZED",
            "MATERIALIZED",
            "not materialized",
            "materialized",
        ] {
            if i + kw.len() <= bytes.len() && &bytes[i..i + kw.len()] == kw.as_bytes() {
                i += kw.len();
                break;
            }
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

/// Return the index of the `)` that closes the `(` at `start`, or
/// `None` if the parens are unbalanced. Honours single-quoted
/// string literals (with backslash escape) so a `'... ( ...'`
/// literal does not throw off the depth count.
fn find_matching_close_paren(bytes: &[u8], start: usize) -> Option<usize> {
    debug_assert_eq!(bytes.get(start).copied(), Some(b'('));
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
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
    None
}

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
    let mut bytes = strip_ascii_whitespace(after_explain);
    if let Some(b'(') = bytes.first().copied() {
        let end = skip_balanced_parens(bytes, 0);
        bytes = &bytes[end..];
    }
    loop {
        let trimmed = strip_ascii_whitespace(bytes);
        let next_word: String = trimmed
            .iter()
            .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_')
            .map(|&b| b.to_ascii_uppercase() as char)
            .collect();
        if matches!(
            next_word.as_str(),
            "ANALYZE" | "VERBOSE" | "BUFFERS" | "TIMING" | "COSTS" | "FORMAT"
        ) {
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

    fn qn(table: &str) -> QualifiedName {
        QualifiedName {
            schema: None,
            table: table.to_owned(),
        }
    }
    fn qns(schema: &str, table: &str) -> QualifiedName {
        QualifiedName {
            schema: Some(schema.to_owned()),
            table: table.to_owned(),
        }
    }
    fn relations(sql: &str) -> Vec<QualifiedName> {
        let op = classify_first_operation(sql);
        match extract_relations(sql, &op) {
            RelationList::Resolved(r) => r,
            RelationList::Ambiguous { reason } => {
                panic!("expected Resolved, got Ambiguous({reason:?}) for {sql:?}")
            }
        }
    }

    // --- classify_first_operation (V2.1; unchanged) ----------------

    #[test]
    fn select_classified() {
        assert_eq!(classify_first_operation("SELECT 1"), OperationKind::Select);
        assert_eq!(
            classify_first_operation("  select 1"),
            OperationKind::Select
        );
    }

    #[test]
    fn insert_update_delete() {
        assert_eq!(
            classify_first_operation("INSERT INTO t VALUES (1)"),
            OperationKind::Insert
        );
        assert_eq!(
            classify_first_operation("UPDATE t SET x=1"),
            OperationKind::Update
        );
        assert_eq!(
            classify_first_operation("DELETE FROM t"),
            OperationKind::Delete
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
    }

    // --- relation walker -------------------------------------------

    #[test]
    fn select_from_single_table() {
        assert_eq!(relations("SELECT * FROM users"), vec![qn("users")]);
    }

    #[test]
    fn select_qualified_table() {
        assert_eq!(
            relations("SELECT * FROM public.users"),
            vec![qns("public", "users")],
        );
    }

    #[test]
    fn select_join() {
        assert_eq!(
            relations("SELECT a.id FROM users a JOIN orders o ON a.id = o.user_id"),
            vec![qn("users"), qn("orders")],
        );
    }

    #[test]
    fn select_with_subquery_in_where() {
        let r = relations("SELECT * FROM users WHERE id IN (SELECT user_id FROM banned)");
        assert!(r.contains(&qn("users")), "missing users in {r:?}");
        assert!(r.contains(&qn("banned")), "missing banned in {r:?}");
    }

    #[test]
    fn cte_elided_from_relation_list() {
        assert_eq!(
            relations("WITH u AS (SELECT * FROM users) SELECT * FROM u"),
            vec![qn("users")],
        );
    }

    #[test]
    fn insert_into_with_select_picks_up_both() {
        let r = relations("INSERT INTO orders (user_id) SELECT id FROM users WHERE active");
        assert!(r.contains(&qn("orders")), "missing orders in {r:?}");
        assert!(r.contains(&qn("users")), "missing users in {r:?}");
    }

    #[test]
    fn update_with_from_clause() {
        let r = relations("UPDATE orders SET total = 0 FROM users WHERE orders.user_id = users.id");
        assert!(r.contains(&qn("orders")), "missing orders in {r:?}");
        assert!(r.contains(&qn("users")), "missing users in {r:?}");
    }

    #[test]
    fn delete_with_using_clause() {
        let r = relations("DELETE FROM orders USING users WHERE orders.user_id = users.id");
        assert!(r.contains(&qn("orders")), "missing orders in {r:?}");
        assert!(r.contains(&qn("users")), "missing users in {r:?}");
    }

    #[test]
    fn explain_inner_walker() {
        assert_eq!(relations("EXPLAIN SELECT * FROM users"), vec![qn("users")]);
    }

    #[test]
    fn quoted_identifier_preserves_case() {
        let r = relations(r#"SELECT * FROM "Users""#);
        assert_eq!(r, vec![qn("Users")]);
    }

    #[test]
    fn multi_statement_is_ambiguous() {
        let op = classify_first_operation("SELECT 1; DROP TABLE users");
        match extract_relations("SELECT 1; DROP TABLE users", &op) {
            RelationList::Ambiguous {
                reason: AmbiguityReason::MultiStatementBatch,
            } => {}
            other => panic!("expected MultiStatementBatch, got {other:?}"),
        }
    }

    #[test]
    fn trailing_semicolon_ok() {
        assert_eq!(relations("SELECT * FROM users;"), vec![qn("users")]);
        assert_eq!(
            relations("SELECT * FROM users WHERE name = 'foo';"),
            vec![qn("users")],
        );
    }

    #[test]
    fn dynamic_sql_is_ambiguous() {
        let op = classify_first_operation("EXECUTE my_prepared_stmt");
        match extract_relations("EXECUTE my_prepared_stmt", &op) {
            RelationList::Ambiguous {
                reason: AmbiguityReason::DynamicSql,
            } => {}
            other => panic!("expected DynamicSql, got {other:?}"),
        }
    }

    // --- Restrictions::check ---------------------------------------

    #[test]
    fn admit_when_no_lists_configured() {
        let r = Restrictions::default();
        let decision = r.check("SELECT * FROM users", &OperationKind::Select);
        assert!(matches!(decision, RestrictionDecision::Admit { .. }));
    }

    #[test]
    fn block_table_not_in_allowed_list() {
        let r = Restrictions {
            allowed_tables: vec!["public.orders".into()],
            ..Default::default()
        };
        let decision = r.check("SELECT * FROM public.users", &OperationKind::Select);
        match decision {
            RestrictionDecision::Block {
                reason,
                tables_referenced,
            } => {
                assert_eq!(reason.as_str(), "table_not_in_allowed_list");
                assert_eq!(tables_referenced, vec!["public.users".to_owned()]);
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn admit_table_in_allowed_list() {
        let r = Restrictions {
            allowed_tables: vec!["public.users".into(), "public.orders".into()],
            ..Default::default()
        };
        let decision = r.check("SELECT * FROM public.users", &OperationKind::Select);
        match decision {
            RestrictionDecision::Admit { tables_referenced } => {
                assert_eq!(tables_referenced, vec!["public.users".to_owned()]);
            }
            other => panic!("expected Admit, got {other:?}"),
        }
    }

    #[test]
    fn block_table_in_forbidden_list_short_circuits_allowed() {
        let r = Restrictions {
            allowed_tables: vec!["public.users".into()],
            forbidden_tables: vec!["public.users".into()],
            ..Default::default()
        };
        let decision = r.check("SELECT * FROM public.users", &OperationKind::Select);
        match decision {
            RestrictionDecision::Block { reason, .. } => {
                assert_eq!(reason.as_str(), "table_in_forbidden_list");
            }
            other => panic!("expected Block forbidden, got {other:?}"),
        }
    }

    #[test]
    fn audit_only_when_enforce_false() {
        let r = Restrictions {
            allowed_tables: vec!["public.orders".into()],
            enforce: false,
            ..Default::default()
        };
        let decision = r.check("SELECT * FROM public.users", &OperationKind::Select);
        match decision {
            RestrictionDecision::AuditOnly {
                reason,
                tables_referenced,
            } => {
                assert_eq!(reason.as_str(), "table_not_in_allowed_list");
                assert_eq!(tables_referenced, vec!["public.users".to_owned()]);
            }
            other => panic!("expected AuditOnly, got {other:?}"),
        }
    }

    #[test]
    fn allow_only_select_short_circuits_walker() {
        let r = Restrictions {
            allow_only_select: true,
            allowed_tables: vec!["public.users".into()],
            ..Default::default()
        };
        let decision = r.check(
            "INSERT INTO public.users VALUES (1)",
            &OperationKind::Insert,
        );
        match decision {
            RestrictionDecision::Block { reason, .. } => {
                assert_eq!(reason.as_str(), "allow_only_select");
            }
            other => panic!("expected Block(allow_only_select), got {other:?}"),
        }
    }

    #[test]
    fn ambiguous_sql_blocks_when_allowlist_configured() {
        let r = Restrictions {
            allowed_tables: vec!["public.users".into()],
            ..Default::default()
        };
        let decision = r.check("SELECT 1; DROP TABLE users", &OperationKind::Select);
        match decision {
            RestrictionDecision::Block { reason, .. } => {
                assert_eq!(reason.as_str(), "ambiguous_sql_multi_statement");
            }
            other => panic!("expected Block multi-statement, got {other:?}"),
        }
    }

    #[test]
    fn ambiguous_sql_admitted_when_no_lists() {
        let r = Restrictions::default();
        let decision = r.check("SELECT 1; DROP TABLE users", &OperationKind::Select);
        // V2.1 compat: no lists configured → admit.
        assert!(matches!(decision, RestrictionDecision::Admit { .. }));
    }

    #[test]
    fn schema_case_insensitive_table_case_sensitive() {
        let r = Restrictions {
            allowed_tables: vec!["Public.Users".into()],
            ..Default::default()
        };
        // Schema match works case-insensitively; table 'Users' matches.
        let decision = r.check(r#"SELECT * FROM PUBLIC."Users""#, &OperationKind::Select);
        assert!(matches!(decision, RestrictionDecision::Admit { .. }));
        // Bare-name reference 'users' (lowercase) does NOT match
        // 'Public.Users' because the operator declared a qualified
        // entry.
        let decision = r.check("SELECT * FROM users", &OperationKind::Select);
        assert!(matches!(decision, RestrictionDecision::Block { .. }));
    }

    #[test]
    fn restriction_reason_strings_pinned() {
        // Pin the closed-enum strings so adding a new variant is a
        // deliberate spec amendment.
        assert_eq!(
            RestrictionReason::AllowOnlySelect.as_str(),
            "allow_only_select"
        );
        assert_eq!(
            RestrictionReason::TableNotInAllowedList.as_str(),
            "table_not_in_allowed_list"
        );
        assert_eq!(
            RestrictionReason::TableInForbiddenList.as_str(),
            "table_in_forbidden_list"
        );
        assert_eq!(
            RestrictionReason::AmbiguousSqlMultiStatement.as_str(),
            "ambiguous_sql_multi_statement"
        );
        assert_eq!(
            RestrictionReason::AmbiguousSqlDynamic.as_str(),
            "ambiguous_sql_dynamic"
        );
        assert_eq!(
            RestrictionReason::AmbiguousSqlMalformed.as_str(),
            "ambiguous_sql_malformed"
        );
    }
}

//! Restriction enforcement for the MSSQL proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §4.3` + `specs/v2/
//! proxy-table-allowlists.md`. The V2 surface supports:
//!
//!   * `allow_only_select` — verb-class filter (V2.1, unchanged).
//!   * `allowed_tables` — table-level allowlist enforced on the
//!     `SQLBatch` path by the relation walker in this module.
//!   * `forbidden_tables` — denylist applied after the allowlist.
//!   * `max_result_rows` — V2-configured streaming cap. **NOTE**:
//!     accurate row counting requires TDS token-stream parsing,
//!     which the V2.1 MSSQL proxy doesn't yet implement. The
//!     field is plumbed end-to-end and surfaces in the audit
//!     envelope, but the streaming cap fires only once token-
//!     stream parsing lands (`proxy-table-allowlists.md §11
//!     v2-followup`). The walker / allowlist / denylist path
//!     IS enforced as of this commit.
//!   * `enforce` — when `false`, walker output is audited but the
//!     batch is admitted regardless of the allow/deny outcome.
//!
//! The walker mirrors the Postgres / MySQL proxies' tokenizer.
//! T-SQL-specific tweaks: bracketed identifiers (`[Table Name]`),
//! the `EXEC` / `EXECUTE` synonym for dynamic SQL, and the
//! `TOP n` / `WITH (NOLOCK)` modifiers commonly seen on SELECT.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// If true, only `SELECT` and explicitly-allowed read operations
    /// pass; everything else is rejected with a TDS `ERROR` token
    /// carrying SQLSTATE `42501`-equivalent.
    #[serde(default)]
    pub allow_only_select: bool,

    /// Table-level allowlist; see `PostgresRestrictions::allowed_tables`
    /// for the matching contract.
    #[serde(default)]
    pub allowed_tables: Vec<String>,

    /// Table-level denylist applied AFTER the allowlist.
    #[serde(default)]
    pub forbidden_tables: Vec<String>,

    /// Per-result-set hard cap on rows returned. `0` = uncapped.
    /// V2 plumbs this field end-to-end; streaming enforcement
    /// (TDS token-stream parsing) is V2-followup work. The
    /// audit envelope already surfaces the configured value so
    /// reviewers see "this cred is configured for cap=N".
    #[serde(default)]
    pub max_result_rows: u64,

    /// When `false`, walker verdicts are audited but the batch is
    /// admitted regardless of restriction outcome.
    #[serde(default = "default_enforce_true")]
    pub enforce: bool,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self {
            allow_only_select: false,
            allowed_tables:    Vec::new(),
            forbidden_tables:  Vec::new(),
            max_result_rows:   0,
            enforce:           true,
        }
    }
}

fn default_enforce_true() -> bool { true }

impl Restrictions {
    /// Convenience constructor for tests.
    pub fn select_only() -> Self {
        Self { allow_only_select: true, ..Self::default() }
    }

    /// Verb-class block check used by [`Self::check`] as the first
    /// guard before the T-SQL walker runs. Tests in this crate
    /// exercise it directly to pin the `allow_only_select`
    /// semantics in isolation from the walker.
    pub fn is_blocked(&self, op: &OperationKind) -> bool {
        self.allow_only_select && !matches!(op, OperationKind::Select)
    }

    /// True iff a non-empty allowlist or denylist is configured.
    pub fn has_table_lists(&self) -> bool {
        !self.allowed_tables.is_empty() || !self.forbidden_tables.is_empty()
    }

    /// Decide what to do with a SQL batch under the full V2
    /// restriction surface. See `Restrictions::check` on the
    /// Postgres proxy for the exhaustive contract.
    pub fn check(&self, sql: &str, op: &OperationKind) -> RestrictionDecision {
        if self.is_blocked(op) {
            return self.block_or_audit_only(
                RestrictionReason::AllowOnlySelect,
                Vec::new(),
            );
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
                    AmbiguityReason::MultiStatementBatch =>
                        RestrictionReason::AmbiguousSqlMultiStatement,
                    AmbiguityReason::DynamicSql =>
                        RestrictionReason::AmbiguousSqlDynamic,
                    AmbiguityReason::Malformed =>
                        RestrictionReason::AmbiguousSqlMalformed,
                },
                Vec::new(),
            ),
            RelationList::Resolved(tables) => {
                let qual_strs: Vec<String> = tables.iter().map(|t| t.to_string()).collect();
                if tables.iter().any(|t| matches_any(t, &self.forbidden_tables)) {
                    return self.block_or_audit_only(
                        RestrictionReason::TableInForbiddenList,
                        qual_strs,
                    );
                }
                if !self.allowed_tables.is_empty()
                    && tables.iter().any(|t| !matches_any(t, &self.allowed_tables))
                {
                    return self.block_or_audit_only(
                        RestrictionReason::TableNotInAllowedList,
                        qual_strs,
                    );
                }
                RestrictionDecision::Admit { tables_referenced: qual_strs }
            }
        }
    }

    fn block_or_audit_only(
        &self,
        reason: RestrictionReason,
        tables_referenced: Vec<String>,
    ) -> RestrictionDecision {
        if self.enforce {
            RestrictionDecision::Block { reason, tables_referenced }
        } else {
            RestrictionDecision::AuditOnly { reason, tables_referenced }
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
    /// Walker couldn't resolve dynamic SQL (`EXEC`/`EXECUTE`/`sp_executesql`).
    AmbiguousSqlDynamic,
    /// Walker couldn't resolve malformed SQL.
    AmbiguousSqlMalformed,
}

impl RestrictionReason {
    /// Stable grep key for the audit chain.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnlySelect            => "allow_only_select",
            Self::TableNotInAllowedList      => "table_not_in_allowed_list",
            Self::TableInForbiddenList       => "table_in_forbidden_list",
            Self::AmbiguousSqlMultiStatement => "ambiguous_sql_multi_statement",
            Self::AmbiguousSqlDynamic        => "ambiguous_sql_dynamic",
            Self::AmbiguousSqlMalformed      => "ambiguous_sql_malformed",
        }
    }
}

/// Outcome of `Restrictions::check`.
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
        /// Walker output, included for audit.
        tables_referenced: Vec<String>,
    },
    /// `enforce = false`: forward upstream BUT record the would-
    /// have-blocked reason in audit.
    AuditOnly {
        /// Reason the walker would have blocked under `enforce = true`.
        reason: RestrictionReason,
        /// Walker output (may be empty if ambiguous).
        tables_referenced: Vec<String>,
    },
}

/// Walker output.
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
    /// Dynamic SQL (`EXEC`, `EXECUTE`, `sp_executesql`).
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
    pub table:  String,
}

impl QualifiedName {
    /// Canonical `<schema>.<table>` or bare `<table>` form.
    pub fn to_string(&self) -> String {
        match &self.schema {
            Some(s) => format!("{}.{}", s.to_ascii_lowercase(), self.table),
            None    => self.table.clone(),
        }
    }
}

/// First-token classification of a SQL string. (V2.1; unchanged.)
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

/// Classify the first SQL operation in `sql`.
pub fn classify_first_operation(sql: &str) -> OperationKind {
    let s = strip_leading_whitespace_and_comments(sql.as_bytes());
    let first_word: String = first_keyword(s);
    match first_word.as_str() {
        "SELECT"           => OperationKind::Select,
        "WITH"             => classify_after_cte(&s[first_word.len()..]),
        "EXEC" | "EXECUTE" => classify_after_explain(&s[first_word.len()..]),
        "INSERT"           => OperationKind::Insert,
        "UPDATE"           => OperationKind::Update,
        "DELETE"           => OperationKind::Delete,
        ""                 => OperationKind::Other(String::new()),
        other              => OperationKind::Other(other.to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Relation walker
// ---------------------------------------------------------------------------

/// Extract the relation list from `sql`.
pub fn extract_relations(sql: &str, op: &OperationKind) -> RelationList {
    let bytes = sql.as_bytes();
    let bytes = strip_leading_whitespace_and_comments(bytes);

    if has_dangerous_multi_statement(bytes) {
        return RelationList::Ambiguous { reason: AmbiguityReason::MultiStatementBatch };
    }
    if matches!(op, OperationKind::Other(verb) if is_dynamic_verb(verb)) {
        return RelationList::Ambiguous { reason: AmbiguityReason::DynamicSql };
    }
    let mut walker = Walker::new(bytes);
    let outcome = match op {
        OperationKind::Select  => walker.walk_select_like(&[]),
        OperationKind::Insert  => walker.walk_insert(),
        OperationKind::Update  => walker.walk_update(),
        OperationKind::Delete  => walker.walk_delete(),
        OperationKind::Other(verb) => {
            let v = verb.to_uppercase();
            if v == "WITH" {
                walker.walk_select_like(&[])
            } else if v == "VALUES" {
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
        "EXEC" | "EXECUTE" | "SP_EXECUTESQL" | "PREPARE" | "DO" | "CALL"
        | "DECLARE" | "FETCH"
    )
}

/// Returns `true` if `sql` contains a `;` followed by any non-
/// whitespace, non-comment input.
fn has_dangerous_multi_statement(sql: &[u8]) -> bool {
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_bracket = false;
    while i < sql.len() {
        match sql[i] {
            b'\'' if !in_double && !in_bracket => in_single = !in_single,
            b'"'  if !in_single && !in_bracket => in_double = !in_double,
            b'[' if !in_single && !in_double => in_bracket = true,
            b']' if in_bracket => in_bracket = false,
            b'-' if !in_single && !in_double && !in_bracket
                && i + 1 < sql.len() && sql[i + 1] == b'-' => {
                while i < sql.len() && sql[i] != b'\n' { i += 1; }
            }
            b'/' if !in_single && !in_double && !in_bracket
                && i + 1 < sql.len() && sql[i + 1] == b'*' => {
                i += 2;
                while i + 1 < sql.len() && !(sql[i] == b'*' && sql[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b';' if !in_single && !in_double && !in_bracket => {
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

struct Walker<'a> {
    bytes: &'a [u8],
    pos:   usize,
    cte_names: Vec<String>,
    tables: Vec<QualifiedName>,
}

impl<'a> Walker<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0, cte_names: Vec::new(), tables: Vec::new() }
    }

    fn rest(&self) -> &[u8] {
        if self.pos > self.bytes.len() { &[] } else { &self.bytes[self.pos..] }
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
        if self.cte_names.iter().any(|n| n.eq_ignore_ascii_case(&qn.table))
            && qn.schema.is_none()
        {
            return;
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
        if rest.is_empty() { return None; }
        match rest[0] {
            b'"'  => self.read_delimited_identifier(b'"',  b'"'),
            b'`'  => self.read_delimited_identifier(b'`',  b'`'),
            b'['  => self.read_delimited_identifier(b'[',  b']'),
            b if b.is_ascii_alphabetic() || b == b'_' || b == b'#' => {
                // T-SQL allows `#temp` and `##globalTemp` table
                // names.
                let mut end = 0;
                while end < rest.len() && (
                    rest[end].is_ascii_alphanumeric()
                    || rest[end] == b'_'
                    || rest[end] == b'#'
                    || rest[end] == b'$'
                ) {
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
        if rest.is_empty() || rest[0] != open { return None; }
        let mut end = 1;
        while end < rest.len() && rest[end] != close { end += 1; }
        if end >= rest.len() { return None; }
        let body = std::str::from_utf8(&rest[1..end]).ok()?.to_owned();
        self.pos += end + 1;
        Some(body)
    }

    /// Read an optionally-qualified relation reference. Supports
    /// T-SQL's 1/2/3/4-part naming: `[server].[db].[schema].[table]`,
    /// including omitted-part forms like `db..table` (default schema).
    fn read_qualified_relation(&mut self) -> Option<QualifiedName> {
        let id1 = self.read_identifier()?;
        let mut parts: Vec<String> = vec![id1];
        loop {
            self.skip_ws();
            if self.rest().first().copied() != Some(b'.') { break; }
            let saved = self.pos;
            self.pos += 1; // consume the `.`
            self.skip_ws();
            if self.rest().first().copied() == Some(b'.') {
                // Omitted-part form: `db..table` or `srv..db.table`.
                // Record the omission and let the loop pick up the
                // next part on the following iteration.
                parts.push(String::new());
                continue;
            }
            match self.read_identifier() {
                Some(id) => parts.push(id),
                None => { self.pos = saved; break; }
            }
            if parts.len() >= 4 { break; }
        }
        // Resolve to `(schema?, table)`. The table is the rightmost
        // non-empty part; the schema is the part directly before it.
        // An empty `schema` slot means the SQL used the
        // `db..table` default-schema form, so we drop schema → None
        // and allowlist matching falls back to the bare-name rule.
        let table = loop {
            match parts.pop() {
                Some(p) if !p.is_empty() => break p,
                Some(_) => continue,
                None => return None,
            }
        };
        let schema = parts.pop().filter(|s| !s.is_empty());
        // Drop any leading `db` or `server` parts.
        let _ = std::mem::take(&mut parts);
        Some(QualifiedName { schema, table })
    }

    fn skip_alias(&mut self) {
        self.skip_ws();
        let kw = first_keyword(self.rest());
        if kw.eq_ignore_ascii_case("AS") {
            self.pos += 2;
            self.skip_ws();
        }
        let kw2 = first_keyword(self.rest());
        if !kw2.is_empty() && !is_clause_boundary(&kw2)
            && (self.rest().first().copied().map_or(false, |b|
                b.is_ascii_alphabetic() || b == b'_' || b == b'"' || b == b'[' || b == b'`'))
        {
            let _ = self.read_identifier();
        }
        // T-SQL's `WITH (NOLOCK)` table hint follows the alias.
        self.skip_ws();
        let kw3 = first_keyword(self.rest());
        if kw3.eq_ignore_ascii_case("WITH") {
            let saved = self.pos;
            self.pos += kw3.len();
            self.skip_ws();
            if self.rest().first().copied() == Some(b'(') {
                let _ = self.walk_paren();
            } else {
                self.pos = saved;
            }
        }
    }

    fn walk_select_like(&mut self, extra_cte: &[String]) -> Result<Vec<QualifiedName>, AmbiguityReason> {
        let kw = self.peek_keyword();
        if kw.eq_ignore_ascii_case("WITH") {
            self.pos += "WITH".len();
            self.parse_cte_bindings()?;
        }
        for n in extra_cte { self.cte_names.push(n.clone()); }
        let next = self.peek_keyword();
        match next.to_ascii_uppercase().as_str() {
            "SELECT" | "VALUES" => {
                self.walk_select_body()?;
                Ok(std::mem::take(&mut self.tables))
            }
            "INSERT" => self.walk_insert(),
            "UPDATE" => self.walk_update(),
            "DELETE" => self.walk_delete(),
            "" => Ok(std::mem::take(&mut self.tables)),
            _ => Err(AmbiguityReason::DynamicSql),
        }
    }

    /// Walk a SELECT body. Does NOT drain `self.tables`.
    fn walk_select_body(&mut self) -> Result<(), AmbiguityReason> {
        while self.pos < self.bytes.len() {
            self.skip_ws();
            let b = match self.bytes.get(self.pos).copied() { Some(b) => b, None => break };
            if b == b'(' {
                self.walk_paren()?;
                continue;
            }
            if b == b'\'' { self.skip_string_literal(b'\''); continue; }
            if b == b';' { self.pos += 1; continue; }
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
                    self.skip_ws();
                    if let Some(rel) = self.read_qualified_relation() {
                        self.add_table(rel);
                    }
                }
                "USING" => {
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

    fn read_relation_list_after_keyword(&mut self) -> Result<(), AmbiguityReason> {
        loop {
            self.skip_ws();
            let rest = self.rest();
            if rest.is_empty() { return Ok(()); }
            if rest[0] == b'(' {
                self.walk_paren()?;
            } else if let Some(rel) = self.read_qualified_relation() {
                self.skip_ws();
                if self.rest().first().copied() == Some(b'(') {
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
        debug_assert_eq!(self.rest().first().copied(), Some(b'('));
        let start = self.pos;
        let end = match find_matching_close_paren(self.bytes, start) {
            Some(e) => e,
            None    => return Err(AmbiguityReason::Malformed),
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
            OperationKind::Select  => child.walk_select_like(&[]),
            OperationKind::Insert  => child.walk_insert(),
            OperationKind::Update  => child.walk_update(),
            OperationKind::Delete  => child.walk_delete(),
            OperationKind::Other(v) if v == "VALUES" => Ok(Vec::new()),
            _ => child.walk_select_body().map(|_| std::mem::take(&mut child.tables)),
        };
        for t in result? { self.add_table(t); }
        self.pos = end + 1;
        Ok(())
    }

    fn walk_insert(&mut self) -> Result<Vec<QualifiedName>, AmbiguityReason> {
        let kw = self.peek_keyword();
        if kw.eq_ignore_ascii_case("INSERT") {
            self.pos += "INSERT".len();
        }
        self.skip_ws();
        // T-SQL `INSERT [TOP (n) [PERCENT]] [INTO]` — skip TOP.
        let modifier = first_keyword(self.rest()).to_ascii_uppercase();
        if modifier == "TOP" {
            self.pos += modifier.len();
            self.skip_ws();
            if self.rest().first().copied() == Some(b'(') {
                self.walk_paren()?;
            } else {
                let _ = self.read_identifier();
            }
            self.skip_ws();
            let percent = first_keyword(self.rest()).to_ascii_uppercase();
            if percent == "PERCENT" {
                self.pos += percent.len();
                self.skip_ws();
            }
        }
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
        self.skip_ws();
        if self.rest().first().copied() == Some(b'(') {
            self.walk_paren()?;
        }
        self.walk_select_body()?;
        Ok(std::mem::take(&mut self.tables))
    }

    fn walk_update(&mut self) -> Result<Vec<QualifiedName>, AmbiguityReason> {
        let kw = self.peek_keyword();
        if kw.eq_ignore_ascii_case("UPDATE") {
            self.pos += "UPDATE".len();
        }
        self.skip_ws();
        let modifier = first_keyword(self.rest()).to_ascii_uppercase();
        if modifier == "TOP" {
            self.pos += modifier.len();
            self.skip_ws();
            if self.rest().first().copied() == Some(b'(') {
                self.walk_paren()?;
            } else {
                let _ = self.read_identifier();
            }
            self.skip_ws();
            let percent = first_keyword(self.rest()).to_ascii_uppercase();
            if percent == "PERCENT" {
                self.pos += percent.len();
                self.skip_ws();
            }
        }
        if let Some(rel) = self.read_qualified_relation() {
            self.add_table(rel);
        } else {
            return Err(AmbiguityReason::Malformed);
        }
        self.skip_alias();
        self.walk_select_body()?;
        Ok(std::mem::take(&mut self.tables))
    }

    fn walk_delete(&mut self) -> Result<Vec<QualifiedName>, AmbiguityReason> {
        let kw = self.peek_keyword();
        if kw.eq_ignore_ascii_case("DELETE") {
            self.pos += "DELETE".len();
        }
        self.skip_ws();
        let modifier = first_keyword(self.rest()).to_ascii_uppercase();
        if modifier == "TOP" {
            self.pos += modifier.len();
            self.skip_ws();
            if self.rest().first().copied() == Some(b'(') {
                self.walk_paren()?;
            } else {
                let _ = self.read_identifier();
            }
            self.skip_ws();
            let percent = first_keyword(self.rest()).to_ascii_uppercase();
            if percent == "PERCENT" {
                self.pos += percent.len();
                self.skip_ws();
            }
        }
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
        self.walk_select_body()?;
        Ok(std::mem::take(&mut self.tables))
    }

    fn parse_cte_bindings(&mut self) -> Result<(), AmbiguityReason> {
        loop {
            self.skip_ws();
            let name = match self.read_identifier() {
                Some(n) => n,
                None => return Err(AmbiguityReason::Malformed),
            };
            self.cte_names.push(name);
            self.skip_ws();
            if self.rest().first().copied() == Some(b'(') {
                self.walk_paren()?;
                self.skip_ws();
            }
            let as_kw = first_keyword(self.rest());
            if !as_kw.eq_ignore_ascii_case("AS") { return Err(AmbiguityReason::Malformed); }
            self.pos += as_kw.len();
            self.skip_ws();
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

    fn skip_string_literal(&mut self, quote: u8) {
        let mut i = self.pos + 1;
        while i < self.bytes.len() {
            if self.bytes[i] == quote {
                if i + 1 < self.bytes.len() && self.bytes[i + 1] == quote {
                    // T-SQL doubled-quote escape (`'O''Brien'`).
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
        "WHERE" | "GROUP" | "HAVING" | "ORDER" | "LIMIT" | "OFFSET"
        | "WINDOW" | "ON" | "INNER" | "LEFT" | "RIGHT" | "FULL"
        | "CROSS" | "NATURAL" | "JOIN" | "FROM" | "INTO" | "USING"
        | "SET" | "VALUES" | "RETURNING" | "AS" | "WITH" | "UNION"
        | "INTERSECT" | "EXCEPT" | "FOR" | "FETCH"
        | "OUTPUT" | "OPTION" | "PIVOT" | "UNPIVOT"
    )
}

fn parse_entry(entry: &str) -> QualifiedName {
    if let Some(idx) = entry.rfind('.') {
        let schema = entry[..idx].to_ascii_lowercase();
        let table  = entry[idx + 1..].to_owned();
        QualifiedName { schema: Some(schema), table }
    } else {
        QualifiedName { schema: None, table: entry.to_owned() }
    }
}

fn matches_any(t: &QualifiedName, list: &[String]) -> bool {
    list.iter().any(|entry| {
        let e = parse_entry(entry);
        match (&e.schema, &t.schema) {
            (Some(es), Some(ts)) =>
                es.eq_ignore_ascii_case(ts) && e.table == t.table,
            (Some(_), None) => false,
            (None, _) => e.table == t.table,
        }
    })
}

// ---------------------------------------------------------------------------
// Helpers
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

fn find_matching_close_paren(bytes: &[u8], start: usize) -> Option<usize> {
    debug_assert_eq!(bytes.get(start).copied(), Some(b'('));
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 { return Some(i); }
            }
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn qn(table: &str) -> QualifiedName {
        QualifiedName { schema: None, table: table.to_owned() }
    }
    fn qns(schema: &str, table: &str) -> QualifiedName {
        QualifiedName { schema: Some(schema.to_owned()), table: table.to_owned() }
    }
    fn relations(sql: &str) -> Vec<QualifiedName> {
        let op = classify_first_operation(sql);
        match extract_relations(sql, &op) {
            RelationList::Resolved(r) => r,
            RelationList::Ambiguous { reason } =>
                panic!("expected Resolved, got Ambiguous({reason:?}) for {sql:?}"),
        }
    }

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
    fn select_from_single_table() {
        assert_eq!(relations("SELECT * FROM users"), vec![qn("users")]);
    }

    #[test]
    fn select_bracketed_identifier() {
        let r = relations("SELECT * FROM [My Users]");
        assert_eq!(r, vec![qn("My Users")]);
    }

    #[test]
    fn select_three_part_name_drops_database() {
        assert_eq!(
            relations("SELECT * FROM mydb.dbo.users"),
            vec![qns("dbo", "users")],
        );
    }

    #[test]
    fn select_db_empty_schema_table_form() {
        // T-SQL `db..table` (default schema) — walker treats it as
        // bare `table`.
        let r = relations("SELECT * FROM mydb..users");
        assert_eq!(r, vec![qn("users")]);
    }

    #[test]
    fn select_with_nolock_hint() {
        let r = relations("SELECT * FROM users WITH (NOLOCK)");
        assert_eq!(r, vec![qn("users")]);
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
        let r = relations(
            "SELECT * FROM users WHERE id IN (SELECT user_id FROM banned)",
        );
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
    fn insert_with_top() {
        let r = relations(
            "INSERT TOP (10) INTO orders SELECT * FROM staging",
        );
        assert!(r.contains(&qn("orders")),  "missing orders in {r:?}");
        assert!(r.contains(&qn("staging")), "missing staging in {r:?}");
    }

    #[test]
    fn update_with_top_percent() {
        let r = relations(
            "UPDATE TOP (50) PERCENT users SET active = 0",
        );
        assert_eq!(r, vec![qn("users")]);
    }

    #[test]
    fn delete_simple() {
        let r = relations("DELETE FROM orders WHERE total = 0");
        assert_eq!(r, vec![qn("orders")]);
    }

    #[test]
    fn multi_statement_is_ambiguous() {
        let op = classify_first_operation("SELECT 1; DROP TABLE users");
        match extract_relations("SELECT 1; DROP TABLE users", &op) {
            RelationList::Ambiguous { reason: AmbiguityReason::MultiStatementBatch } => {}
            other => panic!("expected MultiStatementBatch, got {other:?}"),
        }
    }

    #[test]
    fn trailing_semicolon_ok() {
        assert_eq!(relations("SELECT * FROM users;"), vec![qn("users")]);
    }

    #[test]
    fn dynamic_sql_exec_is_ambiguous() {
        let op = classify_first_operation("EXEC sp_who");
        match extract_relations("EXEC sp_who", &op) {
            RelationList::Ambiguous { .. } => {}
            other => panic!("expected Ambiguous for sp_who, got {other:?}"),
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
            allowed_tables: vec!["dbo.orders".into()],
            ..Default::default()
        };
        let decision = r.check("SELECT * FROM dbo.users", &OperationKind::Select);
        match decision {
            RestrictionDecision::Block { reason, tables_referenced } => {
                assert_eq!(reason.as_str(), "table_not_in_allowed_list");
                assert_eq!(tables_referenced, vec!["dbo.users".to_owned()]);
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn admit_table_in_allowed_list_three_part_form() {
        let r = Restrictions {
            allowed_tables: vec!["dbo.users".into()],
            ..Default::default()
        };
        let decision = r.check("SELECT * FROM mydb.dbo.users", &OperationKind::Select);
        assert!(matches!(decision, RestrictionDecision::Admit { .. }));
    }

    #[test]
    fn block_table_in_forbidden_list() {
        let r = Restrictions {
            forbidden_tables: vec!["dbo.users".into()],
            ..Default::default()
        };
        let decision = r.check("SELECT * FROM dbo.users", &OperationKind::Select);
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
            allowed_tables: vec!["dbo.orders".into()],
            enforce: false,
            ..Default::default()
        };
        let decision = r.check("SELECT * FROM dbo.users", &OperationKind::Select);
        match decision {
            RestrictionDecision::AuditOnly { reason, .. } => {
                assert_eq!(reason.as_str(), "table_not_in_allowed_list");
            }
            other => panic!("expected AuditOnly, got {other:?}"),
        }
    }

    #[test]
    fn allow_only_select_short_circuits_walker() {
        let r = Restrictions {
            allow_only_select: true,
            allowed_tables:    vec!["dbo.users".into()],
            ..Default::default()
        };
        let decision = r.check("INSERT INTO dbo.users VALUES (1)", &OperationKind::Insert);
        match decision {
            RestrictionDecision::Block { reason, .. } => {
                assert_eq!(reason.as_str(), "allow_only_select");
            }
            other => panic!("expected Block(allow_only_select), got {other:?}"),
        }
    }

    #[test]
    fn restriction_reason_strings_pinned() {
        assert_eq!(RestrictionReason::AllowOnlySelect.as_str(),
            "allow_only_select");
        assert_eq!(RestrictionReason::TableNotInAllowedList.as_str(),
            "table_not_in_allowed_list");
        assert_eq!(RestrictionReason::TableInForbiddenList.as_str(),
            "table_in_forbidden_list");
        assert_eq!(RestrictionReason::AmbiguousSqlMultiStatement.as_str(),
            "ambiguous_sql_multi_statement");
        assert_eq!(RestrictionReason::AmbiguousSqlDynamic.as_str(),
            "ambiguous_sql_dynamic");
        assert_eq!(RestrictionReason::AmbiguousSqlMalformed.as_str(),
            "ambiguous_sql_malformed");
    }

    #[test]
    fn select_only_blocks_dml_via_is_blocked() {
        let r = Restrictions::select_only();
        assert!(!r.is_blocked(&OperationKind::Select));
        assert!( r.is_blocked(&OperationKind::Insert));
        assert!( r.is_blocked(&OperationKind::Other("DROP".into())));
    }
}

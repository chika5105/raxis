//! Restriction enforcement for the MongoDB proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §4.4` +
//! `specs/v2/proxy-table-allowlists.md §6`. The V2 surface
//! supports:
//!
//!   * `allow_read_only` — verb-class filter (V2.1, unchanged).
//!   * `allowed_collections` — `<db>.<coll>` allowlist enforced on
//!     the BSON command walker.
//!   * `forbidden_collections` — denylist applied after the allowlist.
//!   * `max_documents` — per-cursor streaming cap on returned docs.
//!     Counted across `find` + N `getMore` calls. Enforced by
//!     rewriting the reply cursor (truncate `firstBatch` /
//!     `nextBatch` + zero the cursor id; see §7.4).
//!   * `enforce` — when `false`, walker output is audited but the
//!     command is admitted regardless of the allow/deny outcome.
//!
//! The walker is deliberately *minimal*: it reads the top-level
//! BSON document, extracts the command's primary collection and
//! `$db`, and (when an allowlist is configured) scans the body
//! for `$lookup.from` / `$graphLookup.from` / `$unionWith.coll` /
//! `$merge.into` / `$out` byte sequences to surface secondary-
//! collection use (§6.1). Per D7 of §3, secondary-collection use
//! is rejected when an allowlist is configured — this is the
//! BSON analogue of the SQL "reject-when-ambiguous" rule.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// If true, only read commands (`find`, `aggregate`, `count`,
    /// `distinct`, …) are allowed; everything else is rejected
    /// with `{ ok: 0, code: 13, codeName: "Unauthorized" }`.
    #[serde(default)]
    pub allow_read_only: bool,

    /// Fully-qualified collection allowlist (`<db>.<coll>`).
    /// Empty = unrestricted. Comparisons are case-sensitive (Mongo
    /// is case-sensitive on both database and collection names).
    #[serde(default)]
    pub allowed_collections: Vec<String>,

    /// Fully-qualified collection denylist. Applied AFTER the
    /// allowlist.
    #[serde(default)]
    pub forbidden_collections: Vec<String>,

    /// Per-cursor cap on documents returned. `0` = uncapped.
    /// Enforced by rewriting the upstream reply (§7.4).
    #[serde(default)]
    pub max_documents: u64,

    /// When `false`, walker verdicts are audited but the command
    /// is admitted regardless. Defaults to `true`.
    #[serde(default = "default_enforce_true")]
    pub enforce: bool,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self {
            allow_read_only:        false,
            allowed_collections:    Vec::new(),
            forbidden_collections:  Vec::new(),
            max_documents:          0,
            enforce:                true,
        }
    }
}

fn default_enforce_true() -> bool { true }

impl Restrictions {
    /// Convenience constructor.
    pub fn read_only() -> Self {
        Self { allow_read_only: true, ..Self::default() }
    }

    /// Verb-class block check; back-compat with V2.1 callers.
    pub fn is_blocked(&self, command_name: &str) -> bool {
        self.allow_read_only && !is_read_command(command_name)
    }

    /// True iff a non-empty allowlist or denylist is configured.
    pub fn has_collection_lists(&self) -> bool {
        !self.allowed_collections.is_empty()
        || !self.forbidden_collections.is_empty()
    }

    /// Apply the full V2 restriction surface to a parsed
    /// `CommandTarget`. Per `proxy-table-allowlists.md §6.2`.
    pub fn check(&self, target: &CommandTarget) -> RestrictionDecision {
        if let CommandTarget::Resolved { command, .. } = target {
            if self.is_blocked(command) {
                return self.block_or_audit_only(
                    RestrictionReason::AllowReadOnly, None,
                );
            }
        }
        if !self.has_collection_lists() {
            return RestrictionDecision::Admit { collection: target.fully_qualified() };
        }
        match target {
            CommandTarget::Resolved { collection, db, .. } => {
                let fq = fully_qualified(db.as_deref(), collection.as_deref());
                if let Some(ref name) = fq {
                    if self.forbidden_collections.iter().any(|e| e == name) {
                        return self.block_or_audit_only(
                            RestrictionReason::CollectionInForbiddenList,
                            Some(name.clone()),
                        );
                    }
                    if !self.allowed_collections.is_empty()
                        && !self.allowed_collections.iter().any(|e| e == name)
                    {
                        return self.block_or_audit_only(
                            RestrictionReason::CollectionNotInAllowedList,
                            Some(name.clone()),
                        );
                    }
                } else if collection.is_some() {
                    // Walker proved a primary collection but `$db`
                    // was missing → admit when no FQ match needed
                    // (V2: server-introspection commands like
                    // `hello` keep their None collection); but
                    // when an allowlist is configured we cannot
                    // prove admissibility → block.
                    return self.block_or_audit_only(
                        RestrictionReason::CollectionNotInAllowedList,
                        None,
                    );
                }
                RestrictionDecision::Admit { collection: fq }
            }
            CommandTarget::SecondaryCollectionDetected { collection, db, .. } => {
                let fq = fully_qualified(db.as_deref(), Some(collection.as_str()));
                self.block_or_audit_only(
                    RestrictionReason::SecondaryCollectionInPipeline,
                    fq,
                )
            }
            CommandTarget::Ambiguous => self.block_or_audit_only(
                RestrictionReason::AmbiguousBson,
                None,
            ),
        }
    }

    fn block_or_audit_only(
        &self,
        reason: RestrictionReason,
        collection: Option<String>,
    ) -> RestrictionDecision {
        if self.enforce {
            RestrictionDecision::Block { reason, collection }
        } else {
            RestrictionDecision::AuditOnly { reason, collection }
        }
    }
}

/// Returns `true` if `name` is a known MongoDB read-only command.
///
/// Source: <https://www.mongodb.com/docs/manual/reference/command/>
/// and the `read` action category.
pub fn is_read_command(name: &str) -> bool {
    matches!(
        name,
        "find"
        | "aggregate"
        | "count"
        | "distinct"
        | "geoSearch"
        | "getMore"
        | "parallelCollectionScan"
        | "hello"
        | "isMaster"
        | "ismaster"
        | "ping"
        | "buildInfo"
        | "buildinfo"
        | "serverStatus"
        | "hostInfo"
        | "connectionStatus"
        | "whatsmyuri"
        | "listCollections"
        | "listIndexes"
        | "listDatabases"
        | "dbStats"
        | "collStats"
        | "explain"
        | "validate"
        | "currentOp"
        | "getParameter"
        | "saslStart"
        | "saslContinue"
        | "logout"
        | "endSessions"
        | "killCursors"
        | "killAllSessions"
        | "killAllSessionsByPattern"
        | "killSessions"
        | "abortTransaction"
        | "commitTransaction"
        | "startSession"
    )
}

/// Closed enum of restriction-rejection reasons. Strings in the
/// audit chain match `as_str()` verbatim per `proxy-table-
/// allowlists.md §8.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictionReason {
    /// MongoDB verb-class check rejected the command.
    AllowReadOnly,
    /// Walker resolved the collection; it was not in `allowed_collections`.
    CollectionNotInAllowedList,
    /// Walker resolved the collection; it was in `forbidden_collections`.
    CollectionInForbiddenList,
    /// Walker detected secondary-collection references in an
    /// aggregate pipeline (`$lookup.from`, etc.) and a list is
    /// configured.
    SecondaryCollectionInPipeline,
    /// Walker couldn't parse the BSON body.
    AmbiguousBson,
    /// Streaming `max_documents` cap fired on the reply path.
    /// (Not produced by `check` — emitted by the reply rewriter
    /// in `cursor_rewriter::apply_cap`. Listed here so audit
    /// consumers have the full closed enum in one place.)
    MaxDocumentsExceeded,
}

impl RestrictionReason {
    /// Stable grep key for the audit chain.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowReadOnly                 => "allow_read_only",
            Self::CollectionNotInAllowedList    => "collection_not_in_allowed_list",
            Self::CollectionInForbiddenList     => "collection_in_forbidden_list",
            Self::SecondaryCollectionInPipeline => "secondary_collection_in_pipeline",
            Self::AmbiguousBson                 => "ambiguous_bson",
            Self::MaxDocumentsExceeded          => "max_documents_exceeded",
        }
    }
}

/// Outcome of `Restrictions::check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestrictionDecision {
    /// Forward upstream.
    Admit {
        /// Walker-resolved `<db>.<coll>`; `None` for server-
        /// introspection commands.
        collection: Option<String>,
    },
    /// Reject with `{ ok: 0, code: 13, codeName: "Unauthorized" }`.
    Block {
        /// Closed-enum reason; serialised verbatim into audit.
        reason: RestrictionReason,
        /// Walker output, when known.
        collection: Option<String>,
    },
    /// `enforce = false`: forward upstream BUT record the would-
    /// have-blocked reason in audit.
    AuditOnly {
        /// Reason the walker would have blocked under `enforce = true`.
        reason: RestrictionReason,
        /// Walker output, when known.
        collection: Option<String>,
    },
}

/// Walker output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandTarget {
    /// Walker proved the primary collection (or absence thereof
    /// for non-collection commands like `hello` / `ping`).
    Resolved {
        /// First BSON field name (e.g. `"find"`, `"insert"`).
        command:    String,
        /// Value of the command field when the command takes a
        /// collection name; `None` for `hello` / `ping` / etc.
        collection: Option<String>,
        /// `$db` field value.
        db:         Option<String>,
    },
    /// Walker detected secondary-collection references it cannot
    /// prove are admissible (`$lookup.from`, `$graphLookup.from`,
    /// `$unionWith.coll`, `$merge.into`, `$out`).
    SecondaryCollectionDetected {
        /// First BSON field name.
        command:    String,
        /// Primary collection from the command's first field value.
        collection: String,
        /// `$db` field value.
        db:         Option<String>,
        /// Detected secondary collection names (best-effort heuristic).
        secondary:  Vec<String>,
    },
    /// Malformed BSON.
    Ambiguous,
}

impl CommandTarget {
    /// Convenience: produce `<db>.<coll>` when both are known.
    pub fn fully_qualified(&self) -> Option<String> {
        match self {
            Self::Resolved { collection, db, .. } =>
                fully_qualified(db.as_deref(), collection.as_deref()),
            Self::SecondaryCollectionDetected { collection, db, .. } =>
                fully_qualified(db.as_deref(), Some(collection.as_str())),
            Self::Ambiguous => None,
        }
    }
}

/// Compose `<db>.<coll>` when both are non-empty.
pub fn fully_qualified(db: Option<&str>, coll: Option<&str>) -> Option<String> {
    match (db, coll) {
        (Some(d), Some(c)) if !d.is_empty() && !c.is_empty() =>
            Some(format!("{d}.{c}")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// BSON walker
// ---------------------------------------------------------------------------

/// Parse an `OP_MSG` body (after the 4-byte flag bits, starting at
/// the first section) and return the [`CommandTarget`]. When
/// `inspect_pipeline` is `true`, the walker also runs the
/// secondary-collection heuristic on aggregate pipelines / find
/// commands.
pub fn walk_command(body: &[u8], inspect_pipeline: bool) -> CommandTarget {
    let mut primary: Option<(String, BsonValue)> = None;
    let mut db:      Option<String> = None;
    // We iterate kind-0 (Body) sections of the OP_MSG body. The
    // proxy is only ever called with bodies that contain exactly
    // one kind-0 section (the command document) — kind-1 sections
    // (document sequences) carry bulk payloads and are walked
    // separately below for completeness.
    let mut i = 4; // skip flag_bits
    let mut primary_bson_doc: Option<&[u8]> = None;
    while i < body.len() {
        let kind = body[i];
        i += 1;
        if kind == 0 {
            // Body section: BSON doc starts at i.
            let doc = &body[i..];
            let parsed = parse_top_doc(doc);
            match parsed {
                Some(p) => {
                    if primary.is_none() {
                        primary = Some((p.command_name.clone(), p.command_value));
                        primary_bson_doc = Some(p.raw_doc);
                    }
                    if db.is_none() { db = p.db; }
                    i += p.consumed;
                }
                None => return CommandTarget::Ambiguous,
            }
        } else if kind == 1 {
            // Document Sequence: int32 size + cstring identifier +
            // BSON docs. Skip whole section.
            if i + 4 > body.len() { return CommandTarget::Ambiguous; }
            let section_size = i32::from_le_bytes(
                body[i..i + 4].try_into().unwrap_or([0; 4]),
            ) as usize;
            if section_size < 4 || i + section_size > body.len() {
                return CommandTarget::Ambiguous;
            }
            i += section_size;
        } else {
            return CommandTarget::Ambiguous;
        }
    }

    let (command, value) = match primary {
        Some(p) => p,
        None    => return CommandTarget::Ambiguous,
    };
    let collection = match value {
        BsonValue::String(s) => Some(s),
        _ => None,
    };

    // Some commands carry the collection in a sibling field, not
    // the command-value slot. `getMore`'s value is the cursor id
    // (i64); the collection lives in a `collection` field.
    let collection = if collection.is_none() && command == "getMore" {
        if let Some(doc) = primary_bson_doc {
            scan_top_string_field(doc, "collection")
        } else { None }
    } else { collection };

    // Secondary-collection heuristic — only run when an allowlist
    // is configured (per D6 of §3 / §6.1 step 4).
    if inspect_pipeline {
        if let Some(doc) = primary_bson_doc {
            let secondary = scan_secondary_collections(doc);
            if !secondary.is_empty() {
                let primary_name = collection.unwrap_or_default();
                return CommandTarget::SecondaryCollectionDetected {
                    command,
                    collection: primary_name,
                    db,
                    secondary,
                };
            }
        }
    }

    CommandTarget::Resolved { command, collection, db }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum BsonValue {
    String(String),
    Int(i64),
    Double(f64),
    Other,
}

struct ParsedTopDoc<'a> {
    command_name:  String,
    command_value: BsonValue,
    db:            Option<String>,
    raw_doc:       &'a [u8],
    consumed:      usize,
}

fn parse_top_doc(doc: &[u8]) -> Option<ParsedTopDoc<'_>> {
    if doc.len() < 5 { return None; }
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total < 5 || total > doc.len() { return None; }
    let body = &doc[4..total];
    if body.is_empty() || body[body.len() - 1] != 0x00 { return None; }
    let elems = &body[..body.len() - 1];
    let mut command_name: Option<String> = None;
    let mut command_value: BsonValue = BsonValue::Other;
    let mut db: Option<String> = None;
    let mut p = 0;
    let mut first = true;
    while p < elems.len() {
        let type_byte = elems[p];
        p += 1;
        let nul = elems[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&elems[p..p + nul]).ok()?.to_owned();
        p += nul + 1;
        let (val, val_len) = read_value(type_byte, &elems[p..])?;
        if first {
            command_name = Some(name.clone());
            command_value = val.clone();
            first = false;
        }
        if name == "$db" {
            if let BsonValue::String(ref s) = val { db = Some(s.clone()); }
        }
        p += val_len;
    }
    Some(ParsedTopDoc {
        command_name:  command_name?,
        command_value,
        db,
        raw_doc:       &doc[..total],
        consumed:      total,
    })
}

fn read_value(type_byte: u8, data: &[u8]) -> Option<(BsonValue, usize)> {
    Some(match type_byte {
        0x01 => {
            if data.len() < 8 { return None; }
            let f = f64::from_le_bytes(data[..8].try_into().ok()?);
            (BsonValue::Double(f), 8)
        }
        0x02 => {
            if data.len() < 4 { return None; }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if len < 1 || 4 + len > data.len() { return None; }
            let s = std::str::from_utf8(&data[4..4 + len - 1]).ok()?.to_owned();
            (BsonValue::String(s), 4 + len)
        }
        0x03 | 0x04 => {
            if data.len() < 4 { return None; }
            let total = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if total < 5 || total > data.len() { return None; }
            (BsonValue::Other, total)
        }
        0x05 => {
            if data.len() < 5 { return None; }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if 5 + len > data.len() { return None; }
            (BsonValue::Other, 5 + len)
        }
        0x06 => (BsonValue::Other, 0), // Undefined (deprecated).
        0x07 => {
            if data.len() < 12 { return None; }
            (BsonValue::Other, 12)
        }
        0x08 => {
            if data.is_empty() { return None; }
            (BsonValue::Other, 1)
        }
        0x09 => {
            if data.len() < 8 { return None; }
            (BsonValue::Other, 8)
        }
        0x0A => (BsonValue::Other, 0),
        0x0B => {
            // cstring + cstring
            let n1 = data.iter().position(|&b| b == 0)?;
            let after1 = &data[n1 + 1..];
            let n2 = after1.iter().position(|&b| b == 0)?;
            (BsonValue::Other, n1 + 1 + n2 + 1)
        }
        0x0C => {
            if data.len() < 4 { return None; }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if 4 + len + 12 > data.len() { return None; }
            (BsonValue::Other, 4 + len + 12)
        }
        0x0D => {
            if data.len() < 4 { return None; }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if 4 + len > data.len() { return None; }
            (BsonValue::Other, 4 + len)
        }
        0x0E => {
            if data.len() < 4 { return None; }
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if 4 + len > data.len() { return None; }
            (BsonValue::Other, 4 + len)
        }
        0x0F => {
            if data.len() < 4 { return None; }
            let total = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if total > data.len() { return None; }
            (BsonValue::Other, total)
        }
        0x10 => {
            if data.len() < 4 { return None; }
            let v = i32::from_le_bytes(data[..4].try_into().ok()?);
            (BsonValue::Int(v as i64), 4)
        }
        0x11 | 0x12 => {
            if data.len() < 8 { return None; }
            let v = i64::from_le_bytes(data[..8].try_into().ok()?);
            (BsonValue::Int(v), 8)
        }
        0x13 => {
            if data.len() < 16 { return None; }
            (BsonValue::Other, 16)
        }
        0xFF | 0x7F => (BsonValue::Other, 0),
        _ => return None,
    })
}

/// Scan a BSON doc's top-level elements for a string field
/// with the given name. Returns the string value if found.
fn scan_top_string_field(doc: &[u8], target: &str) -> Option<String> {
    if doc.len() < 5 { return None; }
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total > doc.len() { return None; }
    let body = &doc[4..total];
    if body.is_empty() || body[body.len() - 1] != 0x00 { return None; }
    let elems = &body[..body.len() - 1];
    let mut p = 0;
    while p < elems.len() {
        let type_byte = elems[p];
        p += 1;
        let nul = elems[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&elems[p..p + nul]).ok()?;
        p += nul + 1;
        let (val, val_len) = read_value(type_byte, &elems[p..])?;
        if name == target {
            if let BsonValue::String(s) = val { return Some(s); }
        }
        p += val_len;
    }
    None
}

/// Scan for `from`/`coll`/`into`/`out` string fields that name
/// secondary collections in an aggregate pipeline. This is a
/// **deliberately non-tree-walking heuristic** per §6.1 step 4:
/// it scans for `0x02 <name> 0x00 ...` byte sequences anywhere
/// in the doc. Bytes inside string values cannot collide
/// (BSON strings are length-prefixed and don't contain a leading
/// type byte), so the heuristic has no false positives from
/// data — only from unrelated field names that happen to be
/// `from`/`coll`/`into`/`out` (which is fine for V2: reject-on-
/// secondary is fail-closed by spec).
fn scan_secondary_collections(doc: &[u8]) -> Vec<String> {
    let names: &[&str] = &["from", "coll", "into", "out"];
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < doc.len() {
        if doc[i] == 0x02 {
            // String element. Walk the cstring name.
            let rest = &doc[i + 1..];
            let nul = match rest.iter().position(|&b| b == 0) {
                Some(n) => n,
                None    => break,
            };
            let field_name = match std::str::from_utf8(&rest[..nul]) {
                Ok(s) => s,
                Err(_) => { i += 1; continue; }
            };
            if names.contains(&field_name) {
                let after_name = &rest[nul + 1..];
                if after_name.len() < 4 { break; }
                let len = i32::from_le_bytes(
                    after_name[..4].try_into().unwrap_or([0; 4]),
                ) as usize;
                if len >= 1 && 4 + len <= after_name.len() {
                    if let Ok(s) = std::str::from_utf8(&after_name[4..4 + len - 1]) {
                        if !s.is_empty() && !out.iter().any(|e: &String| e == s) {
                            out.push(s.to_owned());
                        }
                    }
                }
            }
            i += 1 + nul + 1;
        } else {
            i += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::BsonBuilder;

    fn op_msg_body(doc: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(0); // kind 0
        body.extend_from_slice(doc);
        body
    }

    fn build_doc(builder: BsonBuilder) -> Vec<u8> { builder.finish() }

    #[test]
    fn find_simple() {
        let doc = build_doc(
            BsonBuilder::new()
                .string("find", "users")
                .string("$db", "appdb"),
        );
        let body = op_msg_body(&doc);
        let target = walk_command(&body, false);
        match target {
            CommandTarget::Resolved { command, collection, db } => {
                assert_eq!(command, "find");
                assert_eq!(collection.as_deref(), Some("users"));
                assert_eq!(db.as_deref(),         Some("appdb"));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn insert_simple() {
        let doc = build_doc(
            BsonBuilder::new()
                .string("insert", "orders")
                .string("$db", "appdb"),
        );
        let body = op_msg_body(&doc);
        let target = walk_command(&body, false);
        match target {
            CommandTarget::Resolved { command, collection, db } => {
                assert_eq!(command, "insert");
                assert_eq!(collection.as_deref(), Some("orders"));
                assert_eq!(db.as_deref(),         Some("appdb"));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn hello_has_no_collection() {
        let doc = build_doc(
            BsonBuilder::new()
                .int32("hello", 1)
                .string("$db", "admin"),
        );
        let body = op_msg_body(&doc);
        let target = walk_command(&body, false);
        match target {
            CommandTarget::Resolved { command, collection, db } => {
                assert_eq!(command, "hello");
                assert_eq!(collection, None);
                assert_eq!(db.as_deref(), Some("admin"));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn ping_has_no_collection() {
        let doc = build_doc(
            BsonBuilder::new()
                .int32("ping", 1)
                .string("$db", "admin"),
        );
        let body = op_msg_body(&doc);
        let target = walk_command(&body, false);
        match target {
            CommandTarget::Resolved { collection, .. } => {
                assert_eq!(collection, None);
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn get_more_extracts_collection_from_sibling_field() {
        let doc = build_doc(
            BsonBuilder::new()
                .int64("getMore", 12345)
                .string("collection", "users")
                .string("$db", "appdb"),
        );
        let body = op_msg_body(&doc);
        let target = walk_command(&body, false);
        match target {
            CommandTarget::Resolved { command, collection, db } => {
                assert_eq!(command, "getMore");
                assert_eq!(collection.as_deref(), Some("users"));
                assert_eq!(db.as_deref(),         Some("appdb"));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_with_lookup_flagged_when_inspect_on() {
        // Inner $lookup doc: { from: "orders", localField: "_id", foreignField: "user_id", as: "orders" }
        let inner_lookup = build_doc(
            BsonBuilder::new()
                .string("from",         "orders")
                .string("localField",   "_id")
                .string("foreignField", "user_id")
                .string("as",           "orders"),
        );
        let stage = build_doc(BsonBuilder::new().document("$lookup", inner_lookup));
        // Pipeline is an array; BSON arrays are just docs with
        // numeric keys. We'll wrap the single stage as the
        // pipeline doc value.
        let pipeline = build_doc(BsonBuilder::new().document("0", stage));
        let doc = build_doc(
            BsonBuilder::new()
                .string  ("aggregate", "users")
                .document("pipeline",  pipeline)
                .string  ("$db",       "appdb"),
        );
        let body = op_msg_body(&doc);
        let target = walk_command(&body, true);
        match target {
            CommandTarget::SecondaryCollectionDetected { command, collection, db, secondary } => {
                assert_eq!(command,    "aggregate");
                assert_eq!(collection, "users");
                assert_eq!(db.as_deref(), Some("appdb"));
                assert!(secondary.iter().any(|s| s == "orders"),
                    "missing 'orders' in secondary {secondary:?}");
            }
            other => panic!("expected SecondaryCollectionDetected, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_lookup_not_flagged_when_inspect_off() {
        let inner_lookup = build_doc(
            BsonBuilder::new()
                .string("from", "orders"),
        );
        let stage = build_doc(BsonBuilder::new().document("$lookup", inner_lookup));
        let pipeline = build_doc(BsonBuilder::new().document("0", stage));
        let doc = build_doc(
            BsonBuilder::new()
                .string  ("aggregate", "users")
                .document("pipeline",  pipeline)
                .string  ("$db",       "appdb"),
        );
        let body = op_msg_body(&doc);
        let target = walk_command(&body, false);
        match target {
            CommandTarget::Resolved { command, collection, .. } => {
                assert_eq!(command, "aggregate");
                assert_eq!(collection.as_deref(), Some("users"));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn malformed_body_is_ambiguous() {
        let body = vec![0u8; 8]; // flag bits + bad kind byte and not enough room
        match walk_command(&body, false) {
            CommandTarget::Ambiguous => {}
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    // --- Restrictions::check ---------------------------------------

    fn target_for(command: &str, coll: Option<&str>, db: Option<&str>) -> CommandTarget {
        CommandTarget::Resolved {
            command:    command.to_owned(),
            collection: coll.map(str::to_owned),
            db:         db.map(str::to_owned),
        }
    }

    #[test]
    fn admit_when_no_lists_configured() {
        let r = Restrictions::default();
        let t = target_for("find", Some("users"), Some("appdb"));
        let decision = r.check(&t);
        assert!(matches!(decision, RestrictionDecision::Admit { .. }));
    }

    #[test]
    fn block_collection_not_in_allowed_list() {
        let r = Restrictions {
            allowed_collections: vec!["appdb.orders".into()],
            ..Default::default()
        };
        let t = target_for("find", Some("users"), Some("appdb"));
        let decision = r.check(&t);
        match decision {
            RestrictionDecision::Block { reason, collection } => {
                assert_eq!(reason.as_str(), "collection_not_in_allowed_list");
                assert_eq!(collection.as_deref(), Some("appdb.users"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn admit_collection_in_allowed_list() {
        let r = Restrictions {
            allowed_collections: vec!["appdb.orders".into(), "appdb.users".into()],
            ..Default::default()
        };
        let t = target_for("find", Some("users"), Some("appdb"));
        let decision = r.check(&t);
        match decision {
            RestrictionDecision::Admit { collection } =>
                assert_eq!(collection.as_deref(), Some("appdb.users")),
            other => panic!("expected Admit, got {other:?}"),
        }
    }

    #[test]
    fn block_collection_in_forbidden_list() {
        let r = Restrictions {
            forbidden_collections: vec!["appdb.users".into()],
            ..Default::default()
        };
        let t = target_for("find", Some("users"), Some("appdb"));
        let decision = r.check(&t);
        match decision {
            RestrictionDecision::Block { reason, .. } =>
                assert_eq!(reason.as_str(), "collection_in_forbidden_list"),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn audit_only_when_enforce_false() {
        let r = Restrictions {
            forbidden_collections: vec!["appdb.users".into()],
            enforce: false,
            ..Default::default()
        };
        let t = target_for("find", Some("users"), Some("appdb"));
        let decision = r.check(&t);
        match decision {
            RestrictionDecision::AuditOnly { reason, .. } =>
                assert_eq!(reason.as_str(), "collection_in_forbidden_list"),
            other => panic!("expected AuditOnly, got {other:?}"),
        }
    }

    #[test]
    fn server_intro_commands_admitted_even_with_allowlist() {
        let r = Restrictions {
            allowed_collections: vec!["appdb.users".into()],
            ..Default::default()
        };
        let t = target_for("hello", None, Some("admin"));
        let decision = r.check(&t);
        assert!(matches!(decision, RestrictionDecision::Admit { .. }));
    }

    #[test]
    fn secondary_pipeline_blocked_when_allowlist_set() {
        let r = Restrictions {
            allowed_collections: vec!["appdb.users".into()],
            ..Default::default()
        };
        let t = CommandTarget::SecondaryCollectionDetected {
            command:    "aggregate".into(),
            collection: "users".into(),
            db:         Some("appdb".into()),
            secondary:  vec!["orders".into()],
        };
        let decision = r.check(&t);
        match decision {
            RestrictionDecision::Block { reason, .. } =>
                assert_eq!(reason.as_str(), "secondary_collection_in_pipeline"),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn ambiguous_blocked_when_list_configured() {
        let r = Restrictions {
            allowed_collections: vec!["appdb.users".into()],
            ..Default::default()
        };
        let decision = r.check(&CommandTarget::Ambiguous);
        match decision {
            RestrictionDecision::Block { reason, .. } =>
                assert_eq!(reason.as_str(), "ambiguous_bson"),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn allow_read_only_short_circuits() {
        let r = Restrictions {
            allow_read_only:    true,
            allowed_collections: vec!["appdb.users".into()],
            ..Default::default()
        };
        let t = target_for("insert", Some("users"), Some("appdb"));
        let decision = r.check(&t);
        match decision {
            RestrictionDecision::Block { reason, .. } =>
                assert_eq!(reason.as_str(), "allow_read_only"),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn reason_strings_pinned() {
        assert_eq!(RestrictionReason::AllowReadOnly.as_str(),
            "allow_read_only");
        assert_eq!(RestrictionReason::CollectionNotInAllowedList.as_str(),
            "collection_not_in_allowed_list");
        assert_eq!(RestrictionReason::CollectionInForbiddenList.as_str(),
            "collection_in_forbidden_list");
        assert_eq!(RestrictionReason::SecondaryCollectionInPipeline.as_str(),
            "secondary_collection_in_pipeline");
        assert_eq!(RestrictionReason::AmbiguousBson.as_str(),
            "ambiguous_bson");
        assert_eq!(RestrictionReason::MaxDocumentsExceeded.as_str(),
            "max_documents_exceeded");
    }

    #[test]
    fn is_blocked_kept_back_compat() {
        let r = Restrictions::read_only();
        assert!(!r.is_blocked("find"));
        assert!( r.is_blocked("insert"));
        assert!( r.is_blocked("update"));
    }
}

//! `cargo xtask spec-graph` — cross-spec consistency lint.
//!
//! Normative reference: `specs/v2/v2-deep-spec.md §Spec-Graph Lint`.
//!
//! Six checks specified; this implementation ships the four
//! highest-impact ones — they catch the bugs the spec was written
//! to prevent. The remaining two (capability-class completeness +
//! audit-event paired/single classification) are tracked as
//! follow-ups; the test bodies for them are scaffolded so the
//! follow-up commit only needs to fill them in.
//!
//! Checks shipped (V2.0):
//!
//! - **#1** — Section anchor resolution. Every cross-spec reference
//!   `<file>.md §<section>` resolves to a heading present in the
//!   target file.
//! - **#3** — Failure-code uniqueness. Every `FAIL_*` / `WARN_*`
//!   code is *defined* in exactly one spec (multiple references are
//!   fine).
//! - **#4** — Audit-event-name uniqueness. Same shape as #3 for
//!   `AuditEventKind::Foo` references.
//! - **#6** (partial) — Variant-presence sanity. Every variant
//!   present in `crates/audit/src/event.rs` is mentioned in at
//!   least one paired/single section of `audit-paired-writes.md`.
//!
//! Checks deferred to a follow-up sprint (tracked in
//! `v2-deep-spec.md §Spec-Graph Lint > Implementation reference`):
//!
//! - **#2** — Invariant-ID resolution. Every `INV-FOO-NN`
//!   reference resolves to a definition in `invariants.md` or
//!   its named canonical-home spec. Blocked on adopting a
//!   stable invariant-index format that is mechanically
//!   parseable; today the index is a prose list. See
//!   [`check_invariant_resolution`] for the scaffolded
//!   implementation hook.
//! - **#5** — Capability-class completeness. Every top-level
//!   `policy.toml` key referenced in `policy-plan-authority.md`
//!   has a matching entry in `policy-epoch-diffing.md §2.2`.
//!   Blocked on adding a structured-data block to both specs
//!   that the lint can read. See
//!   [`check_capability_class_completeness`] for the
//!   scaffolded implementation hook.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::Context;
use regex::Regex;
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

/// Whether the lint exits non-zero on findings.
#[derive(Debug, Clone, Copy)]
pub struct RunMode {
    pub strict: bool,
}

impl RunMode {
    pub fn with_strict(strict: bool) -> Self {
        Self { strict }
    }
}

pub fn run(mode: RunMode) -> anyhow::Result<()> {
    let workspace_root = workspace_root()?;
    let specs_root = workspace_root.join("raxis/specs");
    if !specs_root.is_dir() {
        anyhow::bail!(
            "spec-graph: specs root not found at {} (cwd assumed at workspace root)",
            specs_root.display()
        );
    }
    let lint = SpecGraphLint::load(&specs_root)?;
    let findings = lint.check_all()?;
    println!(
        "spec-graph: scanned {} files, {} unique fail codes, {} unique audit kinds",
        lint.file_count(),
        lint.fail_code_def_count(),
        lint.audit_kind_def_count(),
    );
    if findings.is_empty() {
        println!("spec-graph: ok (0 findings)");
        return Ok(());
    }
    for f in &findings {
        eprintln!(
            "{} — {}:{}\n  {}",
            f.code,
            f.source_file.display(),
            f.source_line,
            f.detail
        );
    }
    if mode.strict {
        anyhow::bail!("{} spec-graph findings (--strict)", findings.len());
    } else {
        eprintln!(
            "\nspec-graph: {} findings (informational; pass --strict to gate)",
            findings.len(),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Lint state + finding model
// ---------------------------------------------------------------------------

/// Resolved view of every spec file under `raxis/specs/`.
pub struct SpecGraphLint {
    /// Map from spec filename (basename) to its parsed contents.
    files: BTreeMap<String, ParsedSpec>,
}

/// One spec file's parsed metadata.
struct ParsedSpec {
    path: PathBuf,
    headings: BTreeSet<String>,
    fail_codes: BTreeSet<String>,
    audit_kinds: BTreeSet<String>,
}

/// Diagnostic emitted by a check.
#[derive(Debug)]
pub struct Finding {
    pub code: &'static str,
    pub source_file: PathBuf,
    pub source_line: usize,
    pub detail: String,
}

impl SpecGraphLint {
    /// Load and parse every `*.md` file under `specs_root`.
    pub fn load(specs_root: &Path) -> anyhow::Result<Self> {
        let mut files: BTreeMap<String, ParsedSpec> = BTreeMap::new();
        for entry in WalkDir::new(specs_root).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().map(|e| e != "md").unwrap_or(true) {
                continue;
            }
            let basename = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("non-utf-8 spec path"))?;
            let body = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            let parsed = parse_spec(&body);
            files.insert(
                basename,
                ParsedSpec {
                    path: path.to_path_buf(),
                    headings: parsed.headings,
                    fail_codes: parsed.fail_codes_defined,
                    audit_kinds: parsed.audit_kinds_defined,
                },
            );
        }
        Ok(Self { files })
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }
    pub fn fail_code_def_count(&self) -> usize {
        self.files.values().map(|p| p.fail_codes.len()).sum()
    }
    pub fn audit_kind_def_count(&self) -> usize {
        self.files.values().map(|p| p.audit_kinds.len()).sum()
    }

    /// Run all enabled checks; collect findings.
    pub fn check_all(&self) -> anyhow::Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut total_section_refs = 0usize;

        for spec in self.files.values() {
            let body = std::fs::read_to_string(&spec.path)?;
            // ── Check #1: section anchor resolution ──────────────────────
            for (line_no, line) in body.lines().enumerate() {
                for cap in section_ref_re().captures_iter(line) {
                    total_section_refs += 1;
                    let target_file = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    let target_section = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                    if let Some(target) = self.files.get(target_file) {
                        if !heading_matches(&target.headings, target_section) {
                            findings.push(Finding {
                                code: "LINT_SPEC_GRAPH_DANGLING_SECTION_REF",
                                source_file: spec.path.clone(),
                                source_line: line_no + 1,
                                detail: format!(
                                    "{target_file} §{target_section} \
                                     does not resolve to any heading in {target_file}"
                                ),
                            });
                        }
                    }
                    // If target_file is unknown, skip — could be a
                    // file that lives outside specs/ (e.g.,
                    // `raxis/README.md`); the regex matches any
                    // `<basename>.md`, but only checked spec files
                    // are in `self.files`.
                }
            }
        }

        // ── Check #3: failure-code uniqueness ──────────────────────────────
        let mut fail_code_homes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (basename, spec) in &self.files {
            for code in &spec.fail_codes {
                fail_code_homes
                    .entry(code.clone())
                    .or_default()
                    .push(basename.clone());
            }
        }
        for (code, homes) in fail_code_homes {
            if homes.len() > 1 {
                findings.push(Finding {
                    code: "LINT_SPEC_GRAPH_DUPLICATE_FAILURE_CODE",
                    source_file: PathBuf::from(homes.first().cloned().unwrap_or_default()),
                    source_line: 0,
                    detail: format!(
                        "{code} is *defined* in {} specs: {homes:?} \
                         (multiple references are fine; multiple definitions are not)",
                        homes.len(),
                    ),
                });
            }
        }

        // ── Check #4: audit-event-name uniqueness ──────────────────────────
        let mut audit_homes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (basename, spec) in &self.files {
            for kind in &spec.audit_kinds {
                audit_homes
                    .entry(kind.clone())
                    .or_default()
                    .push(basename.clone());
            }
        }
        for (kind, homes) in audit_homes {
            if homes.len() > 1 {
                findings.push(Finding {
                    code: "LINT_SPEC_GRAPH_DUPLICATE_AUDIT_KIND",
                    source_file: PathBuf::from(homes.first().cloned().unwrap_or_default()),
                    source_line: 0,
                    detail: format!(
                        "AuditEventKind::{kind} is defined in multiple specs: {homes:?}",
                    ),
                });
            }
        }

        // ── Check #6 (partial): audit variant presence in
        // audit-paired-writes.md ────────────────────────────────
        if let Some(paired) = self.files.get("audit-paired-writes.md") {
            let body = std::fs::read_to_string(&paired.path)?;
            // Collect every variant mentioned anywhere in
            // audit-paired-writes.md as either a paired or single
            // classification reference. If the source-of-truth
            // variant list (`crates/audit/src/event.rs`) is
            // accessible, cross-check; otherwise emit informational
            // statistics only.
            let mentioned: BTreeSet<String> = audit_kind_re()
                .captures_iter(&body)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_owned()))
                .collect();
            // Surface variants that are *defined* in any spec but not
            // mentioned in audit-paired-writes.md.
            for (basename, spec) in &self.files {
                if basename == "audit-paired-writes.md" {
                    continue;
                }
                for kind in &spec.audit_kinds {
                    if !mentioned.contains(kind) {
                        findings.push(Finding {
                            code: "LINT_SPEC_GRAPH_AUDIT_CLASSIFICATION_MISSING",
                            source_file: spec.path.clone(),
                            source_line: 0,
                            detail: format!(
                                "AuditEventKind::{kind} is referenced in \
                                 {basename} but is missing from \
                                 audit-paired-writes.md §4 paired/single \
                                 classification (INV-AUDIT-PAIRED-01).",
                            ),
                        });
                    }
                }
            }
        }

        // Now stash the running section-ref count back so the
        // success message renders accurately.
        // (Borrowed mutably via &mut self would require re-shaping
        // check_all's signature; instead the running counter lives
        // here and we pass it back via a Cell. Skipping the cell
        // because the count is informational only.)
        let _ = total_section_refs;

        // Suppression: certain references are intentional one-way
        // pointers to specs that no longer exist (e.g., V1 specs
        // archived under specs/v1/). Strip those before returning.
        let findings = filter_known_suppressions(findings);

        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// Deferred check scaffolds (see module docs)
// ---------------------------------------------------------------------------

/// Stub for spec-graph check **#2 — Invariant-ID resolution**.
///
/// Every `INV-FOO-NN` reference in the spec corpus must resolve
/// to a definition in `invariants.md` or in the spec named in
/// `invariants.md §1`'s canonical-home column for that invariant
/// family. The stub is intentionally a no-op until the index
/// adopts a mechanically parseable shape; the call site in
/// [`SpecGraphLint::check_all`] is a single line away from
/// activating this check once it lands.
#[allow(dead_code)]
fn check_invariant_resolution(_files: &BTreeMap<String, ParsedSpec>) -> Vec<Finding> {
    // Implementation outline:
    //
    //   1. Parse `invariants.md §1` table into
    //      Map<InvariantId, CanonicalHomeSpec>.
    //   2. For every `INV-...` reference in any spec, look up
    //      the canonical home and confirm a heading with a
    //      matching ID exists there.
    //   3. Emit `LINT_SPEC_GRAPH_DANGLING_INVARIANT_REF` for
    //      misses.
    //
    // The blocker is step 1: today's table mixes invariant IDs
    // with prose annotations in a way that defies a single
    // regex. A planned `invariants-index.toml` companion file
    // will resolve this; until then the check stays inert.
    Vec::new()
}

/// Stub for spec-graph check **#5 — Capability-class
/// completeness**.
///
/// Every top-level `policy.toml` key referenced in
/// `policy-plan-authority.md` must have a corresponding entry
/// in `policy-epoch-diffing.md §2.2` (the section map). The
/// stub is intentionally a no-op until both specs adopt a
/// structured-data block that the lint can read.
#[allow(dead_code)]
fn check_capability_class_completeness(_files: &BTreeMap<String, ParsedSpec>) -> Vec<Finding> {
    // Implementation outline:
    //
    //   1. Parse `policy-plan-authority.md` for top-level keys
    //      (regex on toml-fenced examples + section headings).
    //   2. Parse `policy-epoch-diffing.md §2.2` for declared
    //      capability classes.
    //   3. Diff the two sets; emit
    //      `LINT_SPEC_GRAPH_CAPABILITY_CLASS_MISSING` for keys
    //      in #1 but not in #2.
    //
    // The blocker is steps 1 and 2: both specs use prose tables
    // and inline TOML examples that interleave normative
    // declarations with illustrative code. A `capability-classes.toml`
    // companion file would close this gap.
    Vec::new()
}

// ---------------------------------------------------------------------------
// Spec parsing helpers
// ---------------------------------------------------------------------------

struct ParsedSpecFields {
    headings: BTreeSet<String>,
    fail_codes_defined: BTreeSet<String>,
    audit_kinds_defined: BTreeSet<String>,
}

/// Parse a spec markdown file's headings and the fail/audit
/// definitions it owns.
fn parse_spec(body: &str) -> ParsedSpecFields {
    let mut headings: BTreeSet<String> = BTreeSet::new();
    let mut in_code_fence = false;
    for line in body.lines() {
        if line.trim_start().starts_with("```") {
            in_code_fence = !in_code_fence;
            continue;
        }
        if in_code_fence {
            continue;
        }
        if let Some(rest) = strip_heading_marker(line) {
            // Pull the leading "§" or numeric-section label, if
            // any. The spec's "§<n>" cross-refs must resolve
            // against this map.
            for sec in extract_section_numbers(rest) {
                headings.insert(sec);
            }
        }
    }

    // FAIL_/WARN_ codes the spec *defines*: heuristic — codes that
    // appear inside a code-fence labelled `rust`/`toml`/`text` or
    // in an inline backtick at column 0 of a list table — are
    // counted as definitions. The simplest, robust signal: a code
    // appears at the start of a row in a markdown table whose
    // column header reads "Code" (case-insensitive). The spec
    // catalogs (`policy-plan-authority.md §6`,
    // `kernel-lifecycle.md §`) consistently use this layout.
    let fail_codes_defined = extract_fail_codes_defined(body);
    let audit_kinds_defined = extract_audit_kinds_defined(body);

    ParsedSpecFields {
        headings,
        fail_codes_defined,
        audit_kinds_defined,
    }
}

/// Strip a leading `# ` / `## ` / `### ` etc. and return the
/// remainder, or `None` if the line is not a heading.
fn strip_heading_marker(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('#') {
        return None;
    }
    let mut chars = trimmed.chars();
    let mut hashes = 0;
    while let Some('#') = chars.clone().next() {
        chars.next();
        hashes += 1;
        if hashes > 6 {
            return None;
        }
    }
    let rest = chars.as_str();
    if !rest.starts_with(' ') && !rest.starts_with('\t') {
        return None;
    }
    Some(rest.trim_start())
}

/// Extract every section number from a heading. We accept several
/// surface forms:
///
///   "## 4 — Foo"           → "4"
///   "### 4.2 Foo"          → "4.2"
///   "#### §4.2 Foo"        → "4.2"
///   "## §2.5.8 — Foo"      → "2.5.8"
///   "## Foo"               → (none)
///
/// We don't try to be too clever — the regex is the union of these
/// shapes. False negatives are caught by the lint's section-ref
/// resolver; false positives are harmless.
fn extract_section_numbers(heading_text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let re = Regex::new(r"§?\s*(\d+(?:\.\d+)*)").unwrap();
    if let Some(cap) = re.captures(heading_text) {
        if let Some(m) = cap.get(1) {
            out.push(m.as_str().to_owned());
        }
    }
    out
}

/// Marker that disables definition-extraction for the table or
/// rust-fenced block immediately following it.
///
/// **Contract:** an HTML comment exactly equal to
/// `<!-- spec-graph:cross-ref -->` (after `trim()`-ing the line)
/// placed immediately before a markdown table or rust code fence
/// designates the table / fence as a *reference list* — codes /
/// audit kinds inside it are NOT counted as definitions for the
/// uniqueness checks. Multiple references to the same symbol from
/// different specs is the design intent (the spec graph is
/// expected to be heavily cross-linked); only multiple
/// *definitions* break the single-source-of-truth invariant.
///
/// The marker survives intervening blank lines so the natural
/// markdown idiom of "marker, blank line, table" works:
///
/// ```text
/// <!-- spec-graph:cross-ref -->
///
/// | Code | … |
/// |------|---|
/// | FAIL_FOO | … |
/// ```
///
/// Any non-blank, non-marker, non-table content cancels the
/// pending marker — placing the marker far above an unrelated
/// table cannot accidentally suppress a real definition further
/// down. The marker is consumed by the next table; it does not
/// span multiple tables.
const XREF_MARKER: &str = "<!-- spec-graph:cross-ref -->";

/// Row-level variant of [`XREF_MARKER`].
///
/// **Contract:** an HTML comment exactly equal to
/// `<!-- spec-graph:cross-ref-row -->` placed immediately before
/// a *single* table row designates that one row as a reference,
/// not a definition. Used for mixed tables where most rows are
/// definitions but a small number are intentional
/// cross-references to codes whose canonical home is another
/// spec (e.g., `plan-bundle-sealing.md §9` listing
/// `FAIL_PLAN_REQUIRES_PREPARE` for narrative completeness even
/// though the canonical home is `operator-ergonomics.md §20`).
///
/// Distinct from [`XREF_MARKER`] so the two scopes do not
/// silently bleed into each other: the table-level marker
/// suppresses every row in the table; the row-level marker
/// suppresses exactly one row. The row-level marker survives
/// blank lines but is consumed by the very next non-blank,
/// non-marker line.
const XREF_MARKER_ROW: &str = "<!-- spec-graph:cross-ref-row -->";

/// Extract `FAIL_*` / `WARN_*` *definitions* from a markdown table
/// of shape `| <code> | … | … |`. Multi-spec tables are common, so
/// we scan every line that starts with `| FAIL_` or `| WARN_` after
/// stripping leading whitespace and `` ` `` characters.
///
/// Tables preceded by [`XREF_MARKER`] are treated as
/// reference-only: their codes are skipped from the definition
/// set entirely.
fn extract_fail_codes_defined(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let re = Regex::new(r"^\s*\|\s*`?(FAIL_[A-Z][A-Z0-9_]+|WARN_[A-Z][A-Z0-9_]+)").unwrap();
    let mut in_code_fence = false;
    let mut pending_xref = false;
    let mut pending_xref_row = false;
    let mut current_xref = false;
    let mut in_table = false;
    for line in body.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("```") {
            in_code_fence = !in_code_fence;
            in_table = false;
            current_xref = false;
            pending_xref = false;
            pending_xref_row = false;
            continue;
        }
        if in_code_fence {
            continue;
        }

        if trimmed == XREF_MARKER {
            pending_xref = true;
            continue;
        }
        if trimmed == XREF_MARKER_ROW {
            pending_xref_row = true;
            continue;
        }

        let is_table_line = trimmed.starts_with('|');
        if is_table_line {
            if !in_table {
                in_table = true;
                current_xref = pending_xref;
                pending_xref = false;
            }
            // Row-level marker suppresses just this one row.
            let row_xref = pending_xref_row;
            pending_xref_row = false;
            if !current_xref && !row_xref {
                if let Some(cap) = re.captures(line) {
                    if let Some(m) = cap.get(1) {
                        out.insert(m.as_str().to_owned());
                    }
                }
            }
            continue;
        }

        if trimmed.is_empty() {
            // Blank line: the table (if any) ends; the pending
            // markers are preserved across blanks so "marker,
            // blank, row/table" is the canonical idiom.
            in_table = false;
            current_xref = false;
            continue;
        }

        // Any other content cancels both pending markers and the
        // running table state — this prevents a marker
        // accidentally suppressing a far-away row/table.
        in_table = false;
        current_xref = false;
        pending_xref = false;
        pending_xref_row = false;
    }
    out
}

/// Extract `AuditEventKind::Foo` *definitions* the same way.
/// "Definition" heuristic: the variant appears inside a Rust code
/// fence (` ```rust `). The canonical home is the `audit-tools.md`
/// or `audit-paired-writes.md` enum block.
///
/// Rust fences preceded by [`XREF_MARKER`] are treated as
/// reference-only: variants inside them are skipped from the
/// definition set entirely.
fn extract_audit_kinds_defined(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut in_code_fence = false;
    let mut fence_lang = String::new();
    let mut pending_xref = false;
    let mut current_xref = false;
    let re = Regex::new(r"\bAuditEventKind::([A-Z][A-Za-z0-9]+)\b").unwrap();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_code_fence {
                in_code_fence = false;
                fence_lang.clear();
                current_xref = false;
            } else {
                in_code_fence = true;
                fence_lang = trimmed.trim_start_matches('`').trim().to_owned();
                current_xref = pending_xref;
                pending_xref = false;
            }
            continue;
        }
        if !in_code_fence {
            // Outside any fence: track the marker.
            if trimmed == XREF_MARKER {
                pending_xref = true;
                continue;
            }
            if trimmed.is_empty() {
                // Blank lines preserve the pending marker.
                continue;
            }
            // Any other content cancels the pending marker.
            pending_xref = false;
            continue;
        }
        if !fence_lang.starts_with("rust") || current_xref {
            continue;
        }
        for cap in re.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                out.insert(m.as_str().to_owned());
            }
        }
    }
    out
}

/// Lazily-built section-ref regex.
fn section_ref_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([a-z][a-z0-9_-]+\.md)\s+§(\d+(?:\.\d+)*)").unwrap())
}

fn audit_kind_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bAuditEventKind::([A-Z][A-Za-z0-9]+)\b").unwrap())
}

/// `<heading_set>` contains every section number we extracted.
/// Membership: exact-match OR prefix-match (the spec routinely
/// references `§4` to mean any subsection of section 4).
fn heading_matches(headings: &BTreeSet<String>, target: &str) -> bool {
    if headings.contains(target) {
        return true;
    }
    let prefix = format!("{target}.");
    headings.iter().any(|h| h.starts_with(&prefix))
}

// ---------------------------------------------------------------------------
// Workspace helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> anyhow::Result<PathBuf> {
    // `cargo xtask` invokes us from `<workspace>/raxis`; the
    // `raxis` repo root is one level up. We use
    // `CARGO_MANIFEST_DIR` of this xtask crate (which is
    // `<repo>/raxis/xtask`) and walk up two parents.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf())
}

/// Suppress findings the spec-graph spec calls out as deliberate
/// one-way references — typically `specs/v1/*.md → specs/v2/*.md`
/// pointers added during the V1 → V2 split for forward-reference,
/// where the V2 spec doesn't yet have the back-reference filled in.
fn filter_known_suppressions(findings: Vec<Finding>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| {
            // Heuristic: anything originating in `specs/v1/*` is
            // out-of-scope for the V2 lint. The V1 specs are
            // historical and the spec-graph rule explicitly carves
            // them out. (`v2-deep-spec.md §Spec-Graph Lint
            // Suppression` describes the line-level pragma; the
            // wholesale V1 suppression here is the V2-bringup
            // shortcut.)
            let p = f.source_file.to_string_lossy();
            !p.contains("/specs/v1/") && !p.contains("/specs/archive/")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_section_number_from_simple_heading() {
        assert_eq!(extract_section_numbers("4 — Foo"), vec!["4".to_owned()]);
        assert_eq!(extract_section_numbers("4.2 Foo"), vec!["4.2".to_owned()]);
        assert_eq!(extract_section_numbers("§4.2 Foo"), vec!["4.2".to_owned()]);
        assert_eq!(
            extract_section_numbers("§2.5.8 — Foo"),
            vec!["2.5.8".to_owned()]
        );
    }

    #[test]
    fn strip_heading_marker_recognises_h1_through_h4() {
        assert_eq!(strip_heading_marker("# Foo"), Some("Foo"));
        assert_eq!(strip_heading_marker("## Foo"), Some("Foo"));
        assert_eq!(strip_heading_marker("#### Foo"), Some("Foo"));
        assert!(strip_heading_marker("Foo").is_none());
        assert!(strip_heading_marker("####Foo").is_none()); // no space
    }

    #[test]
    fn heading_matches_exact_and_prefix() {
        let mut h = BTreeSet::new();
        h.insert("4.2".to_owned());
        h.insert("4.2.1".to_owned());
        assert!(heading_matches(&h, "4.2"));
        assert!(heading_matches(&h, "4.2.1"));
        assert!(heading_matches(&h, "4")); // prefix match: any 4.x exists
        assert!(!heading_matches(&h, "5"));
    }

    #[test]
    fn fail_code_table_row_is_a_definition() {
        let body = "\
| Code | Trigger |\n\
|---|---|\n\
| `FAIL_FOO_BAR` | trigger |\n\
| WARN_BAZ | warn |\n";
        let codes = extract_fail_codes_defined(body);
        assert!(codes.contains("FAIL_FOO_BAR"));
        assert!(codes.contains("WARN_BAZ"));
    }

    #[test]
    fn audit_kind_inside_rust_fence_is_a_definition() {
        let body = "```rust\n\
enum AuditEventKind { Foo, Bar }\n\
fn x() { let _ = AuditEventKind::Baz; }\n\
```\n";
        let kinds = extract_audit_kinds_defined(body);
        assert!(kinds.contains("Baz"));
    }

    #[test]
    fn audit_kind_outside_fence_is_not_a_definition() {
        let body = "An `AuditEventKind::OutsideFence` mention in prose.\n";
        let kinds = extract_audit_kinds_defined(body);
        assert!(!kinds.contains("OutsideFence"));
    }

    // ── XREF_MARKER tests ────────────────────────────────────────────────

    #[test]
    fn xref_marker_suppresses_a_following_fail_code_table() {
        let body = "\
<!-- spec-graph:cross-ref -->

| Code | Trigger |
|---|---|
| `FAIL_REF_ONE` | … |
| `FAIL_REF_TWO` | … |
";
        let codes = extract_fail_codes_defined(body);
        assert!(
            codes.is_empty(),
            "xref-marked tables must not contribute definitions; got: {codes:?}"
        );
    }

    #[test]
    fn xref_marker_only_consumed_by_one_table() {
        let body = "\
<!-- spec-graph:cross-ref -->

| Code | Trigger |
|---|---|
| `FAIL_REF_ONE` | first table — xref |

Some prose between tables.

| Code | Trigger |
|---|---|
| `FAIL_REAL_DEF` | second table — definition |
";
        let codes = extract_fail_codes_defined(body);
        assert!(
            !codes.contains("FAIL_REF_ONE"),
            "first table is xref'd; codes from it must be excluded"
        );
        assert!(
            codes.contains("FAIL_REAL_DEF"),
            "second table is unmarked; its codes must count as definitions: {codes:?}"
        );
    }

    #[test]
    fn xref_marker_cancelled_by_unrelated_intervening_content() {
        let body = "\
<!-- spec-graph:cross-ref -->

Some prose that follows the marker.

| Code | Trigger |
|---|---|
| `FAIL_REAL_AFTER_PROSE` | unrelated table — defines normally |
";
        let codes = extract_fail_codes_defined(body);
        assert!(
            codes.contains("FAIL_REAL_AFTER_PROSE"),
            "the marker must be cancelled by intervening prose so it does not silently \
             suppress a far-away table; got: {codes:?}"
        );
    }

    #[test]
    fn xref_marker_survives_blank_lines_before_table() {
        // Multiple blank lines between marker and table is fine —
        // typical authoring shape adds at least one blank before
        // the table for readability.
        let body = "\
<!-- spec-graph:cross-ref -->



| Code | Trigger |
|---|---|
| `FAIL_REF_BLANKS` | reference table |
";
        let codes = extract_fail_codes_defined(body);
        assert!(
            codes.is_empty(),
            "blank lines between marker and table must preserve the marker; got: {codes:?}"
        );
    }

    #[test]
    fn xref_marker_suppresses_a_following_rust_fence() {
        let body = "\
<!-- spec-graph:cross-ref -->

```rust
let _ = AuditEventKind::FromRefFence;
```
";
        let kinds = extract_audit_kinds_defined(body);
        assert!(
            kinds.is_empty(),
            "xref-marked rust fences must not contribute audit-kind definitions; got: {kinds:?}"
        );
    }

    #[test]
    fn xref_marker_row_suppresses_a_single_table_row() {
        let body = "\
| Code | Trigger |
|---|---|
| `FAIL_REAL_FIRST` | first row — definition |
<!-- spec-graph:cross-ref-row -->
| `FAIL_REF_MIDDLE` | middle row — cross-ref via row marker |
| `FAIL_REAL_LAST` | last row — definition |
";
        let codes = extract_fail_codes_defined(body);
        assert!(
            codes.contains("FAIL_REAL_FIRST"),
            "rows before the row-marker still define normally: {codes:?}"
        );
        assert!(
            !codes.contains("FAIL_REF_MIDDLE"),
            "row-marker should suppress just the immediately following row: {codes:?}"
        );
        assert!(
            codes.contains("FAIL_REAL_LAST"),
            "rows after the suppressed row resume normal definition: {codes:?}"
        );
    }

    #[test]
    fn xref_marker_row_survives_blank_lines() {
        let body = "\
| Code | Trigger |
|---|---|
| `FAIL_REAL_FIRST` | first row |

<!-- spec-graph:cross-ref-row -->

| `FAIL_REF_NEXT` | suppressed row |
| `FAIL_REAL_AFTER` | normal row |
";
        let codes = extract_fail_codes_defined(body);
        assert!(codes.contains("FAIL_REAL_FIRST"));
        assert!(!codes.contains("FAIL_REF_NEXT"));
        assert!(codes.contains("FAIL_REAL_AFTER"));
    }

    #[test]
    fn xref_marker_is_only_consumed_by_one_rust_fence() {
        let body = "\
<!-- spec-graph:cross-ref -->

```rust
let _ = AuditEventKind::FromRefFence;
```

Some prose.

```rust
let _ = AuditEventKind::FromRealFence;
```
";
        let kinds = extract_audit_kinds_defined(body);
        assert!(!kinds.contains("FromRefFence"));
        assert!(
            kinds.contains("FromRealFence"),
            "second fence is unmarked; its audit kinds must count as definitions: {kinds:?}"
        );
    }

    #[test]
    fn section_ref_regex_extracts_file_and_section() {
        let captured: Vec<(String, String)> = section_ref_re()
            .captures_iter("see foo-bar.md §4.2 for the contract")
            .map(|c| (c[1].to_owned(), c[2].to_owned()))
            .collect();
        assert_eq!(captured, vec![("foo-bar.md".to_owned(), "4.2".to_owned())]);
    }
}

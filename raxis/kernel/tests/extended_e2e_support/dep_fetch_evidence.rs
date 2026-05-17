//! Dep-fetch-evidence witness — exercises the kernel's Path A3
//! mediated-egress stack end-to-end against a real public host.
//!
//! ## What the matching plan task does (`live-e2e/seed/prompts/dep_fetch_evidence.md`)
//!
//!   1. Issues a single `GET https://example.com/` from inside the
//!      executor VM via stdlib `http.client.HTTPSConnection`.
//!   2. Writes a JSON evidence file to
//!      `out/deps/install-evidence.json` carrying the HTTP status,
//!      body size, body SHA-256, and a boolean that pins the
//!      well-known `Example Domain` substring.
//!   3. `git add` + commit + `task_complete`.
//!
//! `example.com` is IANA-reserved (RFC 2606) — its body is stable
//! and contains the literal string `Example Domain` inside the
//! `<h1>`. No pip / npm / cargo / package-manager involvement is
//! needed; the stdlib is enough.
//!
//! ## What this witness asserts
//!
//! Given `(executor_session_id, executor_workdir)`:
//!
//! 1. **Audit-chain: at least one A3 admission grant for the
//!    executor's session targeting `example.com:443`.** The kernel
//!    emits [`AuditEventKind::TproxyAdmissionGranted`] on the
//!    happy path of the in-VM tproxy → vsock → kernel admission →
//!    upstream TCP byte tunnel. The witness scopes by `session_id`
//!    so a sibling task contacting `example.com` (legitimate or
//!    not) cannot accidentally satisfy this witness's grant
//!    requirement.
//!
//! 2. **Audit-chain: zero A3 denials for `example.com` scoped to
//!    the executor's session.** If the kernel ever denies the
//!    fetch the witness fails closed — a partial-success that
//!    silently fell back to a cached / inlined body would otherwise
//!    pass the disk-side check below without ever lighting up the
//!    A3 stack.
//!
//! 3. **Audit-chain: no OTHER A3 grants on the executor's
//!    session.** The task is pinned to a single host; a grant for
//!    any other host on the same session is a scope leak and
//!    fails the witness.
//!
//! 4. **On-disk: `<workdir>/out/deps/install-evidence.json`
//!    exists, parses as JSON, and carries the four contractual
//!    fields**:
//!
//!    | field                          | expected           |
//!    |--------------------------------|--------------------|
//!    | `http_status`                  | `200`              |
//!    | `body_contains_example_domain` | `true`             |
//!    | `body_size_bytes`              | `> 0`              |
//!    | `body_sha256`                  | 64-char lowercase  |
//!
//!    The witness deliberately does NOT pin the body SHA — the
//!    page is updated by IANA on a multi-year cadence, and a
//!    SHA-pinned witness would false-positive on every IANA
//!    refresh. The `body_contains_example_domain` flag — checked
//!    inside the executor against the live response bytes — is
//!    the structural pin instead.
//!
//! ## Cross-witness shape
//!
//! Modeled after [`super::crash_recovery::CrashRecoveryWitness`]
//! (chain-only, scope-by-task) and
//! [`super::transparent_proxy_evidence`] (chain + on-disk
//! companion). Like both, it implements
//! [`super::witnesses::EnforcementWitness`] so it can drop into
//! the realistic-scenario `global_witnesses` vec next to the
//! existing ones with no harness change.
//!
//! Spec references:
//!   * `raxis/specs/v2/mediated-egress.md` — Path A3 description
//!     and admission contract.
//!   * `kernel/src/handlers/tproxy_admit.rs` — emit sites for
//!     `TproxyAdmissionGranted` / `TproxyAdmissionDenied`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditEvent, AuditEventKind};

use super::witnesses::{typed, EnforcementWitness};

// ---------------------------------------------------------------------------
// Pinned task id + path + endpoint constants.
//
// These mirror the prompt at
// `raxis/live-e2e/seed/prompts/dep_fetch_evidence.md`. Pinned in
// one place so the prompt and witness can't drift.
// ---------------------------------------------------------------------------

/// Pinned task id — the realistic plan in `plan_realistic.rs`
/// wires this id with `path_allowlist = ["out/deps/"]` and a
/// small `max_turns` budget (the body is mechanical).
pub const TASK_DEP_FETCH_EVIDENCE: &str = "dep-fetch-evidence";

/// Worktree-relative path of the JSON evidence file the executor
/// must commit. Matches the prompt verbatim.
pub const EVIDENCE_FILE_REL_PATH: &str = "out/deps/install-evidence.json";

/// Pinned target host. The kernel's `[egress].domains` list must
/// carry this entry for the A3 admission to grant the flow.
pub const TARGET_HOST: &str = "example.com";

/// Pinned target port — HTTPS on the default 443.
pub const TARGET_PORT: u16 = 443;

/// Substring the executor must observe in the response body. IANA's
/// example-domain page contains this string inside its `<h1>` tag;
/// using a substring (rather than a body SHA) makes the witness
/// robust to multi-year IANA refresh cycles.
pub const EXPECTED_BODY_SUBSTRING: &str = "Example Domain";

// ---------------------------------------------------------------------------
// Witness type.
// ---------------------------------------------------------------------------

/// Predicate body — see module docs.
pub struct DepFetchEvidenceWitness {
    /// Task id whose audit-chain rows + worktree the witness
    /// inspects. Defaults to [`TASK_DEP_FETCH_EVIDENCE`] when
    /// constructed via [`Self::for_realistic_plan`].
    pub task_id: String,
    /// Executor session id resolved from the audit chain via
    /// `kernel_driver::locate_session_id_for_task` after the task
    /// activates. The session scope is load-bearing: a grant
    /// emitted on a sibling task's session does NOT satisfy this
    /// witness.
    pub executor_session_id: String,
    /// Executor's worktree root (the worktree the on-disk
    /// evidence file lives under).
    pub workdir: PathBuf,
}

impl DepFetchEvidenceWitness {
    /// Construct a witness keyed by the canonical realistic-plan
    /// task id + the pinned evidence path. Used by the
    /// realistic-scenario test driver after it locates the
    /// executor's session id and worktree from the chain.
    #[must_use]
    pub fn for_realistic_plan(executor_session_id: &str, workdir: &Path) -> Self {
        Self {
            task_id: TASK_DEP_FETCH_EVIDENCE.to_owned(),
            executor_session_id: executor_session_id.to_owned(),
            workdir: workdir.to_path_buf(),
        }
    }

    /// Absolute on-disk path the witness reads.
    #[must_use]
    pub fn absolute_evidence_path(&self) -> PathBuf {
        self.workdir.join(EVIDENCE_FILE_REL_PATH)
    }

    /// Best-effort load + parse of the on-disk evidence file.
    /// Returns the parsed structured view or a free-form reason
    /// describing why parsing failed. The split shape lets
    /// [`Self::diagnostic`] render the parse error verbatim
    /// without re-running the load.
    fn parse_evidence(&self) -> Result<EvidenceFile, String> {
        let path = self.absolute_evidence_path();
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse {} as JSON: {e}", path.display()))?;
        EvidenceFile::from_json(&v)
            .map_err(|e| format!("evidence {} shape: {e}", path.display()))
    }

    /// Count `TproxyAdmissionGranted` events that match this
    /// witness's session AND target host+port.
    fn matching_grants(&self, chain: &[AuditEvent]) -> Vec<u64> {
        chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::TproxyAdmissionGranted {
                    session_id,
                    host_or_sni,
                    original_dst_port,
                    ..
                }) if session_id == self.executor_session_id
                    && host_or_sni.as_deref() == Some(TARGET_HOST)
                    && original_dst_port == TARGET_PORT =>
                {
                    Some(ev.seq)
                }
                _ => None,
            })
            .collect()
    }

    /// Find any `TproxyAdmissionGranted` on the executor's session
    /// whose `host_or_sni` is something OTHER than the pinned
    /// target. Returns a vector of `(seq, host_or_sni)` so the
    /// diagnostic can name the leaked host.
    fn off_target_grants(&self, chain: &[AuditEvent]) -> Vec<(u64, String)> {
        chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::TproxyAdmissionGranted {
                    session_id,
                    host_or_sni,
                    ..
                }) if session_id == self.executor_session_id
                    && host_or_sni.as_deref() != Some(TARGET_HOST) =>
                {
                    Some((
                        ev.seq,
                        host_or_sni.unwrap_or_else(|| "<no-sni>".to_owned()),
                    ))
                }
                _ => None,
            })
            .collect()
    }

    /// Find any `TproxyAdmissionDenied` on the executor's session
    /// whose `host_or_sni` matches the pinned target. Returns
    /// (seq, reason) pairs so the diagnostic can name the deny
    /// taxonomy that fired (`host_not_in_allowlist`,
    /// `protocol_not_permitted`, etc.).
    fn target_denials(&self, chain: &[AuditEvent]) -> Vec<(u64, String)> {
        chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::TproxyAdmissionDenied {
                    session_id,
                    host_or_sni,
                    reason,
                    ..
                }) if session_id == self.executor_session_id
                    && host_or_sni.as_deref() == Some(TARGET_HOST) =>
                {
                    Some((ev.seq, reason))
                }
                _ => None,
            })
            .collect()
    }
}

/// Structured view of the on-disk evidence file. Only the four
/// fields the witness pins are decoded; any other fields are
/// retained as `extras` for the diagnostic but not asserted.
#[derive(Debug, Clone)]
pub struct EvidenceFile {
    pub http_status: u16,
    pub body_size_bytes: u64,
    pub body_sha256: String,
    pub body_contains_example_domain: bool,
}

impl EvidenceFile {
    fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let obj = v.as_object().ok_or("not a JSON object")?;
        let http_status = obj
            .get("http_status")
            .and_then(|x| x.as_u64())
            .ok_or("missing or non-integer `http_status`")?;
        let http_status = u16::try_from(http_status)
            .map_err(|_| format!("`http_status` out of u16 range: {http_status}"))?;
        let body_size_bytes = obj
            .get("body_size_bytes")
            .and_then(|x| x.as_u64())
            .ok_or("missing or non-integer `body_size_bytes`")?;
        let body_sha256 = obj
            .get("body_sha256")
            .and_then(|x| x.as_str())
            .ok_or("missing or non-string `body_sha256`")?
            .to_owned();
        if body_sha256.len() != 64 || !body_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "`body_sha256` is not a 64-char lowercase hex string (got len={}, value={body_sha256:?})",
                body_sha256.len()
            ));
        }
        let body_contains_example_domain = obj
            .get("body_contains_example_domain")
            .and_then(|x| x.as_bool())
            .ok_or("missing or non-boolean `body_contains_example_domain`")?;
        Ok(Self {
            http_status,
            body_size_bytes,
            body_sha256,
            body_contains_example_domain,
        })
    }
}

impl EnforcementWitness for DepFetchEvidenceWitness {
    fn name(&self) -> &'static str {
        "dep-fetch-evidence"
    }

    fn satisfied_by(&self, chain: &[AuditEvent]) -> bool {
        // (1) at least one target grant in the executor's session.
        if self.matching_grants(chain).is_empty() {
            return false;
        }
        // (2) zero target denials in the executor's session.
        if !self.target_denials(chain).is_empty() {
            return false;
        }
        // (3) no off-target grants in the executor's session.
        //     (Tightens scope: the pinned task contacts exactly
        //     one host.)
        if !self.off_target_grants(chain).is_empty() {
            return false;
        }
        // (4) on-disk evidence file parses cleanly with the four
        //     contractual fields.
        match self.parse_evidence() {
            Ok(ev) => {
                ev.http_status == 200
                    && ev.body_size_bytes > 0
                    && ev.body_contains_example_domain
            }
            Err(_) => false,
        }
    }

    fn diagnostic(&self, chain: &[AuditEvent]) -> String {
        let grants = self.matching_grants(chain);
        let denials = self.target_denials(chain);
        let off_target = self.off_target_grants(chain);
        let evidence = self.parse_evidence();
        let abs = self.absolute_evidence_path();
        let disk_state = match std::fs::metadata(&abs) {
            Ok(m) if m.is_file() => format!("file present (len={} bytes)", m.len()),
            Ok(_) => "path exists but is not a regular file".to_owned(),
            Err(e) => format!("not present ({e})"),
        };
        let evidence_summary = match &evidence {
            Ok(ev) => format!(
                "http_status={s}, body_size_bytes={n}, \
                 body_contains_example_domain={c}, body_sha256={sh}",
                s = ev.http_status,
                n = ev.body_size_bytes,
                c = ev.body_contains_example_domain,
                sh = ev.body_sha256,
            ),
            Err(e) => format!("(parse error: {e})"),
        };
        format!(
            "DepFetchEvidence[{task}; session={sid}]:\n  \
             TproxyAdmissionGranted matching {host}:{port}: seqs={grants:?}\n  \
             TproxyAdmissionDenied  matching {host}:_:    seqs+reasons={denials:?}\n  \
             off-target grants on this session: {off_target:?}\n  \
             evidence file: {abs}\n  \
             disk state:    {disk_state}\n  \
             parsed:        {evidence_summary}",
            task = self.task_id,
            sid = self.executor_session_id,
            host = TARGET_HOST,
            port = TARGET_PORT,
            abs = abs.display(),
        )
    }
}

// ---------------------------------------------------------------------------
// Smoke-test scaffolding — exported so the realism-scenario wiring
// smoke test can drive the witness against a synthetic chain
// without touching the live network.
// ---------------------------------------------------------------------------

/// Hand-built audit chain that satisfies [`DepFetchEvidenceWitness`].
/// Used by the realism-scenario wiring smoke test and by this
/// module's unit tests. The session id is parameterised so the
/// caller can match it to the witness it constructs.
#[must_use]
pub fn synthetic_satisfying_chain(session_id: &str) -> Vec<AuditEvent> {
    let payload = AuditEventKind::TproxyAdmissionGranted {
        session_id: session_id.to_owned(),
        host_or_sni: Some(TARGET_HOST.to_owned()),
        original_dst_ip: "93.184.216.34".to_owned(),
        original_dst_port: TARGET_PORT,
        protocol: "https".to_owned(),
        tunnel_id: uuid::Uuid::nil().to_string(),
    };
    vec![AuditEvent {
        seq: 1,
        event_id: uuid::Uuid::nil(),
        event_kind: "TproxyAdmissionGranted".to_owned(),
        session_id: Some(session_id.to_owned()),
        task_id: Some(TASK_DEP_FETCH_EVIDENCE.to_owned()),
        initiative_id: Some("init-realistic".to_owned()),
        payload: serde_json::to_value(&payload).unwrap(),
        emitted_at: 1700000000,
        prev_sha256: "0".repeat(64),
    }]
}

/// Write a synthetic-but-shape-faithful evidence file into
/// `workdir/out/deps/install-evidence.json`. Used by the wiring
/// smoke test so it can drive the on-disk arm of the witness
/// without a real network fetch.
pub fn write_synthetic_evidence(workdir: &Path) -> std::io::Result<PathBuf> {
    let dir = workdir.join("out").join("deps");
    std::fs::create_dir_all(&dir)?;
    let abs = dir.join("install-evidence.json");
    // Body is the canonical IANA example.com page from a 2024
    // snapshot — only used inside the smoke test, never wired to
    // a real fetch. The witness does NOT pin this SHA; it only
    // pins the contractual *fields*.
    let body = "<!doctype html><html><body><h1>Example Domain</h1></body></html>";
    let body_sha256 = sha256_hex(body.as_bytes());
    let evidence = serde_json::json!({
        "target_url":                 "https://example.com/",
        "target_host":                TARGET_HOST,
        "target_port":                TARGET_PORT,
        "http_status":                200,
        "body_size_bytes":            body.len(),
        "body_sha256":                body_sha256,
        "body_contains_example_domain": true,
        "fetched_at_unix":            1_700_000_000,
        "transport":                  "https",
    });
    let mut out = serde_json::to_string_pretty(&evidence).expect("serialize evidence");
    out.push('\n');
    std::fs::write(&abs, out)?;
    Ok(abs)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Unit tests — drive each axis of the predicate against synthetic
// chains + tempdir-resident evidence files. The witness has four
// load-bearing components and we cover each one separately.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use raxis_audit_tools::{AuditEvent, AuditEventKind};
    use tempfile::TempDir;
    use uuid::Uuid;

    /// Construct an `AuditEvent` directly from an `AuditEventKind`.
    /// The `event_kind` string slot is derived from the variant
    /// name so the kernel's parsed-payload classifier matches.
    fn ev(seq: u64, kind: AuditEventKind, session_id: Option<&str>) -> AuditEvent {
        let event_kind = match &kind {
            AuditEventKind::TproxyAdmissionGranted { .. } => "TproxyAdmissionGranted",
            AuditEventKind::TproxyAdmissionDenied { .. } => "TproxyAdmissionDenied",
            _ => "Other",
        }
        .to_owned();
        AuditEvent {
            seq,
            event_id: Uuid::nil(),
            event_kind,
            session_id: session_id.map(str::to_owned),
            task_id: Some(TASK_DEP_FETCH_EVIDENCE.to_owned()),
            initiative_id: Some("init-realistic".to_owned()),
            payload: serde_json::to_value(&kind).unwrap(),
            emitted_at: 1700000000 + seq as i64,
            prev_sha256: "0".repeat(64),
        }
    }

    fn grant(seq: u64, session_id: &str, host: Option<&str>, port: u16) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::TproxyAdmissionGranted {
                session_id: session_id.to_owned(),
                host_or_sni: host.map(str::to_owned),
                original_dst_ip: "93.184.216.34".to_owned(),
                original_dst_port: port,
                protocol: "https".to_owned(),
                tunnel_id: Uuid::nil().to_string(),
            },
            Some(session_id),
        )
    }

    fn deny(seq: u64, session_id: &str, host: Option<&str>, reason: &str) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::TproxyAdmissionDenied {
                session_id: session_id.to_owned(),
                host_or_sni: host.map(str::to_owned),
                original_dst_ip: "93.184.216.34".to_owned(),
                original_dst_port: TARGET_PORT,
                protocol: "https".to_owned(),
                reason: reason.to_owned(),
            },
            Some(session_id),
        )
    }

    fn witness_for(workdir: &Path, session_id: &str) -> DepFetchEvidenceWitness {
        DepFetchEvidenceWitness::for_realistic_plan(session_id, workdir)
    }

    #[test]
    fn happy_path_grant_plus_disk_evidence_satisfies() {
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT)];
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn no_grant_in_chain_fails() {
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain: Vec<AuditEvent> = vec![];
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("seqs=[]"), "diagnostic: {diag}");
    }

    #[test]
    fn grant_on_different_session_does_not_satisfy() {
        // Cross-session leak guard. A grant for `example.com` on
        // some OTHER task's session must not be enough.
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(10, "sess-someone-else", Some(TARGET_HOST), TARGET_PORT)];
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn grant_for_wrong_host_does_not_satisfy() {
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(
            10,
            "sess-exec-1",
            Some("api.anthropic.com"),
            443,
        )];
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn grant_on_wrong_port_does_not_satisfy() {
        // The pin is host AND port; a grant on :80 (HTTP) for
        // example.com still fails the witness because the prompt
        // pins HTTPS:443.
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(10, "sess-exec-1", Some(TARGET_HOST), 80)];
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn deny_for_target_in_same_session_fails_closed() {
        // A grant might still be present if the kernel granted
        // then denied a retry — but the witness must fail closed
        // on any deny for the pinned host on the executor's
        // session.
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![
            grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT),
            deny(11, "sess-exec-1", Some(TARGET_HOST), "host_not_in_allowlist"),
        ];
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("host_not_in_allowlist"), "{diag}");
    }

    #[test]
    fn off_target_grant_on_same_session_fails() {
        // The task is pinned to ONE host. A second grant on the
        // executor's session for a different host means the
        // executor went outside its scope.
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![
            grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT),
            grant(11, "sess-exec-1", Some("api.anthropic.com"), 443),
        ];
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn missing_evidence_file_fails_with_named_path() {
        let tmp = TempDir::new().unwrap();
        // NOTE: no `write_synthetic_evidence` — the file is absent.
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT)];
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(
            diag.contains("install-evidence.json"),
            "diagnostic must surface the missing-file path verbatim: {diag}",
        );
    }

    #[test]
    fn evidence_with_wrong_http_status_fails() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("out").join("deps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-evidence.json"),
            serde_json::to_string(&serde_json::json!({
                "http_status":                500,
                "body_size_bytes":            42,
                "body_sha256":                "f".repeat(64),
                "body_contains_example_domain": true,
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT)];
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn evidence_without_example_domain_substring_fails() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("out").join("deps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-evidence.json"),
            serde_json::to_string(&serde_json::json!({
                "http_status":                200,
                "body_size_bytes":            42,
                "body_sha256":                "0".repeat(64),
                "body_contains_example_domain": false,
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT)];
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn evidence_with_non_hex_sha_fails_parse_with_named_field() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("out").join("deps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-evidence.json"),
            serde_json::to_string(&serde_json::json!({
                "http_status":                200,
                "body_size_bytes":            42,
                "body_sha256":                "not-a-hex-string",
                "body_contains_example_domain": true,
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT)];
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("body_sha256"), "{diag}");
    }

    #[test]
    fn synthetic_satisfying_chain_helper_satisfies_when_paired_with_disk() {
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let chain = synthetic_satisfying_chain("sess-smoke");
        let w = witness_for(tmp.path(), "sess-smoke");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }
}

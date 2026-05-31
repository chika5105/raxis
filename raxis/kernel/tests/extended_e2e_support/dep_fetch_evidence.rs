//! Dep-fetch-evidence witness — exercises the kernel's Path A3
//! mediated-egress stack end-to-end against real public hosts.
//!
//! ## What the matching plan task does (`live-e2e/seed/prompts/dep_fetch_evidence.md`)
//!
//!   1. Issues a single `GET https://example.com/` from inside the
//!      executor VM via stdlib `http.client.HTTPSConnection`.
//!   2. **iter69 extension**: runs `python3 -m pip install
//!      --target=out/deps/_pip --report=out/deps/_pip-report.json
//!      certifi` so the kernel admits the two-host pip flow
//!      (`pypi.org` for index resolution + JSON metadata,
//!      `files.pythonhosted.org` for the wheel download) and the
//!      executor produces a verifiable per-wheel SHA256 manifest.
//!   3. Merges the example.com fetch JSON with the pip `--report`
//!      output into a single evidence file at
//!      `out/deps/install-evidence.json`.
//!   4. `git add` + commit + `task_complete`.
//!
//! `example.com` is IANA-reserved (RFC 2606) — its body is stable
//! and contains the literal string `Example Domain` inside the
//! `<h1>`. `certifi` is a pure-Python wheel with no transitive
//! deps and a stable, very small footprint (~165 KiB).
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
//! 3. **Audit-chain: every A3 grant on the executor's session
//!    targets a host in the pinned allowlist
//!    `{example.com, pypi.org, files.pythonhosted.org}`.** A grant
//!    to any other host is a scope leak and fails the witness.
//!
//! 4. **On-disk: `<workdir>/out/deps/install-evidence.json`
//!    exists, parses as JSON, and carries the four HTTPS-arm
//!    contractual fields**:
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
//! 5. **On-disk pip-install arm (iter69)**: the same
//!    `install-evidence.json` carries a `pip_install` object that
//!    parses + asserts:
//!
//!    | field                            | expected                                  |
//!    |----------------------------------|-------------------------------------------|
//!    | `pip_install.success`            | `true`                                    |
//!    | `pip_install.installed[*].sha256`| 64-char lowercase hex per entry           |
//!    | at least one `installed` entry   | `name == "certifi"` (case-insensitive)    |
//!
//!    The witness does NOT pin a specific certifi version or
//!    wheel SHA — both rotate as the upstream package releases
//!    refresh. The structural pin is "pip emitted ≥ 1 install
//!    row with a verifiable SHA256, including certifi".
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

/// PyPI index host — `pip install` resolves the simple index
/// against this host (HTTPS, port 443). Required in the kernel's
/// `[egress].domains` list alongside `files.pythonhosted.org`.
pub const PIP_HOST_INDEX: &str = "pypi.org";

/// File-hosting CDN host — `pip` downloads wheels from
/// `files.pythonhosted.org` after resolving via `pypi.org`. Both
/// hosts must be in the egress allowlist for an install to land.
pub const PIP_HOST_FILES: &str = "files.pythonhosted.org";

/// Pinned package the executor installs. Pure-Python wheel with
/// zero transitive deps so the install path is deterministic.
pub const PIP_PACKAGE_NAME: &str = "certifi";

/// The full set of hosts the witness will permit to appear in
/// `TproxyAdmissionGranted` events on the executor's session. A
/// grant for any host outside this set is treated as a scope
/// leak and fails the witness closed. Includes the example.com
/// HTTPS fetch arm and the two pip-install arm hosts.
pub const ALLOWED_HOSTS: &[&str] = &[TARGET_HOST, PIP_HOST_INDEX, PIP_HOST_FILES];

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
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse {} as JSON: {e}", path.display()))?;
        EvidenceFile::from_json(&v).map_err(|e| format!("evidence {} shape: {e}", path.display()))
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
    /// whose `host_or_sni` is OUTSIDE the pinned allowlist (see
    /// [`ALLOWED_HOSTS`]). Returns a vector of `(seq, host_or_sni)`
    /// so the diagnostic can name the leaked host. A grant with no
    /// SNI also counts as off-target — every host we expect is
    /// HTTPS and SNI-bearing.
    fn off_target_grants(&self, chain: &[AuditEvent]) -> Vec<(u64, String)> {
        chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::TproxyAdmissionGranted {
                    session_id,
                    host_or_sni,
                    ..
                }) if session_id == self.executor_session_id
                    && !host_or_sni
                        .as_deref()
                        .is_some_and(|h| ALLOWED_HOSTS.contains(&h)) =>
                {
                    Some((ev.seq, host_or_sni.unwrap_or_else(|| "<no-sni>".to_owned())))
                }
                _ => None,
            })
            .collect()
    }

    /// Count grants on the executor's session targeting a
    /// specific host (any port). Used by the diagnostic to
    /// surface which arm of the egress flow lit up the audit
    /// chain.
    fn grants_for_host(&self, chain: &[AuditEvent], host: &str) -> Vec<u64> {
        chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::TproxyAdmissionGranted {
                    session_id,
                    host_or_sni,
                    ..
                }) if session_id == self.executor_session_id
                    && host_or_sni.as_deref() == Some(host) =>
                {
                    Some(ev.seq)
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
///
/// The `pip_install` arm (iter69) is optional in the parse type
/// — a missing block surfaces as `None` so the diagnostic can
/// name "pip arm absent" distinctly from "pip arm present but
/// malformed". The witness predicate fails closed when it's
/// `None`.
#[derive(Debug, Clone)]
pub struct EvidenceFile {
    pub http_status: u16,
    pub body_size_bytes: u64,
    pub body_sha256: String,
    pub body_contains_example_domain: bool,
    pub pip_install: Option<PipInstallEvidence>,
}

/// Structured view of the optional `pip_install` block. Mirrors
/// the shape the executor's prompt produces from
/// `pip install --report`. Each row carries the package name
/// (lowercased), the resolved version string (free-form text;
/// pip puts e.g. `2024.7.4` here), and the per-wheel SHA256 from
/// `download_info.archive_info.hash`.
#[derive(Debug, Clone)]
pub struct PipInstallEvidence {
    pub success: bool,
    pub installed: Vec<PipInstallEntry>,
}

#[derive(Debug, Clone)]
pub struct PipInstallEntry {
    pub name: String,
    pub version: String,
    pub sha256: String,
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
        let pip_install = obj
            .get("pip_install")
            .map(PipInstallEvidence::from_json)
            .transpose()?;
        Ok(Self {
            http_status,
            body_size_bytes,
            body_sha256,
            body_contains_example_domain,
            pip_install,
        })
    }
}

impl PipInstallEvidence {
    fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let obj = v.as_object().ok_or("`pip_install` is not a JSON object")?;
        let success = obj
            .get("success")
            .and_then(|x| x.as_bool())
            .ok_or("missing or non-boolean `pip_install.success`")?;
        let installed_raw = obj
            .get("installed")
            .and_then(|x| x.as_array())
            .ok_or("missing or non-array `pip_install.installed`")?;
        let mut installed = Vec::with_capacity(installed_raw.len());
        for (idx, row) in installed_raw.iter().enumerate() {
            installed.push(
                PipInstallEntry::from_json(row)
                    .map_err(|e| format!("`pip_install.installed[{idx}]`: {e}"))?,
            );
        }
        Ok(Self { success, installed })
    }
}

impl PipInstallEntry {
    fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let obj = v.as_object().ok_or("entry is not a JSON object")?;
        let name = obj
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or("missing or non-string `name`")?
            .to_ascii_lowercase();
        let version = obj
            .get("version")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_owned();
        let sha256 = obj
            .get("sha256")
            .and_then(|x| x.as_str())
            .ok_or("missing or non-string `sha256`")?
            .trim();
        let sha256 = sha256
            .strip_prefix("sha256=")
            .or_else(|| sha256.strip_prefix("sha256:"))
            .unwrap_or(sha256)
            .to_ascii_lowercase();
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "`sha256` is not a 64-char lowercase hex string (got len={}, value={sha256:?})",
                sha256.len()
            ));
        }
        Ok(Self {
            name,
            version,
            sha256,
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
        //     The task is pinned to the
        //     `{example.com, pypi.org, files.pythonhosted.org}`
        //     allowlist (see [`ALLOWED_HOSTS`]).
        if !self.off_target_grants(chain).is_empty() {
            return false;
        }
        // (4) pip-install arm: at least one grant to pypi.org
        //     (simple-index resolution) AND at least one grant
        //     to files.pythonhosted.org (wheel download). Both
        //     fire on a real `pip install --no-cache-dir`. If
        //     either is missing, the install evidence below
        //     could in principle be synthesised offline; failing
        //     closed on the chain side keeps the witness honest.
        if self.grants_for_host(chain, PIP_HOST_INDEX).is_empty() {
            return false;
        }
        if self.grants_for_host(chain, PIP_HOST_FILES).is_empty() {
            return false;
        }
        // (5) on-disk evidence file parses cleanly with the four
        //     HTTPS-arm contractual fields, AND the iter69 pip-
        //     install arm carries a `success=true` block with at
        //     least one row whose `name == "certifi"`.
        match self.parse_evidence() {
            Ok(ev) => {
                if !(ev.http_status == 200
                    && ev.body_size_bytes > 0
                    && ev.body_contains_example_domain)
                {
                    return false;
                }
                let Some(pip) = ev.pip_install.as_ref() else {
                    return false;
                };
                if !pip.success || pip.installed.is_empty() {
                    return false;
                }
                pip.installed.iter().any(|e| e.name == PIP_PACKAGE_NAME)
            }
            Err(_) => false,
        }
    }

    fn diagnostic(&self, chain: &[AuditEvent]) -> String {
        let grants = self.matching_grants(chain);
        let denials = self.target_denials(chain);
        let off_target = self.off_target_grants(chain);
        let pip_index_grants = self.grants_for_host(chain, PIP_HOST_INDEX);
        let pip_files_grants = self.grants_for_host(chain, PIP_HOST_FILES);
        let evidence = self.parse_evidence();
        let abs = self.absolute_evidence_path();
        let disk_state = match std::fs::metadata(&abs) {
            Ok(m) if m.is_file() => format!("file present (len={} bytes)", m.len()),
            Ok(_) => "path exists but is not a regular file".to_owned(),
            Err(e) => format!("not present ({e})"),
        };
        let evidence_summary = match &evidence {
            Ok(ev) => {
                let pip = match ev.pip_install.as_ref() {
                    None => "<absent>".to_owned(),
                    Some(p) => {
                        let rows: Vec<String> = p
                            .installed
                            .iter()
                            .map(|e| {
                                format!(
                                    "{}@{} sha256={}",
                                    e.name,
                                    e.version,
                                    &e.sha256[..e.sha256.len().min(12)],
                                )
                            })
                            .collect();
                        format!("success={}, installed={:?}", p.success, rows)
                    }
                };
                format!(
                    "http_status={s}, body_size_bytes={n}, \
                     body_contains_example_domain={c}, body_sha256={sh}; \
                     pip_install: {pip}",
                    s = ev.http_status,
                    n = ev.body_size_bytes,
                    c = ev.body_contains_example_domain,
                    sh = ev.body_sha256,
                )
            }
            Err(e) => format!("(parse error: {e})"),
        };
        format!(
            "DepFetchEvidence[{task}; session={sid}]:\n  \
             TproxyAdmissionGranted matching {host}:{port}: seqs={grants:?}\n  \
             TproxyAdmissionDenied  matching {host}:_:    seqs+reasons={denials:?}\n  \
             off-target grants on this session: {off_target:?}\n  \
             TproxyAdmissionGranted matching {pip_idx}: seqs={pip_index_grants:?}\n  \
             TproxyAdmissionGranted matching {pip_files}: seqs={pip_files_grants:?}\n  \
             evidence file: {abs}\n  \
             disk state:    {disk_state}\n  \
             parsed:        {evidence_summary}",
            task = self.task_id,
            sid = self.executor_session_id,
            host = TARGET_HOST,
            port = TARGET_PORT,
            pip_idx = PIP_HOST_INDEX,
            pip_files = PIP_HOST_FILES,
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
///
/// The chain contains three grants — one per host in
/// [`ALLOWED_HOSTS`] — so the iter69 pip-install arm of the
/// predicate is also satisfied. The `original_dst_ip` /
/// `tunnel_id` fields are dummy values; the witness only pins
/// `host_or_sni` + port + session.
#[must_use]
pub fn synthetic_satisfying_chain(session_id: &str) -> Vec<AuditEvent> {
    fn grant_event(seq: u64, session_id: &str, host: &str) -> AuditEvent {
        let payload = AuditEventKind::TproxyAdmissionGranted {
            session_id: session_id.to_owned(),
            host_or_sni: Some(host.to_owned()),
            original_dst_ip: "93.184.216.34".to_owned(),
            original_dst_port: 443,
            protocol: "https".to_owned(),
            tunnel_id: uuid::Uuid::nil().to_string(),
        };
        AuditEvent {
            seq,
            event_id: uuid::Uuid::nil(),
            event_kind: "TproxyAdmissionGranted".to_owned(),
            session_id: Some(session_id.to_owned()),
            task_id: Some(TASK_DEP_FETCH_EVIDENCE.to_owned()),
            initiative_id: Some("init-realistic".to_owned()),
            payload: serde_json::to_value(&payload).unwrap(),
            emitted_at: 1_700_000_000 + seq as i64,
            prev_sha256: "0".repeat(64),
        }
    }
    vec![
        grant_event(1, session_id, TARGET_HOST),
        grant_event(2, session_id, PIP_HOST_INDEX),
        grant_event(3, session_id, PIP_HOST_FILES),
    ]
}

/// Write a synthetic-but-shape-faithful evidence file into
/// `workdir/out/deps/install-evidence.json`. Used by the wiring
/// smoke test so it can drive the on-disk arm of the witness
/// without a real network fetch.
///
/// Includes a synthetic `pip_install` block with one row whose
/// name is `certifi`, so the iter69 pip-install arm of the
/// witness predicate is satisfied. The wheel SHA256 is a fixed
/// 64-char hex string with no special meaning — the witness
/// only validates structural shape, not the literal bytes.
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
        "pip_install": {
            "requested":  ["certifi"],
            "target_dir": "out/deps/_pip",
            "report_path": "out/deps/_pip-report.json",
            "success":    true,
            "installed":  [
                {
                    "name":    PIP_PACKAGE_NAME,
                    "version": "2024.7.4",
                    "sha256":  "a".repeat(64),
                    "url":     "https://files.pythonhosted.org/packages/.../certifi-2024.7.4-py3-none-any.whl",
                }
            ],
        },
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

    /// Build the canonical chain that satisfies every arm of the
    /// witness — three grants, one per allowed host, scoped to
    /// the supplied executor session. The tests use this as their
    /// happy-path baseline and then mutate / extend it to drive
    /// individual failure axes.
    fn full_chain(session_id: &str) -> Vec<AuditEvent> {
        vec![
            grant(10, session_id, Some(TARGET_HOST), TARGET_PORT),
            grant(11, session_id, Some(PIP_HOST_INDEX), 443),
            grant(12, session_id, Some(PIP_HOST_FILES), 443),
        ]
    }

    #[test]
    fn happy_path_full_chain_plus_disk_evidence_satisfies() {
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
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
        let chain = vec![grant(
            10,
            "sess-someone-else",
            Some(TARGET_HOST),
            TARGET_PORT,
        )];
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn grant_for_wrong_host_does_not_satisfy() {
        // A grant for a host outside the pinned allowlist
        // (`{example.com, pypi.org, files.pythonhosted.org}`)
        // is treated as a scope leak — the witness fails closed
        // even if all the other arms also fire.
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![grant(10, "sess-exec-1", Some("api.anthropic.com"), 443)];
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
        let mut chain = full_chain("sess-exec-1");
        chain.push(deny(
            13,
            "sess-exec-1",
            Some(TARGET_HOST),
            "host_not_in_allowlist",
        ));
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("host_not_in_allowlist"), "{diag}");
    }

    #[test]
    fn off_target_grant_on_same_session_fails() {
        // The task is pinned to `ALLOWED_HOSTS`. A grant on the
        // executor's session for any other host means the
        // executor went outside its scope.
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let mut chain = full_chain("sess-exec-1");
        chain.push(grant(13, "sess-exec-1", Some("api.anthropic.com"), 443));
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn missing_pypi_index_grant_fails() {
        // iter69 pip-install arm — the witness requires a chain
        // grant to `pypi.org` so the `pip install` flow is
        // proven to have round-tripped through the kernel's
        // admission stack.
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![
            grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT),
            // No pypi.org grant — only the wheel host.
            grant(11, "sess-exec-1", Some(PIP_HOST_FILES), 443),
        ];
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn missing_pythonhosted_files_grant_fails() {
        // Symmetric to the above — pypi.org alone is not enough,
        // the wheel host must also fire.
        let tmp = TempDir::new().unwrap();
        write_synthetic_evidence(tmp.path()).expect("smoke evidence");
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = vec![
            grant(10, "sess-exec-1", Some(TARGET_HOST), TARGET_PORT),
            grant(11, "sess-exec-1", Some(PIP_HOST_INDEX), 443),
        ];
        assert!(!w.satisfied_by(&chain));
    }

    /// Canonical `pip_install` block — embedded in the
    /// hand-rolled evidence JSON used by the disk-failure tests
    /// below so each test isolates the on-disk axis it's
    /// targeting (HTTPS status, body substring, sha shape, …)
    /// without also flunking the pip-install arm.
    fn valid_pip_install_block() -> serde_json::Value {
        serde_json::json!({
            "requested":  ["certifi"],
            "target_dir": "out/deps/_pip",
            "report_path": "out/deps/_pip-report.json",
            "success":    true,
            "installed":  [
                {
                    "name":    PIP_PACKAGE_NAME,
                    "version": "2024.7.4",
                    "sha256":  "a".repeat(64),
                    "url":     "https://files.pythonhosted.org/packages/.../certifi-2024.7.4-py3-none-any.whl",
                }
            ],
        })
    }

    #[test]
    fn evidence_with_pip_style_sha256_prefix_satisfies() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("out").join("deps");
        std::fs::create_dir_all(&dir).unwrap();
        let pip = valid_pip_install_block();
        let mut pip = pip.as_object().cloned().unwrap();
        pip.insert(
            "installed".to_owned(),
            serde_json::json!([
                {
                    "name": PIP_PACKAGE_NAME,
                    "version": "2024.7.4",
                    "sha256": format!("sha256={}", "a".repeat(64)),
                    "url": "https://files.pythonhosted.org/packages/.../certifi-2024.7.4-py3-none-any.whl",
                }
            ]),
        );
        std::fs::write(
            dir.join("install-evidence.json"),
            serde_json::to_string(&serde_json::json!({
                "http_status": 200,
                "body_size_bytes": 42,
                "body_sha256": "0".repeat(64),
                "body_contains_example_domain": true,
                "pip_install": serde_json::Value::Object(pip),
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn missing_evidence_file_fails_with_named_path() {
        let tmp = TempDir::new().unwrap();
        // NOTE: no `write_synthetic_evidence` — the file is absent.
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
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
                "pip_install":                valid_pip_install_block(),
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
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
                "pip_install":                valid_pip_install_block(),
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
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
                "pip_install":                valid_pip_install_block(),
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("body_sha256"), "{diag}");
    }

    #[test]
    fn evidence_with_missing_pip_install_block_fails() {
        // iter69 — an evidence file that carries only the
        // HTTPS-fetch arm (no `pip_install` key) must fail; the
        // pip arm is a hard requirement once egress is wired.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("out").join("deps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-evidence.json"),
            serde_json::to_string(&serde_json::json!({
                "http_status":                200,
                "body_size_bytes":            42,
                "body_sha256":                "0".repeat(64),
                "body_contains_example_domain": true,
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("<absent>"), "{diag}");
    }

    #[test]
    fn evidence_with_pip_install_success_false_fails() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("out").join("deps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-evidence.json"),
            serde_json::to_string(&serde_json::json!({
                "http_status":                200,
                "body_size_bytes":            42,
                "body_sha256":                "0".repeat(64),
                "body_contains_example_domain": true,
                "pip_install":                serde_json::json!({
                    "requested":  ["certifi"],
                    "target_dir": "out/deps/_pip",
                    "report_path": "out/deps/_pip-report.json",
                    "success":    false,
                    "installed":  [],
                }),
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn evidence_with_pip_install_missing_certifi_fails() {
        // iter69 — at least one entry in `pip_install.installed`
        // must name `certifi`. If only an unrelated package shows
        // up, the executor installed the wrong thing.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("out").join("deps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-evidence.json"),
            serde_json::to_string(&serde_json::json!({
                "http_status":                200,
                "body_size_bytes":            42,
                "body_sha256":                "0".repeat(64),
                "body_contains_example_domain": true,
                "pip_install":                serde_json::json!({
                    "requested":  ["certifi"],
                    "target_dir": "out/deps/_pip",
                    "report_path": "out/deps/_pip-report.json",
                    "success":    true,
                    "installed":  [
                        {
                            "name":    "idna",
                            "version": "3.7",
                            "sha256":  "b".repeat(64),
                            "url":     "https://files.pythonhosted.org/packages/.../idna-3.7-py3-none-any.whl",
                        }
                    ],
                }),
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn evidence_with_pip_install_non_hex_sha_fails_parse_with_named_field() {
        // iter69 — per-wheel sha256 must be 64-char lowercase hex.
        // A short or non-hex value surfaces with the `sha256`
        // field name in the parse-error diagnostic.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("out").join("deps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-evidence.json"),
            serde_json::to_string(&serde_json::json!({
                "http_status":                200,
                "body_size_bytes":            42,
                "body_sha256":                "0".repeat(64),
                "body_contains_example_domain": true,
                "pip_install":                serde_json::json!({
                    "requested":  ["certifi"],
                    "target_dir": "out/deps/_pip",
                    "report_path": "out/deps/_pip-report.json",
                    "success":    true,
                    "installed":  [
                        {
                            "name":    PIP_PACKAGE_NAME,
                            "version": "2024.7.4",
                            "sha256":  "not-a-hex-string",
                            "url":     "https://files.pythonhosted.org/packages/.../certifi-2024.7.4-py3-none-any.whl",
                        }
                    ],
                }),
            }))
            .unwrap(),
        )
        .unwrap();
        let w = witness_for(tmp.path(), "sess-exec-1");
        let chain = full_chain("sess-exec-1");
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("sha256"), "{diag}");
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

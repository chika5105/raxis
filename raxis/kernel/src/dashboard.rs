// raxis-kernel::dashboard — kernel glue for the operator dashboard.
//
// Normative reference: specs/v2/v2_extended_gaps.md §4.
//
// What this module does
// ─────────────────────
// 1. Defines `KernelDashboardData` — the production
//    `raxis_dashboard::DashboardData` impl that fans out to:
//      - `raxis_store::ro` for read-only snapshots of every
//        kernel.db row the dashboard surfaces,
//      - `raxis_audit_tools::reader::ChainReader` for paginated
//        audit-chain access,
//      - `Arc<ArcSwap<PolicyBundle>>::load()` for the operator
//        roster + current `[notifications]` snapshot,
//      - the operator's on-disk `policy.toml` for the raw editor
//        surface (`/api/policy/toml`).
// 2. Loads the optional `[dashboard]` block out of `policy.toml`
//    on boot so operators can declare bind address / port / TLS
//    paths / JWT TTL / challenge bounds without us having to
//    extend the strongly-typed `PolicyBundle` shape.
// 3. Spawns the axum HTTP server and returns a graceful-shutdown
//    handle the kernel's main loop holds.
//
// Why the policy.toml is parsed twice
// ───────────────────────────────────
// `raxis_policy::PolicyBundle` is the kernel's source of truth
// for everything that needs validation, signing, and epoch
// pinning. The dashboard config (port, JWT TTL, etc.) is a
// runtime knob with no security semantics — duplicating it into
// every test fixture is more harm than good. We re-parse the
// file once at boot to extract the optional block; absence ⇒
// dashboard disabled (zero runtime cost per spec §4.3).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;

use raxis_audit_tools::reader::ChainReader;
use raxis_dashboard::auth::DashboardRole;
use raxis_dashboard::config::DashboardConfig;
use raxis_dashboard::data::{
    AuditEntryView, DagEdge, DashboardData, EscalationView, HealthCheck, HealthSnapshot,
    InitiativeListEntry, InitiativeView, OperatorAuthResolution, PolicyOperatorView,
    PolicySnapshotView, ReviewerVerdictView, SessionView, StructuredOutputView, TaskView,
};
use raxis_dashboard::error::ApiError;
use raxis_dashboard::server::{DashboardServer, ServerHandle};
use raxis_policy::PolicyBundle;
use raxis_store::Store;

/// Kernel-wired implementation of the dashboard data trait.
///
/// Construction is cheap (just `Arc` clones); every read method
/// opens a fresh short-lived `RoConn` per call so the dashboard
/// never holds a WAL snapshot across UI ticks (mirrors the
/// CLI's discipline in `cli-readonly.md §5.4.3`).
pub struct KernelDashboardData {
    /// Live policy bundle (used for operator resolution + policy
    /// snapshot rendering).
    policy: Arc<ArcSwap<PolicyBundle>>,
    /// Path to the kernel data directory. We open a fresh
    /// `RoConn` from here per request rather than caching one,
    /// since the `RoConn` is `!Send + !Sync` (rusqlite handle
    /// uses interior mutability).
    data_dir: PathBuf,
    /// Path to the operator's policy.toml. Read for
    /// `/api/policy/toml` (write-policy role only).
    policy_path: PathBuf,
    /// Audit segment directory (`<data_dir>/audit`).
    audit_dir: PathBuf,
    /// Boot time in unix seconds for the health snapshot.
    booted_at: u64,
    /// Kernel store handle. Reserved for future write surfaces
    /// (PUT /api/policy/toml, mark-notification-read, etc.) —
    /// the read trait does not currently need it because every
    /// view function takes `&RoConn` instead, but we hold the
    /// handle so PUT endpoints (P5) can grab `lock_sync()` for
    /// the actual mutation.
    #[allow(dead_code)]
    store: Arc<Store>,
}

impl KernelDashboardData {
    /// Build a new kernel-wired data layer.
    pub fn new(
        store: Arc<Store>,
        policy: Arc<ArcSwap<PolicyBundle>>,
        data_dir: PathBuf,
        policy_path: PathBuf,
        booted_at: u64,
    ) -> Self {
        let audit_dir = data_dir.join("audit");
        Self { policy, data_dir, policy_path, audit_dir, booted_at, store }
    }

    fn open_ro(&self) -> Result<raxis_store::ro::RoConn, ApiError> {
        raxis_store::ro::open(&self.data_dir).map_err(|e| ApiError::Internal {
            log_only: format!("ro::open failed: {e}"),
        })
    }
}

/// Map an `OperatorEntry::permitted_ops` set to the dashboard's
/// role triplet. The mapping is conservative: every operator
/// has `Read`; `RotateEpoch`-class permissions imply
/// `WritePolicy`; `RotateEpoch` + `OperatorCertInstall` imply
/// `Admin`.
///
/// Why bake this into kernel-side glue rather than the
/// dashboard crate: the canonical permitted-op vocabulary
/// belongs to `raxis-policy` (see kernel-store.md §2.5.5) —
/// the dashboard crate stays generic so tests can plug in
/// mock role sets without standing up the policy crate.
fn roles_from_permitted_ops(permitted: &[String]) -> Vec<DashboardRole> {
    let mut out = vec![DashboardRole::Read];
    let has = |op: &str| permitted.iter().any(|p| p == op);
    if has("RotateEpoch") || has("UpdatePolicy") {
        out.push(DashboardRole::WritePolicy);
    }
    if has("RotateEpoch") && has("OperatorCertInstall") {
        out.push(DashboardRole::Admin);
    }
    out
}

impl DashboardData for KernelDashboardData {
    fn lookup_operator_roles(&self, fingerprint: &str) -> Option<OperatorAuthResolution> {
        let bundle = self.policy.load_full();
        let entry = bundle.operator_entry(fingerprint)?;
        Some(OperatorAuthResolution {
            display_name: entry.display_name.clone(),
            roles: roles_from_permitted_ops(&entry.permitted_ops),
        })
    }

    fn health(&self) -> HealthSnapshot {
        let bundle = self.policy.load_full();
        let policy_epoch = bundle.epoch();
        let (active_initiatives, active_sessions, pending_escalations) =
            match self.open_ro() {
                Ok(conn) => {
                    let inits = raxis_store::views::initiatives::counts_by_state(&conn)
                        .map(|c| (c.draft + c.approved_plan + c.executing + c.blocked) as u32)
                        .unwrap_or(0);
                    let sess = raxis_store::views::sessions::active_counts(&conn)
                        .map(|c| c.active as u32)
                        .unwrap_or(0);
                    let esc = raxis_store::views::escalations::pending_count(&conn)
                        .map(|n| n as u32)
                        .unwrap_or(0);
                    (inits, sess, esc)
                }
                Err(_) => (0, 0, 0),
            };
        // Coarse status:
        //   - chain readable + store readable + policy loaded ⇒ "ok"
        //   - any one absent ⇒ "degraded"
        // We deliberately surface the per-check list only to
        // `admin` (the route handler degrades for `read` roles).
        let mut checks = Vec::new();
        match raxis_store::ro::open(&self.data_dir) {
            Ok(_) => checks.push(HealthCheck {
                id: "store_open".into(),
                status: "ok".into(),
                message: "kernel.db opened read-only".into(),
            }),
            Err(e) => checks.push(HealthCheck {
                id: "store_open".into(),
                status: "failing".into(),
                message: format!("kernel.db unreadable: {e}"),
            }),
        }
        match ChainReader::open(&self.audit_dir) {
            Ok(r) => checks.push(HealthCheck {
                id: "audit_chain".into(),
                status: "ok".into(),
                message: format!(
                    "{} segment(s) discovered",
                    r.segment_count()
                ),
            }),
            Err(e) => checks.push(HealthCheck {
                id: "audit_chain".into(),
                status: "failing".into(),
                message: format!("chain unreadable: {e}"),
            }),
        }
        let status = if checks.iter().all(|c| c.status == "ok") {
            "ok"
        } else if checks.iter().any(|c| c.status == "failing") {
            "failing"
        } else {
            "degraded"
        };
        HealthSnapshot {
            status: status.into(),
            checks,
            kernel_booted_at: self.booted_at,
            policy_epoch,
            active_initiatives,
            active_sessions,
            pending_escalations,
        }
    }

    fn list_initiatives(
        &self,
        limit: u32,
        state_filter: Option<&str>,
    ) -> Result<Vec<InitiativeListEntry>, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::initiatives::list(
            &conn,
            state_filter,
            limit.min(200) as usize,
        )
        .map_err(|e| ApiError::Internal { log_only: format!("initiatives::list: {e}") })?;
        // Per-initiative task counts (one extra read per row — bounded
        // by `limit` so worst-case is 200 lookups).
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let tasks = raxis_store::views::tasks::list_by_initiative(
                &conn,
                &r.initiative_id,
                500,
            )
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::list_by_initiative: {e}") })?;
            let task_count = tasks.len() as u32;
            let completed_tasks = tasks.iter().filter(|t| t.state == "Completed").count() as u32;
            let failed_tasks = tasks.iter().filter(|t| t.state == "Failed").count() as u32;
            let updated_at = tasks.iter().map(|t| t.transitioned_at).max().unwrap_or(r.created_at);
            out.push(InitiativeListEntry {
                initiative_id: r.initiative_id,
                display_name: String::new(), // initiative-table has no display name today
                state: r.state,
                task_count,
                completed_tasks,
                failed_tasks,
                created_at: r.created_at,
                updated_at,
            });
        }
        Ok(out)
    }

    fn get_initiative(&self, id: &str) -> Result<InitiativeView, ApiError> {
        let conn = self.open_ro()?;
        let row = raxis_store::views::initiatives::by_id(&conn, id)
            .map_err(|e| ApiError::Internal { log_only: format!("initiatives::by_id: {e}") })?
            .ok_or(ApiError::NotFound { kind: "initiative".into() })?;
        let bundle = self.policy.load_full();
        let task_rows = raxis_store::views::tasks::list_by_initiative(&conn, id, 500)
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::list_by_initiative: {e}") })?;
        let task_count = task_rows.len() as u32;
        let completed_tasks = task_rows.iter().filter(|t| t.state == "Completed").count() as u32;
        let failed_tasks = task_rows.iter().filter(|t| t.state == "Failed").count() as u32;
        let updated_at = task_rows.iter().map(|t| t.transitioned_at).max().unwrap_or(row.created_at);
        let mut tasks = Vec::with_capacity(task_rows.len());
        let mut edges: Vec<DagEdge> = Vec::new();
        for t in &task_rows {
            // Pull DAG edges (downstream) for the edge list.
            if let Ok(downstream) = raxis_store::views::tasks::dag_edges_for_task(
                &conn,
                &t.task_id,
                raxis_store::views::tasks::EdgeDirection::Downstream,
                100,
            ) {
                for e in downstream {
                    edges.push(DagEdge {
                        from: t.task_id.clone(),
                        to: e.other_task_id,
                    });
                }
            }
            tasks.push(task_row_to_view(&conn, t));
        }
        Ok(InitiativeView {
            summary: InitiativeListEntry {
                initiative_id: row.initiative_id.clone(),
                display_name: String::new(),
                state: row.state,
                task_count,
                completed_tasks,
                failed_tasks,
                created_at: row.created_at,
                updated_at,
            },
            approved_by: None, // not stored on initiatives row
            plan_sha256: Some(row.plan_artifact_sha256),
            target_ref: None,
            policy_epoch: bundle.epoch(),
            tasks,
            edges,
        })
    }

    fn list_tasks(&self, initiative_id: &str) -> Result<Vec<TaskView>, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::tasks::list_by_initiative(&conn, initiative_id, 500)
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::list_by_initiative: {e}") })?;
        Ok(rows.iter().map(|t| task_row_to_view(&conn, t)).collect())
    }

    fn get_task(&self, task_id: &str) -> Result<TaskView, ApiError> {
        let conn = self.open_ro()?;
        let row = raxis_store::views::tasks::by_id(&conn, task_id)
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::by_id: {e}") })?
            .ok_or(ApiError::NotFound { kind: "task".into() })?;
        Ok(task_row_to_view(&conn, &row))
    }

    fn list_sessions(&self, limit: u32) -> Result<Vec<SessionView>, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::sessions::active_list(&conn, limit.min(200) as usize)
            .map_err(|e| ApiError::Internal { log_only: format!("sessions::active_list: {e}") })?;
        Ok(rows
            .into_iter()
            .map(|s| SessionView {
                session_id: s.session_id,
                role: s.role_id,
                initiative_id: None,
                task_id: None,
                state: if s.revoked { "Revoked".into() } else { "Active".into() },
                provider: None,
                model: None,
                input_tokens: 0,
                output_tokens: 0,
                created_at: s.created_at,
                updated_at: s.created_at,
            })
            .collect())
    }

    fn get_session(&self, session_id: &str) -> Result<SessionView, ApiError> {
        // The store's session catalog is keyed by token; we walk
        // the active list as an O(N) lookup (N ≤ 200). For V2.5 this
        // is the most truthful surface — the kernel does not expose a
        // by_id session view yet because every other consumer either
        // filters by FK (tasks.session_id) or scans the active list.
        let conn = self.open_ro()?;
        let rows = raxis_store::views::sessions::active_list(&conn, 200)
            .map_err(|e| ApiError::Internal { log_only: format!("sessions::active_list: {e}") })?;
        rows.into_iter()
            .find(|s| s.session_id == session_id)
            .map(|s| SessionView {
                session_id: s.session_id,
                role: s.role_id,
                initiative_id: None,
                task_id: None,
                state: if s.revoked { "Revoked".into() } else { "Active".into() },
                provider: None,
                model: None,
                input_tokens: 0,
                output_tokens: 0,
                created_at: s.created_at,
                updated_at: s.created_at,
            })
            .ok_or(ApiError::NotFound { kind: "session".into() })
    }

    fn list_escalations(&self) -> Result<Vec<EscalationView>, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::escalations::list(
            &conn,
            raxis_store::views::escalations::EscalationStatusFilter::Pending,
            200,
        )
        .map_err(|e| ApiError::Internal { log_only: format!("escalations::list: {e}") })?;
        Ok(rows
            .into_iter()
            .map(|e| EscalationView {
                escalation_id: e.escalation_id,
                initiative_id: e.initiative_id,
                task_id: Some(e.task_id),
                severity: severity_from_class(&e.class),
                reason: e.justification,
                action_required: e.class,
                created_at: e.created_at,
            })
            .collect())
    }

    fn get_escalation(&self, id: &str) -> Result<EscalationView, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::escalations::list(
            &conn,
            raxis_store::views::escalations::EscalationStatusFilter::All,
            500,
        )
        .map_err(|e| ApiError::Internal { log_only: format!("escalations::list: {e}") })?;
        rows.into_iter()
            .find(|e| e.escalation_id == id)
            .map(|e| EscalationView {
                escalation_id: e.escalation_id,
                initiative_id: e.initiative_id,
                task_id: Some(e.task_id),
                severity: severity_from_class(&e.class),
                reason: e.justification,
                action_required: e.class,
                created_at: e.created_at,
            })
            .ok_or(ApiError::NotFound { kind: "escalation".into() })
    }

    fn list_audit(
        &self,
        cursor_seq: Option<u64>,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<AuditEntryView>, ApiError> {
        // Walk the chain newest-first by collecting ALL records
        // matching the filter then paginating. The chain reader
        // walks oldest→newest, so we collect into a Vec and reverse.
        // For V2.5 chains (single segment, ≤ 100K events for a
        // typical operator) this is acceptable. A larger
        // workspace will need a server-side index — tracked under
        // §3 of the dashboard spec under "future indexing".
        let reader = ChainReader::open(&self.audit_dir).map_err(|e| ApiError::Internal {
            log_only: format!("ChainReader::open: {e}"),
        })?;
        let cap = limit.min(500) as usize;
        let mut matched: Vec<AuditEntryView> = Vec::new();
        for rec in reader.records() {
            let rec = match rec {
                Ok(r) => r,
                Err(_) => continue, // tolerate one malformed line per spec
            };
            if let Some(want) = initiative_id {
                if rec.initiative_id.as_deref() != Some(want) {
                    continue;
                }
            }
            let payload = rec
                .parsed_value
                .as_ref()
                .and_then(|v| v.get("payload").cloned())
                .unwrap_or(serde_json::Value::Null);
            matched.push(AuditEntryView {
                seq: rec.seq,
                event_id: rec
                    .parsed_value
                    .as_ref()
                    .and_then(|v| v.get("event_id"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_owned(),
                event_kind: rec.event_kind,
                initiative_id: rec.initiative_id,
                task_id: rec.task_id,
                session_id: rec.session_id,
                at: rec.emitted_at.unwrap_or(0).max(0) as u64,
                payload,
            });
        }
        // Newest first.
        matched.sort_by(|a, b| b.seq.cmp(&a.seq));
        let from = match cursor_seq {
            Some(c) => matched
                .iter()
                .position(|e| e.seq < c)
                .unwrap_or(matched.len()),
            None => 0,
        };
        let end = (from + cap).min(matched.len());
        Ok(matched[from..end].to_vec())
    }

    fn list_inbox(&self) -> Result<Vec<AuditEntryView>, ApiError> {
        // Inbox surface: union of escalations + reviews awaiting
        // operator action. Today the kernel-owned `notifications`
        // table is the durable inbox (see kernel/src/notifications);
        // for V2.5 we surface the pending escalations as inbox rows
        // until the dashboard P4 (notification table) lands.
        let escs = self.list_escalations()?;
        let inbox = escs
            .into_iter()
            .map(|e| AuditEntryView {
                seq: 0,
                event_id: e.escalation_id.clone(),
                event_kind: "EscalationPending".to_owned(),
                initiative_id: Some(e.initiative_id),
                task_id: e.task_id,
                session_id: None,
                at: e.created_at,
                payload: serde_json::json!({
                    "severity":        e.severity,
                    "reason":          e.reason,
                    "action_required": e.action_required,
                }),
            })
            .collect();
        Ok(inbox)
    }

    fn policy_snapshot(&self) -> Result<PolicySnapshotView, ApiError> {
        let bundle = self.policy.load_full();
        let operators = bundle
            .operators()
            .iter()
            .map(|o| PolicyOperatorView {
                fingerprint: o.pubkey_fingerprint.clone(),
                display_name: o.display_name.clone(),
                permitted_ops: o.permitted_ops.clone(),
            })
            .collect();
        let mut routes = std::collections::HashMap::new();
        for ch in bundle.notification_channels() {
            routes
                .entry("default".to_owned())
                .or_insert_with(Vec::new)
                .push(ch.id.clone());
        }
        Ok(PolicySnapshotView {
            epoch: bundle.epoch(),
            policy_sha256: hex::encode(bundle.policy_sha256().as_bytes()),
            signed_by: bundle.signed_by().to_owned(),
            signed_at: bundle.signed_at(),
            operators,
            notification_routes: routes,
        })
    }

    fn policy_toml_bytes(&self) -> Result<String, ApiError> {
        std::fs::read_to_string(&self.policy_path)
            .map_err(|e| ApiError::Internal { log_only: format!("policy.toml read: {e}") })
    }
}

/// Common task-row → TaskView projection. Pulls structured
/// outputs from the V2 §3.2 table; reviewer verdicts are not
/// surfaced yet (the store does not own that read view today).
fn task_row_to_view(
    conn: &raxis_store::ro::RoConn,
    t: &raxis_store::views::tasks::TaskRow,
) -> TaskView {
    let outputs = raxis_store::views::structured_outputs::list_for_task(conn, &t.task_id)
        .unwrap_or_default()
        .into_iter()
        .map(|o| StructuredOutputView {
            kind: o.kind,
            payload: serde_json::from_str(&o.payload_json).unwrap_or(serde_json::Value::Null),
            at: o.emitted_at.max(0) as u64,
        })
        .collect();
    TaskView {
        task_id: t.task_id.clone(),
        initiative_id: t.initiative_id.clone(),
        title: String::new(), // tasks table doesn't store a display title
        state: t.state.clone(),
        session_id: t.session_id.clone(),
        reviewer_verdicts: Vec::<ReviewerVerdictView>::new(),
        structured_outputs: outputs,
        path_allowlist: Vec::new(),
        created_at: t.admitted_at,
        updated_at: t.transitioned_at,
    }
}

/// Map an escalation `class` discriminator to a coarse
/// `Low/Normal/High` severity for the dashboard. Mirrors the CLI
/// `raxis escalations` rendering.
fn severity_from_class(class: &str) -> String {
    match class {
        "PolicyViolation" | "SecurityViolation" => "High",
        "CapabilityUpgrade" => "Normal",
        _ => "Low",
    }
    .into()
}

// ---------------------------------------------------------------------------
// policy.toml [dashboard] block parser
// ---------------------------------------------------------------------------

/// Minimal struct used to extract only the `[dashboard]` block
/// out of policy.toml without re-validating the entire bundle.
/// Everything is `Option` so a missing block produces
/// `Outer { dashboard: None }`.
#[derive(Debug, Deserialize)]
struct OuterPolicy {
    #[serde(default)]
    dashboard: Option<DashboardConfig>,
}

/// Read the optional `[dashboard]` block from `policy_path`.
/// Returns `Ok(None)` when:
///   - the file is missing,
///   - the file is unreadable,
///   - the `[dashboard]` block is absent,
///   - `enabled = false`.
/// Any other parse failure surfaces as `Err`.
pub fn load_dashboard_config(policy_path: &Path) -> Result<Option<DashboardConfig>, String> {
    let raw = match std::fs::read_to_string(policy_path) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let outer: OuterPolicy = toml::from_str(&raw).map_err(|e| e.to_string())?;
    let cfg = match outer.dashboard {
        Some(c) if c.enabled => c,
        _ => return Ok(None),
    };
    Ok(Some(cfg))
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

/// Spawn the dashboard server in the background. Returns the
/// handle the kernel main loop holds until shutdown. Caller is
/// responsible for awaiting `handle.shutdown()` during the
/// orderly exit path.
pub async fn start_dashboard(
    cfg: DashboardConfig,
    store: Arc<Store>,
    policy: Arc<ArcSwap<PolicyBundle>>,
    data_dir: PathBuf,
    policy_path: PathBuf,
    booted_at: u64,
) -> Result<ServerHandle, String> {
    let data = Arc::new(KernelDashboardData::new(
        store,
        policy,
        data_dir,
        policy_path,
        booted_at,
    ));
    let server = DashboardServer::bind(cfg, data)
        .await
        .map_err(|e| format!("dashboard bind failed: {e}"))?;
    Ok(ServerHandle::spawn(server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_from_permitted_ops_default_is_read() {
        let r = roles_from_permitted_ops(&[]);
        assert_eq!(r, vec![DashboardRole::Read]);
    }

    #[test]
    fn rotate_epoch_implies_write_policy() {
        let r = roles_from_permitted_ops(&["RotateEpoch".into()]);
        assert!(r.contains(&DashboardRole::Read));
        assert!(r.contains(&DashboardRole::WritePolicy));
        assert!(!r.contains(&DashboardRole::Admin));
    }

    #[test]
    fn admin_requires_both_rotate_and_cert_install() {
        let r = roles_from_permitted_ops(&[
            "RotateEpoch".into(),
            "OperatorCertInstall".into(),
        ]);
        assert!(r.contains(&DashboardRole::Admin));
    }

    #[test]
    fn load_dashboard_config_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let r = load_dashboard_config(&tmp.path().join("does-not-exist.toml")).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn load_dashboard_config_returns_none_when_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("policy.toml");
        std::fs::write(
            &p,
            "[dashboard]\nenabled = false\nbind_address = \"127.0.0.1\"\nbind_port = 9820\n",
        )
        .unwrap();
        assert!(load_dashboard_config(&p).unwrap().is_none());
    }

    #[test]
    fn load_dashboard_config_parses_enabled_block() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("policy.toml");
        std::fs::write(
            &p,
            "[dashboard]\n\
             enabled = true\n\
             bind_address = \"127.0.0.1\"\n\
             bind_port = 0\n\
             jwt_ttl_secs = 1800\n",
        )
        .unwrap();
        let cfg = load_dashboard_config(&p).unwrap().unwrap();
        assert_eq!(cfg.bind_address, "127.0.0.1");
        assert_eq!(cfg.bind_port, 0);
        assert_eq!(cfg.jwt_ttl_secs, 1800);
        assert!(cfg.enabled);
    }

    #[test]
    fn severity_mapping_matches_class_set() {
        assert_eq!(severity_from_class("PolicyViolation"), "High");
        assert_eq!(severity_from_class("CapabilityUpgrade"), "Normal");
        assert_eq!(severity_from_class("Other"), "Low");
    }
}

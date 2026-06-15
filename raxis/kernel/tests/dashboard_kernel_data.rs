//! Integration tests for the dashboard kernel-glue layer.
//!
//! What this exercises (with REAL runtime objects, no mocks):
//!   - `KernelDashboardData` against a real on-disk `Store` after
//!     migrations are applied.
//!   - The HTTP server bound to an OS-assigned port serving JSON
//!     over `/api/initiatives` / `/api/health` / `/api/policy`.
//!   - JWT challenge-response flow over real HTTP using real
//!     Ed25519 signatures.
//!   - Audit chain reads against a real `segment-000.jsonl` written
//!     by `raxis_audit_tools::write_genesis_segment`.
//!
//! No subprocess, no kernel binary — these tests link the
//! production `KernelDashboardData` directly so any drift between
//! kernel-glue and dashboard surfaces is caught at compile time
//! AND at runtime.

#![cfg(test)]

use std::sync::Arc;

use arc_swap::ArcSwap;
use ed25519_dalek::{Signer, SigningKey};
use raxis_audit_tools::genesis::write_genesis_segment;
use raxis_dashboard::auth::DashboardRole;
use raxis_dashboard::config::DashboardConfig;
use raxis_dashboard::data::{AuditListFilters, DashboardData};
use raxis_policy::{OperatorEntry, PolicyBundle};
use raxis_store::Store;
use raxis_test_support::stub_cert_for_pubkey;

/// Spin up a fresh on-disk data dir with kernel.db migrated and a
/// genesis-ed audit chain. Returns the tempdir so its lifetime
/// outlives the caller's reads.
fn fresh_data_dir() -> (tempfile::TempDir, Arc<Store>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path();
    std::fs::create_dir_all(dd.join("audit")).unwrap();
    write_genesis_segment(&dd.join("audit"), &[0xC1u8; 32], &[0u8; 64], 1_700_000_000)
        .expect("write_genesis_segment");
    let store = Store::open(&dd.join("kernel.db")).expect("Store::open");
    (tmp, Arc::new(store))
}

/// Seed two initiatives and three tasks across them so the
/// dashboard list / detail / DAG paths have something to render.
///
/// Uses the async `lock()` so it can be called from `#[tokio::test]`
/// async tests — `lock_sync()` panics inside a tokio runtime.
async fn seed_initiatives(store: &Store) {
    let conn = store.lock().await;
    let initiatives = raxis_store::Table::Initiatives.as_str();
    let tasks = raxis_store::Table::Tasks.as_str();
    let signed_plan_artifacts = raxis_store::Table::SignedPlanArtifacts.as_str();
    conn.execute_batch(&format!(
        "INSERT INTO {initiatives} \
         (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
         VALUES \
         ('init-A', 'Executing', '{{}}', 'sha-A', 100), \
         ('init-B', 'Completed', '{{}}', 'sha-B', 200); \
         INSERT INTO {tasks} \
         (task_id, initiative_id, lane_id, state, actor, \
          policy_epoch, admitted_at, transitioned_at) \
         VALUES \
         ('task-A1', 'init-A', 'default', 'Running', 'op', 1, 100, 110), \
         ('task-A2', 'init-A', 'default', 'Completed', 'op', 1, 100, 120), \
         ('task-B1', 'init-B', 'default', 'Completed', 'op', 1, 200, 250);"
    ))
    .unwrap();
    let plan_a = br#"
        [workspace]
        name = "Dashboard Alpha"

        [plan.initiative]
        description = "Dashboard fixture initiative A"

        [[tasks]]
        task_name = "task-A1"
        session_agent_type = "Executor"

        [[tasks]]
        task_name = "task-A2"
        session_agent_type = "Reviewer"
    "#;
    let plan_b = br#"
        [workspace]
        name = "Dashboard Beta"

        [plan.initiative]
        description = "Dashboard fixture initiative B"

        [[tasks]]
        task_name = "task-B1"
        session_agent_type = "Executor"
    "#;
    conn.execute(
        &format!(
            "INSERT INTO {signed_plan_artifacts} \
             (initiative_id, plan_bytes, plan_sig, stored_at) \
             VALUES (?1, ?2, X'00', 100)"
        ),
        rusqlite::params!["init-A", &plan_a[..]],
    )
    .unwrap();
    conn.execute(
        &format!(
            "INSERT INTO {signed_plan_artifacts} \
             (initiative_id, plan_bytes, plan_sig, stored_at) \
             VALUES (?1, ?2, X'00', 200)"
        ),
        rusqlite::params!["init-B", &plan_b[..]],
    )
    .unwrap();
}

/// Build a policy bundle whose only operator's pubkey is `op_pk`,
/// with the supplied permitted-ops set so the dashboard can map
/// roles correctly.
fn policy_with_operator(op_pk: [u8; 32], permitted_ops: Vec<&str>) -> Arc<ArcSwap<PolicyBundle>> {
    policy_with_operator_and_roots(op_pk, permitted_ops, Vec::new())
}

/// Like [`policy_with_operator`] but also seeds the
/// `[sessions].allowed_worktree_roots` set so the dashboard's
/// worktree resolver sees roots to enumerate.
fn policy_with_operator_and_roots(
    op_pk: [u8; 32],
    permitted_ops: Vec<&str>,
    allowed_roots: Vec<String>,
) -> Arc<ArcSwap<PolicyBundle>> {
    let pubkey_hex = hex::encode(op_pk);
    let fingerprint = {
        use sha2::Digest;
        let h = sha2::Sha256::digest(op_pk);
        hex::encode(&h[..16])
    };
    let mut bundle = PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
        pubkey_fingerprint: fingerprint,
        display_name: "alice".into(),
        pubkey_hex: pubkey_hex.clone(),
        permitted_ops: permitted_ops.into_iter().map(str::to_owned).collect(),
        cert: stub_cert_for_pubkey(pubkey_hex),
        force_misconfig_bypass: false,
    }]);
    if !allowed_roots.is_empty() {
        bundle.set_allowed_worktree_roots_for_tests(allowed_roots);
    }
    Arc::new(ArcSwap::from_pointee(bundle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_initiatives_returns_seeded_rows_with_real_store() {
    let (tmp, store) = fresh_data_dir();
    seed_initiatives(&store).await;
    let policy = policy_with_operator([0xAAu8; 32], vec!["RotateEpoch"]);

    let data = raxis_dashboard_kernel::KernelDashboardData::new(
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    )
    .expect("KernelDashboardData::new");

    let entries = data.list_initiatives(50, None).expect("list");
    let ids: Vec<&str> = entries.iter().map(|e| e.initiative_id.as_str()).collect();
    assert!(
        ids.contains(&"init-A"),
        "init-A must be listed; got {ids:?}"
    );
    assert!(ids.contains(&"init-B"));

    // Filter narrows correctly.
    let only_completed = data
        .list_initiatives(50, Some("Completed"))
        .expect("filtered list");
    let ids: Vec<&str> = only_completed
        .iter()
        .map(|e| e.initiative_id.as_str())
        .collect();
    assert_eq!(ids, vec!["init-B"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_initiative_includes_tasks_and_dag_edges() {
    let (tmp, store) = fresh_data_dir();
    seed_initiatives(&store).await;
    // Add a DAG edge between init-A's tasks so the edge list has
    // something to surface.
    {
        let conn = store.lock().await;
        let edges = raxis_store::Table::TaskDagEdges.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {edges} \
                 (initiative_id, predecessor_task_id, successor_task_id, predecessor_satisfied) \
                 VALUES ('init-A', 'task-A1', 'task-A2', 1)"
            ),
            [],
        )
        .unwrap();
    }
    let policy = policy_with_operator([0xAAu8; 32], vec![]);

    let data = raxis_dashboard_kernel::KernelDashboardData::new(
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    )
    .expect("KernelDashboardData::new");

    let view = data.get_initiative("init-A").expect("get_initiative");
    assert_eq!(view.summary.initiative_id, "init-A");
    assert_eq!(view.tasks.len(), 2);
    let task_ids: Vec<&str> = view.tasks.iter().map(|t| t.task_id.as_str()).collect();
    assert!(task_ids.contains(&"task-A1"));
    assert!(task_ids.contains(&"task-A2"));
    assert!(
        view.edges
            .iter()
            .any(|e| e.from == "task-A1" && e.to == "task-A2"),
        "DAG must surface the inserted edge; got {:?}",
        view.edges
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_snapshot_reports_ok_when_chain_and_store_are_clean() {
    let (tmp, store) = fresh_data_dir();
    seed_initiatives(&store).await;
    {
        let conn = store.lock().await;
        let initiatives = raxis_store::Table::Initiatives.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {initiatives} \
                 (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                 VALUES ('init-draft', 'Draft', '{{}}', 'sha-draft', 300)"
            ),
            [],
        )
        .unwrap();
    }
    let policy = policy_with_operator([0xBBu8; 32], vec![]);

    let data = raxis_dashboard_kernel::KernelDashboardData::new(
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    )
    .expect("KernelDashboardData::new");
    let h = data.health();
    assert_eq!(
        h.status, "ok",
        "checks should all pass against a fresh dir; got {:#?}",
        h
    );
    assert_eq!(h.policy_epoch, 0); // for_tests_with_operators starts at epoch 0
    assert_eq!(
        h.active_initiatives, 1,
        "Draft rows must not count as active/in-flight"
    );
}

#[tokio::test]
async fn lookup_operator_roles_maps_permitted_ops_to_dashboard_roles() {
    let (tmp, store) = fresh_data_dir();
    let pk = [0x77u8; 32];
    let policy = policy_with_operator(pk, vec!["RotateEpoch", "OperatorCertInstall"]);

    let data = raxis_dashboard_kernel::KernelDashboardData::new(
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    )
    .expect("KernelDashboardData::new");

    let fingerprint = {
        use sha2::Digest;
        let h = sha2::Sha256::digest(pk);
        hex::encode(&h[..16])
    };
    let res = data
        .lookup_operator_roles(&fingerprint)
        .expect("operator must resolve");
    assert!(res.roles.contains(&DashboardRole::Read));
    assert!(res.roles.contains(&DashboardRole::WritePolicy));
    assert!(res.roles.contains(&DashboardRole::Admin));
}

#[tokio::test]
async fn audit_list_returns_genesis_record_from_real_chain() {
    let (tmp, store) = fresh_data_dir();
    let policy = policy_with_operator([0x33u8; 32], vec![]);

    let data = raxis_dashboard_kernel::KernelDashboardData::new(
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    )
    .expect("KernelDashboardData::new");

    let page = data
        .list_audit(None, 100, None, AuditListFilters::default())
        .expect("list_audit");
    assert!(!page.is_empty(), "genesis record should appear");
    let genesis = page
        .iter()
        .find(|e| e.event_kind == "GenesisRecord")
        .expect("GenesisRecord must surface as the chain anchor");
    assert_eq!(genesis.seq, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_server_serves_initiatives_endpoint_after_jwt_handshake() {
    use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
    use serde_json::json;

    let (tmp, store) = fresh_data_dir();
    seed_initiatives(&store).await;

    // Sign the policy with a known operator key so the JWT
    // challenge-response works end-to-end.
    let signing = SigningKey::from_bytes(&[0x99u8; 32]);
    let pk_bytes = signing.verifying_key().to_bytes();
    let policy = policy_with_operator(pk_bytes, vec!["RotateEpoch"]);

    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        ..Default::default()
    };

    let handle = raxis_dashboard_kernel::start_dashboard(
        cfg,
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
        None,
    )
    .await
    .expect("start_dashboard");

    let base = format!("http://{}", handle.local_addr());
    let client = reqwest::Client::new();

    // 1) Get a challenge.
    let chal_resp: serde_json::Value = client
        .get(format!("{base}/api/auth/challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge_hex = chal_resp["challenge"]
        .as_str()
        .expect("challenge field")
        .to_owned();

    // 2) Sign the decoded challenge bytes with our Ed25519 key.
    let challenge_bytes = hex::decode(&challenge_hex).expect("hex");
    let sig = signing.sign(&challenge_bytes);

    // 3) POST verify and grab the JWT.
    let verify_body = json!({
        "challenge":  challenge_hex,
        "signature":  hex::encode(sig.to_bytes()),
        "public_key": hex::encode(pk_bytes),
    });
    let verify_resp: serde_json::Value = client
        .post(format!("{base}/api/auth/verify"))
        .header(CONTENT_TYPE, "application/json")
        .body(verify_body.to_string())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = verify_resp["token"]
        .as_str()
        .unwrap_or_else(|| panic!("verify must return a JWT; got {verify_resp}"))
        .to_owned();

    // 4) Authorized GET /api/initiatives.
    let inits: serde_json::Value = client
        .get(format!("{base}/api/initiatives"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = inits.as_array().expect("array");
    let ids: Vec<&str> = arr
        .iter()
        .filter_map(|v| v["initiative_id"].as_str())
        .collect();
    assert!(
        ids.contains(&"init-A"),
        "real HTTP path must surface seeded initiatives; got {ids:?}"
    );
    assert!(ids.contains(&"init-B"));

    // 5) Same call without auth must 401.
    let unauth = client
        .get(format!("{base}/api/initiatives"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);

    handle.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// Git-worktree (P3) — exercises a REAL on-disk git repo seeded
// with two commits and walks every dashboard worktree endpoint.
// ---------------------------------------------------------------------------

/// Initialise a tiny git repo at `dir`, commit two files, and
/// return `(base_sha, head_sha)`.
fn init_repo_with_two_commits(dir: &std::path::Path) -> (String, String) {
    use std::process::Command;
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "raxis-test")
            .env("GIT_AUTHOR_EMAIL", "test@raxis.local")
            .env("GIT_COMMITTER_NAME", "raxis-test")
            .env("GIT_COMMITTER_EMAIL", "test@raxis.local")
            .output()
            .expect("git spawn");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    run(&["init", "-q"]);
    // `git init -b main` needs git 2.28+; older binaries fall
    // through here and we set the branch name explicitly so the
    // test does not depend on the host's `init.defaultBranch`.
    run(&["symbolic-ref", "HEAD", "refs/heads/main"]);
    run(&["config", "commit.gpgsign", "false"]);
    std::fs::write(dir.join("a.txt"), "alpha\n").unwrap();
    run(&["add", "a.txt"]);
    run(&["commit", "-q", "-m", "first"]);
    let base = run(&["rev-parse", "HEAD"]).trim().to_owned();
    std::fs::write(dir.join("b.txt"), "beta\n").unwrap();
    std::fs::write(dir.join("a.txt"), "alpha + delta\n").unwrap();
    run(&["add", "a.txt", "b.txt"]);
    run(&["commit", "-q", "-m", "second"]);
    let head = run(&["rev-parse", "HEAD"]).trim().to_owned();
    (base, head)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worktree_endpoints_surface_real_git_state() {
    let (tmp, store) = fresh_data_dir();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let (base_sha, head_sha) = init_repo_with_two_commits(&repo);

    // Build a policy whose allowed worktree roots include the
    // freshly-initialised repo path.
    let policy =
        policy_with_operator_and_roots([0x55u8; 32], vec![], vec![repo.display().to_string()]);
    {
        let conn = store.lock().await;
        let sessions = raxis_store::Table::Sessions.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {sessions} \
                 (session_id, role_id, session_token, lineage_id, \
                  worktree_root, base_sha, base_tracking_ref, \
                  fetch_quota, sequence_number, \
                  created_at, expires_at, revoked, revoked_at) \
                 VALUES (?1, 'Planner', ?2, ?3, ?4, ?5, 'refs/heads/main', 1000, 0, 10, 9999999999, 1, 20)"
            ),
            rusqlite::params![
                "11111111-1111-4111-8111-111111111111",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "22222222-2222-4222-8222-222222222222",
                repo.display().to_string(),
                base_sha.as_str(),
            ],
        )
        .expect("seed revoked session worktree");
    }

    let data = raxis_dashboard_kernel::KernelDashboardData::new(
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
    )
    .expect("KernelDashboardData::new");

    // 1) Listing surfaces our root.
    let listed = data.list_worktrees().expect("list_worktrees");
    assert!(
        listed
            .iter()
            .any(|w| w.kind == "Main" && w.path == repo.display().to_string()),
        "expected a Main worktree at {}, got {listed:#?}",
        repo.display()
    );
    let session = listed
        .iter()
        .find(|w| w.session_id.as_deref() == Some("11111111-1111-4111-8111-111111111111"))
        .cloned()
        .expect("revoked session worktree must remain visible for review");
    assert_eq!(session.base_sha.as_deref(), Some(base_sha.as_str()));
    let main = listed
        .iter()
        .find(|w| w.kind == "Main" && w.path == repo.display().to_string())
        .cloned()
        .expect("seeded allowed root must be the reviewable main worktree");

    // 2) Detail stays cheap for large repositories. Exact Git facts are loaded
    //    by the explicit Log/Diff endpoints below, not by the initial detail
    //    header route.
    let detail = data.get_worktree(&main.name).expect("get_worktree");
    assert_eq!(detail.head_sha, None);
    assert_eq!(detail.branch, None);
    assert!(
        detail.status_lines.is_empty(),
        "fresh commit must report clean status; got {:?}",
        detail.status_lines
    );

    // 3) Log returns both commits in newest-first order.
    let log = data.worktree_log(&main.name, 10).expect("worktree_log");
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].sha, head_sha);
    assert_eq!(log[1].sha, base_sha);
    assert_eq!(log[0].subject, "second");

    // 4) Ranged diff between the two commits surfaces both files.
    let diff = data
        .worktree_diff_range(&main.name, &base_sha, &head_sha)
        .expect("worktree_diff_range");
    assert_eq!(diff.from_sha, base_sha);
    assert_eq!(diff.to_sha, head_sha);
    let paths: Vec<&str> = diff.files.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"a.txt"), "expected a.txt; got {paths:?}");
    assert!(paths.contains(&"b.txt"), "expected b.txt; got {paths:?}");
    let a = diff.files.iter().find(|f| f.path == "a.txt").unwrap();
    assert_eq!(a.status, "M");
    assert!(a.insertions >= 1);
    assert!(!a.hunk.is_empty(), "modified file must include a hunk body");
    let b = diff.files.iter().find(|f| f.path == "b.txt").unwrap();
    assert_eq!(b.status, "A");

    // 5) Session default-diff uses the recorded session base SHA even when
    //    the session is already revoked.
    let session_diff = data
        .worktree_diff_default(&session.name)
        .expect("session default diff");
    assert_eq!(session_diff.from_sha, base_sha);
    assert_eq!(session_diff.to_sha, head_sha);

    // 6) Default-diff fails when no base SHA is recorded for
    //    the main worktree (the listing reports `base_sha = None`
    //    for main roots — operator-recorded base SHAs only flow
    //    through the per-session view).
    let err = data
        .worktree_diff_default(&main.name)
        .expect_err("default diff requires recorded base sha");
    assert!(
        matches!(err, raxis_dashboard::error::ApiError::NotFound { .. }),
        "expected NotFound; got {err:?}"
    );

    // 7) Resolution refuses paths outside `allowed_worktree_roots`.
    let err = data.get_worktree("session-deadbeefdead").unwrap_err();
    assert!(matches!(
        err,
        raxis_dashboard::error::ApiError::NotFound { .. }
    ));
}

// ---------------------------------------------------------------------------
// Agent stream capture (P4) — exercises the file ring + SSE
// surface end-to-end against a real on-disk capture and a real
// HTTP listener.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_capture_round_trips_through_real_sse_endpoint() {
    use futures_util::StreamExt;
    use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
    use serde_json::json;
    use tokio::io::AsyncBufReadExt;

    let (tmp, store) = fresh_data_dir();

    // Sign the policy with a known operator key for the JWT
    // handshake.
    let signing = SigningKey::from_bytes(&[0x4Du8; 32]);
    let pk_bytes = signing.verifying_key().to_bytes();
    let policy = policy_with_operator(pk_bytes, vec![]);

    // Seed the kernel store with the session row the SSE handler
    // pre-checks via `get_session` (the dashboard returns a
    // structured 404 for unknown session ids — see
    // `dashboard-hardening.md §1.6`).
    {
        let conn = store.lock().await;
        let sessions = raxis_store::Table::Sessions.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {sessions} \
                 (session_id, role_id, session_token, lineage_id, \
                  fetch_quota, created_at, expires_at, revoked) \
                 VALUES \
                 ('sess-stream-test', 'planner', 'tok-stream', 'lin', \
                  0, 100, 9999999999, 0)"
            ),
            [],
        )
        .unwrap();
    }

    // Build the capture once and share it between the data
    // layer (subscribed by the dashboard) and the test
    // (publisher role).
    let capture = raxis_dashboard_kernel::SessionStreamCapture::new(
        tmp.path(),
        raxis_dashboard_kernel::CaptureConfig::default(),
    )
    .expect("capture::new");

    // Pre-allocate the session so the SSE handler attaches to a
    // ready broadcast channel.
    capture.ensure_session("sess-stream-test").unwrap();
    // Seed two tail events so a fresh subscriber sees recent
    // context before the live stream begins.
    capture
        .append(
            "sess-stream-test",
            raxis_dashboard::stream::StreamEvent {
                at_ms: 1,
                kind: "model_chunk".into(),
                payload: json!({"text": "hello"}),
            },
        )
        .unwrap();
    capture
        .append(
            "sess-stream-test",
            raxis_dashboard::stream::StreamEvent {
                at_ms: 2,
                kind: "model_chunk".into(),
                payload: json!({"text": " world"}),
            },
        )
        .unwrap();

    let data = Arc::new(raxis_dashboard_kernel::KernelDashboardData::with_capture(
        Arc::clone(&store),
        Arc::clone(&policy),
        tmp.path().to_path_buf(),
        tmp.path().join("policy/policy.toml"),
        1_700_000_000,
        Arc::clone(&capture),
    ));

    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        ..Default::default()
    };
    let server = raxis_dashboard::server::DashboardServer::bind(cfg, data)
        .await
        .expect("DashboardServer::bind");
    let handle = raxis_dashboard::server::ServerHandle::spawn(server);
    let base = format!("http://{}", handle.local_addr());
    let client = reqwest::Client::new();

    // Auth handshake (challenge → sign → JWT).
    let chal_resp: serde_json::Value = client
        .get(format!("{base}/api/auth/challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge_hex = chal_resp["challenge"].as_str().unwrap().to_owned();
    let challenge_bytes = hex::decode(&challenge_hex).unwrap();
    let sig = signing.sign(&challenge_bytes);
    let verify_body = json!({
        "challenge":  challenge_hex,
        "signature":  hex::encode(sig.to_bytes()),
        "public_key": hex::encode(pk_bytes),
    });
    let verify_resp: serde_json::Value = client
        .post(format!("{base}/api/auth/verify"))
        .header(CONTENT_TYPE, "application/json")
        .body(verify_body.to_string())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = verify_resp["token"].as_str().unwrap().to_owned();

    // Open the SSE stream — request 5 tail events (we only have
    // 2 so the handler emits both, then `tail-complete`, then
    // any live frames).
    let resp = client
        .get(format!(
            "{base}/api/sessions/sess-stream-test/stream?tail=5"
        ))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "stream connect: {}",
        resp.status()
    );
    let stream = resp.bytes_stream();
    let reader =
        tokio_util::io::StreamReader::new(stream.map(|r| r.map_err(std::io::Error::other)));
    let mut lines = tokio::io::BufReader::new(reader).lines();

    // Capture lines until we see the `tail-complete` marker.
    let mut tail_lines = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Ok(Some(line)) = lines.next_line().await {
            tail_lines.push(line.clone());
            if line == "event: tail-complete" {
                return Ok::<_, std::io::Error>(());
            }
        }
        Err(std::io::Error::other("EOF before tail-complete"))
    })
    .await
    .expect("did not see tail-complete in 10s")
    .expect("tail read");

    let body = tail_lines.join("\n");
    assert!(
        body.contains("hello") && body.contains("world"),
        "expected the two seeded chunks in the SSE tail; got {body}"
    );

    // Push live events repeatedly so the subscriber sees the
    // event regardless of any HTTP-layer chunk batching the
    // first frame might wait on.
    let cap_clone = Arc::clone(&capture);
    let pusher = tokio::spawn(async move {
        for i in 0..10 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            cap_clone
                .append(
                    "sess-stream-test",
                    raxis_dashboard::stream::StreamEvent {
                        at_ms: 3 + i,
                        kind: "tool_call".into(),
                        payload: json!({"tool": "FetchPath"}),
                    },
                )
                .unwrap();
        }
    });

    // Per `INV-DASHBOARD-STREAM-ENVELOPE-01` data frames now
    // ship as default-`message` SSE events with the full
    // envelope packed into the `data:` field — so the
    // `event: tool_call` line the old wire emitted no longer
    // exists. Scan for the kind discriminant inside the JSON
    // envelope instead.
    let live = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if line.starts_with("data:") && line.contains("\"kind\":\"tool_call\"") {
                return Ok::<String, std::io::Error>(line);
            }
        }
        Err(std::io::Error::other("EOF before live event"))
    })
    .await
    .expect("did not see live tool_call event in 10s")
    .expect("live read");
    assert!(
        live.contains("\"kind\":\"tool_call\""),
        "expected tool_call envelope on the wire; got `{live}`"
    );
    assert!(
        live.contains("\"at_ms\":"),
        "expected at_ms in the envelope; got `{live}`"
    );

    pusher.abort();
    // Drop the SSE reader first so the server-side handler
    // observes the connection close and unparks its broadcast
    // recv (otherwise `handle.shutdown()` waits forever for the
    // in-flight SSE stream to finish).
    drop(lines);
    // Bound the shutdown wait — the SSE handler's parked recv
    // is woken by the broadcast sender being dropped. We do not
    // drop `capture` here because the test has not exited yet,
    // so we cap the shutdown await instead.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown()).await;
}

// ---------------------------------------------------------------------------
// Policy update (P5) — exercises the `PUT /api/policy/toml`
// route end-to-end with a closure-backed PolicyAdvancer + the
// real HTTP listener. Verifies role enforcement, JSON body
// shape, base64 signature handling, and the full advancement
// payload returned to the operator UI.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_update_endpoint_round_trips_through_real_http_with_role_enforcement() {
    use base64::Engine;
    use raxis_dashboard_kernel::{
        AdvanceError, AdvanceResult, ClosurePolicyAdvancer, KernelDashboardData,
        SessionStreamCapture,
    };
    use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (tmp, store) = fresh_data_dir();

    // Mint two operator keys: alice has `RotateEpoch` (=>
    // write_policy role); bob has nothing (=> read-only).
    let alice = SigningKey::from_bytes(&[0xA1u8; 32]);
    let bob = SigningKey::from_bytes(&[0xB0u8; 32]);
    let alice_pk = alice.verifying_key().to_bytes();
    let bob_pk = bob.verifying_key().to_bytes();

    // Build a policy that knows BOTH operators. We extend the
    // helper inline because `policy_with_operator` only takes
    // one operator entry.
    let policy = {
        use sha2::Digest;
        let mk_entry = |pk: [u8; 32], name: &str, ops: Vec<&str>| {
            let pubkey_hex = hex::encode(pk);
            let fingerprint = hex::encode(&sha2::Sha256::digest(pk)[..16]);
            raxis_policy::OperatorEntry {
                pubkey_fingerprint: fingerprint,
                display_name: name.into(),
                pubkey_hex: pubkey_hex.clone(),
                permitted_ops: ops.into_iter().map(str::to_owned).collect(),
                cert: stub_cert_for_pubkey(pubkey_hex),
                force_misconfig_bypass: false,
            }
        };
        Arc::new(ArcSwap::from_pointee(
            raxis_policy::PolicyBundle::for_tests_with_operators(vec![
                mk_entry(alice_pk, "alice", vec!["RotateEpoch"]),
                mk_entry(bob_pk, "bob", vec![]),
            ]),
        ))
    };

    // Stub PolicyAdvancer that records inputs + returns a
    // fixed AdvanceResult on the happy path. The dashboard
    // handler is the system-under-test; the advancer is
    // intentionally minimal.
    let advance_calls = Arc::new(AtomicUsize::new(0));
    let last_op_fp = Arc::new(parking_lot::Mutex::new(String::new()));
    let last_toml_len = Arc::new(AtomicUsize::new(0));
    {
        let advance_calls_for_closure = Arc::clone(&advance_calls);
        let last_op_fp_for_closure = Arc::clone(&last_op_fp);
        let last_toml_len_for_closure = Arc::clone(&last_toml_len);
        let advancer = Arc::new(ClosurePolicyAdvancer::new(
            move |toml: &[u8], _sig: &[u8], op: &str| {
                advance_calls_for_closure.fetch_add(1, Ordering::SeqCst);
                *last_op_fp_for_closure.lock() = op.to_owned();
                last_toml_len_for_closure.store(toml.len(), Ordering::SeqCst);
                if toml.starts_with(b"# bad") {
                    return Err(AdvanceError::Validation("bad bytes".into()));
                }
                Ok(AdvanceResult {
                    previous_epoch: 1,
                    new_epoch: 2,
                    policy_sha256: "deadbeef".repeat(8),
                    signed_by_authority: "deadbeefdeadbeef".into(),
                    n_delegations_marked_stale: 4,
                    n_sessions_invalidated: 7,
                    advanced_at: 1_700_000_500,
                })
            },
        )) as Arc<dyn raxis_dashboard_kernel::PolicyAdvancer>;
        let capture =
            SessionStreamCapture::new(tmp.path(), raxis_dashboard_kernel::CaptureConfig::default())
                .expect("capture::new");
        let data = Arc::new(
            KernelDashboardData::with_capture(
                Arc::clone(&store),
                Arc::clone(&policy),
                tmp.path().to_path_buf(),
                tmp.path().join("policy/policy.toml"),
                1_700_000_000,
                capture,
            )
            .with_advancer(advancer),
        );

        let cfg = DashboardConfig {
            enabled: true,
            bind_address: "127.0.0.1".into(),
            bind_port: 0,
            ..Default::default()
        };
        let server = raxis_dashboard::server::DashboardServer::bind(cfg, data)
            .await
            .expect("DashboardServer::bind");
        let handle = raxis_dashboard::server::ServerHandle::spawn(server);
        let base = format!("http://{}", handle.local_addr());
        let client = reqwest::Client::new();

        // Helper closure: complete the JWT challenge handshake
        // for the supplied operator key and return the bearer
        // token string.
        let auth = |signing: SigningKey, pk: [u8; 32]| {
            let base = base.clone();
            let client = client.clone();
            async move {
                let chal_resp: serde_json::Value = client
                    .get(format!("{base}/api/auth/challenge"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                let challenge_hex = chal_resp["challenge"].as_str().unwrap().to_owned();
                let challenge_bytes = hex::decode(&challenge_hex).unwrap();
                let sig = signing.sign(&challenge_bytes);
                let body = json!({
                    "challenge":  challenge_hex,
                    "signature":  hex::encode(sig.to_bytes()),
                    "public_key": hex::encode(pk),
                });
                let verify_resp: serde_json::Value = client
                    .post(format!("{base}/api/auth/verify"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(body.to_string())
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                verify_resp["token"].as_str().unwrap().to_owned()
            }
        };

        let alice_token = auth(alice.clone(), alice_pk).await;
        let bob_token = auth(bob.clone(), bob_pk).await;

        // 1) Bob (read-only) gets 403 — his cert lacks
        //    RotateEpoch so the role mapper grants only Read.
        let new_toml = b"[meta]\nepoch = 2\n";
        let put_body = json!({
            "toml":          String::from_utf8_lossy(new_toml).into_owned(),
            "signature_b64": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        });
        let resp = client
            .put(format!("{base}/api/policy/toml"))
            .header(AUTHORIZATION, format!("Bearer {bob_token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(put_body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "bob must be forbidden");
        assert_eq!(
            advance_calls.load(Ordering::SeqCst),
            0,
            "advancer must not be called for forbidden requests"
        );

        // 2) Alice with malformed signature (wrong length) gets 400.
        let put_body = json!({
            "toml":          String::from_utf8_lossy(new_toml).into_owned(),
            "signature_b64": base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
        });
        let resp = client
            .put(format!("{base}/api/policy/toml"))
            .header(AUTHORIZATION, format!("Bearer {alice_token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(put_body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "short signature must 400");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], "FAIL_DASHBOARD_BAD_REQUEST");

        // 3) Alice with valid bytes ⇒ 200 + the AdvanceResult
        //    surfaces through the wire as a `PolicyAdvancement`
        //    JSON envelope.
        let put_body = json!({
            "toml":          String::from_utf8_lossy(new_toml).into_owned(),
            "signature_b64": base64::engine::general_purpose::STANDARD.encode([0xCDu8; 64]),
        });
        let resp = client
            .put(format!("{base}/api/policy/toml"))
            .header(AUTHORIZATION, format!("Bearer {alice_token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(put_body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "happy path must 200");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["previous_epoch"], 1);
        assert_eq!(body["new_epoch"], 2);
        assert_eq!(body["policy_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(body["n_sessions_invalidated"], 7);
        assert_eq!(body["n_delegations_marked_stale"], 4);
        assert_eq!(body["advanced_at"], 1_700_000_500);

        // 4) The advancer was called exactly once with alice's
        //    fingerprint and the supplied TOML byte length.
        assert_eq!(advance_calls.load(Ordering::SeqCst), 1);
        assert_eq!(last_toml_len.load(Ordering::SeqCst), new_toml.len());
        let alice_fp = {
            use sha2::Digest;
            hex::encode(&sha2::Sha256::digest(alice_pk)[..16])
        };
        assert_eq!(*last_op_fp.lock(), alice_fp);

        // 5) Validation failures from the advancer are surfaced
        //    as 400 with the FAIL_DASHBOARD_POLICY_INVALID code
        //    (not the 500 internal-error code).
        let put_body = json!({
            "toml":          "# bad bytes\n",
            "signature_b64": base64::engine::general_purpose::STANDARD.encode([0xEEu8; 64]),
        });
        let resp = client
            .put(format!("{base}/api/policy/toml"))
            .header(AUTHORIZATION, format!("Bearer {alice_token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(put_body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], "FAIL_DASHBOARD_POLICY_INVALID");

        // 6) An anonymous PUT (no JWT) gets 401.
        let put_body = json!({
            "toml": "[meta]\n",
            "signature_b64": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        });
        let resp = client
            .put(format!("{base}/api/policy/toml"))
            .header(CONTENT_TYPE, "application/json")
            .body(put_body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown()).await;
    }
}

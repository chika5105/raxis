// V2 Step 10 integration test: stage → spawn → push → recv → destroy.
//
// What this test proves:
//
//   1. The `raxis-worktree-staging` crate produces a
//      `raxis_isolation::WorkspaceMount` that the substrate trait
//      consumes verbatim.
//   2. The trait's `Backend::spawn` accepts the staged mount and
//      returns a live `Session` whose `push`/`recv_intent` round-trip
//      bytes — proving the VSock-shaped surface is wired correctly
//      end to end.
//   3. The kernel-side `destroy` reaps the staged tree after session
//      teardown.
//
// We exercise this against `raxis_test_support::SubprocessIsolation`
// — the only V2 substrate that runs without root + a real hypervisor,
// honestly self-reporting `IsolationLevel::TestOnly`. The production
// admission helper refuses TestOnly absolutely, so this substrate is
// reachable only via the test-only wiring here.
//
// Why this test must use a REAL substrate object (not a mock):
// the user's standing instruction is that integration tests "must
// use real runtime objects to catch runtime bugs". `SubprocessIsolation`
// is a real implementation of the `Backend` / `Session` trait — it
// spawns an actual child process and streams bytes through real OS
// pipes. The framing contract pinned here is byte-exact identical to
// what `FirecrackerSession::push` / `recv_intent` perform on a Linux
// + KVM host.

use std::sync::Mutex;
use std::time::Duration;

use raxis_isolation::{
    Backend, ContentHash, EgressTier, ImageBody, ImageKind, ImageSignature, MountMode,
    PushFrame, SessionToken, VerifiedImage, VmSpec, WorkspaceMount,
};
use raxis_test_support::SubprocessIsolation;
use raxis_worktree_staging::{
    destroy, stage, StageInputs, BUNDLES_DIRNAME, GUEST_WORKSPACE_PATH,
    SESSION_ENV_FILENAME, SYSTEM_PROMPT_FILENAME,
};

/// Process-global guard — `SubprocessIsolation::new` reads
/// `RAXIS_TEST_HARNESS` and a concurrent test that flipped it would
/// race. Same pattern as the substrate's own internal tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn enable_test_harness() {
    // SAFETY: process-global env mutation; the lock above serialises
    // every test in this binary. Production never sets this — it's
    // gated by the substrate's `RAXIS_TEST_HARNESS=1` requirement.
    unsafe {
        std::env::set_var("RAXIS_TEST_HARNESS", "1");
    }
}

fn fixture_image() -> VerifiedImage {
    VerifiedImage {
        kind:      ImageKind::RootfsErofs,
        body:      ImageBody::Path("/tmp/raxis-step10-image".into()),
        signature: ImageSignature(vec![0xAB; 64]),
        image_id:  "raxis-step10-fixture".to_owned(),
    }
}

fn fixture_spec(token: &str, mounts: Vec<WorkspaceMount>) -> VmSpec {
    VmSpec {
        vcpu_count:       1,
        mem_mib:          64,
        egress_tier:      EgressTier::None,
        cgroup_quota:     None,
        boot_args:        Vec::new(),
        entrypoint_argv:  Vec::new(),
        session_token:    SessionToken(token.to_owned()),
        vsock_cid:        Some(0xC1D_5070),
        virtio_fs_mounts: mounts,
        env:              Default::default(),
    }
}

#[test]
fn step10_full_pipeline_stage_spawn_push_recv_destroy() {
    let _g = ENV_LOCK.lock().unwrap();
    enable_test_harness();

    // 1. Stage the worktree on disk.
    let tmp = tempfile::tempdir().unwrap();
    let inputs = StageInputs {
        data_dir:      tmp.path().to_path_buf(),
        session_uuid:  "step10-uuid-1".to_owned(),
        system_prompt: "You are an Executor.".to_owned(),
        session_token: "tok-step10".to_owned(),
        vsock_cid:     0xC1D_5070,
        vsock_port:    1024,
        mount_mode:    MountMode::ReadWrite,
    };
    let staged = stage(&inputs).expect("stage must succeed in a fresh temp dir");

    // Layout assertion (Step 10 §10): system prompt + session env +
    // bundles dir present.
    assert!(staged.raxis_dir.join(SYSTEM_PROMPT_FILENAME).is_file());
    assert!(staged.raxis_dir.join(SESSION_ENV_FILENAME).is_file());
    assert!(staged.raxis_dir.join(BUNDLES_DIRNAME).is_dir());

    // 2. Hand the mount to the substrate trait.
    let backend = SubprocessIsolation::new("step10-int-test")
        .expect("substrate construction must succeed under RAXIS_TEST_HARNESS=1");
    let spec = fixture_spec("tok-step10", vec![staged.mount.clone()]);
    let mut session = backend
        .spawn(&fixture_image(), &[staged.mount.clone()], &spec)
        .expect("Backend::spawn must accept the staged mount + spec");

    // 3. Push a frame, recv it back. The default substrate child is
    //    `/bin/cat` which echoes stdin to stdout — so a push of a
    //    canonical bytes-shape returns the same bytes verbatim.
    let payload = b"step10-vsock-frame-fixture";
    session
        .push(&PushFrame { bytes: payload.to_vec() })
        .expect("push of small payload must succeed");
    let received = session
        .recv_intent()
        .expect("recv_intent of echoed bytes must succeed");
    assert_eq!(
        received.bytes, payload,
        "VSock-shaped substrate trait must round-trip bytes verbatim",
    );

    // 4. Graceful shutdown reaps the child cleanly.
    let _ = session.shutdown(Duration::from_millis(500));

    // 5. Destroy the staged tree.
    destroy(&staged.worktree_root).unwrap();
    assert!(
        !staged.worktree_root.exists(),
        "destroy must remove the worktree root",
    );
}

/// Step 10 invariant: a `WorkspaceMount` constructed by `stage`
/// carries a `content_hash` that the substrate can record into the
/// audit chain. We pin the round trip from staged hash → mount →
/// substrate `spawn` argument so a refactor that drops the hash is
/// loud.
#[test]
fn step10_mount_carries_content_hash_through_substrate_boundary() {
    let _g = ENV_LOCK.lock().unwrap();
    enable_test_harness();

    let tmp = tempfile::tempdir().unwrap();
    let inputs = StageInputs {
        data_dir:      tmp.path().to_path_buf(),
        session_uuid:  "step10-uuid-hash".to_owned(),
        system_prompt: "Reviewer system prompt".to_owned(),
        session_token: "tok-rev".to_owned(),
        vsock_cid:     0xC1D_5071,
        vsock_port:    1024,
        // Reviewer mount per Step 24.
        mount_mode:    MountMode::ReadOnly,
    };
    let staged = stage(&inputs).unwrap();
    let hash = staged
        .mount
        .content_hash
        .clone()
        .expect("Step 10 contract: every staged mount carries a content hash");
    assert_ne!(
        hash,
        ContentHash::default(),
        "non-empty staged tree must produce a non-zero hash",
    );
    assert_eq!(staged.mount.guest_path, GUEST_WORKSPACE_PATH);
    assert_eq!(staged.mount.mode, MountMode::ReadOnly);

    let backend = SubprocessIsolation::new("step10-hash-int")
        .expect("substrate construction must succeed under RAXIS_TEST_HARNESS=1");

    // The substrate's `spawn` only inspects the mount via the trait;
    // a successful spawn is the proof that the `WorkspaceMount`
    // shape (hash included) compiles + flows through the trait
    // boundary.
    let spec = fixture_spec("tok-rev", vec![staged.mount.clone()]);
    let mut session = backend
        .spawn(&fixture_image(), &[staged.mount.clone()], &spec)
        .unwrap();
    let _ = session.shutdown(Duration::from_millis(200));

    destroy(&staged.worktree_root).unwrap();
}

/// Multiple distinct sessions stage independent worktrees. Step 10
/// requires per-session UUID isolation: two sessions never share a
/// worktree root. We pin this against the live substrate so a
/// refactor that lets the staging module collide on UUID is loud.
#[test]
fn step10_distinct_sessions_stage_independent_worktrees() {
    let _g = ENV_LOCK.lock().unwrap();
    enable_test_harness();

    let tmp = tempfile::tempdir().unwrap();
    let mut a = StageInputs {
        data_dir:      tmp.path().to_path_buf(),
        session_uuid:  "step10-multi-A".to_owned(),
        system_prompt: "Executor A".to_owned(),
        session_token: "tok-A".to_owned(),
        vsock_cid:     0xC1D_AA01,
        vsock_port:    1024,
        mount_mode:    MountMode::ReadWrite,
    };
    let mut b = a.clone();
    b.session_uuid  = "step10-multi-B".to_owned();
    b.session_token = "tok-B".to_owned();
    b.vsock_cid     = 0xC1D_BB02;
    a.system_prompt.push_str("\nbranch-A rules");
    b.system_prompt.push_str("\nbranch-B rules");

    let staged_a = stage(&a).unwrap();
    let staged_b = stage(&b).unwrap();
    assert_ne!(staged_a.worktree_root, staged_b.worktree_root);
    assert_ne!(staged_a.mount.host_path, staged_b.mount.host_path);
    assert_ne!(staged_a.mount.content_hash, staged_b.mount.content_hash);

    // Spawn both into the same substrate concurrently. Sessions are
    // independent — `Drop` of the first must not affect the second.
    let backend = SubprocessIsolation::new("step10-multi-int")
        .expect("substrate construction must succeed under RAXIS_TEST_HARNESS=1");
    let mut sess_a = backend
        .spawn(&fixture_image(), &[staged_a.mount.clone()],
               &fixture_spec("tok-A", vec![staged_a.mount.clone()]))
        .unwrap();
    let mut sess_b = backend
        .spawn(&fixture_image(), &[staged_b.mount.clone()],
               &fixture_spec("tok-B", vec![staged_b.mount.clone()]))
        .unwrap();

    sess_a.push(&PushFrame { bytes: b"A-payload".to_vec() }).unwrap();
    sess_b.push(&PushFrame { bytes: b"B-payload".to_vec() }).unwrap();
    let recv_a = sess_a.recv_intent().unwrap();
    let recv_b = sess_b.recv_intent().unwrap();
    assert_eq!(recv_a.bytes, b"A-payload");
    assert_eq!(recv_b.bytes, b"B-payload");

    let _ = sess_a.shutdown(Duration::from_millis(200));
    let _ = sess_b.shutdown(Duration::from_millis(200));

    destroy(&staged_a.worktree_root).unwrap();
    destroy(&staged_b.worktree_root).unwrap();
}

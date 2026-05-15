//! BYO (Bring-Your-Own-Image) Executor V2.5 audit-trust witness.
//!
//! Validates the operator-published image trust contract specified
//! in:
//!
//!   * `raxis/specs/v2/canonical-images.md §3` — the BYO flow.
//!   * `raxis/specs/v2/image-cache.md §4` — `<data_dir>/oci-cache/`
//!     layout the resolver consumes.
//!   * `raxis/specs/invariants.md`:
//!       - `INV-IMAGE-RESOLUTION-PER-ROLE-01`
//!       - `INV-OPERATOR-CUSTOM-IMAGE-01`
//!       - `INV-OPERATOR-CUSTOM-IMAGE-02`
//!
//! ## Two-mode design
//!
//! Mirrors `extended_e2e_realistic_scenario.rs`'s two-mode pattern:
//!
//!   * **Smoke mode (default).** Runs at every `cargo test -p
//!     raxis-kernel` invocation. Exercises:
//!       - the BYO bake → stage → policy-inject pipeline against a
//!         synthetic rootfs (no docker, no kernel, no LLM);
//!       - the byte-equality contract between the helper-baked
//!         digest and the on-disk SHA-256 the kernel resolver
//!         would compute;
//!       - the tamper hook (one-byte flip) that seeds the negative-
//!         path fixture;
//!       - the `[[vm_images]]` + `[default_executor_image]` shape
//!         the helper writes into `policy.toml` (subsequently
//!         consumed by `validate_vm_images` /
//!         `validate_default_executor_image`);
//!       - the stable wire-shape of the `VmImageResolved` and
//!         `SecurityViolationDetected { violation_kind:
//!         "OperatorImageDigestMismatch" }` audit-event variants
//!         the kernel emits (no notification-inbox spam for
//!         success; Critical for tamper).
//!
//!     This guards against drift in the helper APIs, the
//!     audit-event surface, and the `policy.toml` injection
//!     format.
//!
//!   * **Live mode (gated).** Requires `RAXIS_LIVE_E2E=1` AND
//!     `RAXIS_LIVE_E2E_BYO=1`. Bakes the BYO Containerfile via
//!     docker, stages the result in `<data_dir>/oci-cache/`,
//!     amends `policy.toml`, boots the kernel, submits a
//!     single-Executor-task plan whose prompt instructs the
//!     planner to invoke `BashTool` for `python3.12 --version`
//!     and `node --version`, and asserts:
//!       - Tier 1 (mechanical): the audit chain carries
//!         `VmImageResolved { alias: "byo-executor-py312-node22",
//!         oci_digest: "sha256:...", agent_role: "Executor" }`
//!         (`INV-OPERATOR-CUSTOM-IMAGE-02` mechanical witness;
//!         positive path only).
//!       - Tier 2 (`assert!`): the executor's worktree-committed
//!         version-witness file contains `Python 3.12.x` AND
//!         `v22.x.x` patterns (the BYO image actually booted; a
//!         silent fallback to the canonical starter would surface
//!         `Python 3.11.x` and fail the regex).
//!       - Tier 3: kernel log path, audit dir, worktree, dashboard
//!         URL printed via `Tier3Reporter`.
//!
//!     A negative variant tampers the digest in `policy.toml`
//!     (last hex char flipped), submits the same plan, and
//!     asserts `SecurityViolationDetected { violation_kind:
//!     "OperatorImageDigestMismatch" }` fires before the spawn
//!     proceeds (`INV-OPERATOR-CUSTOM-IMAGE-01`).
//!
//! The live-mode body is **scaffolded but disabled** in this PR.
//! Branch A's auto-bake pipeline only landed days before this
//! commit; the BYO live-mode flow needs the iter-13 stack
//! (Anthropic key, gateway binary, working canonical executor
//! image) to be green end-to-end before the BYO heavyweight
//! variant can be validated. The smoke mode runs unconditionally
//! and pins every code surface the live mode would exercise; the
//! live-mode body is a TODO-fenced stub with the harness wiring
//! present so a follow-up commit can flip the gate without
//! re-architecting the test.

#![allow(clippy::too_many_lines)]
#![allow(dead_code)]

mod common;
mod extended_e2e_support;

use std::path::PathBuf;

use raxis_audit_tools::AuditEventKind;
use raxis_dashboard_kernel::notification_filter::{notification_priority, NotificationPriority};

use extended_e2e_support::byo_image::{
    bake_byo_executor_image_synthetic, inject_byo_executor_image_in_policy, sha256_of_file,
    stage_byo_image_in_oci_cache, tampered_digest_one_hex_off, BYO_ALIAS, BYO_DESCRIPTION,
    BYO_LINUX_KERNEL_MIN, PINNED_NODE_MAJOR, PINNED_PYTHON_MAJOR_MINOR,
};

const LIVE_E2E_GATE: &str = "RAXIS_LIVE_E2E";
const BYO_GATE: &str = "RAXIS_LIVE_E2E_BYO";

// ---------------------------------------------------------------------------
// Top-level test entry — chooses smoke vs live based on env gates.
// ---------------------------------------------------------------------------

#[test]
fn byo_executor_image_lifecycle() {
    let live_gate_on = std::env::var(LIVE_E2E_GATE).as_deref() == Ok("1");
    let byo_gate_on = std::env::var(BYO_GATE).as_deref() == Ok("1");

    if !(live_gate_on && byo_gate_on) {
        eprintln!(
            "[byo-e2e] gates off (LIVE_E2E={live_gate_on}, BYO={byo_gate_on}); \
             running smoke-mode wiring assertions only. To run the live-driven \
             BYO flow:\n  \
             1. docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait\n  \
             2. ensure raxis/.env carries ANTHROPIC-API-DEV-KEY=sk-ant-...\n  \
             3. ensure docker is on PATH and `docker buildx ls` shows a \
                multi-arch builder\n  \
             4. RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_BYO=1 cargo test -p raxis-kernel \
                --test extended_e2e_byo_executor_image -- --nocapture",
        );
        smoke_mode();
        return;
    }

    // Live mode is intentionally a TODO in this commit — the
    // harness primitives (bake, stage, inject, tamper) are
    // smoke-validated below, and the audit-emit wiring in
    // `kernel/src/handlers/intent.rs::handle_activate_sub_task` is
    // exercised at the type level by the smoke mode's
    // `audit_event_kind_classifications` block. Wiring the
    // heavyweight live flow needs the iter-13 stack (auto-baked
    // canonical images, gateway binary, working LLM, real microVM
    // boot of the BYO image with the planner binary overlaid) to
    // be green end-to-end first.
    //
    // Until then the smoke mode runs unconditionally and a future
    // commit will replace this `todo!` with the full bake → boot
    // → submit → poll → assert flow described in the file
    // doc-comment, without re-architecting the test.
    todo!(
        "BYO live-mode body — replace with full bake/boot/submit/poll/assert flow.\n\
         See raxis/specs/v2/canonical-images.md §4 for the live-mode test plan and\n\
         raxis/guides/recipes/ops/17-bring-your-own-executor-image.md for the\n\
         operator-facing recipe this test exercises. The harness primitives in\n\
         extended_e2e_support::byo_image are ready to consume."
    );
}

// ---------------------------------------------------------------------------
// Smoke mode — wiring assertions that always run
// ---------------------------------------------------------------------------

fn smoke_mode() {
    eprintln!("[byo-e2e:smoke] §1 bake → stage → inject pipeline (synthetic rootfs)");
    smoke_bake_stage_inject_pipeline();
    eprintln!("[byo-e2e:smoke] §2 tampered-digest negative-path fixture");
    smoke_tampered_digest_pipeline();
    eprintln!(
        "[byo-e2e:smoke] §3 audit-event surface (VmImageResolved + OperatorImageDigestMismatch)"
    );
    smoke_audit_event_surface();
    eprintln!("[byo-e2e:smoke] all wiring assertions pass");
}

/// Pipe the harness through one end-to-end sweep against a
/// synthetic rootfs. Mirrors what live-mode would do (minus the
/// docker bake), validating that:
///   * the digest the helper declares matches the on-disk bytes
///     (the resolver byte-equality check passes);
///   * the staged file lands at the
///     `<data_dir>/oci-cache/images/sha256/<aa>/<full>/rootfs.img`
///     path the resolver computes from `oci_digest`;
///   * `policy.toml` carries the `[[vm_images]]` +
///     `[default_executor_image]` blocks the kernel's policy
///     validator expects.
fn smoke_bake_stage_inject_pipeline() {
    let data_dir = tempfile::tempdir().expect("tempdir for data_dir");
    let staging = tempfile::tempdir().expect("tempdir for bake staging");

    // ── bake ─────────────────────────────────────────────────────
    let baked = bake_byo_executor_image_synthetic(staging.path()).expect("synthetic bake");
    assert!(
        baked.oci_digest.starts_with("sha256:"),
        "BYO bake must produce a sha256:-prefixed digest"
    );
    assert_eq!(
        baked.oci_digest.len(),
        "sha256:".len() + 64,
        "BYO bake digest length wrong: {}",
        baked.oci_digest
    );

    // ── stage (clean) ────────────────────────────────────────────
    let staged = stage_byo_image_in_oci_cache(data_dir.path(), &baked, false).expect("stage clean");
    let staged_hash = format!("sha256:{}", sha256_of_file(&staged).unwrap());
    assert_eq!(
        staged_hash, baked.oci_digest,
        "INV-OPERATOR-CUSTOM-IMAGE-01: clean stage MUST produce a rootfs.img \
         whose on-disk SHA-256 equals the policy-declared digest. The kernel \
         resolver stream-hashes this file at every session-spawn and aborts \
         with FAIL_OCI_IMAGE_DIGEST_MISMATCH on divergence.",
    );

    // ── seed a fake policy.toml so inject_byo... has somewhere to write ──
    let policy_dir = data_dir.path().join("policy");
    std::fs::create_dir_all(&policy_dir).unwrap();
    let policy_path = policy_dir.join("policy.toml");
    std::fs::write(&policy_path, "# raxis policy stub for BYO smoke test\n").unwrap();

    // ── inject ───────────────────────────────────────────────────
    inject_byo_executor_image_in_policy(data_dir.path(), &baked.oci_digest);

    let body = std::fs::read_to_string(&policy_path).unwrap();
    assert!(
        body.contains(&format!("name                     = \"{BYO_ALIAS}\"")),
        "policy.toml missing [[vm_images]] alias `{BYO_ALIAS}`:\n---\n{body}"
    );
    assert!(
        body.contains(&format!(
            "oci_digest               = \"{}\"",
            baked.oci_digest
        )),
        "policy.toml missing oci_digest line for BYO image:\n---\n{body}"
    );
    assert!(
        body.contains("role_restriction         = [\"Executor\"]"),
        "policy.toml [[vm_images]] missing role_restriction = [\"Executor\"]:\n---\n{body}"
    );
    assert!(
        body.contains(&format!(
            "linux_kernel_version_min = \"{BYO_LINUX_KERNEL_MIN}\""
        )),
        "policy.toml [[vm_images]] missing linux_kernel_version_min:\n---\n{body}"
    );
    assert!(
        body.contains(&format!("description              = \"{BYO_DESCRIPTION}\"")),
        "policy.toml [[vm_images]] missing description:\n---\n{body}"
    );
    assert!(
        body.contains(&format!("alias = \"{BYO_ALIAS}\"")),
        "policy.toml missing [default_executor_image] alias = \"{BYO_ALIAS}\":\n---\n{body}"
    );
}

/// The negative-path fixture: tamper the staged rootfs (one byte
/// XOR) so the on-disk SHA-256 diverges from the policy-declared
/// digest. The kernel resolver MUST detect this at session-spawn
/// time and emit `SecurityViolationDetected { violation_kind:
/// "OperatorImageDigestMismatch" }` per `INV-OPERATOR-CUSTOM-IMAGE-01`.
/// The smoke mode here asserts the tamper hook actually changed
/// the bytes; the live mode would assert the audit emit fires.
fn smoke_tampered_digest_pipeline() {
    let data_dir = tempfile::tempdir().expect("tempdir for data_dir");
    let staging = tempfile::tempdir().expect("tempdir for bake staging");
    let baked = bake_byo_executor_image_synthetic(staging.path()).expect("synthetic bake");

    // Stage with tamper=true — write one-byte-different bytes.
    let staged =
        stage_byo_image_in_oci_cache(data_dir.path(), &baked, true).expect("stage tampered");
    let staged_hash = format!("sha256:{}", sha256_of_file(&staged).unwrap());
    assert_ne!(
        staged_hash, baked.oci_digest,
        "tamper hook MUST produce a rootfs whose on-disk SHA differs from \
         the bake's declared digest — otherwise the negative-path test \
         silently passes against the wrong fixture.",
    );

    // The other negative-path knob: tamper the DIGEST in policy
    // (e.g. the operator typo'd the digest) while the on-disk
    // bytes are clean. Same kernel-side outcome: the resolver
    // hashes the on-disk file, finds it doesn't match the
    // declared digest, emits OperatorImageDigestMismatch.
    let typo_digest = tampered_digest_one_hex_off(&baked.oci_digest);
    assert_ne!(
        typo_digest, baked.oci_digest,
        "tampered_digest_one_hex_off must actually change the digest"
    );
    assert_eq!(
        typo_digest.len(),
        baked.oci_digest.len(),
        "tampered digest must preserve the sha256:<64-hex> shape"
    );
}

/// The kernel emits two new `AuditEventKind` variants for the BYO
/// flow; smoke-test the wire shape and the dashboard
/// notification-priority classification so a future renaming
/// (which would silently break operator audit dashboards) fails
/// loudly here.
fn smoke_audit_event_surface() {
    // VmImageResolved — the success-path mechanical witness for
    // INV-OPERATOR-CUSTOM-IMAGE-02. Single-class observability;
    // dashboard does NOT route to the inbox (a 50-task initiative
    // would otherwise produce 50 inbox rows).
    let resolved = AuditEventKind::VmImageResolved {
        session_id: "00000000-0000-7000-8000-000000000001".to_owned(),
        task_id: Some("byo-task-001".to_owned()),
        initiative_id: "00000000-0000-7000-8000-00000000000a".to_owned(),
        alias: BYO_ALIAS.to_owned(),
        oci_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_owned(),
        agent_role: "Executor".to_owned(),
    };
    assert_eq!(
        resolved.as_str(),
        "VmImageResolved",
        "VmImageResolved::as_str MUST return the variant name verbatim — \
         dashboards / forensics tools key on this string"
    );
    assert_eq!(
        notification_priority(&resolved),
        None,
        "VmImageResolved is routine-lifecycle observability; the dashboard \
         MUST NOT surface it in the operator inbox (would flood at >1 task \
         per initiative)"
    );

    // SecurityViolationDetected { violation_kind:
    // "OperatorImageDigestMismatch" } — the negative-path
    // mechanical witness for INV-OPERATOR-CUSTOM-IMAGE-01. Fires
    // when the kernel's BYO digest verification surfaces an
    // on-disk SHA mismatch. Dashboard MUST route Critical so the
    // operator is paged (same priority class as the canonical
    // ReviewerImageDigestMismatch / OrchestratorImageDigestMismatch
    // variants).
    let mismatch = AuditEventKind::SecurityViolationDetected {
        violation_kind: "OperatorImageDigestMismatch".to_owned(),
        expected: Some("sha256:aaaa...".to_owned()),
        actual: Some("sha256:bbbb...".to_owned()),
        path: Some("/data/oci-cache/images/sha256/aa/...rootfs.img".to_owned()),
    };
    assert_eq!(mismatch.as_str(), "SecurityViolationDetected");
    assert_eq!(
        notification_priority(&mismatch),
        Some(NotificationPriority::Critical),
        "OperatorImageDigestMismatch (and every other SecurityViolationDetected \
         kind) MUST classify as Critical — the operator needs to be paged \
         immediately on a supply-chain trust violation",
    );

    // Pin the documented BYO constants so a typo in the helper
    // module cannot silently drift away from the spec / recipe /
    // operator-facing examples.
    assert_eq!(BYO_ALIAS, "byo-executor-py312-node22");
    assert_eq!(PINNED_PYTHON_MAJOR_MINOR, "3.12");
    assert_eq!(PINNED_NODE_MAJOR, "22");
    assert_eq!(BYO_LINUX_KERNEL_MIN, "5.14");

    // The Containerfile lives in the workspace; sanity-check it's
    // there so a future cleanup that accidentally removes it does
    // not break the harness silently.
    let containerfile = workspace_root_from_manifest_dir()
        .join("live-e2e")
        .join("seed")
        .join("byoi-executor")
        .join("Containerfile");
    assert!(
        containerfile.exists(),
        "BYO Containerfile missing at {} — the harness's bake_byo_executor_image_full \
         depends on this path verbatim",
        containerfile.display(),
    );
}

// ---------------------------------------------------------------------------
// Tiny helper — workspace root resolution (mirrors kernel_driver.rs)
// ---------------------------------------------------------------------------

fn workspace_root_from_manifest_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(s) = std::fs::read_to_string(&candidate) {
                if s.contains("[workspace]") {
                    return p;
                }
            }
        }
        if !p.pop() {
            panic!("could not locate workspace root");
        }
    }
}

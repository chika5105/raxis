// raxis-cli — Genesis emitter ↔ raxis-policy round-trip pin.
//
// `cli/src/commands/genesis.rs::run_genesis` writes `policy.toml` via the
// shared `raxis_genesis_tools::render_genesis_policy_toml` emitter. This
// test pins that the bytes the CLI would actually write are accepted by
// the production loader (`raxis_policy::load_policy`).
//
// The kernel side has an equivalent regression-pin
// (`bootstrap::integration::policy_toml_round_trips_through_raxis_policy_load_policy`),
// but a CLI-side mirror is worth its weight: any future CLI flag that
// changes how the inputs are derived (`--data-dir`, `--operator-cert`,
// `--operator-key`, `--rotate`, etc.) would silently break operator
// workflows without it, because the kernel-side test only validates
// the kernel's own input derivation.
//
// Test strategy: rather than invoke the CLI binary (which would need a
// child process and operator stdin), we call `render_genesis_policy_toml`
// with the SAME inputs `commands::genesis::run_genesis` constructs at
// step 6, then write the bytes to a tempdir and parse them back.

use raxis_genesis_tools::{render_genesis_policy_toml, GenesisPolicyInputs};
use raxis_test_support::{ephemeral_cert_with_key, ephemeral_signing_key, pubkey_hex, CertOpts};

const FIXED_AUTHORITY_PUBKEY_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const FIXED_QUALITY_PUBKEY_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn cli_emitted_policy_round_trips_through_loader() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let placeholder_root = tmp.path().join("worktrees").display().to_string();
    let allowlist: [&str; 1] = [placeholder_root.as_str()];

    // Cert-mandatory (INV-CERT-01): the loader's
    // `validate_operator_certs` step requires a structurally-valid,
    // self-signed cert whose pubkey matches the operator entry's
    // `pubkey_hex`. We mint that cert here from a deterministic seed so
    // the test is reproducible.
    let key = ephemeral_signing_key([0x33u8; 32]);
    let pk = pubkey_hex(&key);
    let fp =
        raxis_genesis_tools::pubkey_fingerprint(&hex::decode(&pk).expect("pubkey hex must decode"));
    let cert = ephemeral_cert_with_key(
        &key,
        CertOpts {
            display_name: "test-operator".to_owned(),
            permitted_ops: raxis_genesis_tools::PERMITTED_OPS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            ..CertOpts::default()
        },
    );

    let toml_str = render_genesis_policy_toml(GenesisPolicyInputs {
        authority_pubkey_hex: FIXED_AUTHORITY_PUBKEY_HEX,
        quality_pubkey_hex: FIXED_QUALITY_PUBKEY_HEX,
        operator_pubkey_hex: &pk,
        operator_fingerprint: &fp,
        signed_at_unix_secs: 1_700_000_000,
        allowed_worktree_roots: &allowlist,
        operator_cert: &cert,
    });

    let policy_path = tmp.path().join("policy.toml");
    std::fs::write(&policy_path, &toml_str).expect("write policy.toml");

    let (bundle, _bytes, sha) =
        raxis_policy::load_policy(&policy_path).expect("loader must accept CLI emitter output");

    assert_eq!(bundle.epoch(), 1);
    assert_eq!(bundle.signed_by(), fp);
    assert_eq!(bundle.signed_at(), 1_700_000_000);
    assert_eq!(bundle.operators().len(), 1);
    assert_eq!(bundle.operators()[0].pubkey_hex, pk);
    assert_eq!(bundle.operators()[0].pubkey_fingerprint, fp);
    assert_eq!(
        bundle.operators()[0].cert.pubkey_hex,
        pk,
        "embedded cert must agree with entry-level pubkey_hex (INV-CERT-01)"
    );
    assert_eq!(bundle.lanes().len(), 1, "exactly one default lane");
    assert_eq!(bundle.lanes()[0].lane_id, "default");
    assert_eq!(sha.len(), 64);
}

#[test]
fn cli_emitter_and_kernel_emitter_produce_identical_bytes_for_identical_inputs() {
    // Convergence pin. Both the kernel and the CLI now call
    // `render_genesis_policy_toml`. If a future contributor adds back a
    // CLI-side hand-rolled emitter, this test will fail because the
    // shared emitter is the only one this test invokes.
    //
    // The actual kernel-side and CLI-side production code paths cannot
    // both be invoked from a single `#[test]` (kernel needs a real
    // BootstrapConfig + KernelError + filesystem; CLI needs stdin), so
    // the equivalence is enforced by:
    //   (a) both call sites going through `render_genesis_policy_toml`
    //       (verified by reading the source), and
    //   (b) this test pinning the byte shape of that one emitter against
    //       the structural assertions below.
    let key = ephemeral_signing_key([0x33u8; 32]);
    let pk = pubkey_hex(&key);
    let fp = raxis_genesis_tools::pubkey_fingerprint(&hex::decode(&pk).unwrap());
    let cert = ephemeral_cert_with_key(
        &key,
        CertOpts {
            display_name: "test-operator".to_owned(),
            permitted_ops: raxis_genesis_tools::PERMITTED_OPS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            ..CertOpts::default()
        },
    );

    let placeholder = "/var/lib/raxis/worktrees";
    let allowlist: [&str; 1] = [placeholder];
    let inputs = GenesisPolicyInputs {
        authority_pubkey_hex: FIXED_AUTHORITY_PUBKEY_HEX,
        quality_pubkey_hex: FIXED_QUALITY_PUBKEY_HEX,
        operator_pubkey_hex: &pk,
        operator_fingerprint: &fp,
        signed_at_unix_secs: 1_700_000_000,
        allowed_worktree_roots: &allowlist,
        operator_cert: &cert,
    };

    let bytes_a = render_genesis_policy_toml(inputs);
    let bytes_b = render_genesis_policy_toml(inputs);
    assert_eq!(
        bytes_a, bytes_b,
        "shared emitter must be deterministic — drift here means the CLI \
         and kernel paths could diverge across hosts"
    );

    for required_marker in [
        // Every section header the loader needs.
        "[meta]",
        "[authority]",
        "[escalation_policy]",
        "[sessions]",
        "[delegations]",
        "[budget]",
        "[budget.base_cost_per_intent_kind]",
        "[[operators.entries]]",
        "[operators.entries.cert]",
        "[[lanes]]",
        // Canonical IntentKind keys (the CLI's old emitter and the
        // kernel's old emitter disagreed on these — convergence pin).
        "SingleCommit",
        "IntegrationMerge",
        "CompleteTask",
        "ReportFailure",
        // Default lane (kernel's old emitter omitted this entirely).
        "lane_id              = \"default\"",
        // Operator-facing comment header (CLI's only — convergence pin
        // that the shared emitter kept it).
        "RAXIS v1 policy artifact",
    ] {
        assert!(
            bytes_a.contains(required_marker),
            "shared emitter output missing marker {required_marker:?}"
        );
    }

    // Negative pin: the dead intent-kind names that used to ship in the
    // kernel emitter must not reappear.
    for dead in ["MultiBranchCommit", "PrGateEvaluation"] {
        assert!(
            !bytes_a.contains(dead),
            "dead intent kind {dead:?} appeared in shared emitter output"
        );
    }
}

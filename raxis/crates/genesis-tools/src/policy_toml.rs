// raxis-genesis-tools::policy_toml — render the epoch-1 policy artifact.
//
// One canonical emitter for the genesis policy.toml. Both `raxis genesis`
// (CLI) and `RAXIS_BOOTSTRAP=1 raxis-kernel` (kernel self-bootstrap) call
// `render_genesis_policy_toml`; neither does its own `format!`. See the
// crate-level docstring for the drift history that motivated this module.

use std::fmt::Write;

use raxis_types::operator_cert::OperatorCert;

// ---------------------------------------------------------------------------
// Canonical inputs (named for spec correspondence, not for terseness)
// ---------------------------------------------------------------------------

/// Every variable input the genesis policy.toml depends on.
///
/// Holding a struct (rather than a long positional argument list) means
/// (a) callers cannot accidentally swap `authority_pubkey_hex` and
/// `quality_pubkey_hex` at the call site, and (b) when a future spec
/// amendment adds a new input we add a struct field rather than churning
/// every call site. Each field is `&'a str` (or `&'a [&'a str]`) to keep
/// allocations off the hot path of the emitter; the concrete strings are
/// owned by the caller (typically the bootstrap binary).
#[derive(Debug, Clone, Copy)]
pub struct GenesisPolicyInputs<'a> {
    /// Hex-encoded 32-byte authority Ed25519 public key (64 hex chars).
    pub authority_pubkey_hex: &'a str,
    /// Hex-encoded 32-byte quality Ed25519 public key (64 hex chars).
    pub quality_pubkey_hex: &'a str,
    /// Hex-encoded 32-byte operator Ed25519 public key (64 hex chars).
    pub operator_pubkey_hex: &'a str,
    /// `SHA-256[:16]` of the operator pubkey bytes — 32 hex chars. The caller
    /// MUST compute this through `super::pubkey_fingerprint(...)` to keep
    /// every emitter on the same hash function. Not derived from
    /// `operator_pubkey_hex` here so that a misuse (e.g. computing the
    /// fingerprint over the hex string instead of the raw bytes) surfaces
    /// at the call site rather than being silently absorbed.
    pub operator_fingerprint: &'a str,
    /// Unix-seconds timestamp written into `[meta] signed_at`. Caller-injected
    /// so tests can produce deterministic golden output and so production
    /// callers can route through their `Clock` of choice.
    pub signed_at_unix_secs: i64,
    /// `[sessions] allowed_worktree_roots` is REQUIRED to be non-empty by
    /// `raxis_policy::PolicyBundle::validate` (the genesis-time placeholder
    /// is typically `<data_dir>/worktrees`; the operator MUST replace it
    /// before creating sessions). The vec must contain at least one path —
    /// passing an empty slice is a programming error and panics; see the
    /// `empty_worktree_roots_panics` test.
    pub allowed_worktree_roots: &'a [&'a str],
    /// The genesis operator's cert. **Required** (cert is mandatory —
    /// INV-CERT-01); the emitter writes it under
    /// `[operators.entries.cert]` so the artifact survives the
    /// loader's strict-deserialise check. The cert's `pubkey_hex` MUST
    /// equal `operator_pubkey_hex` and the cert's `self_sig_hex` MUST
    /// be a valid Ed25519 self-signature; both are validated by
    /// `raxis_policy::PolicyBundle::validate` on the round-trip read.
    pub operator_cert: &'a OperatorCert,
}

// ---------------------------------------------------------------------------
// Canonical constants — DO NOT inline these into the format string.
// Centralising the ops list and the header comment is the WHOLE POINT of
// this crate; if a spec amendment changes them it changes here, once.
// ---------------------------------------------------------------------------

/// The 13-operation v1 permitted-ops set, per `cli-ceremony.md` §4.2 step 6
/// and `kernel-store.md` §2.5.5 IPC discriminant table. Order matters for
/// byte-identical reproducibility of the genesis artifact across hosts.
pub const PERMITTED_OPS: &[&str] = &[
    "CreateInitiative",
    "ApprovePlan",
    "RejectPlan",
    "CreateSession",
    "RevokeSession",
    "GrantDelegation",
    "RetryTask",
    "ResumeTask",
    "AbortTask",
    "AbortInitiative",
    "ApproveEscalation",
    "DenyEscalation",
    "RotateEpoch",
    "QuarantineInitiative",
    "QuarantinePlansBy",
];

/// The four canonical `IntentKind` variants, matching `raxis_types::IntentKind`.
/// Each entry is `(toml_key, base_cost)`. The previous kernel-side emitter
/// shipped `MultiBranchCommit = 25` and `PrGateEvaluation = 15` here, neither
/// of which is a real `IntentKind`, while omitting `CompleteTask` and
/// `ReportFailure` (the variants the budget code actually looks up at
/// admission time). That P0 latent bug is fixed by keeping this list
/// *here* and letting the type system surface any future `IntentKind`
/// addition that forgets to update genesis defaults — see the
/// `intent_kind_keys_match_canonical_set` test in `lib.rs::tests`.
const BASE_COST_PER_INTENT_KIND: &[(&str, u64)] = &[
    ("SingleCommit", 10),
    ("IntegrationMerge", 50),
    ("CompleteTask", 5),
    ("ReportFailure", 1),
];

/// Default lane configuration shipped at genesis. Operators replace this in
/// epoch 2 by advancing the policy with their real lane partition. Without
/// at least one `[[lanes]]` entry, `scheduler::admit::admit_task` cannot
/// resolve `lane_id = "default"` (which is what every plan defaults to)
/// and admission fails with `SchedulerError::UnknownLane`. The kernel-side
/// emitter previously omitted this entirely — that's the third drift the
/// convergence fixes.
const DEFAULT_LANE_NAME: &str = "default";
const DEFAULT_LANE_MAX_CONCURRENT_TASKS: u32 = 4;
const DEFAULT_LANE_MAX_COST_PER_EPOCH: u64 = 10_000;
const DEFAULT_LANE_PRIORITY: u8 = 100;

/// Default `[dashboard]` values shipped at genesis (per
/// `v2_extended_gaps.md §4.3` and the field defaults in
/// `raxis_dashboard::config::DashboardConfig`). The dashboard is
/// emitted with `enabled = true` so a fresh operator gets a
/// working dashboard out of the box on loopback; binding stays on
/// `127.0.0.1` and port `9820` is the documented spec default
/// (well above the privileged-port ceiling). Operators who want
/// the dashboard off explicitly set `enabled = false` in epoch 2.
///
/// **Why enabled by default (vs. `[gateway]` which is commented):**
/// the dashboard's authentication is challenge-response over the
/// kernel's existing operator key, so it carries no out-of-band
/// secrets to provision. `[gateway]` is commented because it
/// requires real provider credentials under
/// `<data_dir>/providers/` before it can do anything useful.
const DEFAULT_DASHBOARD_BIND_ADDRESS: &str = "127.0.0.1";
const DEFAULT_DASHBOARD_BIND_PORT: u16 = 9820;
/// `INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01`: the autologin URL
/// printed at kernel boot MUST remain valid for the kernel's
/// process lifetime. The realistic-scenario live-e2e harness
/// routinely runs 60+ minutes, the previous 1-hour TTL expired
/// mid-run, and the QA worker landed on the manual challenge-
/// response form because `parseAutologinHash` happily stored an
/// already-expired profile in `localStorage` and `RequireAuth`
/// bounced to `/login`. 24 hours keeps the URL alive through
/// every realistic kernel uptime while the per-boot HMAC secret
/// regeneration still invalidates every token the instant the
/// kernel exits. Mirrors `raxis_dashboard::config::DEFAULT_JWT_TTL_SECS`.
const DEFAULT_DASHBOARD_JWT_TTL_SECS: u64 = 86_400;

// ---------------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------------

/// Escape a string for emission as a TOML basic string. Conservative:
/// quotes get escaped so the operator-supplied display name cannot break
/// out of the surrounding `"..."` and inject TOML structure. The cert
/// validator (`validate_cert_structurally::DisplayNameLength`) already
/// rejects empty / overlong names; this layer just guards against
/// quote injection on names that DO pass that check.
fn escape_toml_basic_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build the epoch-1 policy.toml as a `String`. Pure function — caller is
/// responsible for writing the bytes to disk (kernel uses
/// `write_file_0644`; CLI uses `fs::write`).
///
/// Output shape matches `raxis_policy::PolicyBundle` parser exactly. The
/// round-trip is asserted by the test at the bottom of this file.
///
/// # Panics
///
/// Panics if `inputs.allowed_worktree_roots` is empty. The validator in
/// `raxis_policy::PolicyBundle::validate` rejects empty allowlists, so a
/// caller passing an empty slice would produce an unloadable artifact;
/// failing fast at emit time gives a clearer error than a downstream
/// `MalformedArtifact("sessions.allowed_worktree_roots is empty")` from
/// the loader on the very next boot.
pub fn render_genesis_policy_toml(inputs: GenesisPolicyInputs<'_>) -> String {
    assert!(
        !inputs.allowed_worktree_roots.is_empty(),
        "render_genesis_policy_toml: allowed_worktree_roots must contain at \
         least one path; an empty list would produce a policy artifact the \
         loader rejects (raxis_policy::PolicyBundle::validate)",
    );

    // We pre-allocate a chunky buffer (~1 KiB) so every `write!` below avoids
    // a re-grow. The exact size doesn't matter for correctness; the magic
    // number was sized off the actual genesis output (~900 bytes today).
    let mut out = String::with_capacity(1024);

    // Header — operator-facing comment block. We deliberately put the spec
    // reference in the first comment line so a curious operator running
    // `head -5 policy.toml` learns where to find the schema.
    out.push_str(
        "# RAXIS v1 policy artifact — generated by genesis ceremony.\n\
         # Schema: raxis_policy::PolicyBundle (crates/policy/src/bundle.rs).\n\
         # Sign with: raxis policy sign policy.toml --key <operator_private_key>.\n\n",
    );

    // [meta] — epoch + signer fingerprint + timestamp. `signed_by` is the
    // operator's pubkey fingerprint; `signed_at` is caller-injected.
    write!(
        out,
        "[meta]\n\
        epoch         = 1\n\
        signed_by     = \"{op_fp}\"\n\
        signed_at     = {ts}\n\
        \n",
        op_fp = inputs.operator_fingerprint,
        ts = inputs.signed_at_unix_secs,
    )
    .expect("String write_fmt is infallible");

    // [authority] — pubkeys for the kernel-issued signing identities.
    write!(
        out,
        "[authority]\n\
        authority_pubkey = \"{auth}\"\n\
        quality_pubkey   = \"{qual}\"\n\
        \n",
        auth = inputs.authority_pubkey_hex,
        qual = inputs.quality_pubkey_hex,
    )
    .expect("String write_fmt is infallible");

    // [escalation_policy] — fixed v1 defaults; the operator can re-tune via
    // epoch advance once they've observed real escalation traffic.
    out.push_str(
        "[escalation_policy]\n\
         timeout_secs         = 3600\n\
         window_secs          = 300\n\
         max_per_window       = 5\n\
         quarantine_threshold = 3\n\
         \n",
    );

    // [sessions] — TTLs + allowed worktree roots. The roots list is the
    // single most error-prone genesis field; we annotate it with a TOML
    // comment directing the operator to update it before first use.
    out.push_str(
        "[sessions]\n\
         default_ttl_secs       = 86400\n\
         max_ttl_secs           = 604800\n\
         # Placeholder — REPLACE before creating sessions. See cli-ceremony.md §4.2.\n\
         allowed_worktree_roots = [",
    );
    for (i, root) in inputs.allowed_worktree_roots.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        // We do NOT escape backslashes inside the path — every supported
        // platform (Unix, macOS) uses `/`, and TOML basic-string escaping
        // is unnecessary for the placeholder. If a future Windows port
        // changes this, route through the `toml` crate's encoder rather
        // than reinventing escaping here.
        write!(out, "\"{root}\"").expect("String write_fmt is infallible");
    }
    out.push_str("]\n\n");

    // [delegations] — capability TTL ceiling.
    out.push_str(
        "[delegations]\n\
         max_ttl_secs = 86400\n\
         \n",
    );

    // [budget] — per-touched-path cost + per-task cap + per-IntentKind base
    // costs. Both per-touched-path fields use `raxis_policy`'s defaults but
    // we serialise them explicitly so the artifact is self-documenting; the
    // operator can `cat policy.toml` and see every effective value.
    out.push_str(
        "[budget]\n\
         cost_per_touched_path = 1\n\
         max_cost_per_task     = 10000\n\
         \n",
    );
    out.push_str("[budget.base_cost_per_intent_kind]\n");
    for (kind, cost) in BASE_COST_PER_INTENT_KIND {
        // Right-pad keys to 17 chars so the equals signs align — purely
        // cosmetic, but operators read this file by hand and the alignment
        // makes a missed entry stand out at review time.
        writeln!(out, "{kind:<17} = {cost}").expect("String write_fmt is infallible");
    }
    out.push('\n');

    // [[operators.entries]] — the genesis operator. Exactly one entry; the
    // operator can register additional keys via `raxis epoch advance`.
    // Cert is mandatory (INV-CERT-01): we ALWAYS emit a
    // `[operators.entries.cert]` sub-table here. The cert's
    // `permitted_ops` is the authority at runtime; the entry-level
    // `permitted_ops` field is preserved for backward compatibility
    // with operators who `cat policy.toml` looking for the op set, but
    // `validate_operator_certs` overwrites it from the cert at load
    // time.
    write!(
        out,
        "[[operators.entries]]\n\
        pubkey_fingerprint = \"{op_fp}\"\n\
        display_name       = \"{display_name}\"\n\
        pubkey_hex         = \"{op_pk}\"\n\
        permitted_ops      = [\n",
        op_fp = inputs.operator_fingerprint,
        op_pk = inputs.operator_pubkey_hex,
        display_name = escape_toml_basic_string(&inputs.operator_cert.display_name),
    )
    .expect("String write_fmt is infallible");
    for (i, op) in PERMITTED_OPS.iter().enumerate() {
        // Trailing comma after every op including the last is legal TOML
        // and means inserting a new op is a one-line diff that doesn't
        // touch the previous line — much friendlier in code review.
        if i > 0 {
            out.push_str(",\n");
        }
        write!(out, "  \"{op}\"").expect("String write_fmt is infallible");
    }
    out.push_str(",\n]\n\n");

    // [operators.entries.cert] — the embedded self-signed cert. We
    // route through the `toml` crate's serializer rather than
    // hand-rolling the field block: the cert format owns its own
    // canonical-byte contract (`raxis-crypto::cert::cert_canonical_signing_input`)
    // and the only safe way to keep that contract while avoiding
    // hand-rolled escaping bugs is to delegate to the same serde
    // pipeline that `[[operators.entries]]` itself goes through on
    // load. The serialiser is infallible for `OperatorCert` (every
    // field is `String`/`i64`/`u32`/`Vec<String>`).
    let cert_block =
        toml::to_string(inputs.operator_cert).expect("OperatorCert serialise is infallible");
    out.push_str("[operators.entries.cert]\n");
    out.push_str(&cert_block);
    if !cert_block.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');

    // [[lanes]] — the default execution lane. Without at least one lane
    // entry, `scheduler::admit::admit_task` cannot resolve `lane_id = "default"`
    // and admission fails with `SchedulerError::UnknownLane`.
    write!(
        out,
        "[[lanes]]\n\
        lane_id              = \"{lane_id}\"\n\
        max_concurrent_tasks = {max_conc}\n\
        max_cost_per_epoch   = {max_cost}\n\
        priority             = {priority}\n\n",
        lane_id = DEFAULT_LANE_NAME,
        max_conc = DEFAULT_LANE_MAX_CONCURRENT_TASKS,
        max_cost = DEFAULT_LANE_MAX_COST_PER_EPOCH,
        priority = DEFAULT_LANE_PRIORITY,
    )
    .expect("String write_fmt is infallible");

    // [dashboard] — operator dashboard HTTP server (per
    // `v2_extended_gaps.md §4.3`). Emitted with `enabled = true` so
    // a fresh operator gets a working dashboard immediately on
    // loopback. The kernel boot path
    // (`raxis_dashboard_kernel::load_dashboard_config` →
    // `kernel/src/main.rs`) reads this section directly; it is
    // outside `RawPolicy` (no strict-deserialise interaction with
    // the policy loader). Operators turn it off by setting
    // `enabled = false` and rotating the policy epoch.
    write!(
        out,
        "[dashboard]\n\
        enabled      = true\n\
        bind_address = \"{addr}\"\n\
        bind_port    = {port}\n\
        jwt_ttl_secs = {ttl}\n\n",
        addr = DEFAULT_DASHBOARD_BIND_ADDRESS,
        port = DEFAULT_DASHBOARD_BIND_PORT,
        ttl = DEFAULT_DASHBOARD_JWT_TTL_SECS,
    )
    .expect("String write_fmt is infallible");

    // [gateway] + [[providers]] — OPTIONAL. We emit them as commented
    // template blocks so operators get a working starting point without
    // forcing them to know the schema upfront. A kernel started against a
    // genesis policy with no `[gateway]` boots cleanly; it just cannot
    // dispatch FetchRequests until the operator advances the policy with
    // a real `[gateway]` and at least one `[[providers]]`.
    //
    // **Why commented vs. omitted entirely?** A commented template is
    // self-documenting: an operator running `cat policy.toml` sees the
    // full schema in front of them. Omitting the section would force them
    // to pull the schema from peripherals.md §3.2 and bundle.rs at the
    // same time, which is exactly the kind of friction that produces
    // hand-edited policy.toml files with subtle errors.
    out.push_str(
        "# ── External provider integration (OPTIONAL) ──────────────────────────\n\
         # Uncomment the [gateway] block and at least one [[providers]] entry to\n\
         # enable inference / data-fetch. Provider credentials live separately\n\
         # under <data_dir>/providers/<credentials_file> (mode 0600); the kernel\n\
         # NEVER reads provider credentials directly. See peripherals.md §3.2.\n\
         #\n\
         # [gateway]\n\
         # binary_path              = \"/usr/local/bin/raxis-gateway\"\n\
         # spawn_timeout_secs       = 5\n\
         # respawn_backoff_ms       = 1000\n\
         # max_consecutive_respawns = 5\n\
         #\n\
         # [[providers]]\n\
         # provider_id           = \"anthropic-prod\"\n\
         # kind                  = \"Anthropic\"\n\
         # credentials_file      = \"anthropic-prod.toml\"\n\
         # inference_timeout_ms  = 30000\n\
         # data_fetch_timeout_ms = 10000\n\
         # max_response_bytes    = 16777216\n\
         # # v2_extended_gaps.md §2.5 — pricing is REQUIRED for every\n\
         # # model-bearing provider kind (Anthropic, OpenAI, Gemini,\n\
         # # Bedrock, http_sidecar). Operators declare the inverse of\n\
         # # the published per-million price (tokens per US dollar) so\n\
         # # the kernel can compute cost via integer math.\n\
         # pricing.input_tokens_per_dollar  = 200000   # $5  / 1M input\n\
         # pricing.output_tokens_per_dollar = 50000    # $20 / 1M output\n\
         # # pricing.cache_read_tokens_per_dollar    = 2000000  # $0.50 / 1M cache hit\n\
         # # pricing.cache_creation_tokens_per_dollar = 160000  # $6.25 / 1M cache write\n",
    );

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubkey_fingerprint;
    use raxis_test_support::{
        ephemeral_cert_with_key, ephemeral_signing_key, pubkey_hex, CertOpts,
    };

    /// Fixed all-zero / all-1s test pubkeys for the AUTHORITY and
    /// QUALITY keys (these are validated at the loader as 64-hex-char
    /// strings only — they don't need to be real Ed25519 keys for
    /// these unit tests). The OPERATOR pubkey, by contrast, MUST be a
    /// real Ed25519 key now so the cert it embeds can self-sign and
    /// pass `PolicyBundle::validate`'s mandatory cert-validation step
    /// (INV-CERT-01).
    const FIXED_AUTHORITY_PUBKEY_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const FIXED_QUALITY_PUBKEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Deterministic seed for the test operator key. Same seed on every
    /// run → byte-identical pubkey + cert → byte-identical policy.toml
    /// (which is what makes `output_is_byte_deterministic_across_invocations`
    /// hold even after we mint a cert here).
    const FIXED_OPERATOR_SEED: [u8; 32] = [0x42u8; 32];

    /// Build a cert + the matching pubkey hex + fingerprint, all derived
    /// from the deterministic test seed.
    fn fixture_operator_identity() -> (String, String, OperatorCert) {
        let key = ephemeral_signing_key(FIXED_OPERATOR_SEED);
        let pk_hex = pubkey_hex(&key);
        let fp = pubkey_fingerprint(&hex::decode(&pk_hex).unwrap());
        let cert = ephemeral_cert_with_key(
            &key,
            CertOpts {
                display_name: "operator-1".to_owned(),
                permitted_ops: PERMITTED_OPS.iter().map(|s| (*s).to_owned()).collect(),
                ..CertOpts::default()
            },
        );
        (pk_hex, fp, cert)
    }

    fn fixed_inputs<'a>(
        roots: &'a [&'a str],
        op_pk: &'a str,
        op_fp: &'a str,
        cert: &'a OperatorCert,
    ) -> GenesisPolicyInputs<'a> {
        GenesisPolicyInputs {
            authority_pubkey_hex: FIXED_AUTHORITY_PUBKEY_HEX,
            quality_pubkey_hex: FIXED_QUALITY_PUBKEY_HEX,
            operator_pubkey_hex: op_pk,
            operator_fingerprint: op_fp,
            signed_at_unix_secs: 1_700_000_000, // 2023-11-14T22:13:20Z
            allowed_worktree_roots: roots,
            operator_cert: cert,
        }
    }

    // ── Property tests — the round trip ─────────────────────────────────────

    #[test]
    fn output_round_trips_through_load_policy() {
        // The single most important test in this crate. Anything that
        // breaks the loader contract surfaces here on the next test run.
        let (op_pk_hex, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-test-worktrees"];
        let toml_str = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk_hex, &op_fp, &cert));

        // Write to a temp file because `load_policy` takes a path.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &toml_str).unwrap();
        let (bundle, _bytes, sha) = raxis_policy::load_policy(tmp.path())
            .expect("loader must accept render_genesis_policy_toml output");

        assert_eq!(bundle.epoch(), 1, "genesis epoch is always 1");
        assert_eq!(
            bundle.operators().len(),
            1,
            "genesis registers exactly one operator"
        );
        assert_eq!(bundle.operators()[0].pubkey_hex, op_pk_hex);
        assert_eq!(bundle.operators()[0].pubkey_fingerprint, op_fp);
        assert_eq!(bundle.signed_by(), op_fp);
        assert_eq!(bundle.signed_at(), 1_700_000_000);
        assert_eq!(
            bundle.lanes().len(),
            1,
            "exactly one default lane at genesis"
        );
        assert_eq!(bundle.lanes()[0].lane_id, "default");
        assert_eq!(sha.len(), 64, "policy_sha256 is hex-SHA-256 = 64 chars");
        // Cert mandatory: every operator entry MUST carry a cert that
        // round-trips losslessly through TOML.
        assert_eq!(
            bundle.operators()[0].cert.pubkey_hex,
            op_pk_hex,
            "embedded cert must agree with entry-level pubkey_hex"
        );
    }

    #[test]
    fn every_canonical_intent_kind_appears_in_budget_table() {
        // Pin the exact TOML keys we emit against the four real
        // `IntentKind` variants. If a future spec amendment adds a fifth
        // intent kind without updating BASE_COST_PER_INTENT_KIND here,
        // any task admission of that kind would fail with
        // `BudgetError::UnknownIntentKindCost`. We can't depend on
        // `raxis-types` (would create a cycle: types → policy → genesis-tools
        // → types is fine, but the existing budget code already lives in
        // the kernel and isn't a workspace dep we have here), so the
        // canonical list is hardcoded. Any addition MUST update this test
        // AND BASE_COST_PER_INTENT_KIND in lock step.
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-test-worktrees"];
        let toml_str = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
        for kind in &[
            "SingleCommit",
            "IntegrationMerge",
            "CompleteTask",
            "ReportFailure",
        ] {
            assert!(
                toml_str.contains(&format!("{kind:<17} = ")),
                "expected canonical intent kind {kind:?} in output, got:\n{toml_str}"
            );
        }
        // Negative pin: the dead names that used to ship in the kernel
        // emitter must NOT reappear. If a future contributor copy-pastes
        // the wrong constant set this test will catch it.
        for dead in &["MultiBranchCommit", "PrGateEvaluation"] {
            assert!(
                !toml_str.contains(dead),
                "dead intent kind {dead:?} reappeared in genesis output:\n{toml_str}"
            );
        }
    }

    #[test]
    fn dashboard_section_is_emitted_with_enabled_true_and_loopback_defaults() {
        // Pinned because a fresh operator should get a working
        // dashboard out of the box. If a future change demotes the
        // section to commented-template (the `[gateway]` style) or
        // removes it entirely, this test surfaces the regression
        // immediately.
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-test-worktrees"];
        let toml_str = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
        assert!(
            toml_str.contains("[dashboard]"),
            "missing [dashboard] section in output:\n{toml_str}"
        );
        assert!(
            toml_str.contains("enabled      = true"),
            "expected dashboard enabled by default in genesis output:\n{toml_str}"
        );
        assert!(
            toml_str.contains("bind_address = \"127.0.0.1\""),
            "expected loopback bind_address by default:\n{toml_str}"
        );
        assert!(
            toml_str.contains("bind_port    = 9820"),
            "expected port 9820 (spec default) by default:\n{toml_str}"
        );
        assert!(
            toml_str.contains("jwt_ttl_secs = 86400"),
            "expected 24 h JWT TTL by default (INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01 — \
             autologin URL minted at boot must remain valid for the kernel's process \
             lifetime; the realistic-scenario live-e2e harness runs >1h):\n{toml_str}"
        );

        // Round-trip through the dashboard-config loader so the
        // bytes we emit are exactly what the kernel boot path reads.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &toml_str).unwrap();
        let cfg = raxis_dashboard_kernel::load_dashboard_config(tmp.path())
            .expect("load_dashboard_config must accept emitter output")
            .expect("[dashboard] is enabled, so cfg must be Some");
        assert!(cfg.enabled, "loaded config must agree with TOML");
        assert_eq!(cfg.bind_address, "127.0.0.1");
        assert_eq!(cfg.bind_port, 9820);
        assert_eq!(cfg.jwt_ttl_secs, 86_400);
    }

    #[test]
    fn default_lane_section_is_present_and_loadable() {
        // Pinned because the kernel emitter previously omitted [[lanes]]
        // entirely. Without this section, every task admission for the
        // default lane fails with SchedulerError::UnknownLane.
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-test-worktrees"];
        let toml_str = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
        assert!(toml_str.contains("[[lanes]]"), "missing [[lanes]] section");
        assert!(
            toml_str.contains("lane_id              = \"default\""),
            "missing default lane_id"
        );
    }

    #[test]
    fn all_thirteen_v1_permitted_ops_appear_in_operator_entry() {
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-test-worktrees"];
        let toml_str = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
        for op in PERMITTED_OPS {
            assert!(
                toml_str.contains(&format!("\"{op}\"")),
                "permitted op {op:?} missing from output"
            );
        }
        // Confirm exactly 15 (the original 13 v1 ops plus the two
        // quarantine ops added in step 10 — kernel-store.md §2.5.8).
        assert_eq!(
            PERMITTED_OPS.len(),
            15,
            "v1+quarantine permitted_ops set is fixed at 15 (cli-ceremony.md §4.2 + §2.5.8)"
        );
    }

    #[test]
    fn multiple_worktree_roots_are_emitted_with_correct_separator() {
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-a", "/tmp/raxis-b", "/tmp/raxis-c"];
        let toml_str = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
        // Expect `["/tmp/raxis-a", "/tmp/raxis-b", "/tmp/raxis-c"]` — one
        // pair of brackets, two separators of exactly `, ` between three
        // string literals.
        assert!(
            toml_str.contains(
                "allowed_worktree_roots = [\"/tmp/raxis-a\", \"/tmp/raxis-b\", \"/tmp/raxis-c\"]"
            ),
            "multi-root list produced wrong shape:\n{toml_str}"
        );
    }

    #[test]
    fn output_is_byte_deterministic_across_invocations() {
        // No SystemTime::now() inside the emitter, no random bytes — for
        // the same inputs the bytes MUST match. This is what gives us
        // reproducible genesis policy artifacts across machines.
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-test-worktrees"];
        let a = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
        let b = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
        assert_eq!(a, b, "emitter must be byte-deterministic for fixed inputs");
    }

    #[test]
    fn signed_at_value_appears_verbatim_in_meta_block() {
        // The previous emitters called SystemTime::now() inline, which
        // made the goldens above impossible to write. Pin the contract
        // that the caller-supplied timestamp is the one that appears.
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-test-worktrees"];
        let inputs = GenesisPolicyInputs {
            signed_at_unix_secs: 42,
            ..fixed_inputs(&roots, &op_pk, &op_fp, &cert)
        };
        let toml_str = render_genesis_policy_toml(inputs);
        assert!(
            toml_str.contains("signed_at     = 42"),
            "expected `signed_at = 42` literal, got:\n{toml_str}"
        );
    }

    /// New contract (INV-CERT-01): the emitter MUST always produce a
    /// `[operators.entries.cert]` sub-table. A consumer scanning the
    /// emitted bytes MUST see the cert block; a missing block would
    /// make the loader reject the artifact at next boot.
    #[test]
    fn output_always_emits_an_operators_entries_cert_subtable() {
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots = ["/tmp/raxis-test-worktrees"];
        let toml_str = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
        assert!(
            toml_str.contains("[operators.entries.cert]"),
            "emitter MUST always produce a `[operators.entries.cert]` sub-table; got:\n{toml_str}"
        );
    }

    // ── Negative cases ─────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "allowed_worktree_roots must contain at least one path")]
    fn empty_worktree_roots_panics() {
        // Loader-rejects-empty-list contract: failing fast here gives a
        // clearer error than waiting for the loader to choke.
        let (op_pk, op_fp, cert) = fixture_operator_identity();
        let roots: [&str; 0] = [];
        let _ = render_genesis_policy_toml(fixed_inputs(&roots, &op_pk, &op_fp, &cert));
    }
}

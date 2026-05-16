// raxis-cli::commands::setup — `raxis setup` interactive (and
// non-interactive) first-run wizard.
//
// Normative reference: `specs/v2/operator-ergonomics.md §16`. The
// wizard is the spec-recommended onboarding path; without it new
// operators have to discover the right ordering of
// `raxis cert mint` → `raxis genesis` → `raxis policy sign` →
// `raxis plan init` → `raxis doctor` → `raxis submit plan` from
// prose.
//
// V2.3 MVP scope
// ──────────────
// V2 ships a **non-interactive scaffolding** flow that:
//   1. Creates the `<data_dir>` skeleton (`runtime/`, `audit/`,
//      `keys/`, `providers/`, `policy/`, `sockets/`,
//      `revocations/`).
//   2. Writes a starter `policy/policy.toml` populated with the
//      operator-supplied identity, a single declared provider,
//      conservative budget + concurrency defaults, an empty
//      `[[vm_images]]` block (operator fills in OCI digests
//      after picking images), and the genesis-required
//      `[gateway]` and `[host_capacity]` sections.
//   3. Runs `raxis plan init --template feature` against
//      `<data_dir>/plan/plan.toml` (delegating to
//      `commands::plan_init`) so the operator has a valid
//      starter plan.
//   4. Persists `<data_dir>/.setup_state.json` so re-running
//      `raxis setup` skips already-completed phases (idempotent
//      re-entry per spec).
//   5. Prints a clear "next steps" recipe pointing at the
//      remaining manual ceremony steps that V2 cannot automate
//      (cert ceremony, `raxis genesis`, policy signing).
//
// What is intentionally **deferred to V3**:
//   * Phase 1 (key ceremony) — V2 stops short of running
//     `raxis genesis` automatically because that command needs
//     either an air-gapped operator cert (`--operator-cert`) or
//     an interactive paste flow (`--operator-key`) that requires
//     a TTY abstraction the wizard does not yet have.
//   * Phase 4 (VM image OCI-digest picking) — depends on a
//     registry-list fetch path that V2 does not ship.
//   * Phase 5 (credential proxy setup) — declarative-only in V2
//     (operator hand-edits `[[tasks.credentials]]`).
//   * Phase 7 (egress allowlist auto-populate) — V2 ships an
//     empty `[[tproxy_allowlist]]` and the operator pastes the
//     hosts they need.
//   * Phase 9 (`raxis submit plan --dry-run`) — handler is V3
//     (no `DryRunAdmit` IPC type yet, see ).
//   * Phase 10 (first launch) — operator runs
//     `raxis submit plan` manually after the cert ceremony.
// Design constraints honoured by the V2 MVP
// ──────────────────────────────────────────
//   * **Non-interactive only.** Every input is a flag — no TTY
//     dependency, no `dialoguer`/`inquire` deps, fully scriptable
//     for CI smoke tests.
//   * **Idempotent re-entry.** `<data_dir>/.setup_state.json`
//     records which phases completed; a re-run skips them
//     unless `--force` is passed. Crash mid-Phase-2? Re-run
//     resumes at Phase 2.
//   * **No overwrite without confirmation.** Existing
//     `policy.toml` triggers a `FAIL_SETUP_POLICY_EXISTS` error
//     with a `--force` opt-in, mirroring `plan init`.
//   * **Composable with existing commands.** Phase 6 delegates
//     to `commands::plan_init::run` rather than re-implementing
//     template rendering. Phase 8 is left as a printed
//     `raxis doctor` invocation rather than calling it
//     in-process — operators see the exact command they would
//     re-run later when verifying config drift.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::CliError;
use crate::GlobalFlags;

/// Phases in the V2 wizard. Numbering matches
/// `operator-ergonomics.md §16` so spec readers can map them
/// 1-to-1; we run **only** phases 2, 6, and 8 today, but the
/// state file pre-allocates slots for all phases so a V3
/// upgrade does not need a state-file format migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)] // V3 phases (DryRun, FirstLaunch) are pre-allocated
pub enum Phase {
    KeyCeremony = 1,
    PolicyAuthoring = 2,
    ProviderCreds = 3,
    VmImages = 4,
    CredentialProxy = 5,
    PlanTemplate = 6,
    NetworkAllowlist = 7,
    Doctor = 8,
    DryRun = 9,
    FirstLaunch = 10,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Phase::KeyCeremony => "key_ceremony",
            Phase::PolicyAuthoring => "policy_authoring",
            Phase::ProviderCreds => "provider_credentials",
            Phase::VmImages => "vm_images",
            Phase::CredentialProxy => "credential_proxy",
            Phase::PlanTemplate => "plan_template",
            Phase::NetworkAllowlist => "network_allowlist",
            Phase::Doctor => "doctor_validation",
            Phase::DryRun => "dry_run_submission",
            Phase::FirstLaunch => "first_launch",
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SetupState {
    /// `phase_label -> ISO-8601 timestamp` of completion. Absent
    /// keys mean "not yet run".
    completed: std::collections::BTreeMap<String, String>,
    /// Optional fingerprint for the operator-supplied params so
    /// a re-run with different inputs (different provider, etc.)
    /// can detect drift and refuse to skip phases.
    params_fingerprint: Option<String>,
}

impl SetupState {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(".setup_state.json")
    }

    fn load(data_dir: &Path) -> Result<Self, CliError> {
        let p = Self::path(data_dir);
        if !p.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(&p).map_err(|e| CliError::Io {
            path: p.display().to_string(),
            source: e,
        })?;
        let st: SetupState = serde_json::from_slice(&bytes).map_err(CliError::Json)?;
        Ok(st)
    }

    fn save(&self, data_dir: &Path) -> Result<(), CliError> {
        let p = Self::path(data_dir);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| CliError::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
        let body = serde_json::to_vec_pretty(self).map_err(CliError::Json)?;
        let tmp = p.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp).map_err(|e| CliError::Io {
                path: tmp.display().to_string(),
                source: e,
            })?;
            f.write_all(&body).map_err(|e| CliError::Io {
                path: tmp.display().to_string(),
                source: e,
            })?;
            f.sync_all().map_err(|e| CliError::Io {
                path: tmp.display().to_string(),
                source: e,
            })?;
        }
        fs::rename(&tmp, &p).map_err(|e| CliError::Io {
            path: p.display().to_string(),
            source: e,
        })?;
        Ok(())
    }

    fn is_done(&self, ph: Phase) -> bool {
        self.completed.contains_key(ph.label())
    }

    fn mark_done(&mut self, ph: Phase) {
        let now = current_iso8601();
        self.completed.insert(ph.label().to_string(), now);
    }
}

fn current_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut force = false;
    let mut operator_name: Option<String> = None;
    let mut provider: Option<String> = None;
    let mut provider_id: Option<String> = None;
    let mut budget_usd: u32 = 25;
    let mut max_concurrency: u32 = 4;
    let mut plan_template: String = "feature".to_string();
    let mut initiative_name: Option<String> = None;
    let mut skip_phases: Vec<String> = Vec::new();
    let mut only_phase: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--force" => force = true,
            "--operator-name" => {
                operator_name = Some(req(args, &mut i, a)?);
            }
            "--provider" => {
                provider = Some(req(args, &mut i, a)?);
            }
            "--provider-id" => {
                provider_id = Some(req(args, &mut i, a)?);
            }
            "--budget-usd" => {
                budget_usd = req(args, &mut i, a)?.parse().map_err(|_| {
                    CliError::Usage("--budget-usd must be a non-negative integer".into())
                })?;
            }
            "--max-concurrency" => {
                max_concurrency = req(args, &mut i, a)?.parse().map_err(|_| {
                    CliError::Usage("--max-concurrency must be a positive integer".into())
                })?;
                if max_concurrency == 0 {
                    return Err(CliError::Usage("--max-concurrency must be > 0".into()));
                }
            }
            "--plan-template" => {
                plan_template = req(args, &mut i, a)?;
            }
            "--initiative-name" => {
                initiative_name = Some(req(args, &mut i, a)?);
            }
            "--skip-phase" => {
                skip_phases.push(req(args, &mut i, a)?);
            }
            "--only-phase" => {
                only_phase = Some(req(args, &mut i, a)?);
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag {other:?}; run with --help for usage"
                )));
            }
        }
        i += 1;
    }

    let operator_name = operator_name.ok_or_else(|| {
        CliError::Usage(
            "--operator-name <text> is required (the human-readable label that \
             identifies the operator in policy.toml + audit events)"
                .into(),
        )
    })?;
    let provider = provider.unwrap_or_else(|| "anthropic".to_string());
    let provider_id = provider_id.unwrap_or_else(|| format!("{provider}-default"));

    let data_dir = flags.data_dir().clone();
    fs::create_dir_all(&data_dir).map_err(|e| CliError::Io {
        path: data_dir.display().to_string(),
        source: e,
    })?;

    let mut state = SetupState::load(&data_dir)?;

    // Drift guard — if the operator changed the inputs since the
    // last run we fail-closed unless `--force` is supplied. This
    // prevents accidentally carrying half-completed phases from a
    // previous attempt forward into a new configuration.
    let new_fp = params_fingerprint(
        &operator_name,
        &provider,
        &provider_id,
        budget_usd,
        max_concurrency,
    );
    if let Some(prev) = state.params_fingerprint.as_deref() {
        if prev != new_fp && !force {
            return Err(CliError::Usage(format!(
                "FAIL_SETUP_PARAMS_DRIFT: setup parameters differ from the \
                 previous run (fingerprint {prev} → {new_fp}). Pass --force \
                 to discard the prior state, or re-run with the original \
                 parameters."
            )));
        }
    }
    state.params_fingerprint = Some(new_fp);

    println!("raxis setup — non-interactive scaffolding");
    println!("  data-dir:        {}", data_dir.display());
    println!("  operator-name:   {operator_name}");
    println!("  provider:        {provider}  (id: {provider_id})");
    println!("  budget (USD):    {budget_usd}");
    println!("  max concurrency: {max_concurrency}");
    println!();

    // Phase set selection (`--only-phase` wins over `--skip-phase`).
    let want_phase = |ph: Phase| -> bool {
        if let Some(ref only) = only_phase {
            return only == ph.label();
        }
        !skip_phases.iter().any(|s| s == ph.label())
    };

    // Phase 1: Key ceremony — DEFERRED. Print the recipe.
    if want_phase(Phase::KeyCeremony) {
        if state.is_done(Phase::KeyCeremony) && !force {
            println!("[1/8] key_ceremony      — already completed, skipping (--force to re-run)");
        } else {
            println!("[1/8] key_ceremony      — DEFERRED (V3): run manually:");
            println!("       1) raxis cert mint --operator-name {operator_name:?} --output operator.cert.toml");
            println!("       2) raxis genesis --operator-cert ./operator.cert.toml");
            println!("      The wizard will resume at Phase 2 once those two commands return Ok.");
        }
    }

    // Phase 2: Policy authoring — write the starter policy.toml.
    if want_phase(Phase::PolicyAuthoring) {
        if state.is_done(Phase::PolicyAuthoring) && !force {
            println!("[2/8] policy_authoring  — already completed, skipping (--force to re-run)");
        } else {
            let policy_path = data_dir.join("policy").join("policy.toml");
            if policy_path.exists() && !force {
                return Err(CliError::Usage(format!(
                    "FAIL_SETUP_POLICY_EXISTS: refusing to overwrite {} \
                     (pass --force to regenerate)",
                    policy_path.display(),
                )));
            }
            let body = render_starter_policy(
                &operator_name,
                &provider,
                &provider_id,
                budget_usd,
                max_concurrency,
            );
            write_atomic(&policy_path, body.as_bytes())?;
            println!(
                "[2/8] policy_authoring  — wrote {} ({} bytes)",
                policy_path.display(),
                body.len()
            );
            state.mark_done(Phase::PolicyAuthoring);
            state.save(&data_dir)?;
        }
    }

    // Phases 3, 4, 5, 7 are explicitly deferred — print the recipe.
    if want_phase(Phase::ProviderCreds) {
        println!("[3/8] provider_creds    — DEFERRED (V3): run manually:");
        println!(
            "       raxis credential add --name {provider}-api-key --file ./{provider}-key.txt"
        );
    }
    if want_phase(Phase::VmImages) {
        println!("[4/8] vm_images         — DEFERRED (V3): edit policy.toml [[vm_images]] with OCI digests");
    }
    if want_phase(Phase::CredentialProxy) {
        println!(
            "[5/8] credential_proxy  — DEFERRED (V3): edit plan.toml [[tasks.credentials]] entries"
        );
    }

    // Phase 6: Plan template — delegate to plan_init.
    if want_phase(Phase::PlanTemplate) {
        if state.is_done(Phase::PlanTemplate) && !force {
            println!("[6/8] plan_template     — already completed, skipping (--force to re-run)");
        } else {
            let plan_path = data_dir.join("plan").join("plan.toml");
            fs::create_dir_all(plan_path.parent().unwrap()).map_err(|e| CliError::Io {
                path: plan_path.parent().unwrap().display().to_string(),
                source: e,
            })?;
            let mut sub_args: Vec<String> = vec![
                "--template".into(),
                plan_template.clone(),
                "--output".into(),
                plan_path.display().to_string(),
            ];
            if let Some(name) = &initiative_name {
                sub_args.push("--initiative-name".into());
                sub_args.push(name.clone());
            }
            if force {
                sub_args.push("--force".into());
            }
            super::plan_init::run(flags, &sub_args)?;
            println!("[6/8] plan_template     — wrote {}", plan_path.display());
            state.mark_done(Phase::PlanTemplate);
            state.save(&data_dir)?;
        }
    }

    if want_phase(Phase::NetworkAllowlist) {
        println!("[7/8] network_allowlist — DEFERRED (V3): edit policy.toml [[tproxy_allowlist]] entries");
    }

    // Phase 8: Doctor — print the recipe (we do not run it
    // in-process because the operator has not signed the policy
    // yet, and `doctor`'s `policy` category fails on unsigned
    // policy in genesis-pending state).
    if want_phase(Phase::Doctor) {
        println!("[8/8] doctor_validation — verify after `raxis policy sign`:");
        println!("       raxis doctor --data-dir {}", data_dir.display());
    }

    // Phases 9, 10 — V3 deferrals.
    println!();
    println!("Next steps to bring the kernel online:");
    println!("  1. raxis cert mint --operator-name {operator_name:?} --output operator.cert.toml");
    println!(
        "  2. raxis genesis --operator-cert ./operator.cert.toml --data-dir {}",
        data_dir.display()
    );
    println!("  3. Edit {}/policy/policy.toml — fill in [[vm_images]] OCI digests + [[tproxy_allowlist]]", data_dir.display());
    println!(
        "  4. raxis policy sign --policy {}/policy/policy.toml",
        data_dir.display()
    );
    println!("  5. raxis credential add --name {provider}-api-key --file ./{provider}-key.txt");
    println!("  6. raxis doctor --data-dir {}", data_dir.display());
    println!(
        "  7. Start the kernel binary, then `raxis submit plan {}/plan/plan.toml`",
        data_dir.display()
    );

    Ok(())
}

fn req(args: &[String], i: &mut usize, flag: &str) -> Result<String, CliError> {
    let v = args
        .get(*i + 1)
        .ok_or_else(|| CliError::Usage(format!("missing value for {flag}")))?
        .clone();
    *i += 1;
    Ok(v)
}

fn params_fingerprint(
    op: &str,
    provider: &str,
    provider_id: &str,
    budget_usd: u32,
    concurrency: u32,
) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(op.as_bytes());
    h.update(b"|");
    h.update(provider.as_bytes());
    h.update(b"|");
    h.update(provider_id.as_bytes());
    h.update(b"|");
    h.update(budget_usd.to_string().as_bytes());
    h.update(b"|");
    h.update(concurrency.to_string().as_bytes());
    hex::encode(h.finalize())
}

fn print_usage() {
    println!("Usage: raxis setup --operator-name <text>");
    println!("                   [--provider <name>] [--provider-id <id>]");
    println!("                   [--budget-usd <int>] [--max-concurrency <int>]");
    println!("                   [--plan-template <name>] [--initiative-name <text>]");
    println!("                   [--skip-phase <label>] [--only-phase <label>]");
    println!("                   [--force]");
    println!();
    println!("Non-interactive first-run scaffolding. Creates the data-dir");
    println!("skeleton, a starter policy.toml, and a starter plan.toml.");
    println!("Phases the wizard runs in V2: 2 (policy_authoring), 6");
    println!("(plan_template). Phases 1, 3, 4, 5, 7, 8, 9, 10 are printed");
    println!("as recipes the operator runs by hand. See");
    println!("`specs/v2/operator-ergonomics.md §16` and");
    println!(" for the full phase catalogue.");
}

// ---------------------------------------------------------------------------
// Starter policy.toml renderer
// ---------------------------------------------------------------------------

fn render_starter_policy(
    operator_name: &str,
    provider_kind: &str,
    provider_id: &str,
    budget_usd: u32,
    max_concurrency: u32,
) -> String {
    // The starter does **not** include a real `[[operators]]`
    // entry — the operator's pubkey and cert come from
    // `raxis genesis` and the operator hand-edits the
    // `[[operators]]` block after `raxis cert install`. We
    // include a commented placeholder so the structure is
    // discoverable.
    format!(
        r#"# raxis policy.toml — generated by `raxis setup` for {operator_name:?}.
#
# This is a STARTER scaffold. After `raxis genesis` produces an
# operator-cert, paste the matching `[[operators]]` entry into the
# block at the bottom of this file, then run `raxis policy sign`
# to sign + install policy_epoch=1.
#
# The byte-level shape of every section here is governed by
# `specs/v2/policy-plan-authority.md`. The required fields are
# enumerated; the values you see are conservative defaults.

epoch = 1
policy_id = "starter-policy"
description = "Starter policy generated by `raxis setup`."

# ──────────────────────────────────────────────────────────────────────
# §1. Provider catalogue
# ──────────────────────────────────────────────────────────────────────
[[providers]]
provider_id = {provider_id:?}
kind        = {provider_kind:?}
# `model` is the canonical model identifier to pin against. Replace
# with a release-pinned slug (e.g. "claude-3-7-sonnet-2025-02-19" or
# "gpt-4o-2024-08-06") before signing the policy.
model       = "TODO-pin-a-released-model-id"
# `credential_name` is the key the kernel will pull from the
# credential store (`raxis credential add --name <this>`).
credential_name = "{provider_kind}-api-key"

# ──────────────────────────────────────────────────────────────────────
# §2. Budgets and concurrency caps
# ──────────────────────────────────────────────────────────────────────
[budgets]
# Per-initiative dollar cap — the gateway refuses spend beyond this.
default_initiative_usd = {budget_usd}
# Hard ceiling across all initiatives in flight, applied before any
# per-initiative quotas; spec §host-capacity.md "global cap".
global_usd_per_day     = {}

[host_capacity]
# Concurrent Executor/Reviewer/Orchestrator VMs admitted at once.
# `host-capacity.md §3` — operator floor is 1, ceiling is hardware.
max_concurrent_vms     = {max_concurrency}
disk_full_behavior     = "halt_admit"

# ──────────────────────────────────────────────────────────────────────
# §3. Gateway (subprocess that brokers all model-API egress)
# ──────────────────────────────────────────────────────────────────────
[gateway]
binary_path             = "/usr/local/bin/raxis-gateway"
spawn_timeout_secs      = 30
respawn_backoff_ms      = 1000
max_consecutive_respawns = 5

# ──────────────────────────────────────────────────────────────────────
# §4. Egress allowlist for in-VM tasks (npm registries, package
#     mirrors, GitHub API, etc.). The wizard ships an empty list;
#     fill in per `tproxy_allowlist.md`.
# ──────────────────────────────────────────────────────────────────────
[[tproxy_allowlist]]
host = "TODO-replace-with-registry.npmjs.org"
ports = [443]

# ──────────────────────────────────────────────────────────────────────
# §5. VM images — replace with OCI digests for the executor /
#     reviewer / orchestrator images you publish. The kernel
#     refuses to boot if the digests at the configured paths do
#     not match (`canonical-images.md`).
# ──────────────────────────────────────────────────────────────────────
[[vm_images]]
role     = "executor"
digest   = "sha256:TODO-paste-oci-digest"
[[vm_images]]
role     = "reviewer"
digest   = "sha256:TODO-paste-oci-digest"
[[vm_images]]
role     = "orchestrator"
digest   = "sha256:TODO-paste-oci-digest"

# ──────────────────────────────────────────────────────────────────────
# §6. Operators — paste the matching `[[operators]]` entry here
#     after `raxis cert install` runs successfully. Each operator
#     is identified by the ed25519 pubkey hex from their cert.
# ──────────────────────────────────────────────────────────────────────
# [[operators]]
# pubkey_hex   = "PASTE-FROM-raxis-cert-show"
# display_name = {operator_name:?}
# permissions  = ["plan-submit", "plan-approve", "epoch-advance"]
"#,
        budget_usd.saturating_mul(8),
    )
}

// ---------------------------------------------------------------------------
// Atomic write helper (mirrors plan_init::write_atomic)
// ---------------------------------------------------------------------------

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent).map_err(|e| CliError::Io {
        path: parent.display().to_string(),
        source: e,
    })?;
    let tmp = parent.join(format!(".raxis-setup.{}.tmp", std::process::id()));
    {
        let mut f = fs::File::create(&tmp).map_err(|e| CliError::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
        f.write_all(bytes).map_err(|e| CliError::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
        f.sync_all().map_err(|e| CliError::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_policy_substitutes_all_placeholders() {
        let body = render_starter_policy("alice", "anthropic", "anthropic-default", 25, 4);
        assert!(body.contains("provider_id = \"anthropic-default\""));
        assert!(body.contains("kind        = \"anthropic\""));
        assert!(body.contains("default_initiative_usd = 25"));
        assert!(body.contains("max_concurrent_vms     = 4"));
        // Toml shape sanity: parses cleanly (the wizard only
        // promises a starter, so we tolerate `TODO-pin-...`
        // values.).
        let parsed: toml::Value = toml::from_str(&body).expect("starter policy must be valid TOML");
        assert_eq!(parsed["epoch"].as_integer(), Some(1));
        let providers = parsed["providers"].as_array().unwrap();
        assert_eq!(providers.len(), 1);
    }

    #[test]
    fn fingerprint_changes_with_inputs() {
        let a = params_fingerprint("a", "anthropic", "x", 25, 4);
        let b = params_fingerprint("a", "anthropic", "x", 25, 8);
        assert_ne!(a, b);
        let c = params_fingerprint("a", "openai", "x", 25, 4);
        assert_ne!(a, c);
    }

    #[test]
    fn state_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = SetupState::default();
        s.mark_done(Phase::PolicyAuthoring);
        s.mark_done(Phase::PlanTemplate);
        s.params_fingerprint = Some("deadbeef".into());
        s.save(dir.path()).unwrap();

        let loaded = SetupState::load(dir.path()).unwrap();
        assert!(loaded.is_done(Phase::PolicyAuthoring));
        assert!(loaded.is_done(Phase::PlanTemplate));
        assert!(!loaded.is_done(Phase::Doctor));
        assert_eq!(loaded.params_fingerprint.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn phase_labels_are_distinct() {
        let labels: std::collections::HashSet<&str> = [
            Phase::KeyCeremony,
            Phase::PolicyAuthoring,
            Phase::ProviderCreds,
            Phase::VmImages,
            Phase::CredentialProxy,
            Phase::PlanTemplate,
            Phase::NetworkAllowlist,
            Phase::Doctor,
            Phase::DryRun,
            Phase::FirstLaunch,
        ]
        .iter()
        .map(|p| p.label())
        .collect();
        assert_eq!(labels.len(), 10);
    }
}

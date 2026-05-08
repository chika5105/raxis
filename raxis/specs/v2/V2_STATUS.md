# RAXIS V2 — Implementation Status

> **Audience:** operators evaluating V2 readiness, contributors deciding
> what to pick up next, and reviewers auditing spec-vs-code drift.
>
> **Authority:** every line below is grounded in either committed code,
> a passing test, or a normative spec section. Anything not in this
> file is V3 or later.
>
> **Last sync:** the SHA that ships this file is the V2 sign-off SHA.
> When you change V2 status, edit this file in the same commit so the
> ledger never drifts from `git log`.

---

## 1. Shipped — V2 surface area you can rely on today

### 1.1 Kernel core

| Subsystem | Status | Implementation reference |
|---|---|---|
| Plan parser + signed-plan-bytes admission | shipped | `kernel/src/initiatives/lifecycle.rs::approve_plan` |
| Task DAG validation, path-allowlist, budget ceiling | shipped | `kernel/src/initiatives/lifecycle.rs` (shift-left rejections) |
| Audit chain (paired writes for the four privileged kinds) | shipped | `crates/audit/`, `crates/audit-tools/`, `kernel/src/audit/` |
| Kernel-state-block (KSB) renderer | shipped | `crates/kernel-mechanics-prompt/`, exercised via planner harness |
| Operator IPC (TLS, ed25519 fingerprint pin) | shipped | `kernel/src/ipc/operator.rs` |
| Orchestrator auto-spawn at `ApprovePlan` | shipped | `kernel/src/ipc/operator.rs::handle_approve_plan` → `ctx.orchestrator_spawn.spawn_for_initiative(...)` |
| `IntegrationMerge` admission (Checks 1..5c, plan-side path-allowlist union, protected-path approvals) | shipped | `kernel/src/handlers/intent.rs::handle_integration_merge` |
| Recovery + reconcile on kernel restart | shipped | `kernel/src/recovery.rs` |

### 1.2 Planner harness

| Surface | Status | Reference |
|---|---|---|
| `raxis-planner-core` (BootArgs, BootEnv, Role, structured exit codes, token-redacting boot log) | shipped | `crates/planner-core/` |
| `raxis-planner-orchestrator` binary (boots, parks on SIGTERM/SIGINT) | shipped | `planner/orchestrator/src/main.rs` |
| `raxis-planner-executor` binary | shipped | `planner/executor/src/main.rs` |
| `raxis-planner-reviewer` binary | shipped | `planner/reviewer/src/main.rs` |
| Orchestrator NNSP (Non-Negotiable System Prompt) embedded in `raxis-prompts` and version-locked with the kernel | shipped | `crates/prompts/src/orchestrator_nnsp.txt` + 12 unit tests in `crates/prompts/src/lib.rs` |

### 1.3 VM isolation backends

| Backend | Status | Reference |
|---|---|---|
| `SubprocessIsolation` (test/dev backend, no VM) | shipped | `crates/test-support/src/subprocess_isolation.rs` |
| Apple Virtualization Framework (AVF) | shipped (skeleton VM lifecycle wired) | `crates/isolation-apple-vz/` |
| Firecracker | shipped (skeleton VM lifecycle wired) | `crates/isolation-firecracker/` |

### 1.4 Image manifest, signing, distribution

| Artifact | Status | Reference |
|---|---|---|
| `raxis-image-manifest` schema (TOML, schema_version=2) | shipped | `crates/image-manifest/` |
| `raxis-image-builder` (Ed25519 signing, SHA-256 image digest, `SOURCE_DATE_EPOCH`) | shipped | `crates/image-builder/` |
| `raxis-canonical-images` (kernel-pinned image digests via `build.rs`) | shipped | `crates/canonical-images/` (env vars: `RAXIS_KERNEL_SIGNING_KEY_HEX`, `RAXIS_EXPECTED_*_IMAGE_DIGEST_HEX`) |
| `raxis-image-cache` (OCI digest → local rootfs path resolver) | shipped | `crates/image-cache/` |

### 1.5 Egress (two-tier)

| Tier | Status | Reference |
|---|---|---|
| Tier 1 — public unauthenticated egress (SNI-allowlist tproxy) | shipped | `tproxy/`, `crates/tproxy-protocol/`, `crates/egress-admission/` |
| Tier 2 — authenticated egress via credential proxies | shipped | per §1.6 |

### 1.6 Credential proxies (Tier 2)

All eleven proxies bind a real loopback listener per `ProxyDecl` variant
during `start_for_session`, emit `CredentialProxyStarted` on bind and
`CredentialProxyStopped` on shutdown, and resolve credential bytes
through the `CredentialBackend` trait. None of them ever expose
credential bytes to the agent VM.

| `proxy_type` | Status | MVP scope | Reference |
|---|---|---|---|
| `postgres` | shipped (handshake-tier) | startup-message rewrite, parameter-status forwarding, simple-query SELECT pass-through, `allow_only_select` enforcement, `ReadyForQuery` advancement | `crates/credential-proxy-postgres/` + live-e2e slice `postgres-proxy` |
| `http`     | shipped | bearer / basic auth modes, host rewrite, method+path-prefix allowlist, real upstream forwarding | `crates/credential-proxy-http/` + live-e2e slices `http-proxy-bearer`, `http-proxy-restrictions` |
| `k8s`      | shipped (rides HTTP) | bearer auth, RBAC-style verb allowlist via the HTTP proxy | `crates/credential-proxy-http/` (k8s convenience layer) |
| `smtp`     | shipped | RCPT/MAIL/DATA framing, sender allowlist, recipient-domain allowlist, per-message and per-minute rate caps, TLS upstream | `crates/credential-proxy-smtp/` + live-e2e slice `smtp-proxy` |
| `redis`    | shipped | RESP2 framing, AUTH/HELLO interception, command allowlist, downstream forwarding | `crates/credential-proxy-redis/` + live-e2e slice `redis-proxy` |
| `aws`      | shipped (handshake-tier) | IMDS-shaped `/creds` envelope, path allowlist, `AWS_CONTAINER_CREDENTIALS_FULL_URI` mount | `crates/credential-proxy-aws/` + live-e2e slice `aws-proxy` |
| `gcp`      | shipped (handshake-tier) | metadata-server endpoints (`/computeMetadata/v1/...`), `Metadata-Flavor: Google` enforcement, path allowlist | `crates/credential-proxy-gcp/` + live-e2e slice `gcp-proxy` |
| `azure`    | shipped (handshake-tier) | IMDS `/metadata/identity/oauth2/token`, `Metadata: true` enforcement, resource allowlist | `crates/credential-proxy-azure/` + live-e2e slice `azure-proxy` |
| `mysql`    | shipped (handshake-tier) | `HandshakeV10` greeting, `OK_Packet` synth, `COM_QUERY` classifier with `allow_only_select` | `crates/credential-proxy-mysql/` + live-e2e slice `mysql-proxy` |
| `mssql`    | shipped (handshake-tier) | TDS `PRELOGIN` / `LOGIN7` greeting, `LOGINACK+DONE` synth, `SQLBatch` classifier with `allow_only_select` | `crates/credential-proxy-mssql/` + live-e2e slice `mssql-proxy` |
| `mongodb`  | shipped (handshake-tier) | `OP_MSG` framing, `hello`/`isMaster` synth without auth advertisement, BSON command classifier with `allow_read_only` | `crates/credential-proxy-mongodb/` + live-e2e slice `mongodb-proxy` |

"**Handshake-tier**" means the proxy implements the protocol greeting,
authentication interception, and command classification end-to-end —
including audit emission and restriction enforcement — but synthesises
success packets locally rather than forwarding to a real upstream
service. The agent's wire contract is identical to the upstream
contract; swapping in a real upstream is a V3 patch that does not
change the operator-facing interface.

### 1.7 Pre-merge verifier admission (validation, not dispatch)

| Surface | Status | Reference |
|---|---|---|
| `[[integration_merge_verifiers]]` in `policy.toml` (operator-side) — schema, validation, persistence | shipped | `crates/policy/`, `kernel/src/initiatives/lifecycle.rs::validate_plan_integration_merge_verifiers` |
| `[[plan.integration_merge_verifiers]]` in `plan.toml` (plan-side) — schema, parsing, validation | shipped | `kernel/src/initiatives/lifecycle.rs::parse_plan_integration_merge_verifiers` |
| `integration_merge_attempts` table + recovery reconciliation | shipped | migration 12, `kernel/src/recovery.rs::reconcile_integration_merge_attempts` |
| Pre-merge verifier **runtime dispatch** at `IntegrationMerge` Check 5d | **deferred** (see §2.1) | — |

### 1.8 Live end-to-end test harness

The `raxis-live-e2e` binary drives 15 in-process slices end-to-end
against real subsystems (real listeners, real wire bytes, real audit
chain, real credential backend). All 15 pass on
`cargo run -p raxis-live-e2e -- all`:

```
gateway-anthropic, egress-enforcement, session-spawn,
postgres-proxy, postgres-proxy-restrictions,
http-proxy-bearer, http-proxy-restrictions,
smtp-proxy, redis-proxy,
aws-proxy, gcp-proxy, azure-proxy,
mysql-proxy, mssql-proxy, mongodb-proxy
```

`gateway-anthropic` and `egress-enforcement` exercise a real call to
the Anthropic API and require `ANTHROPIC_API_KEY` in the environment;
the other 13 slices run with no external dependencies. Skip the two
opt-in slices with `cargo run -p raxis-live-e2e -- <slice>` for any
specific named slice when an API key is not available.

### 1.9 Spec-graph linter

| Check | Status | Reference |
|---|---|---|
| #1 — Cross-reference resolution | shipped | `xtask/src/spec_graph.rs::check_cross_references` |
| #3 — Audit-kind paired/single classification | shipped | `xtask/src/spec_graph.rs::check_audit_kind_classification` |
| #4 — `FAIL_*` failure-code symmetry | shipped | `xtask/src/spec_graph.rs::check_fail_code_symmetry` |
| #6 — Failure-code uniqueness | shipped | `xtask/src/spec_graph.rs::check_fail_code_uniqueness` |
| #2 — Invariant-ID resolution | **deferred** (see §2.4) | scaffolded as `check_invariant_resolution` (no-op) |
| #5 — Capability-class completeness | **deferred** (see §2.4) | scaffolded as `check_capability_class_completeness` (no-op) |

`cargo xtask spec-graph --strict` succeeds with **0 findings** across
**42 spec files, 117 unique fail codes, 64 unique audit kinds** at the
V2 sign-off SHA.

---

## 2. Deferred to V3 — explicit, with rationale

### 2.1 Pre-merge verifier runtime dispatch (Check 5d)

**Spec home:** `verifier-processes.md §16`, `integration-merge.md §4 Check 5d`.

**What's missing:** the actual VM-spawn pipeline that, on
`IntegrationMerge` admission:

1. computes the **candidate merged tree** as an orphan commit,
2. looks up matching `[[integration_merge_verifiers]]` (operator + plan,
   filtered by `applies_to`),
3. spawns one verifier-VM per matching entry against the candidate
   merged tree,
4. aggregates verdicts,
5. discards the candidate tree (and emits
   `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED`) on `block_merge` failure
   or advances `main` on pass.

**Why deferred:** `verifier-processes.md §19.8` plans this as a
**five-phase, ~13-engineer-day** rollout with three new crates
(`raxis-verifier-protocol`, `raxis-verifier`, `raxis-verifier-runtime`)
plus a new image-build pipeline (`raxis-verifier-images`). Each phase
ships an independently-mergeable kernel; the spec already plots the
sequencing. This is genuinely a follow-up arc, not a V2-completion
task.

**What you can do today:** declare `[[integration_merge_verifiers]]`
in either policy.toml or plan.toml — the kernel parses, validates,
and persists them. They are observable via the
`integration_merge_attempts` table. They do not yet cause merges to
block; that is the runtime piece §16 specifies.

### 2.2 Worktree-provision wiring into `ApprovePlan` / `ActivateSubTask`

**Spec home:** `kernel-lifecycle.md §Step 24 / 24b`.

**What's missing:** the kernel currently spawns the orchestrator with
its working tree provided by the test harness. The intended flow is:

* On `ApprovePlan`, call
  `worktree-provision::provision_orchestrator(initiative.current_sha,
   CloneStrategy::Blobless)`.
* On `ActivateSubTask`, call
  `worktree-provision::provision_reviewer(activation_sha,
   CloneStrategy::Sparse { paths })` and the matching
  `provision_executor`.

**Why deferred:** the call site needs an `initiative.current_sha`
anchor that the kernel does not yet plumb through
`InitiativeState`. Adding the column requires a migration and a
recovery-reconciliation update; doing it correctly is a half-day of
its own.

**What you can do today:** the `worktree-provision` crate is shipped
and its `Full | Blobless | Sparse` strategies are unit-tested. Once
the `current_sha` anchor lands, the wiring is a one-line change in
`handle_approve_plan` / `handle_activate_sub_task`.

### 2.3 Image-build + release pipeline

| Piece | Status | Why deferred |
|---|---|---|
| `mkfs.erofs` canonical-image producer | deferred | needs a Linux runner with privileged-container support; macOS-developer-only environments cannot exercise it |
| `.github/workflows/release.yml`, `build-images.yml` | deferred | needs Apple notarization secrets + signing keys provisioned in the repo's GitHub Actions secret store |
| `aegis-ai/tap` Homebrew tap | deferred | downstream of release.yml — the tap formula fetches release assets that don't exist yet |

The local-build path is fully working: an operator can run
`cargo run -p raxis-image-builder -- build {orchestrator,executor,reviewer}`
to produce signed manifests, then build the kernel with
`RAXIS_KERNEL_SIGNING_KEY_HEX=...` to bind the trust anchor to their
own ed25519 key. The release pipeline simply automates this for the
shipped binaries.

### 2.4 Spec-graph deferred checks #2 and #5

Both are linter-only improvements, both blocked on the same root
cause: the source specs use prose tables with interleaved normative
declarations and illustrative TOML, which is not mechanically
parseable. The spec amendment that introduces a structured companion
file (e.g., `invariants-index.toml`,
`capability-classes.toml`) is the unblocking step. Until then the
checks live as `Vec::new()`-returning stubs in
`xtask/src/spec_graph.rs` so the surface is named for the follow-up
PR.

---

## 3. Test status (V2 sign-off SHA)

* `cargo build --workspace` — clean
* `cargo build --release -p raxis-kernel -p raxis-gateway -p raxis-cli -p raxis-planner-orchestrator -p raxis-planner-executor -p raxis-planner-reviewer -p raxis-tproxy` — clean
* `cargo test --workspace --no-fail-fast` — **all green**, 1700+ tests
* `cargo run -p raxis-live-e2e -- all` — **15/15 slices pass** (incl. real Anthropic API call)
* `cargo xtask spec-graph --strict` — **0 findings**, 42 files / 117 fail codes / 64 audit kinds

`cargo build --workspace --release` deliberately **fails** because
`raxis-test-support` (a dev-dependency-only crate) is consumed by
`raxis-live-e2e`. This is by design (`raxis-test-support` is
gated on `cfg(any(debug_assertions, test))` so it cannot ship in any
release binary). The release-distributed crates (kernel, gateway,
cli, planner binaries, tproxy) build clean in release mode; the
live-e2e binary is intentionally a debug-only test driver.

---

## 4. How to verify this file in 60 seconds

```bash
cd raxis
cargo build --workspace
cargo test --workspace --no-fail-fast
cargo xtask spec-graph --strict
cargo run -p raxis-live-e2e -- all
```

Every line in §1 is observable from the green output; every line in
§2 is documented in the named spec section.

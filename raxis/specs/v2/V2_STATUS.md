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

| `proxy_type` | Status | Scope | Reference |
|---|---|---|---|
| `postgres` | **shipped (real-upstream-tier, V2.1; V2.4 table allowlists)** | full simple-query relay against a live Postgres via `tokio-postgres`, real `RowDescription`/`DataRow`/`CommandComplete` frames, lazy upstream connect on first allowed query, `allow_only_select` short-circuits before upstream, V2.1 audit envelope (`DatabaseQueryCompleted`, `CredentialProxyUpstreamConnected`, `CredentialProxyUpstreamFailed`); V2.4 SQL walker + `allowed_tables` / `forbidden_tables` / `max_result_rows` streaming cap / `enforce = false` audit-only mode per `proxy-table-allowlists.md` | `crates/credential-proxy-postgres/` + integration tests in `tests/proxy_handshake.rs` (6 passing) + live-e2e slices `postgres-proxy`, `postgres-proxy-restrictions`, `postgres-proxy-table-allowlists` |
| `http`     | shipped | bearer / basic auth modes, host rewrite, method+path-prefix allowlist, real upstream forwarding | `crates/credential-proxy-http/` + live-e2e slices `http-proxy-bearer`, `http-proxy-restrictions` |
| `k8s`      | shipped (rides HTTP) | bearer auth, RBAC-style verb allowlist via the HTTP proxy | `crates/credential-proxy-http/` (k8s convenience layer) |
| `smtp`     | shipped (real-upstream-tier) | RCPT/MAIL/DATA framing, sender allowlist, recipient-domain allowlist, per-message and per-minute rate caps, real upstream relay with optional STARTTLS | `crates/credential-proxy-smtp/` + live-e2e slice `smtp-proxy` |
| `redis`    | **shipped (real-upstream-tier, V2.1 audit)** | RESP2 framing, AUTH/HELLO interception, command allowlist, real upstream forwarding (predates V2.1), V2.1 audit envelope (`CredentialProxyUpstreamConnected`, `CredentialProxyUpstreamFailed`) | `crates/credential-proxy-redis/` + live-e2e slice `redis-proxy` |
| `aws`      | shipped (handshake-tier — real cloud creds) | IMDS-shaped `/creds` envelope, path allowlist, `AWS_CONTAINER_CREDENTIALS_FULL_URI` mount; the proxy returns **real IAM credentials** from the configured backend so the agent's AWS SDK can call real AWS APIs end-to-end | `crates/credential-proxy-aws/` + live-e2e slice `aws-proxy` |
| `gcp`      | shipped (handshake-tier — real cloud creds) | metadata-server endpoints (`/computeMetadata/v1/...`), `Metadata-Flavor: Google` enforcement, path allowlist; same real-credentials posture as AWS | `crates/credential-proxy-gcp/` + live-e2e slice `gcp-proxy` |
| `azure`    | shipped (handshake-tier — real cloud creds) | IMDS `/metadata/identity/oauth2/token`, `Metadata: true` enforcement, resource allowlist; same real-credentials posture as AWS | `crates/credential-proxy-azure/` + live-e2e slice `azure-proxy` |
| `mysql`    | **shipped (real-upstream-tier, V2.1; V2.4 table allowlists)** | full `COM_QUERY` relay against a live MySQL upstream via a hand-rolled `mysql_native_password` connector, byte-relayed text-resultset frames (`ResultSetHeader`/`ColumnDef`/`EOF`/`RowData`/`EOF`), lazy upstream connect on first allowed query, `allow_only_select` short-circuits before upstream, V2.1 audit envelope; V2.4 SQL walker + `allowed_tables` / `forbidden_tables` / `max_result_rows` (truncating `ERR_Packet` 1226/54000 on overflow) / `enforce = false` audit-only mode; `caching_sha2_password` deferred to V3 | `crates/credential-proxy-mysql/` + integration tests in `tests/proxy_upstream.rs` (4 passing) + live-e2e slice `mysql-proxy` |
| `mssql`    | **shipped (real-upstream-tier, V2.1; V2.4 table allowlists)** | full `SQLBatch` relay against a live SQL Server upstream over plaintext TDS — `PRELOGIN` (ENC_NOT_SUP), `LOGIN7` with SQL Authentication (nibble-swap+XOR(0xA5) password obfuscation per `[MS-TDS] 2.2.6.4`), TABULAR_RESULT relay-until-EOM, `allow_only_select` short-circuits before upstream, V2.1 audit envelope; V2.4 T-SQL walker + `allowed_tables` / `forbidden_tables` / `enforce = false` audit-only mode. `max_result_rows` is plumbed + audited but its streaming cap is a V2 followup (TDS token-stream parsing — see `proxy-table-allowlists.md §11.1`). Windows Auth / Entra ID / `?encrypt=true` deferred to V3 | `crates/credential-proxy-mssql/` + integration tests in `tests/proxy_upstream.rs` (4 passing) + live-e2e slice `mssql-proxy` |
| `mongodb`  | **shipped (real-upstream-tier, V2.1; V2.4 collection allowlists + cursor cap)** | full `OP_MSG` relay against a `--noauth` upstream, hello/isMaster/ping/buildInfo answered locally, `allow_read_only` short-circuits before upstream, V2.1 audit envelope; V2.4 BSON command walker resolves primary collection + `$db`; `allowed_collections` / `forbidden_collections` admit/deny; `max_documents` cursor-rewrite cap (truncate `firstBatch` / `nextBatch` + zero cursor id per `§7.4`); fail-closed secondary-collection rejection for `$lookup` / `$unionWith` / `$merge` / `$out`; `enforce = false` audit-only mode. SCRAM-SHA-256 upstream auth + TLS upstream deferred to V2.2 (URLs with userinfo or `tls=true` fail fast with `CredentialProxyUpstreamFailed { reason: "ProtocolHandshakeFailed" }`) | `crates/credential-proxy-mongodb/` + integration tests in `tests/proxy_upstream.rs` (4 passing) + live-e2e slices `mongodb-proxy`, `mongodb-proxy-collection-allowlists` |

**V2.1 real-upstream-forwarding contract** (per `credential-proxy.md
§14`): each TCP-protocol proxy opens a real upstream connection on
the first allowed agent query, relays classified-and-approved
packets, and streams results back to the agent. Spec-amendment
`§14.5` defines three new audit kinds the proxies emit
(`DatabaseQueryCompleted`, `CredentialProxyUpstreamConnected`,
`CredentialProxyUpstreamFailed`).

* **Postgres**: shipped at V2.1 in commit
  `e44f69a credential-proxy-postgres: real upstream forwarding`.
* **Redis** + **SMTP**: were already real-upstream in V2.0; Redis
  upgraded to the V2.1 audit envelope in commit
  `0cf013e credential-proxy-redis: emit V2.1 upstream-forwarding
  audit events`. SMTP retains its protocol-specific
  `SmtpProxyConnected` / `SmtpProxyDisconnected` audit kinds
  (which serve the same purpose) and is **not** migrated to the
  generic envelope.
* **MySQL** — shipped at V2.1 in commit
  `880bc5e credential-proxy-mysql: real upstream forwarding` with
  hand-rolled `mysql_native_password`; `caching_sha2_password`
  (MySQL 8.0 default) deferred to V3.
* **MongoDB** — shipped at V2.1 in commit
  `e6c9445 credential-proxy-mongodb: real upstream forwarding`
  for `--noauth` upstreams; SCRAM-SHA-256 + TLS deferred to V2.2.
  URLs with userinfo or `tls=true` fail fast with a clear
  `CredentialProxyUpstreamFailed { reason: "ProtocolHandshakeFailed" }`
  audit signal so operators get a precise migration message.
* **MSSQL** — shipped at V2.1 in commit
  `9e8ca39 credential-proxy-mssql: real upstream forwarding` with
  plaintext-TDS SQL-Authentication (`[MS-TDS] 2.2.6.4` password
  obfuscation); Windows Auth, Entra ID, and `?encrypt=true`
  deferred to V3.

"**Handshake-tier — real cloud creds**" means the proxy returns the
operator's actual cloud credentials in the metadata-service envelope
shape; the agent's cloud SDK uses them to talk to real AWS / GCP /
Azure APIs. The "handshake" terminology here refers to the
metadata-protocol hand-off, NOT to whether the proxy reaches a real
upstream — for cloud proxies the agent IS the only client, and the
upstream is the cloud API itself, which the agent reaches directly
through the cloud SDK using the served credentials.

### 1.7 Pre-merge verifier admission (validation, not dispatch)

| Surface | Status | Reference |
|---|---|---|
| `[[integration_merge_verifiers]]` in `policy.toml` (operator-side) — schema, validation, persistence | shipped | `crates/policy/`, `kernel/src/initiatives/lifecycle.rs::validate_plan_integration_merge_verifiers` |
| `[[plan.integration_merge_verifiers]]` in `plan.toml` (plan-side) — schema, parsing, validation | shipped | `kernel/src/initiatives/lifecycle.rs::parse_plan_integration_merge_verifiers` |
| `integration_merge_attempts` table + recovery reconciliation | shipped | migration 12, `kernel/src/recovery.rs::reconcile_integration_merge_attempts` |
| Pre-merge verifier **runtime dispatch** at `IntegrationMerge` Check 5d | **deferred** (see §2.1) | — |

### 1.8 Live end-to-end test harness

The `raxis-live-e2e` binary drives 17 in-process slices end-to-end
against real subsystems (real listeners, real wire bytes, real audit
chain, real credential backend). All 17 pass on
`cargo run -p raxis-live-e2e -- all`:

```text
gateway-anthropic, egress-enforcement, session-spawn,
postgres-proxy, postgres-proxy-restrictions,
postgres-proxy-table-allowlists,
http-proxy-bearer, http-proxy-restrictions,
smtp-proxy, redis-proxy,
aws-proxy, gcp-proxy, azure-proxy,
mysql-proxy, mssql-proxy,
mongodb-proxy, mongodb-proxy-collection-allowlists
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
**50 spec files, 120 unique fail codes, 64 unique audit kinds** at
the current HEAD (the file count rose from 44→50 with the V2.4
`proxy-table-allowlists.md` spec and the five `raxis-concepts/`
explainer-tier documents that index it; the fail-code count remains
at 120 because table-allowlist denials reuse the existing
proxy-error envelope per `proxy-table-allowlists.md §7`).

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
| `chika5105/tap` Homebrew tap | deferred | downstream of release.yml — the tap formula fetches release assets that don't exist yet |

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

### 2.5 Real-upstream-forwarding refinements (V2.2 / V3)

**Spec home:** `credential-proxy.md §14` + per-proxy notes in §14.8.

**What's shipped (V2.1):** all six TCP-protocol proxies (Postgres,
MySQL, MSSQL, MongoDB, Redis, SMTP) open a real upstream
connection on the first allowed agent query and relay
classified-and-approved packets through. See §1.6 for the per-
proxy status row and the "V2.1 real-upstream-forwarding contract"
note that follows it.

**What's deferred to V2.2:**

* **MongoDB SCRAM-SHA-256 + TLS upstream** — the V2.1 MongoDB
  proxy supports `--noauth` upstreams only. URLs with userinfo
  or `tls=true` fail fast at `connect()` with a
  `CredentialProxyUpstreamFailed { reason: "ProtocolHandshakeFailed" }`
  and a detail string mentioning `--noauth`. The SCRAM-SHA-256
  saslStart/saslContinue handshake plus a `tokio-rustls` upstream
  layer is ~150 LOC + ~40 LOC, scheduled as a focused V2.2 follow-up.

**What's deferred to V3:**

* **MySQL `caching_sha2_password`** — V2.1 ships
  `mysql_native_password` only. MySQL 8.0 defaults to
  `caching_sha2_password`, which adds a public-key exchange + a
  fast-auth-cache code path. URLs naming a user whose plugin is
  `caching_sha2_password` fail fast with the same
  `CredentialProxyUpstreamFailed` envelope and a detail string
  pointing operators at V3.
* **MSSQL Windows Auth + Entra ID + `?encrypt=true`** — V2.1 ships
  plaintext-TDS SQL Authentication only. Windows Auth requires
  GSS-API/SSPI; Entra ID requires the OAuth2 token-exchange flow;
  TLS-to-MSSQL requires negotiating the TDS PRELOGIN ENC_REQ
  branch and bringing up `tokio-rustls`. URLs with
  `?encrypt=true` or non-SQL auth modes fail fast with
  `CredentialProxyUpstreamFailed`.
* **Redis ACL-form `AUTH user password`** — V2.1 supports the
  legacy `AUTH password` form. Redis 6.0 added named users;
  ACL-form auth is ~30 LOC + a `CredentialBackend` change to
  return `(username, password)` tuples (see V2_GAPS §3
  upstream-auth status table).
* **Redis TLS-to-upstream** — required by Elasticache,
  Memorystore, Azure Cache; ~40 LOC with `tokio-rustls`
  (already a workspace dep).

**What you can do today:** all six TCP proxies relay real query
results from real upstream services. The deferred items above
are protocol extensions; the core relay path is V2-shipped.

### 2.6 Planner agent loop (T1-1 from the V2.1 audit)

**Spec home:** `planner-harness.md` (the §15 VSock control-plane
section is forthcoming; for now the harness's §14 boot contract is
authoritative for the scaffold that ships today).

**What's missing:** the three planner binaries
(`raxis-planner-orchestrator/executor/reviewer`) currently boot,
parse argv + env, log the boot context, and then park on
`tokio::signal::ctrl_c().await`. The kernel can spawn a session
and the VM stays alive long enough for the lifecycle FSM to
observe `Running`, but the agent process inside the VM does not
yet:

1. open a VSock control plane back to the kernel,
2. ingest the KSB,
3. call the model API through the gateway,
4. dispatch tool calls (`file_write`, `shell_exec`, `git_commit`),
5. submit Intents (executor) / Witnesses (reviewer) back over
   VSock.

**Why deferred:** this is a ~1,500-line cross-cutting milestone
spanning four crates (`planner-core` extension, `planner-tools`,
the model-API client, and the VSock IPC client). Landing it as
one atomic PR makes review hard; landing it after the database-
proxy real-upstream work means the model loop will have a real
end-to-end DB call to issue when it comes online.

**What you can do today:** the kernel + gateway + credential
proxies are wired and observable. A future planner binary linked
against the `raxis-planner-core` scaffold + a model client can
slot in without touching kernel code.

---

## 3. Test status (current HEAD)

* `cargo build --workspace` — clean
* `cargo build --release -p raxis-kernel -p raxis-gateway -p raxis-cli -p raxis-planner-orchestrator -p raxis-planner-executor -p raxis-planner-reviewer -p raxis-tproxy` — clean
* `cargo test --workspace --no-fail-fast` — **all green** (1700+ tests; the V2.1 real-upstream-forwarding sequence added integration tests across four crates: Postgres `tests/proxy_handshake.rs` (6 tests), MySQL `tests/proxy_upstream.rs` (4 tests), MSSQL `tests/proxy_upstream.rs` (4 tests + 25 unit tests in `upstream.rs`), MongoDB `tests/proxy_upstream.rs` (4 tests + 11 unit tests))
* `cargo run -p raxis-live-e2e -- all` — **15/15 slices pass** (incl. real Anthropic API call)
* `cargo xtask spec-graph --strict` — **0 findings**, 44 files / 120 fail codes / 64 audit kinds

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

---

## 5. Audit corrections — what the V2.1 audit got right, and where it conflated layers

The "RAXIS V2 — Remaining Work Roadmap" audit dated 2026-05-08 was
sharp on the database-proxy capability gap and correctly promoted
real upstream forwarding from V3 to V2. The implementation in
e44f69a (Postgres) and 0cf013e (Redis audit upgrade) closes the
first half of T1-2 from that roadmap. For completeness, here is
what the audit conflated with code that was already shipped:

* **T0-1 "Session Spawn Handler"** — claimed a missing
  `kernel/src/handlers/session.rs`. The file does not exist as
  named, but the **session-spawn callsites are wired**:
  - `kernel/src/ipc/operator.rs::handle_approve_plan` (lines
    1227–1264) calls
    `ctx.orchestrator_spawn.spawn_for_initiative(...)` →
    `LiveOrchestratorSpawn::spawn_for_initiative` →
    `session_spawn_orchestrator::spawn_session_for_initiative`
    → `SessionSpawnService::spawn_session` →
    `CredentialProxyManager::start_for_session` →
    `IsolationBackend::spawn`.
  - `kernel/src/handlers/intent.rs::handle_activate_sub_task`
    calls the analogous executor / reviewer path through
    `spawn_executor_for_task`.
  The "kernel handler that transitions an admitted intent into a
  running VM" is therefore split across `ipc/operator.rs` and
  `handlers/intent.rs` rather than living in a dedicated
  `session.rs` file. The audit's bulleted call chain (start_for_session,
  IsolationBackend::spawn, env-var injection, task-state transition,
  SessionStarted audit) is **all present at the named call sites**.

* **T1-3 "Gateway ↔ Kernel IPC"** — claimed missing. The kernel's
  `gateway/{supervisor.rs (715 LOC), client.rs (806 LOC),
  accept.rs (617 LOC)}` ship the supervisor (crash-and-respawn
  with backoff), kernel-side client, and accept loop. `main.rs`
  spawns the supervisor at boot and tears it down on shutdown.

* **T1-4 "Heartbeat Writer"** — claimed missing. `main.rs:526–540`
  spawns `runtime::heartbeat_loop` in a `tokio::spawn` at boot
  with shutdown channel; the loop writes
  `runtime/heartbeat.json` atomically every 5s with one initial
  write at boot per the cli-readonly.md §5.2.1 contract.

* **T2-1 "mkfs.erofs integration"** — claimed not wired. The
  shell-out IS implemented in
  `crates/image-builder/src/lib.rs::erofs_assemble` with
  `-z zstd -T <SOURCE_DATE_EPOCH>` flags and a graceful skip
  when `mkfs.erofs` is not on the host. What's still missing
  is the CI determinism gate (build twice, byte-equal) — a
  separate piece called out in §2.3 above.

* **T2-3 "raxis doctor CLI"** — claimed missing. Shipped at
  `cli/src/commands/doctor.rs` (1,681 lines) with all eight
  documented checks plus `signing-key-fp` and
  `canonical-images` subcommands. The Homebrew formula's
  `post_install` block already references the latter.

The audit's genuine open items, in order of remaining work:

1. **T1-1 — Planner agent loop** (~1,500 LOC across four crates).
   Confirmed gap; see §2.6 above. Largest remaining V2.1 piece.
2. **T1-2 — MySQL / MSSQL / MongoDB real upstream forwarding**
   — **shipped at V2.1** in commits `880bc5e` (MySQL),
   `9e8ca39` (MSSQL), `e6c9445` (MongoDB). The remaining
   per-protocol refinements (MongoDB SCRAM-SHA-256, MSSQL
   Windows Auth / Entra ID, MySQL `caching_sha2_password`)
   are documented in §2.5 with explicit `CredentialProxyUpstreamFailed`
   audit signals at `connect()` time so operators get a
   precise migration message.
3. **T2-1 — CI determinism gate for `mkfs.erofs`** (~40 LOC of
   YAML in `.github/workflows/build-images.yml`). Small.
4. **T2-2 — Homebrew tap auto-update from `release.yml`**
   (~40 LOC of shell). Small.
5. **T3 polish items** (CLA enforcement, coverage CI, egress
   firewall injection, operator notification transport, etc.)
   — all post-GA, none block V2.1 sign-off.

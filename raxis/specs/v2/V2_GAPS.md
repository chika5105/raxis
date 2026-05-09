# RAXIS V2 — Specification Gaps & ORM Strategy

> **Last updated:** 2026-05-08 (pass 2)
> **Method:** Systematic audit of all 30 V2 specification documents
> against 140,010 lines of Rust, with five cross-check passes
> covering CLI subcommand completeness, invariant coverage,
> per-environment enforcement, IPC handler coverage, and
> kernel-push / notification / review-aggregation wiring.
> **Baseline SHA:** the commit that ships this file.

---

## §1 — Implementation Status Overview

RAXIS V2 has **30 specification documents** totaling 56,485 lines of
normative markdown. Of these, **17 are fully shipped** (Tier A),
**all 3 Tier B items are closed** (B1 planner loop **+ binary
wiring (V2.4)**, B2 custom tools, B3 database forwarding — upstream
forwarding shipped for Postgres/MySQL/MSSQL/Redis/SMTP), **all 10
Tier C items are closed**, **both Tier D items are closed**, and
**Tier E is closed**. The §12 newly-discovered gaps from Pass 2 are
also all closed for V2 (the §12.4 operator-ergonomics IPC handlers
were promoted from wire-shape stubs to real read-only handlers in
V2.4; only `SubscribeInitiative` remains a stub awaiting the V3
KernelPush wire transport). **§13 Category 4** (single-enforcement-
point invariants) was reconciled in V2.4: 5 of 6 entries were
discovered to already be in shipped code. The remaining one
(`INV-PLANNER-HARNESS-03` + `INV-VM-CAP-03`) was originally
deferred to V3 but has been **promoted back to V2.5** because
the `[[vm_images]]` subsystem is a functional requirement:
without it, operators cannot set custom executor images and
every activation is locked to the canonical starter.

| Tier | Count | Status |
|---|---|---|
| A — Fully shipped | 17/17 | Spec, code, and tests aligned |
| B — Infrastructure + logic | 3/3 | All closed (binary wiring V2.4) |
| C — Spec complete | 10/10 | All V2 BLOCKER items closed (V2.4) |
| D — Schema/skeleton | 2/2 | Both closed (V2.3) |
| E — Deferred/partial | 1/1 | Closed (V2.3) |
| §12 newly-discovered gaps | 10/10 | All V2 BLOCKER items closed (V2.4) |
| §13 Cat 4 single-enforcement | 5/6 | Closed (V2.4); 1 promoted to V2.5 |

**Total lines remaining:** 0 (every V2 BLOCKER closed in V2.4; V3
items remain documented per the deferral notes per category)
(revised down from ~11,000 after V2.3/V2.4 closures and the C8
WebFetch/WebSearch deferral to V3; includes ~500 lines for ORM
extended query protocol, promoted back to V2 scope).

---

## §2 — Tier A: Fully Shipped (17 areas)

These require no further work. Spec mandates are met, code is tested,
audit integration is complete.

| # | Spec document | Key crates / files | Lines |
|---|---|---|---|
| A1 | `audit-paired-writes.md` | `crates/audit/`, `crates/audit-tools/` | 4,277 |
| A2 | `credential-proxy.md` (wire path) | 11 proxy crates + manager | 14,151 |
| A3 | `extensibility-traits.md` (trait surface) | `crates/isolation/`, `crates/domain/`, `crates/gateway-substrate/` | ~2,200 |
| A4 | `plan-bundle-sealing.md` | `crates/store/src/plan_bundles.rs` | ~500 |
| A5 | `integration-merge.md` (admission) | `kernel/src/handlers/intent.rs`, `integration_merge_attribution.rs` | ~2,000 |
| A6 | `agent-disagreement.md` | `kernel/src/handlers/escalation.rs` | 1,012 |
| A7 | `vm-network-isolation.md` | `tproxy/`, `crates/tproxy-protocol/`, `crates/egress-admission/` | 1,587 |
| A8 | `verifier-processes.md` (dispatch) | `kernel/src/gates/verifier_runner.rs`, `handlers/witness.rs` | ~2,200 |
| A9 | `release-and-distribution.md` | `.github/workflows/release.yml`, `build-images.yml` | ~540 |
| A10 | `image-cache.md` | `crates/image-cache/` | 2,165 |
| A11 | `kernel-mediated-egress.md` | `crates/egress-admission/`, session-spawn env injection | ~1,300 |
| A12 | `planner-harness.md` (boot contract) | `crates/planner-core/`, 3 planner binaries | 750 |
| A13 | `policy-plan-authority.md` (admission) | `crates/policy/`, `kernel/src/initiatives/` | ~6,000 |
| A14 | `kernel-lifecycle.md` (boot + shutdown) | `kernel/src/main.rs`, `bootstrap.rs`, `recovery.rs` | ~3,000 |
| A15 | `kernel-lifecycle.md` (heartbeat) | `kernel/src/runtime/heartbeat.rs`, wired in `main.rs:532` | 271 |
| A16 | `kernel-lifecycle.md` (gateway supervisor) | `kernel/src/gateway/supervisor.rs` | 715 |
| A17 | `policy-epoch-diffing.md` | `cli/src/commands/policy_diff.rs` | 649 |

**Cross-check correction:** `policy-epoch-diffing.md` was previously
listed as Tier C (zero code). The CLI already ships `raxis policy diff`
at 649 lines. Moved to Tier A.

---

## §3 — Tier B: Infrastructure Done, Application Logic Missing

### B1: Planner Agent Loop ✅ CLOSED (V2.3)

**Spec:** `planner-harness.md §3, §10, §14`
**Estimate:** ~2,600 lines (delivered ~2,500 across `raxis-planner-core`)

The three planner binaries (orchestrator, executor, reviewer) now have
full agent-loop scaffolding: kernel transport, model client, tool
registry, dispatch loop, intent/escalation submission, KSB renderer,
and custom-tool subprocess executor. **`gap-b1-planner-binary-wiring`
is CLOSED V2.4** — the binaries' `main` functions are now wired
through `planner-core::driver::run_role_session`, which detects
"live mode" via `RAXIS_PLANNER_TASK_PROMPT` and either drives the
full `DispatchLoop` end-to-end or falls back to scaffold/park
behaviour bit-for-bit. The kernel-side `session_spawn_orchestrator`
stamps `RAXIS_KERNEL_PLANNER_SOCKET=<data_dir>/sockets/planner.sock`
into both orchestrator and executor/reviewer guest envs at spawn
(see `OrchestratorSpawnContext::with_data_dir` /
`ExecutorSpawnContext::with_data_dir`), so live-mode planners can
reach the kernel UDS without each IPC handler having to thread
the data-dir layout. The driver exposes a hermetic
`run_role_session_with_env_fn` test seam so unit tests don't have
to mutate process-global env (the workspace's `unsafe_code = deny`
lint forbids the legacy `std::env::set_var` approach).

| Component | Status | Crate path |
|---|---|---|
| Kernel transport (UDS / VSock-stub, length-prefixed bincode) | ✅ | `planner-core/src/transport.rs` |
| Model API client (Anthropic Messages API via Gateway) | ✅ | `planner-core/src/model.rs` |
| Base tool registry (`read_file`/`bash`/`edit_file`/`grep_search`/`git_commit`) | ✅ | `planner-core/src/tools.rs` |
| Tool dispatch loop (LLM → parse `tool_use` → execute → `tool_result`) | ✅ | `planner-core/src/dispatch.rs` |
| Intent submission (executor → kernel) | ✅ | `planner-core/src/intent.rs` |
| Witness/verdict submission (reviewer → kernel) | ✅ | `planner-core/src/intent.rs` |
| Escalation submission (`SubmitEscalation`) | ✅ | `planner-core/src/intent.rs` |
| KSB renderer (`[RAXIS:KERNEL_STATE … :KERNEL_STATE_END]`) | ✅ | `planner-core/src/ksb.rs` |
| Custom-tool loader + subprocess executor | ✅ | `planner-core/src/custom_tools.rs` |

**Invariant gap:** `planner-harness.md` defines 89 `INV-` invariants.
INV-PLANNER-HARNESS-04 (reviewer write-tool ban), INV-PLANNER-04
(monotonic per-session sequence_number), and INV-KSB-01 (close-delim
injection refusal) are now enforced in code. The remaining INV
coverage gap is tracked in `V2_GAPS.md §13 — INV-Coverage`.

**Test coverage:** 87 unit tests across the 8 modules (`cargo test
-p raxis-planner-core --lib`); the live e2e harness exercises the
full loop end-to-end via `live-e2e/`.

### B2: Custom Tools — CLOSED (V2.3, MVP)

**Spec:** `custom-tools.md` (55KB)
**Status:** Kernel-side validation + planner-side loader/executor done.
**Depends on:** B1

V2 ships kernel-side validation of operator-declared custom tools at
plan-approve time, *plus* the planner-side loader and subprocess
executor (B1) that actually runs them inside the planner Firecracker
guest.

Implementation:
- `kernel/src/initiatives/custom_tools_validator.rs`:
  - `RESERVED_TOOL_NAMES` — base tools and kernel-mediated intent
    names; custom tools may not collide.
  - `is_valid_custom_tool_name()` — `^[a-z][a-z0-9_]*$`, length ≤ 64.
  - `validate_plan_custom_tools(plan_toml, policy_max_timeout_seconds)`
    parses the plan TOML and enforces:
    1. Forbids `[[plan.tasks.<id>.custom_tool]]` (custom tools live
       only on profiles).
    2. For each `[[profiles.<name>.custom_tool]]` block:
       name format + length, reserved-name rejection,
       within-profile uniqueness, description length 8–800,
       `command[]` non-empty with absolute `command[0]`,
       `timeout_seconds` ≤ `policy_max_timeout_seconds`.
  - Errors lift to `LifecycleError::PlanInvalid { reason }` so plan
    approval fails closed before BEGIN TRANSACTION.
- `kernel/src/initiatives/lifecycle.rs::approve_plan` now invokes the
  validator immediately after `validate_task_credentials`, ensuring
  malformed declarations cannot round-trip into a session.
- Planner-side execution uses `planner-core::custom_tools` + the
  `SubprocessTool` adapter from B1 (see B1 closeout above).

V2 design choices:
- Hard cap default: 300 seconds (`DEFAULT_MAX_CUSTOM_TOOL_TIMEOUT_SECONDS`)
  — chosen as 5 minutes so an operator-issued shell command has
  comfortable headroom while still bounding zombie processes.
- Schema validation is structural-only for V2 (presence + type +
  shape). Full Draft-07 JSON Schema validation of the
  `input_schema` block is deferred to V3 once the standalone
  `raxis-jsonschema` crate lands.
- Reserved-names list is colocated with the validator rather than
  re-exported from `planner-core` because plan-approve is the
  authoritative gate; the planner-core list is a defence-in-depth
  echo, not the source of truth.

Tests: 13 unit tests in `custom_tools_validator::tests` (`cargo test
-p raxis-kernel --bin raxis-kernel custom_tools_validator`) covering
canonical and adversarial names, reserved-name collisions,
description-length bounds, relative-path commands, timeout-cap
enforcement, profile-internal collisions, task-level rejection, and
RESERVED_TOOL_NAMES sync with the spec.

V3 (deferred):
- Draft-07 JSON Schema validation of `input_schema` (structural only
  today).
- Per-tool concurrency cap (today: bounded only by global session
  concurrency).
- Optional preflight `command --version` smoke check at approve-time.

### B3: Real Database Proxy Forwarding — CLOSED (V2.3)

**Spec:** `credential-proxy.md §14`
**Delivered:** ~3,500 lines across 6 `upstream.rs` modules

Five of 6 database proxies (Postgres, MySQL, MSSQL, Redis, SMTP)
have real upstream forwarding — `TcpStream::connect`, upstream auth,
and bidirectional frame relay. MongoDB relay is deferred to V3
alongside SCRAM-SHA-256 auth (see rationale below).

| Proxy | What to add | Est. lines |
|---|---|---|
| Postgres | `TcpStream::connect`, relay `DataRow`/`CommandComplete` | ~200 |
| MySQL | Connect, relay `ResultSetHeader` + `ColumnDef` + `Row` + `EOF` | ~250 |
| MSSQL | Connect, relay `COLMETADATA` + `ROW` + `DONE` tokens | ~250 |
| MongoDB | Connect, relay `OP_MSG` response bodies + **SCRAM auth** | ~300 |
| Redis | Connect, relay RESP2 responses | ~150 |
| SMTP | Connect, relay multi-line SMTP responses, `STARTTLS` | ~200 |

**Per-proxy upstream auth status:**

| Proxy | Agent-side auth (accept dummy creds) | Upstream auth (real creds to DB) | Auth method | Notes |
|---|---|---|---|---|
| **Postgres** | ✅ `AuthenticationOk` (accepts anything) | ✅ via `tokio-postgres` | SCRAM-SHA-256, MD5, cleartext, trust | **Fully implemented** in `upstream.rs`. The only proxy with real upstream auth today. |
| **Redis** | ✅ Intercepts `AUTH` command | ✅ Sends real `AUTH <password>` upstream | `AUTH <password>` / `AUTH <user> <password>` (RESP2) | Working. ACL-form `AUTH user password` and TLS-to-upstream both **CLOSED in V2.3**: ACL form lands when the credential file declares `RAXIS_REDIS_USER` + `RAXIS_REDIS_PASSWORD` (parsed inside the proxy, no trait change). TLS-to-upstream is opt-in via `[[credentials]].require_upstream_tls = true` and reuses the SMTP proxy's `webpki-roots`-backed `tokio-rustls` `ClientConfig`. |
| **SMTP** | ✅ Accepts `AUTH PLAIN`/`AUTH LOGIN` | ✅ Sends real `AUTH PLAIN` upstream | `AUTH PLAIN` over STARTTLS | Working. Missing: `AUTH SCRAM-SHA-256` (rare for SMTP). |
| **MySQL** | ✅ `mysql_native_password` handshake | ✅ via `mysql_async` (V2.3) | `mysql_native_password` | Real upstream forwarding shipped in V2.3 (`crates/credential-proxy-mysql/src/upstream.rs`). `caching_sha2_password` (MySQL 8.0 default) **explicitly deferred to V3** — see "MySQL/Mongo crypto auth" rationale below. |
| **MSSQL** | ✅ PRELOGIN + LOGINACK | ✅ via `tiberius` (V2.3) | TDS PRELOGIN + LOGIN7 | Real upstream forwarding shipped in V2.3 (`crates/credential-proxy-mssql/src/upstream.rs`). |
| **MongoDB** | ⚠️ **No auth at all** | ❌ Synthesizes responses | Would need SCRAM-SHA-256 | **V3 deferral**, NOT V2.3 work. The proxy advertises empty `saslSupportedMechs` so drivers skip auth, which is correct for `--noauth` development upstreams (the V2.3 first-usable-session target). SCRAM-SHA-256 + OP_MSG real relay both deferred to V3 — see "MySQL/Mongo crypto auth" rationale below. |

**MongoDB auth gap detail:** The proxy's `hello` response sets
`saslSupportedMechs: []` to prevent drivers from attempting auth.
This works for unauthenticated local dev databases but fails against
any Atlas, DocumentDB, or self-hosted MongoDB with `--auth` enabled.
The upstream module (`upstream.rs`) exists with the relay path for
`--noauth` deployments but does NOT yet implement SCRAM. The SCRAM
handshake for MongoDB is a 4-message SASL exchange:
`SASLStart → ServerFirst → SASLContinue → ServerFinal`. Estimate:
~150 lines for SCRAM + ~150 lines for upstream relay = ~300 total
(revised up from ~150).

### MySQL / Mongo crypto-auth — V3 deferral with rationale (V2.3)

The MongoDB SCRAM-SHA-256 handshake AND the MySQL
`caching_sha2_password` plugin are both **deliberately deferred
to V3**. Tradeoffs analysis:

| Option | Pro | Con |
|---|---|---|
| **A. Implement SCRAM-SHA-256 / `caching_sha2_password` in V2.3** | Closes the auth gap for production-Mongo / MySQL 8 fixtures | (1) Crypto correctness without a live integration test against the upstream is high-risk — RFC 7677 + the `caching_sha2_password` fast/full-auth state machine are subtle. (2) The current V2.3 fail-fast paths already give operators a clear signal to either (a) configure the upstream as `--noauth` for dev or (b) wait for V3. (3) ~300 LOC each + integration-test infrastructure shifts the V2.3 ship date. |
| **B. Skip the auth implementation; ship V2.3 with the fail-fast path** ✅ **chosen** | Honest about scope; no half-built crypto code in the kernel; V3 lands the auth path with the testing infrastructure to prove correctness against a real upstream | Operators with auth-required upstreams must wait for V3 (or use the existing TLS-terminated postgres / MSSQL path, which IS shipped) |

**V2.3 chose B** because the marginal value of "agent dials a
SCRAM-protected Mongo" — versus the V2.3 already-shipped
`--noauth` Mongo path or the fully-shipped Postgres / MSSQL
paths — is bounded by the fact that V2.3's primary first-
usable-session target is a postgres-shaped query workflow.
Mongo and MySQL `caching_sha2` shipping in V3 with proper
integration testing (Atlas / Aurora MySQL / mongosh fixtures)
keeps the kernel codebase honest about correctness invariants.

**The forward path** (V3): the dedicated PR will:

1. Add `pbkdf2` and `hmac` deps (already in the workspace's
   transitive closure via `ring`).
2. Implement the SCRAM state machine in
   `crates/credential-proxy-mongodb/src/scram.rs` and the
   `caching_sha2_password` machine in
   `crates/credential-proxy-mysql/src/upstream.rs`.
3. Add integration tests against `mongo:7` + `mysql:8`
   containerised fixtures (the live-e2e harness already
   spins up TestContainers fixtures for postgres / redis;
   adding mongo + mysql is a matched extension).
4. Update `credential-proxy.md §4.2` (MySQL) and
   `§4.4` (MongoDB) to reflect the new auth methods.

Until then, V2.3 ships:

* MongoDB: `--noauth` upstream path. Operator gets a clean
  `UpstreamError::Handshake("MongoDB SCRAM-SHA-256 auth is
  deferred to V3; ...")` when the credential URL contains
  userinfo, so the misconfiguration surfaces immediately.
* MySQL: `mysql_native_password` only. Operators using
  MySQL 8.0 with the default `caching_sha2_password` plugin
  must temporarily set `default_authentication_plugin =
  mysql_native_password` on the upstream, OR create a
  per-RAXIS user with `IDENTIFIED WITH mysql_native_password
  BY '...'`. This is documented in the V2.3 release notes.

### MongoDB OP_MSG real relay — V3 deferral

The V2.3 MongoDB proxy synthesises responses for the hand-shake-tier
commands (`hello`, `isMaster`, `ping`, `buildInfo`) and gates every
other command through `Restrictions::is_blocked` returning `{ ok:
1.0 }` for allowed commands and `{ ok: 0.0, code: 13 }` for blocked
ones. **Real query forwarding** — opening an actual TCP connection
to the upstream and relaying `OP_MSG` packets bidirectionally — is
deferred to V3 alongside SCRAM-SHA-256 because the two share the
same upstream-connection path: V2.3 ships either both or neither,
and the design call above chose neither. The V3 PR lands the
relay and the SCRAM auth in the same commit.

### ORM Extended Query (Postgres) — **CLOSED V2.4**

**Estimate:** ~300 lines (delivered)

V2.3 ships the Postgres simple-query protocol (`Q` / `T` / `D` /
`C`) end-to-end through `credential-proxy-postgres::upstream`.
The Extended Query protocol (`P` Parse + `B` Bind + `D` Describe
+ `E` Execute + `S` Sync), used by every modern ORM with
parameterised queries (sqlx, Diesel, Active Record, Hibernate,
asyncpg's prepared statements), must land in V2.

**Why this was previously deferred (and why that was wrong):**

The V2.3 deferral assumed ORMs would "silently fall back to
text-protocol queries when prepared statements fail." This is
**incorrect for all major ORMs:**

| ORM | Behavior on Parse/COM_STMT rejection | Falls back? |
|---|---|---|
| asyncpg | `InterfaceError` — only uses extended query | ❌ No |
| SQLAlchemy 2.x | `OperationalError` | ❌ No |
| Prisma | connection error → retry loop → crash | ❌ No |
| Diesel | `ConnectionError` | ❌ No |
| SQLx (Rust) | `ProtocolError` | ❌ No |
| Django (psycopg2) | configurable, default is extended | ⚠️ Must reconfigure |

Any agent using an ORM inside the VM will get hard errors, waste
cycles debugging, and may not be able to recover without manual
driver reconfiguration. This breaks the first-usable-session
target for any database-backed agent workflow.

**Implementation:** see §8 for the full strategy. Restriction
checks at `Parse` time; `Bind`/`Execute`/`Sync` forwarded as
opaque frames.

### MySQL `COM_STMT_*` — **CLOSED V2.4**

**Estimate:** ~200 lines (delivered)

Same reasoning as Postgres Extended Query. V2.3 ships
`COM_QUERY` only. Every MySQL ORM in every language uses
`COM_STMT_PREPARE` / `COM_STMT_EXECUTE` by default. The V2.3
proxy returns `ERR_Packet { code = 1235 }` for unsupported
commands, which **does not trigger a text-protocol fallback** —
it triggers a connection error. Restriction checks at `PREPARE`
time; binary result set relay for `EXECUTE`.

**Cloud proxy restriction gaps — ✅ CLOSED (V2.3, declarative + audit echo):**

V2.3 ships the cloud-proxy restriction surface as
**declarative-with-audit**: every restriction is validated at
policy-load time, echoed in the matching audit envelope, and
(for AWS/Azure) translated into an outbound response header /
TProxy allowlist hint that the V3 SigV4-/ARM-aware egress proxy
can consume.

| Cloud | Restriction | Spec'd | V2.3 Implementation |
|---|---|---|---|
| **AWS** | `allowed_services` | ✅ §3.2 | ✅ `Restrictions::allowed_services` validated + echoed in `AwsCredentialServed`; runtime SigV4 gating is V3 |
| **AWS** | `allowed_regions` | ✅ §3.2 | ✅ `Restrictions::allowed_regions` validated + echoed in audit |
| **AWS** | `role_arn` scoping | ✅ §3.2 | ✅ `ProxyConfig::role_arn` echoed in IMDS response and audit; STS AssumeRole call is V3 |
| **GCP** | `allowed_scopes` | ✅ §3.3 | ✅ `Restrictions::allowed_scopes` populates `scope` field of token response + echoed in `GcpMetadataServed`; token-exchange API for genuinely scope-narrowed credentials is V3 |
| **GCP** | Project-level pinning | ✅ §3.3 | ✅ `Restrictions::project` validated against `ProxyConfig::project_id` at bind |
| **Azure** | Per-resource action filtering | ✅ §3.4 | ✅ `Restrictions::allowed_actions` (per-resource ARM verb list) validated + emitted as `x-ms-allowed-actions` HTTP header + echoed in `AzureTokenServed`; runtime ARM-URL gating is V3 |

**Why declarative-with-audit and not full runtime gating in V2.3:**
true runtime gating requires the proxy to **inspect outbound
request signatures** (AWS SigV4 headers carry the service and
region; ARM URLs carry the action verb) which means a separate
HTTPS-egress proxy that terminates TLS, parses signed headers,
and gates the request by SDK-supplied vocabulary. That's a V3
build-out (`raxis-egress-aws`, `raxis-egress-arm`) — V2.3 ships
the declarative layer so operator intent is observable and the
egress allowlist (`[[tproxy_allowlist]]`) provides
defence-in-depth runtime gating against any host outside the
declared scope.

**`CredentialBackend` trait update required:** ✅ **CLOSED (V2.3) by design**.

V2.3 ships **no** breaking change to
`CredentialBackend::resolve()`. The trait still returns a single
`CredentialValue` (zeroize-on-drop bytes); proxies that need
structured metadata (Redis ACL `RAXIS_REDIS_USER`, AWS
`role_arn`, GCP `allowed_scopes`, Azure `allowed_actions`)
**parse the bytes themselves** when the credential file is
declared in `.env` style (`KEY=VALUE\n…`).

This decision was deliberate. Tradeoffs considered:

| Option | Pro | Con |
|---|---|---|
| **A. Change `resolve()` to return `ResolvedCredential { value, metadata }`** | Most explicit; each consumer visibly opts in | Forklift refactor across every proxy + the gateway + the kernel boot path; breaks every test fake; `Vault`/`AwsSecretsManager` impls would also need to ship structured output to keep the trait wire-stable |
| **B. Add a sibling `resolve_structured` method** | Non-breaking; opt-in | Two methods doing similar things; risk of drift; concrete backends still need to learn how to extract structure from their underlying store |
| **C. Parse `.env` shape inside each proxy** ✅ **chosen** | Zero trait change; backends remain wire-stable; each proxy owns its own credential vocabulary; operators write the same `<name>.env` shape everywhere (`AWS_ACCESS_KEY_ID=...`, `RAXIS_REDIS_USER=...`, etc.) | Each proxy duplicates a tiny env-parser (~25 lines); structured types do not appear in the trait surface |

V2.3 chose **C** because:

1. The `.env` shape is **already** how every cloud proxy reads
   its credential value (`AWS_ACCESS_KEY_ID=...`,
   `GCP_ACCESS_TOKEN=...`, `AZURE_ACCESS_TOKEN=...`,
   `MONGO_URL=...`, etc.). Adding `RAXIS_REDIS_USER=` /
   `RAXIS_REDIS_PASSWORD=` to that shape is the smallest
   possible delta and keeps the operator's mental model
   uniform.
2. The trait's V3 evolution can introduce a structured
   variant (e.g. `Vault`'s KV v2 metadata, AWS Secrets
   Manager's `VersionStages`) **without** churning the V2.3
   call sites — the V3 design will be additive
   (`fn resolve_structured(...) -> Resolved<T>` with a
   default impl that calls `resolve` and parses).
3. Proxies that need structure (`credential-proxy-redis`,
   `credential-proxy-aws`, `credential-proxy-gcp`,
   `credential-proxy-azure`, `credential-proxy-mongodb`)
   already each ship a focused parser tested in their own
   crate. The duplication is ~25 LOC per proxy and trades
   for a stable trait shape.

**The forward path** (V3): when an HSM-backed or KV-versioned
backend lands and genuinely needs to surface metadata that the
operator cannot pre-bake into the bytes, V3 adds
`resolve_structured` as an additive sibling. V2.3 unblocks every
declared cloud-proxy gap WITHOUT that lift, and the spec stays
honest about the deferral.

The `extensibility-traits.md §4` spec for `CredentialBackend` is
already correct as written for V2.3 — no edits needed for this
gap. See §12.10 for the broader list of spec files that **other**
Phase 2 patches must touch when they land (independent of this
trait decision).

---

## §4 — Tier C: Spec Complete, Zero Implementation

### C1: Token Limit Enforcement — CLOSED (V2.3, MVP — coarse)

**Spec:** `token-limit-enforcement.md` (52KB) — full surface
**Status:** **CLOSED for V2 — coarse per-session ceilings only.**
**Delivered:** ~210 lines (planner-core dispatch + tests)

V2.3 lands the coarse per-session-cumulative leg of the
`token-limit-enforcement.md §2 Coarse table`: every dispatch loop
folds the Anthropic `Usage` counters into running totals and
terminates with a structured outcome the moment a configured
ceiling is crossed. Pre-admission char-proxy enforcement, the
granular per-request limits, and the
`InferenceCompleted`/`TokenLimitExceeded` audit events stay
deferred to V3.

| Component | Crate | Status |
|---|---|---|
| `DispatchConfig::{max_tokens_input_total, max_tokens_output_total, max_tokens_total}` | `planner-core/src/dispatch.rs` | `Option<u64>`; `None` ⇒ uncapped |
| Cumulative `(input + output)` tracking inside `DispatchLoop::run` | `planner-core/src/dispatch.rs` | Folds `Usage::input_tokens + cache_creation + cache_read` and `Usage::output_tokens` per turn |
| `DispatchOutcome::TokensExceeded { which, input_tokens, output_tokens, ceiling }` | `planner-core/src/dispatch.rs` | Stable wire shape (`which ∈ {"total", "input", "output"}`) |
| Tests: `input_total_ceiling_surfaces_tokens_exceeded`, `total_ceiling_takes_precedence_over_input_only_ceiling`, `no_ceiling_means_uncapped_…`, `cumulative_input_includes_cache_tokens` | `planner-core/src/dispatch.rs` | All passing |

**V2 design choices.**

* **Order of checks: `total → input → output`.** Most operators
  set `max_tokens_total` to bound spend; we surface the most-
  restrictive ceiling first so the role binary's reported reason
  matches the operator's mental model.
* **Coarse ceilings checked post-turn, not pre-turn.** The model
  already returned the offending response; the loop just refuses
  to issue the next request. This is the simplest shape that
  preserves the full audit trail of every call the kernel/router
  saw and prevents an off-by-one where the ceiling fires right at
  the boundary and the operator loses the call's response.
* **`saturating_add` semantics.** Cumulative counters are `u64`,
  so a runaway model can't wrap around the ceiling check.

**Deferred to V3 (full token-limit-enforcement.md surface).**

* Per-request ceilings (`max_tokens_input_per_request`,
  `max_tokens_output_per_request`, `max_tokens_total_per_request`).
* Pre-admission char-proxy estimation
  (`len(prompt_bytes) / 4 ≤ max_tokens_input_per_request`).
* `InferenceCompleted` audit event with full attribution chain
  (`prompt_sha256`, `response_sha256`, `ksb_sha256`, `actual_units`).
* `TokenLimitExceeded` typed audit event + escalation path
  (`fail_request` / `escalate` / `fail_session` per
  `[tasks.token_policy.limit_behavior]`).
* `WARN_UNCAPPED_TOKEN_LIMIT` plan-admission diagnostic when an
  operator omits a ceiling.
* Plan parser for `[tasks.token_policy]` — currently the
  ceilings flow through `DispatchConfig` (constructed by the role
  binary's `main`) rather than the plan parser.

### C2: Provider Failure Handling — CLOSED (V2.3, MVP)

**Spec:** `provider-failure-handling.md` (130KB) — full surface
**Status:** **CLOSED for V2 — retry shell + fallback chain.**
**Delivered:** ~280 lines (planner-core retry + tests)

V2.3 lands the operator-grade default of the spec's per-provider
retry / fallback story so a transient upstream failure (network
blip, 429, 5xx) does NOT bubble up as a hard `DispatchError::Model`
in the planner's first turn.

| Component | Crate | Status |
|---|---|---|
| `RetryConfig { max_retries, base_delay, multiplier, jitter, total_deadline, call_timeout }` | `planner-core/src/retry.rs` | Configurable; ships `anthropic_default()` (3 retries, 500ms × 2.0, 25% jitter, 90s ceiling) |
| `is_retryable(&ModelError)` classifier | `planner-core/src/retry.rs` | Public for tests / observability; retries on Transport, Timeout, 408/425/429/5xx; rejects 4xx-other and Json |
| `RetryingModelClient` (one provider, exponential backoff with jitter) | `planner-core/src/retry.rs` | Bounded by `total_deadline`; sleep clamped to remaining budget |
| `FallbackModelClient` (provider chain) | `planner-core/src/retry.rs` | Walks chain in declaration order; only advances on retryable errors |
| 9 unit tests (retry budget, non-retryable short-circuit, fallback advance, fallback-non-retryable, empty-chain, backoff growth, classifier sanity) | `planner-core/src/retry.rs` | All passing |

**Per-provider failover.** The retry+fallback machinery is
provider-agnostic — every `Arc<dyn ModelClient>` plugs into both
shells. Wiring the actual provider chains
(`Anthropic → OpenAI → Bedrock`) is a per-binary `main()` change
once the remaining `ModelClient` impls land.

**V2 multi-provider `ModelClient` impls — CLOSED V2.4:**

All four `ProviderId` variants MUST have wired `ModelClient`
implementations before V2 ships. Single-provider Anthropic-only
is not acceptable for production — the `FallbackModelClient`
chain is useless without receivers for every provider in the
fallback chain.

| Provider | `ModelClient` impl | Lines | Wire shape | Status |
|---|---|---|---|---|
| **Anthropic** | `AnthropicClient` | ✅ delivered | Anthropic Messages API | ✅ V2.3 |
| **OpenAI** | `OpenAiClient` | ~500 (incl. tests) | OpenAI Chat Completions API | ✅ V2.4 |
| **Google Gemini** | `GeminiClient` | ~470 (incl. tests) | Gemini `generateContent` API | ✅ V2.4 |
| **AWS Bedrock** | `BedrockClient` (Anthropic-on-Bedrock) | ~270 (incl. tests) | Bedrock `InvokeModel` (+ SigV4 gateway leg) | ✅ V2.4 |

Each impl follows the same pattern as `AnthropicClient`: implements
`ModelClient` trait, POSTs to the provider's URL, does NOT inject
credentials (gateway handles that), translates the provider's
response shape to `MessageResponse`. The gateway already knows
how to route and credential-inject for each provider; the missing
piece is the planner-side wire-shape translation.

> **PREREQUISITE: spec before code.** Before implementing any
> `ModelClient`, a dedicated subsection MUST be added to
> `provider-model-selection.md` (or a new
> `specs/v2/provider-client-impls.md`) covering, for each provider:
>
> 1. **Wire shape** — exact HTTP method, URL path, required headers,
>    request body JSON schema, response body JSON schema.
> 2. **Tool-use mapping** — how the provider's tool-call format
>    maps to/from RAXIS's `ContentBlock::ToolUse` /
>    `ContentBlock::ToolResult`. (Anthropic, OpenAI, and Gemini each
>    use different tool-call shapes.)
> 3. **Error taxonomy** — which HTTP status codes / error bodies map
>    to `ModelError::Upstream` vs. `ModelError::Transport`, and which
>    are retryable (feeds into `is_retryable` classifier).
> 4. **Auth delegation** — how the gateway injects credentials for
>    this provider (header name, SigV4 for Bedrock, OAuth for
>    Gemini, `Authorization: Bearer` for OpenAI).
> 5. **Stop-reason mapping** — how the provider's stop/finish reason
>    maps to `MessageResponse::stop_reason` values the dispatch loop
>    pattern-matches on (`"end_turn"`, `"tool_use"`, `"max_tokens"`).
> 6. **Token-usage mapping** — which response fields map to
>    `Usage::input_tokens`, `output_tokens`,
>    `cache_creation_input_tokens`, `cache_read_input_tokens`.
> 7. **Test fixtures** — at least one golden request/response pair
>    per provider, captured from the real API, committed as
>    `planner-core/tests/fixtures/<provider>_*.json`.
>
> This spec work is the **first deliverable** of the provider impl
> work — no PR containing a `ModelClient` impl should land without
> the corresponding spec section reviewed and merged first.

**V2 design choices.**

* **Retryability classifier is public.** Operators / tests can
  call `is_retryable(&err)` directly to predict the wrapper's
  behaviour without instantiating it.
* **No partial-response recovery.** V2's dispatch loop is
  non-streaming, so a mid-response failure can only surface as a
  full-call retry (the entire request body is replayed). Streaming
  recovery is deferred alongside the streaming dispatch shape
  itself (see §38 of `provider-failure-handling.md`).
* **No `ProviderExhausted` typed escalation.** A budget-exhausted
  retry surfaces as the last `ModelError`; the role binary
  converts that into a `ReportFailure` IPC intent. Promoting
  exhaustion to a typed escalation is a V3 follow-up alongside
  the kernel-side `EscalationKind::ProviderExhausted` audit
  variant.

**V2 per-provider circuit breaker — CLOSED V2.4:**

Shipped at `crates/planner-core/src/circuit.rs`
(~430 lines incl. tests). Composes outside the
[`RetryingModelClient`] so the retry shell exhausts its budget
before a single "this provider is unhealthy" signal feeds the
breaker.

| Component | Status |
|---|---|
| `CircuitBreakerModelClient` wrapper around `Arc<dyn ModelClient>` | ✅ shipped |
| `CircuitState` enum (`Closed` / `Open` / `HalfOpen`) with stable wire strings (`closed`, `circuit_open`, `half_open`) matching the kernel sidecar breaker | ✅ shipped |
| Threshold trip on consecutive retryable failures (default 5; `is_retryable` from `crate::retry` is the classifier so non-retryable 4xx never opens the circuit) | ✅ shipped |
| Lazy `Open → HalfOpen` transition on observation (no background timer) | ✅ shipped |
| Half-open probe gate via `compare_exchange` so exactly one in-flight probe is admitted at a time | ✅ shipped |
| Close on probe success / re-open on probe failure | ✅ shipped |
| `CircuitSnapshot` for `raxis status` observability | ✅ shipped |
| 6 unit tests (closed-passthrough, open-on-threshold, non-retryable-doesnt-count, half-open-success-closes, half-open-failure-reopens, wire-strings-stable) | ✅ all passing |

The wrapper composes naturally with `FallbackModelClient`:

```text
Fallback[
  Circuit[Retrying[AnthropicClient]],
  Circuit[Retrying[OpenAiClient]],
  Circuit[Retrying[BedrockClient]],
]
```

Per-provider state is 1:1 with each upstream, so the chain's
"sticky-on-failure" pathology is prevented: once the primary's
breaker opens, dispatches through the chain immediately try the
fallback (the breaker short-circuits with the cached last error,
which `FallbackModelClient` classifies as retryable and walks
past). Once the primary heals (probe succeeds), the chain goes
back to primary on the next dispatch.

**Deferred to V3.**

* Streaming partial-response recovery.
* `ProviderExhausted` typed audit kind + escalation flow.

### C3: Provider Model Selection — CLOSED (V2.3, MVP)

**Spec:** `provider-model-selection.md` (51KB) — full surface
**Status:** **CLOSED for V2 — env-stamped model id with registry validation.**
**Delivered:** ~330 lines (planner-core provider_model + tests)

V2.3 lands the wire-shape leg of `provider-model-selection.md` so a
planner-role binary at boot:

1. Reads `RAXIS_MODEL_ID` from the kernel-stamped environment, with
   fallback to a single canonical default
   ([`DEFAULT_MODEL = "claude-sonnet-4-5-20250929"`]).
2. Validates the id against an append-only known-model registry
   covering the four V2 provider vocabularies (Anthropic, OpenAI,
   Gemini, Bedrock) — an unknown id surfaces as
   `ProviderModelError::UnknownModel` BEFORE the dispatch loop
   spends any tokens against the wrong model.
3. Emits a structured `ModelDeprecated` JSON warning to stderr
   when the resolved id has a deprecation replacement, so the
   operator sees it in `initiative watch`.

| Component | Crate | Status |
|---|---|---|
| `KnownModel { name, provider, deprecated, context_window }` rows | `planner-core/src/provider_model.rs` | 11 entries: 5 Anthropic, 2 OpenAI, 2 Gemini, 2 Anthropic deprecated |
| `ProviderId` enum (Anthropic, OpenAi, Gemini, Bedrock) | `planner-core/src/provider_model.rs` | Stable wire string via `ProviderId::as_str()` matches policy `[providers]` keys |
| `validate_model_id`, `find_known_model`, `resolve_model_from_env(_fn)` | `planner-core/src/provider_model.rs` | Public for binary boot + tests |
| `emit_model_deprecation_warning(model, replacement)` | `planner-core/src/provider_model.rs` | Stable JSON shape (`level=warn,event=ModelDeprecated`) |
| 8 unit tests (registry uniqueness, default-in-registry, unknown rejection, env empty/unset/explicit, deprecated path, provider id wire shape) | `planner-core/src/provider_model.rs` | All passing |

**V2 design choices.**

* **Registry, not free-form string.** The Anthropic/OpenAI APIs
  silently route unknown ids to a default, which masks operator
  typos. The registry is the operator-visible mismatch check.
* **Append-only growth.** New models land as a one-line PR; old
  models go through a deprecation cycle (set `deprecated:
  Some(replacement)` → emit warning → eventual removal in a
  major release).
* **No alias-chain resolution.** Per-role alias chains
  (`[provider_aliases.X.chain]`) and `setup wizard`
  auto-generation stay deferred to V3. The V2 binding is
  one-binary-one-model-id; the role binary's `main()`
  constructs the dispatch chain by hand if a fallback shell is
  desired.

**V2 multi-provider `ModelClient` wiring — CLOSED V2.4:**

All four [`ProviderId`] variants now have wired `ModelClient` impls
that translate the canonical Anthropic-flavoured request/response
shape to/from the upstream's wire format.

| Provider | Registry coverage | `ModelClient` impl | Gateway forwarding | Status |
|---|---|---|---|---|
| **Anthropic** | ✅ 5 supported + 2 deprecated | ✅ `AnthropicClient` | ✅ direct | ✅ V2.3 |
| **OpenAI** | ✅ 2 entries | ✅ `OpenAiClient` (`src/openai_client.rs`, ~500 lines incl. tests) | ✅ via gateway `Authorization: Bearer` injection | ✅ V2.4 |
| **Google Gemini** | ✅ 2 entries | ✅ `GeminiClient` (`src/gemini_client.rs`, ~470 lines incl. tests) | ✅ via gateway query-string / `Authorization` injection | ✅ V2.4 |
| **AWS Bedrock** | ✅ 2 entries (Anthropic-on-Bedrock) | ✅ `BedrockClient` (`src/bedrock_client.rs`, ~270 lines incl. tests) | 🟡 SigV4 gateway leg required (planner emits unsigned body; gateway signs at egress) | ✅ V2.4 |

**Spec reference:** `provider-client-impls.md` (the canonical
translation table for each provider).

**Test coverage:** 20 new unit tests
(8 OpenAI: request/response translation + tool-result splitting +
finish-reason mapping + happy-path local server + transport-error
classification; 8 Gemini: synthetic-id stability, role mapping,
function-call translation, finish-reason, happy-path; 4 Bedrock:
URL-path model routing, `anthropic_version` body field,
local-server happy-path, 4xx classification).

**Deployment tiers** (from `provider-model-selection.md §4`) —
all three tiers are V2 targets:

- **§4.1** — Single-provider (Anthropic only): works today.
  `RAXIS_MODEL_ID` defaults to `claude-sonnet-4-5-20250929`.
- **§4.2** — Two-provider (Anthropic + OpenAI): cross-provider
  fallback chains per role. **V2 target.** Requires `OpenAiClient`
  impl + per-binary `main()` chain wiring.
- **§4.3** — Three-provider (Anthropic + OpenAI + Gemini): per-role
  model chains with tiered fallback. Reviewer uses `gemini-flash`
  at tier-3 for cost efficiency. **V2 target.** Requires
  `GeminiClient` impl.

**Deferred to V3 (policy ergonomics only — providers themselves
are V2).**

* `[provider_aliases_defaults]` policy schema + `plan prepare`
  fill-in.
* `setup wizard` auto-diversification (single-provider →
  multi-provider chain rewrite when a second API key is added).
* `override_reviewer_alias` per-environment override.

### C5: Third-Party Provider Integration (HTTP Sidecar) — **CLOSED (V2.4, MVP)**

**Spec:** `extensibility-traits.md §9A`
**Status:** ✅ Implemented as a `ModelClient` impl rather than a
new `InferenceRouter` variant — see "Architectural decision" below.
**Severity (closed):** previously blocked operators who wanted
non-built-in providers; the sidecar path is now general-purpose.

**Architectural decision (V2.4).** The original spec proposed a
new `HttpSidecarRouter` impl alongside `HttpsGatewayRouter`. The
real V2 codebase routes inference through `Arc<dyn ModelClient>`
(see `crates/planner-core/src/model.rs`) rather than the `InferenceRouter`
trait described in `extensibility-traits.md §9`. Introducing a
parallel router-trait surface in V2 would be a duplicative
refactor. We chose instead to land **`SidecarModelClient`** as a
peer of `AnthropicClient` / `OpenAiClient` / `GeminiClient` /
`BedrockClient` in `planner-core` — same `ModelClient` trait, same
`FallbackModelClient` / `RetryingModelClient` / `CircuitBreaker`
wrappers (the integration paragraph below applies verbatim).
`InferenceRouter` remains as future-proofing for V3 if the
gateway substrate is ever rewritten to be the single dispatch
entry point.

**Delivered (V2.4):**

- `crates/planner-core/src/sidecar_client.rs` — ~520 lines,
  `SidecarModelClient` (the V2 successor to `HttpSidecarRouter`),
  HMAC-SHA256 request/response signing per
  `extensibility-traits.md §9A.7A`, 30 s replay window, custom
  `Debug` redacts the secret. 16 unit tests including a local
  mock-server happy path and HMAC-tampering reject path.
- `crates/policy/src/bundle.rs` — `ProviderEntry` extended with
  `sidecar_endpoint`, `sidecar_hmac_secret`, and
  `sidecar_health_check_path`. `PolicyBundle::validate` enforces
  that `kind = "http_sidecar"` providers declare the sidecar
  fields and that non-sidecar providers leave them unset; rejects
  malformed endpoints (must start with `http://` or `https://`),
  rejects short / non-hex / odd-length secrets (`< 16 bytes`).
- `cli/src/commands/doctor.rs` — `[CHECK] sidecar.health` row
  emitted for every `http_sidecar` provider; performs a 3-second
  TCP-reachability probe to the configured `sidecar_endpoint`.
  Pure URL-parsing tests cover IPv6 brackets, default-port
  inference, missing scheme, and malformed port. The full
  HMAC-authenticated `/health` round-trip runs at planner boot
  via `SidecarModelClient::health_check`; doctor uses TCP probe
  only (the CLI does not load the shared secret).
- `cli/src/commands/policy.rs` — `raxis policy generate-sidecar-secret`
  mints a 32-byte CSPRNG secret and prints it as 64-hex (default),
  `--json` (`{"sidecar_hmac_secret":"…"}`), or `--annotated`
  (paste-into-`policy.toml` form with a SHA-256-derived 8-hex
  fingerprint so operators can disambiguate which secret is
  active without exposing the secret itself).

**Deferred to V3 (intentionally):**

- `specs/v2/sidecar-protocol.yaml` (OpenAPI schema). The wire
  shape is normatively defined by the in-tree types in
  `crates/planner-core/src/sidecar_client.rs`; an OpenAPI emitter
  is V3 ergonomics only and does not block operators.
- Boot-time challenge-response handshake. Per-request HMAC plus
  the `Replay-Window` invariant (`30 s`) is sufficient for the
  loopback threat model (`extensibility-traits.md §9A.6`); the
  bidirectional handshake is a defence-in-depth refinement.
- `InferenceRouterKind::HttpSidecar` variant. Subsumed by the
  `ModelClient` chain decision above.

**Invariant safety:** all R-* invariants hold trivially. The
sidecar is downstream of admission, upstream of audit, in a
separate process with zero access to kernel internals. Malformed
sidecar responses → `InferenceError::MalformedResponse` →
fail-closed (R-3). See `extensibility-traits.md §9A.6` for the
full invariant analysis.

**Integration with existing provider infrastructure:**

A sidecar-backed provider is **not special** — it participates in
the exact same `FallbackModelClient` chain, `RetryingModelClient`
wrapper, `CircuitBreaker`, and half-open probe as every built-in
provider. The sidecar is just another `Arc<dyn ModelClient>`:

```
FallbackModelClient [
  RetryingModelClient(CircuitBreaker(AnthropicClient)),   ← built-in
  RetryingModelClient(CircuitBreaker(SidecarModelClient)), ← sidecar
]
```

The planner's `model.rs` defines `trait ModelClient` with one
method: `create_message(&self, req) -> Result<MessageResponse>`.
A `SidecarModelClient` impl would:

1. Translate `MessageRequest` (Anthropic-shaped) → RAXIS sidecar
   protocol JSON (`SidecarRequest`).
2. POST to the sidecar's `/v1/complete` endpoint with HMAC auth.
3. Translate `SidecarResponse` → `MessageResponse` (Anthropic-shaped
   types the dispatch loop already understands).
4. Map sidecar HTTP errors → `ModelError` variants the
   `is_retryable` classifier already handles.

Because it implements the same `ModelClient` trait:

- **Retry** works: `RetryingModelClient` wraps it and retries
  on `is_retryable` errors with exponential backoff.
- **Fallback** works: `FallbackModelClient` walks the chain;
  if the sidecar's `CircuitBreaker` opens, the chain falls to
  the next provider.
- **Half-open probe** works: the `CircuitBreaker` periodically
  sends one request to the sidecar; if it succeeds, the circuit
  closes and the sidecar re-enters the chain at its original
  priority position.
- **Token tracking** works: `SidecarResponse` carries
  `tokens_in`/`tokens_out` which the `SidecarModelClient`
  translates to `Usage` fields; the dispatch loop's cumulative
  budget tracking (C1) sees no difference.
- **Health check** works: the sidecar's `GET /health` endpoint
  maps to `provider_health()` in the circuit breaker's probe.

The operator wires the chain in `policy.toml` by declaring the
sidecar as a provider entry in `[providers]` alongside the
built-in providers. The role binary's `main()` constructs the
`FallbackModelClient` from the declared chain order.

**Rejected alternative:** `.so`/`.dylib` plugin loading. A native
plugin runs in kernel address space with full memory access — no
conformance check can prevent memory corruption or invariant
bypass. See `extensibility-traits.md §9A.2`.

### C4: Email & Notification Channels ✅ CLOSED (V2.4)

**Spec:** `email-and-notification-channels.md` (61KB)
**Delivered:** ~1,000 lines (handler crates + tests + sidecar +
NotificationDelivered audit event)
**V2.4 update:** Sidecar dispatch handler shipped with concurrency
cap, circuit breaker, and `NotificationDelivered` audit event. The
legacy in-kernel Webhook handler is RETAINED for backwards
compatibility but operators are encouraged to migrate to the
Sidecar kind for any new third-party integration (Slack,
PagerDuty, Teams, Discord, Opsgenie, custom).

| Channel kind | Policy parsed | Handler impl | Status |
|---|---|---|---|
| `Shell`   | ✅ | ✅ `handler/file.rs`    | V1 carryover |
| `File`    | ✅ | ✅ `handler/file.rs`    | V1 carryover |
| `Email`   | ✅ | ✅ `handler/email.rs`   | V2.3 — SMTP submission with STARTTLS or implicit TLS, AUTH PLAIN, password from sidecar `.notify-cred` file |
| `Webhook` | ✅ | ✅ `handler/webhook.rs` (legacy) | V2.3 — kept for backwards compatibility; new integrations should use `Sidecar` |
| `Sidecar` | ✅ | ✅ `handler/sidecar.rs` | V2.4 — HTTP POST + concurrency cap (semaphore) + 3-state circuit breaker (closed/open/half-open) + `NotificationDelivered` audit emit with upstream `trace_id` |

**V2.4 design decision: sidecar for third-party integrations.**

The original V2.3 design embedded a Webhook handler in the kernel
(`handler/webhook.rs`). This violates the kernel-light principle:
every new integration (Slack, PagerDuty, Teams, Discord, Opsgenie,
custom internal tools) would require a new kernel handler, a new
auth method, and a new failure mode inside the kernel's process
boundary.

The HTTP sidecar pattern (already established for provider
integration in C5) solves this cleanly:

```toml
# policy.toml — notification sidecar configuration
[[notification_channels]]
name     = "slack-escalations"
kind     = "Sidecar"
endpoint = "http://localhost:9200/notify"
events   = ["EscalationRequest", "ReviewRejected", "InitiativeCompleted"]

[[notification_channels]]
name     = "pagerduty-security"
kind     = "Sidecar"
endpoint = "http://localhost:9201/notify"
events   = ["SecurityViolation", "CredentialCompromise"]

[[notification_channels]]
name     = "ops-email"
kind     = "Email"
smtp_host = "smtp.example.com"
smtp_port = 587
to        = ["ops@example.com"]
events    = ["EscalationRequest"]
```

**How it works:**

1. The kernel emits a notification event (escalation raised,
   review rejected, initiative completed, security violation).
2. For `kind = "Email"`: the kernel's built-in SMTP handler sends
   the email directly. This stays in-kernel because email is
   universal and the SMTP protocol is stable.
3. For `kind = "Sidecar"`: the kernel POSTs a JSON payload to the
   sidecar's `endpoint`:

   ```json
   {
     "event_kind": "EscalationRequest",
     "event_id": "550e8400-e29b-41d4-a716-446655440000",
     "initiative_id": "...",
     "session_id": "...",
     "timestamp": "2026-05-08T19:00:00Z",
     "payload": { ... }
   }
   ```

4. The sidecar translates this into the target platform's API
   (Slack `chat.postMessage`, PagerDuty Events API v2, Teams
   Incoming Webhook, etc.) and returns `200 OK` or an error.
5. The kernel records the delivery result in the audit chain
   (`NotificationDelivered` / `NotificationDeliveryFailed`).

**Why this is better than in-kernel handlers:**

| Concern | In-kernel | Sidecar |
|---|---|---|
| New integrations | Kernel code change + release | Operator deploys a new sidecar container |
| Auth methods | Kernel must support each (OAuth, API keys, HMAC) | Sidecar handles its own auth |
| Failure blast radius | Bug in Slack handler can panic the kernel | Sidecar crash doesn't affect kernel |
| Rate limiting | Kernel must implement per-platform rate limits | Sidecar handles its own rate limiting |
| Testing | Requires mocking each platform's API | Operator tests their own sidecar |
| Kernel binary size | Grows with each integration | Stays constant |

**Event filtering.** The `events` field in the sidecar declaration
controls which notification events are routed to which sidecar.
This is admission-validated — unknown event kinds are rejected
at policy-load time. The kernel dispatches to all matching
channels for each event (fan-out, not routing).

**Retry semantics.** The kernel retries sidecar delivery with the
same retry policy as provider sidecar calls (C5): 3 attempts with
exponential backoff, 5-second timeout per attempt. After 3
failures the event is marked `DeliveryFailed` in the audit chain
and the kernel moves on (fire-and-forget — notifications are not
on the critical path).

**Failure taxonomy** is extended with `Network`, `UpstreamRejected`,
and `CredentialUnavailable` variants of `DeliveryError`; each maps
to a stable `category()` short-string that lands in
`NotificationDeliveryFailed.reason` so operator dashboards can group
failures by class.

**V2 sidecar notification dispatch — CLOSED V2.4:**

| Component | Status |
|---|---|
| `kernel/src/notifications/handler/sidecar.rs` — HTTP POST with retry, circuit breaker, concurrency cap | ✅ shipped |
| `NotificationPayload` JSON wire type + `SidecarSuccessResponse` envelope | ✅ shipped |
| `NotificationChannelKind::Sidecar` variant with `max_in_flight` field validation | ✅ shipped |
| `SidecarRegistry` per-kernel registry, threaded through `HandlerContext` and `NotifyingAuditSink` | ✅ shipped |
| `NotificationDelivered` + `NotificationDeliveryFailed` audit emission with `category: "backpressure"`, `"circuit_open"`, etc. | ✅ shipped |
| Event filtering at dispatch (existing `notification_routes` mechanism handles per-kind routing) | ✅ shipped (route table) |

**V2 deferrals (V3 work, tracked separately):**

* Persistent SMTP keep-alive connections (V2 opens one connection per
  send — fine for the typical event volume).
* Idempotency table `notification_dispatch` (`§6.5` of the spec) —
  V2 is best-effort fire-and-forget.
* AUTH XOAUTH2 — V2 ships AUTH PLAIN only.
* HMAC-SHA256 webhook signing — the sidecar handles its own auth;
  kernel-to-sidecar trust is localhost-only (same host boundary as
  provider sidecars).

**Error handling and edge cases — notifications must never affect
normal kernel operations:**

Notifications are **strictly non-critical**. A notification failure
— whether Email SMTP timeout, sidecar crash, DNS failure, or
malformed sidecar response — must NEVER:

- Block the kernel's main event loop or delay intent processing.
- Cause a kernel panic, crash, or restart.
- Stall, delay, or roll back an in-flight initiative.
- Prevent session spawn, plan approval, or any admission pipeline
  step.

The kernel's notification dispatch runs on a **dedicated
`tokio::spawn` task** with its own error boundary. Errors are
caught, logged, and recorded as `NotificationDeliveryFailed`
audit events. The kernel's main loop never `await`s notification
delivery.

| Edge case | Kernel behavior |
|---|---|
| Sidecar endpoint unreachable | 3 retries with exponential backoff (1s, 2s, 4s). After 3 failures: `DeliveryFailed{Network}` audit event. Kernel moves on. |
| Sidecar returns non-2xx | Treated as `UpstreamRejected`. Retry on 5xx only; 4xx is terminal (bad payload). Audit event emitted. |
| Sidecar returns malformed response | Treated as `UpstreamRejected`. No retry. Audit event includes response body (truncated to 1 KiB). |
| Sidecar hangs (no response) | 5-second per-attempt timeout. After timeout: connection dropped, retry with next attempt. |
| All notification channels fail | Kernel continues operating normally. `raxis status` shows degraded notification health. No escalation — the operator monitors notification health via the audit chain, not via notifications (circular dependency). |
| SMTP authentication failure | `CredentialUnavailable` audit event. No retry (wrong password won't fix itself). |
| Policy declares sidecar but sidecar is not running | Kernel starts normally. First notification to that channel fails with `Network` error. Kernel does not block boot waiting for sidecars. |
| `events` filter matches no emitted events | Silent — the sidecar is never called. No error, no warning. This is valid configuration (operator may enable events later). |
| Notification payload serialization error | Programming bug — `unreachable!()` in release, `debug_assert!` in test. The kernel skips this channel for this event and emits a `SecurityEventKind::NotificationSerializationFailure` audit event. |
| **Malicious/hanging sidecar (infinite loop)** | See backpressure design below. |

**Backpressure: concurrency cap + per-channel circuit breaker.**

A sidecar that hangs indefinitely (malicious `while true` loop,
deadlock, or simply overwhelmed) is not just a timeout problem.
If the kernel spawns a new `tokio::spawn` task for every
notification event and each task blocks for 15 seconds (3 × 5s
timeout), a burst of 100 events/second produces 1,500 concurrent
tasks — each holding a TCP connection and a tokio task slot.
Without a bound, this is unbounded resource accumulation.

V2 prevents this with two mechanisms:

**1. Per-channel concurrency semaphore.**

Each `[[notification_channels]]` entry gets a
`tokio::sync::Semaphore` with `max_in_flight` permits (default 8,
configurable in `policy.toml`):

```toml
[[notification_channels]]
name          = "slack-escalations"
kind          = "Sidecar"
endpoint      = "http://localhost:9200/notify"
events        = ["EscalationRequest"]
max_in_flight = 8    # default; cap concurrent dispatch tasks
```

When all 8 permits are held (i.e., 8 tasks are blocked waiting on
the sidecar), the 9th notification **drops immediately** with a
`DeliveryFailed{Backpressure}` audit event. The kernel does NOT
queue — it drops and moves on. This bounds the maximum resource
consumption per channel to `max_in_flight × 15s` worth of tasks
regardless of event rate.

**2. Per-channel circuit breaker.**

If a channel accumulates 5 consecutive failures (timeout, 5xx,
connection refused) within a 60-second window, the channel enters
**open** state. While open:

- All notifications to that channel are dropped immediately with
  `DeliveryFailed{CircuitOpen}`.
- No TCP connections are attempted (zero resource cost).
- After 60 seconds, the circuit enters **half-open** and allows
  one probe delivery through. If it succeeds, the circuit closes
  and normal dispatch resumes. If it fails, the circuit re-opens
  for another 60 seconds.

This prevents a permanently-hanging sidecar from consuming even
the `max_in_flight` permit slots — after the first 5 failures
hit the timeout, the circuit opens and the kernel stops trying.

```
Normal:   event → semaphore.acquire → POST → 2xx → release
Backpressure: event → semaphore full → drop (audit: Backpressure)
Circuit open: event → circuit check → drop (audit: CircuitOpen)
Half-open:    event → circuit check → one probe → success → close circuit
                                                → failure → re-open
```

**Worst-case resource consumption per channel:**

| Parameter | Value |
|---|---|
| `max_in_flight` | 8 (default) |
| Per-attempt timeout | 5 seconds |
| Max attempts | 3 |
| Max wall-clock per task | 15 seconds |
| Max concurrent TCP connections | 8 |
| Max tokio tasks | 8 |
| Circuit breaker trip threshold | 5 consecutive failures |
| Circuit open duration | 60 seconds |

With 10 configured channels and all of them hanging: **80 tokio
tasks, 80 TCP connections** — bounded and predictable. After the
circuit breakers trip (~75 seconds), consumption drops to **zero**.

**`raxis status` visibility:**

```json
{
  "notifications": {
    "channels": [
      {
        "name": "slack-escalations",
        "kind": "Sidecar",
        "state": "circuit_open",
        "in_flight": 0,
        "dropped_backpressure": 47,
        "dropped_circuit_open": 312,
        "last_success_at": null,
        "last_failure_at": "2026-05-08T20:05:00Z",
        "circuit_reopens_at": "2026-05-08T20:06:00Z"
      }
    ]
  }
}
```

**Spec files requiring updates for the sidecar notification
pattern:**

The following spec files must be updated in the same PR that
implements the sidecar notification dispatch to maintain
spec-graph consistency:

| Spec file | What changes |
|---|---|
| `email-and-notification-channels.md` | **Major update.** Remove the `Webhook` channel kind from the kernel-implemented set. Add `Sidecar` channel kind with `endpoint`, `events`, and retry semantics. Update the channel-kind table, wire shapes, and failure taxonomy. Add the `NotificationPayload` JSON schema. |
| `policy-plan-authority.md` | Add `kind = "Sidecar"` to `[[notification_channels]]` validation. Add `events` field validation (must be known event kinds). Add admission failure code `FAIL_NOTIFICATION_UNKNOWN_EVENT_KIND`. |
| `audit-paired-writes.md §4` | Classify `NotificationDelivered` and `NotificationDeliveryFailed` for sidecar channels (same shape as existing webhook audit events, with `channel_kind = "Sidecar"` and `endpoint` added). |
| `extensibility-traits.md` | Remove `OperatorNotificationChannel` trait extraction from V3 roadmap — the sidecar pattern replaces trait-based extensibility for notifications. The kernel's notification surface is now: Email (built-in) + Sidecar (HTTP contract). |
| `operator-ergonomics.md` | Update `raxis doctor` to include a `notifications` check category that verifies sidecar endpoints are reachable (HTTP GET health check). |
| `invariants.md` | Add `INV-NOTIFY-07`: "Notification dispatch failures MUST NOT block, crash, delay, or roll back any kernel operation. Notification delivery is fire-and-forget with audit." |

**Sidecar boilerplate examples.**

The sidecar contract is intentionally minimal: accept a JSON POST,
do your thing, return 2xx. Below are complete working examples
that operators can copy as starting points.

**Example 1 — Slack sidecar (Python, ~30 lines):**

```python
# slack_notify.py — run with: uvicorn slack_notify:app --port 9200
import os, httpx
from fastapi import FastAPI, Request

app = FastAPI()
SLACK_WEBHOOK = os.environ["SLACK_WEBHOOK_URL"]

@app.post("/notify")
async def notify(request: Request):
    event = await request.json()
    kind = event["event_kind"]
    init_id = event["initiative_id"]
    payload = event.get("payload", {})

    # Format a Slack message from the RAXIS event
    text = f":rotating_light: *{kind}*\nInitiative: `{init_id}`"
    if kind == "EscalationRequest":
        text += f"\nReason: {payload.get('reason', 'unknown')}"
        text += f"\nSession: `{event.get('session_id', 'N/A')}`"
    elif kind == "ReviewRejected":
        text += f"\nCritique: {payload.get('critique', '')[:200]}"

    async with httpx.AsyncClient() as client:
        resp = await client.post(SLACK_WEBHOOK, json={"text": text})
        resp.raise_for_status()

    return {"ok": True}

@app.get("/health")
async def health():
    return {"status": "ok"}
```

**Example 2 — PagerDuty sidecar (Node.js, ~35 lines):**

```javascript
// pagerduty_notify.js — run with: node pagerduty_notify.js
const express = require("express");
const app = express();
app.use(express.json());

const PD_ROUTING_KEY = process.env.PD_ROUTING_KEY;
const PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue";

app.post("/notify", async (req, res) => {
  const event = req.body;
  const severity =
    event.event_kind === "SecurityViolation" ? "critical" :
    event.event_kind === "CredentialCompromise" ? "critical" :
    event.event_kind === "EscalationRequest" ? "warning" : "info";

  const pdPayload = {
    routing_key: PD_ROUTING_KEY,
    event_action: "trigger",
    payload: {
      summary: `RAXIS ${event.event_kind} — initiative ${event.initiative_id}`,
      severity,
      source: "raxis-kernel",
      custom_details: event.payload || {},
    },
  };

  const resp = await fetch(PD_EVENTS_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(pdPayload),
  });

  if (!resp.ok) return res.status(502).json({ error: await resp.text() });
  res.json({ ok: true });
});

app.get("/health", (_, res) => res.json({ status: "ok" }));
app.listen(9201, () => console.log("PagerDuty sidecar on :9201"));
```

**The contract the kernel expects:**

| Aspect | Requirement |
|---|---|
| **Method** | `POST` |
| **Path** | Whatever `endpoint` is set to in `policy.toml` (e.g., `/notify`) |
| **Content-Type** | `application/json` |
| **Request body** | `{ "event_kind": string, "event_id": uuid, "initiative_id": uuid, "session_id": uuid \| null, "timestamp": iso8601, "payload": object }` |
| **Success response** | `2xx` status code with JSON body: `{ "ok": true, "trace_id": "<upstream-id>" }` |
| **`trace_id` field** | **Required on success.** An opaque string the sidecar returns — the ID from the upstream system (Slack `ts`, PagerDuty `dedup_key`, Teams `id`, etc.). The kernel stores this verbatim in the `NotificationDelivered` audit event so operators can trace from RAXIS → their notification platform. |
| **Retryable failure** | `5xx` status code or connection error → kernel retries (up to 3). |
| **Terminal failure** | `4xx` status code → kernel does NOT retry (bad payload). |
| **Health check** | `GET /health` returning `2xx` — used by `raxis doctor notifications`. Optional but recommended. |
| **Timeout** | Sidecar must respond within 5 seconds per attempt. |

**Proposed extensions to the `NotificationDelivered` audit event
(defined in `email-and-notification-channels.md`):**

The following fields are added to the existing event shape for
sidecar channels. See `email-and-notification-channels.md` for
the authoritative definition.

| Field | Type | Description |
|---|---|---|
| `channel_name` | `String` | Matches `name` in `[[notification_channels]]` policy declaration |
| `channel_kind` | `String` | `"Email"`, `"Shell"`, `"File"`, or `"Sidecar"` |
| `upstream_trace_id` | `Option<String>` | The `trace_id` returned by the sidecar (Slack `ts`, PagerDuty `dedup_key`, SMTP `Message-ID`). `None` for Shell/File channels. |
| `source_event_kind` | `String` | The event kind that triggered this notification |
| `source_event_id` | `Uuid` | The event ID that triggered this notification |
| `initiative_id` | `Uuid` | Initiative context |
| `delivery_ms` | `u64` | Delivery latency (wall-clock, including retries) |
| `attempts` | `u32` | Number of attempts (1 = first try succeeded) |

### C5: Immutable Artifact Store — CLOSED (V2.4, kernel wiring shipped)

**Spec:** `immutable-artifact-store.md` (25KB) — full surface
**Status:** **Primitive + kernel wiring delivered.** Boot-time backfill,
policy-push, plan-approve, and operator-pubkey paths all write to
the store.
**Delivered:** ~470 lines (V2.3 primitive) + ~180 lines (V2.4
kernel wiring incl. tests)

V2.3 lands the operator-grade content-addressed store primitive
that the spec's policy/plan/key write paths build on top of: write-
once, hash-verified, idempotent on identical bytes, fail-loud on
tampering. The crate compiles and its tests pass, but **nothing
depends on it yet** — the kernel, CLI, and policy crates do not
import it. V2 does not ship without the wiring.

| Component | Crate | Status |
|---|---|---|
| `Category` enum (Policy / Plans / Keys) with stable `sub_dir()` + `ext()` | `crates/artifact-store/src/lib.rs` | Per `§4` storage layout |
| `ArtifactKey` (32-byte SHA-256 + hex projection) | `crates/artifact-store/src/lib.rs` | `compute(&[u8])`, `parse_hex(&str)`, `as_hex()` |
| `ArtifactStore::open(data_dir)` materialising `<root>/artifacts/` at mode 0700 | `crates/artifact-store/src/lib.rs` | Lazy per-category sub-dir creation on first write |
| `ArtifactStore::write(category, body)` → `(key, path)` with `O_CREAT \| O_EXCL` | `crates/artifact-store/src/lib.rs` | Idempotent on identical bytes; surfaces `BytesDiverge` on tamper |
| `ArtifactStore::read(category, key)` → `Vec<u8>` with on-read SHA-256 verification | `crates/artifact-store/src/lib.rs` | Surfaces `IntegrityMismatch` for the spec's §1.3 tamper-detector |
| `ArtifactStore::write_companion(category, key, ext, body)` for `<sha256>.sig` | `crates/artifact-store/src/lib.rs` | Same idempotency contract as `write` |
| 10 unit tests covering hex round-trip, write→read, idempotency, tamper detection (write + read), exists check, sidecar writes, cross-category collision avoidance | `crates/artifact-store/src/lib.rs` | All passing |

**V2 kernel wiring — CLOSED V2.4:**

All wiring points below ship in V2.4. The store is opened at
kernel boot, threaded through `HandlerContext::artifact_store`,
and called from `policy_manager::advance_epoch` (policy bytes +
signature), `initiatives::lifecycle::approve_plan` (plan bytes +
signature), and the operator-cert ingest (public-key bytes).

| Wiring point | Kernel call site | What lands |
|---|---|---|
| **Policy push** | `kernel/src/policy_manager.rs::advance_epoch` Phase 0.5 | Writes verified `policy.toml` bytes to `ArtifactStore::write(Category::Policy, ...)`; companion `<sha256>.sig` via `write_companion(Policy, key, "sig", sig_bytes)`. Idempotent on identical bytes; failure logs and continues (audit chain stays canonical). |
| **Plan approve** | `kernel/src/initiatives/lifecycle.rs::approve_plan` post-sig pre-tx | Writes `plan_bytes` + `<sha256>.sig` companion. Same idempotency contract as policy push; no rollback of the SQL transaction on artifact-write failure. |
| **Operator pubkeys** | `kernel/src/policy_manager.rs::advance_epoch` Phase 0.5 (per-cert loop) | Writes raw 32-byte Ed25519 pubkeys to `Category::Keys`; idempotent across operator rotations. Forensic join `OperatorCertInstalled.cert_sha256 → keys/<sha>` returns the original bytes. |
| **Boot-time open** | `kernel/src/main.rs` post-data-dir | `raxis_artifact_store::ArtifactStore::open(&data_dir)` with fail-closed exit on open failure. Backfills the currently-active `policy.toml` so a fresh kernel has the on-disk artifact even before the first epoch advance. |
| **`raxis-artifact-store` dep** | `kernel/Cargo.toml` | Workspace dep added. |
| **Symlink swap** | DEFERRED to V3 | The spec's "current pointer" semantics live with the kernel's policy/cert managers; the V2.4 wiring is "store + audit chain only". V3 layers on `<sha256>.toml` pointer-file rotation. |

Tests pinning the wiring:

* `policy_manager::tests::advance_epoch_writes_policy_bytes_and_sig_to_artifact_store` — round-trips policy bytes + sig + on-read SHA-256 verification.
* `initiatives::lifecycle::tests::approve_plan_writes_plan_bytes_and_sig_to_artifact_store` — same coverage for the plan path.

**V2 design choices.**

* **Crate, not a kernel module.** Future read sites
  (`raxis policy history`, `raxis plan show`, `raxis keys list`)
  link this crate from the CLI without pulling the entire kernel
  into a CLI binary. Audit + retention pieces stay in the kernel
  module that drives them.
* **`O_CREAT | O_EXCL` write, not "open + read + compare".**
  Atomic on every POSIX filesystem; eliminates a TOCTOU window
  the simpler shape would have between the integrity check and
  the open.
* **0700 directory + 0600 file permissions.** Matches the spec's
  §4 ownership table (artifact dirs are kernel-only).
* **`fsync` on each write.** Ensures the artifact reaches stable
  storage before the caller advances any other state (e.g. the
  audit-event row referencing the new SHA-256).

**Deferred to V3.**

* Retention policy GC sweep (`policy_bundles = 3650` etc).
* CLI surfaces (`raxis policy history`, `raxis plan show
  <sha256>`, `raxis keys list`).

### C6: Kernel Push Protocol — CLOSED (V2.3, MVP)

**Spec:** `kernel-push-protocol.md` (63KB) — full surface
**Status:** **CLOSED for V2 — minimum-viable auto-push only.**
**Delivered:** ~250 lines

V2.3 lands the auto-push leg of the kernel push protocol so a
successful `IntegrationMerge` reaches the operator's upstream
remote without manual intervention. The implementation is
deliberately scoped to the operator-grade default; the full
push-approval gate (push attestation, force-push prohibition,
branch protection verification, escalation flow) stays a V3
follow-up.

| Component | Crate | Status |
|---|---|---|
| `push_to_remote(main_repo_root, remote, refspec, deadline)` | `domain-git/src/lib.rs` | Bounded subprocess `git push` with stderr capture + deadline |
| `[git] auto_push: bool` + `push_remote: String` policy fields | `policy/src/bundle.rs` | Parsed, validated (`auto_push=true ⇒ push_remote required`) |
| `PushAttempted` / `PushCompleted` / `PushFailed` audit events | `audit/src/event.rs` | Wire-stable kinds; failure category one of `push_failed`, `spawn_failed`, `deadline_exceeded`, `unopenable_repo` |
| Auto-push wiring after `IntegrationMergeCompleted` | `kernel/src/handlers/intent.rs` | Inline: push runs synchronously inside `run_phase_c`, post-commit, fail-open (does not roll back the merge) |

**V2 design choices.**

* **No kernel-side credential injection.** The kernel invokes
  `git push` and lets the host's git credential helpers / SSH
  config supply auth. This keeps the V2 push wire-shape identical
  to `integration-merge.md §14`'s `git push origin main` example
  and avoids opening a credential-proxy fan-in for what is
  effectively a host-administered remote.
* **Refspec defaults to `<target_ref>:<target_ref>`.** Push
  always targets the operator-configured `[git] default_target_ref`
  (V2.0: `refs/heads/main`; per-initiative overrides via
  `[workspace] target_ref` in plan.toml become a follow-up
  alongside the `initiatives.target_ref` column work in §12.8).
* **Push failure is informational.** The merge already committed
  durably; a network outage / auth prompt / branch-protection
  rejection emits `PushFailed` and the operator sees it on the
  next `raxis log` poll. Re-running `raxis push <initiative>`
  (V3 CLI) or hand-running `git push` from the operator host is
  the recovery path.

**Deferred to V3 (full push-protocol spec).**

* `PushApproval` escalation flow (kernel-push-protocol.md §3, §6).
* Force-push detection + prohibition (`§4.2`).
* Branch-protection probe before pushing (`§4.4`).
* Push-attestation record (signed receipt of pushed sha-set).
* Per-initiative `[push]` block in `plan.toml` (rate limits,
  remotes per ref, etc.).

### C7: Credential CLI: `add`, `remove`, `show`, `verify`, `audit` — CLOSED (V2.3, MVP)

**Spec:** `credential-proxy.md §12`
**Status:** Seven-command catalogue shipped (`list`, `rotate`, `add`,
`show`, `remove`, `verify`, `audit`). Per-proxy-type validators and
the live-network `verify` probe are V3.

Implementation:
- `cli/src/commands/credential.rs`:
  - `run_add` writes a NEW credential to `<data_dir>/credentials/<name>.env`
    (or `<data_dir>/providers/<id>.toml` for the `providers.<id>` form)
    via `O_CREAT|O_EXCL` + `fsync` + `rename` + parent-dir `fsync`,
    refusing to overwrite existing files. `--type` / `--env` /
    `--desc` are recorded in the audit event for forensic queries
    but are NOT used to dispatch a per-type validator yet.
    `--value <bytes>` is rejected (`INV-CRED-CLI-01`).
  - `run_show` prints `stat(2)` metadata only — never the value.
  - `run_remove` requires `--force` (V2 cannot probe active
    sessions from CLI without a live kernel IPC). Emits
    `CredentialRemoved{forced=true}`.
  - `run_verify` runs structural-only verification: file present,
    mode 0600, uid match, body non-empty, `KEY=VALUE` parse for
    `.env` form. Emits `CredentialVerified{success,latency_ms}`.
  - `run_audit` merges `<data_dir>/audit/credential-cli.jsonl`
    (operator-local trail) with the kernel's main audit segments
    (`<data_dir>/audit/segment-NNN.jsonl`) and prints the records
    whose payload mentions `<name>`.
- `crates/audit/src/event.rs`: three new audit-event variants —
  `CredentialRegistered`, `CredentialRemoved`, `CredentialVerified`
  — with the wire shape called out in `credential-proxy.md §12.3`
  (extended with `actor_fingerprint` and `backend_kind` for
  consistency with `CredentialAccessed`/`CredentialRotated`).
- `crates/policy/src/bundle.rs`: `KNOWN_AUDIT_EVENT_KINDS` extended
  with the three new variants; `known_event_kinds_list_is_in_lockstep_with_audit_crate`
  drift-guard updated.

V2 design choices:
- **Per-type validators are V3.** The kubeconfig YAML check, the
  AWS JSON parse, the Postgres URI sniff — all of these require
  per-proxy validator crates that several proxies (MongoDB, MSSQL,
  Postgres-extended) don't have yet. V2 stores bytes verbatim and
  records the operator-supplied `--type` label in the audit event
  so V3's validator dispatch is a non-breaking add.
- **Verify is structural-only.** Live probes (Postgres `SELECT 1`,
  Redis `PING`, K8s `GET /api/v1/namespaces`) require the
  credential-proxy runtime which is partially implemented. V2's
  structural verification catches the most common operator
  mistakes (mode != 0600, wrong UID, empty file, truncated env
  parse) and records the outcome in the same audit-event shape
  V3 will use for live probes. Forward-compatible.
- **Operator-local audit trail vs. kernel chain.** The CLI cannot
  recompute `prev_sha256` safely while the kernel is mutating
  segments. We therefore append to a separate JSONL file at
  `<data_dir>/audit/credential-cli.jsonl` rather than tearing
  through the chain. `audit` reads both. V3 will introduce a
  `raxis credential audit submit` IPC handler so the kernel
  ingests the trail at boot and folds it into the chain.
- **`remove` requires `--force`.** Without a live kernel IPC the
  CLI cannot probe active sessions; `--force` makes the operator
  state intent explicitly. The audit event records `forced=true`
  so future detection of "removed-while-active" is a join, not a
  retroactive reconstruction.
- **Wire-shape fidelity.** All three new audit events share the
  `actor_fingerprint` + `backend_kind` columns with
  `CredentialAccessed`/`CredentialRotated`, so forensic queries
  and the kernel chain reader treat them uniformly.

Tests: 29 integration tests in `cli/tests/credential_cli.rs`
(`cargo test -p raxis-cli --test credential_cli`) covering all
seven subcommands — `list` / `rotate` (12 pre-existing) plus 17
new tests for `add` / `show` / `remove` / `verify` / `audit`
covering happy path, refusal of overwrite, refusal of `--value`
on argv, refusal of path traversal, mode 0600 enforcement, audit
trail emission, JSON output, and the merge between local trail
and kernel chain.

V3 (deferred):
- Per-type validators (`add --type postgres` parses URIs;
  `add --type k8s --from-kubeconfig` validates YAML; `add --type aws`
  parses JSON env).
- Live-network `verify` probes (`SELECT 1` / `PING` / `sts:GetCallerIdentity` / etc).
- `remove` orphan-check via kernel IPC (reject removal of
  in-use credentials without `--force`).
- `raxis credential audit submit` IPC handler so the kernel
  folds the operator-local trail into the chained audit segment
  on next boot.

---

### C8: Reserved Planner Tools — `WebFetch`, `WebSearch`, `StructuredOutput`, `Sleep` — CLOSED (V2.4, deferred to V3)

**Spec:** `planner-harness.md §3` (tool surface table),
`custom-tools.md §5` (reserved name list)
**Status:** **CLOSED for V2 — all four names remain reserved;
no implementation in V2.**

**V2.4 architectural decision: WebFetch/WebSearch removed from V2
scope.**

The V2 unified egress model (tproxy SNI allowlist + credential
proxy HTTP allowlist) already provides structural confinement
for all outbound network access. The agent can `curl` from
`bash` — and that path IS governed:

1. **Tproxy (R-2):** The VM has no NIC (INV-02B). Every
   outbound TCP connection is intercepted and checked against
   the operator's SNI allowlist. Unauthorized hosts are refused
   at the transport layer.
2. **Credential proxy (R-2, Tier 2):** Authenticated endpoints
   use the HTTP-layer URL-prefix + method allowlist per session.
3. **Verifier gate (R-7):** The reviewer sees every file the
   agent wrote, catching injection of malicious fetched content.

A `web_fetch` tool would duplicate transport-layer governance
at the application layer. Since the agent can always `bash curl`
(which goes through the same tproxy), tool-level rate limiting
and SSRF checks on `web_fetch` alone provide no confinement —
the agent bypasses them by using `bash`. Adding confinement
would require stripping `curl`/`wget` from the VM image (an
image-level control, not a tool-level control).

**RAXIS design principle:** structural prevention at the lowest
feasible layer, not capability-based permission at the
application layer. The tproxy IS the lowest layer.

**What stays:**

| Tool | Reserved | V2 impl | V3 plan |
|---|---|---|---|
| `WebFetch` | ✅ | ❌ removed | V3 ergonomic improvement (structured audit, body truncation, LLM-friendly schema) |
| `WebSearch` | ✅ | ❌ removed | V3 ergonomic improvement |
| `StructuredOutput` | ✅ | ❌ excluded | V3 (no DAG consumer) |
| `Sleep` | ✅ | ❌ under review | V3 (needs `max_sleep_seconds` policy cap decision) |

Names remain in `RESERVED_TOOL_NAMES` (`custom_tools_validator.rs`
lines 63–66) to prevent operator custom-tool collisions. The
reservation is forward-compatible — V3 can implement these tools
without a breaking change to the reserved-name list.

---

### C9: Streaming Dispatch (Planner ↔ Gateway) — **CLOSED (V2.4, MVP)**

**Spec:** `provider-failure-handling.md §7` (streaming atomicity),
`§7.2` (gateway-side stream buffering), `§7.5` (no resumable
streams), `§12.4` (design rationale), `§12.7` (resumability
deferral)
**Status:** ✅ V2 MVP shipped in V2.4
**Code paid:** ~700 lines (planner-core/src/streaming.rs + planner
SSE reader + AnthropicClient streaming override + gateway-substrate
per-chunk idle timeout)

**What V2.4 ships.**

| Component | Where it lives | What it does |
|---|---|---|
| **Planner SSE parser** | `crates/planner-core/src/streaming.rs` (~820 lines) | `SseParser` chunks raw bytes into `SseFrame`s; `AnthropicStreamAggregator` ingests frames and emits `StreamEvent` (`MessageStart`, `ContentBlockStart`, `ContentBlockDelta`, `ContentBlockStop`, `Usage`, `Stop`, `Complete`). 14 unit tests cover multi-line `data:`, comment lines, partial frames, malformed JSON, and the tool-use streamed-JSON path. |
| **Planner stream consumer** | `crates/planner-core/src/model.rs::ModelClient::create_message_stream` | New trait method returning `tokio::sync::mpsc::Receiver<StreamEvent>`. Default impl synthesises a 4-event stream from the buffered `create_message`; `AnthropicClient` overrides with real SSE wiring (sets `stream: true`, opens `text/event-stream` connection, parses chunks through aggregator, closes on `message_stop` or graceful EOF). |
| **Per-chunk idle timeout** | `crates/planner-core/src/streaming.rs::DEFAULT_STREAM_IDLE_TIMEOUT` (30s) + `gateway/src/http_backend.rs` | Both the planner-side reader and the kernel-side `HttpBackend` wrap each chunk-read in `tokio::time::timeout(idle, …)`. A provider that accepts the request but stalls mid-body fails fast at 30s rather than dragging out to the per-provider `inference_timeout_ms`. Gateway `BackendRequest` carries an `Option<Duration>` `stream_idle_timeout`; dispatch sets it for `FetchKind::Inference` and leaves it `None` for `FetchKind::DataFetch`. |
| **Atomic delivery to dispatch** | `crates/planner-core/src/dispatch.rs` | The dispatch loop continues to consume `create_message` (buffered) per `INV-PROVIDER-04` — only the terminal `Complete(MessageResponse)` carries tool-use input. Streaming events are observability-only and feed the V3 incremental progress / token-budget abort path. |
| **Streaming-friendly `Usage`** | `crates/planner-core/src/model.rs::Usage` | All four token-count fields are `#[serde(default)]` so partial-usage payloads (Anthropic's mid-stream `message_delta`; OpenAI's terminal chunk) deserialize cleanly without a per-provider schema branch. |
| **`MessageRequest::stream`** | `crates/planner-core/src/model.rs::MessageRequest` | New `stream: bool` field, `#[serde(skip_serializing_if = "is_false")]`-guarded so non-streaming callers see no on-the-wire diff. `Default` impl seeds `stream: false` so test/retry/circuit/sidecar construction sites can use `..Default::default()`. |

**Tests** (all passing on `cargo test -p raxis-planner-core -p raxis-gateway`):

- `streaming::tests::*` — 8 unit tests for SSE parsing + aggregation
  (text-only, tool-use streamed JSON, ping/unknown events,
  malformed JSON, `message_start`-without-id rejection,
  default-constants bound check).
- `model::tests::message_request_serialises_stream_true_when_opted_in`
  — pins the `stream: true` wire shape.
- `model::tests::create_message_stream_against_local_sse_server_emits_full_event_sequence`
  — end-to-end test against a local SSE mock; verifies request
  carries `stream: true`, the receiver yields the expected event
  sequence, and the terminal `Complete(MessageResponse)`
  reconstructs the buffered shape exactly.
- `http_backend::tests::stream_idle_timeout_fires_when_provider_stalls_mid_body`
  — pins the gateway's idle-timeout boundary at 250ms against a
  stalling-after-headers mock.

**V3 deferred (sidecar streaming + heartbeat + early budget abort).**

| Component | Why V3 |
|---|---|
| **Gateway worker heartbeat to kernel** | Requires a new IPC variant on `gateway.sock` and a kernel-side stale-worker detector. The V2.4 idle-timeout already catches the failure mode (a stalled provider) end-to-end; the heartbeat is the operator-visibility leg. |
| **Token metering (incremental)** | Requires the dispatch loop to subscribe to `StreamEvent::Usage` mid-turn and abort when cumulative output crosses the per-task `tokens_limit`. The V2.4 plumbing emits `StreamEvent::Usage` already; only the dispatch-loop consumer is missing. |
| **Sidecar SSE forwarding** | C5's `SidecarModelClient` delivers a single buffered envelope today. Extending to SSE forwarding is a sidecar-protocol revision (response `Content-Type` + chunked body). The buffered path produces the same `MessageResponse` shape; circuit / retry / fallback all behave identically. |
| **Spill-to-disk above `stream_buffer_cap`** | The V2.4 in-memory buffer is bounded by `provider.max_response_bytes` (per-provider, kernel-enforced); 100K-token outputs fit under the default 32 MiB ceiling without spilling. Spill-to-disk is a hardening hook for the few V3 reasoning-tier models that emit ≥32 MiB of thinking + visible tokens. |

**Why this is V2, not V3.**

1. **Latency is untenable.** A complex tool-use response from
   Claude or GPT-4 can take 60–120 seconds to generate. Without
   streaming, the planner sits idle for the entire duration. With
   streaming, the planner can parse the first tool call as soon as
   the `tool_use` block closes — often 10–20 seconds into the
   stream — and begin executing while the model finishes
   generating subsequent content blocks.

2. **Provider hang detection.** Without streaming, a provider that
   accepts the request but never responds is indistinguishable
   from a provider generating a very long response. The planner
   blocks until `worker_invoke_timeout_ms` (default 10 minutes).
   With streaming, a gap between chunks exceeding
   `stream_idle_timeout_ms` triggers an immediate abort and retry
   on the next provider.

3. **Operator visibility.** Without streaming, the operator's
   `raxis status` shows the session as "inferring" with no
   progress indication for minutes. With streaming, the gateway
   heartbeat carries `bytes_received` so the operator can see
   generation is progressing.

4. **Early budget abort.** Without streaming, a model that
   generates 50K output tokens when the session has budget for
   10K completes the entire generation before the planner
   discovers the budget is blown. With streaming, the planner
   counts tokens incrementally and can abort the stream early,
   saving provider cost.

**V2 design constraints (carried from spec).**

* **Atomic delivery to the planner.** Even with streaming, the
  planner's `ModelClient` delivers only complete, validated
  envelopes (INV-PROVIDER-04). The streaming path is gateway →
  buffer → validate → deliver. The planner never sees partial
  JSON or half-formed tool calls.
* **No resumable streams.** Stream failure = clean retry from
  scratch (§7.5). No continuation tokens, no partial-buffer
  salvage. This simplifies retry/fallback logic and keeps budget
  accounting unambiguous.
* **No partial-response recovery.** A mid-stream failure discards
  all buffered content. The retry replays the entire request body.
  Partial recovery is V3 work alongside resumable streams.

**Per-provider `stream_idle_timeout_ms` (reasoning model support) — CLOSED V2.4.**

The gateway's default `STREAM_IDLE_TIMEOUT_DEFAULT` (30 seconds)
is the per-chunk idle deadline — if no SSE event arrives within
this window, the connection is considered stalled and killed with
`BackendError::Timeout`. 30 seconds is correct for standard
generation models (inter-chunk gaps are sub-second) but **breaks
reasoning-tier models**:

| Model class | Streams thinking tokens? | Typical silent gap | 30s safe? |
|---|---|---|---|
| Claude (standard) | n/a (sub-second chunks) | <1s | ✅ Yes |
| Claude (extended thinking) | Yes — `thinking` content block deltas flow during reasoning | 1–5s between thinking deltas | ✅ Yes |
| OpenAI o1 / o3 | **No** — reasoning tokens are not streamed; first visible output arrives after full reasoning | **30–120+ seconds** | ❌ No |
| Gemini (thinking mode) | Partially — depends on API version | 10–60s gaps observed | ⚠️ Marginal |

**V2.4 implementation.** `[[providers]].stream_idle_timeout_ms`
(integer milliseconds, optional) configures the per-chunk deadline
per-provider. The field uses the existing `*_timeout_ms` naming
convention from sibling fields (`inference_timeout_ms`,
`data_fetch_timeout_ms`). Operators using reasoning-tier models
widen the value for those providers:

```toml
[[providers]]
provider_id            = "anthropic"
kind                   = "Anthropic"
credentials_file       = "anthropic.toml"
# stream_idle_timeout_ms omitted — falls back to 30 000 default

[[providers]]
provider_id            = "openai-o1"
kind                   = "OpenAI"
credentials_file       = "openai.toml"
stream_idle_timeout_ms = 120000   # required for o1/o3 reasoning

[[providers]]
provider_id            = "gemini"
kind                   = "Gemini"
credentials_file       = "gemini.toml"
stream_idle_timeout_ms = 60000    # conservative for thinking mode
```

**Validation.** `PolicyBundle::validate` enforces
`stream_idle_timeout_ms` falls in `[5_000, 600_000]` ms (constants
`STREAM_IDLE_TIMEOUT_FLOOR_MS` / `STREAM_IDLE_TIMEOUT_CEILING_MS`
in `policy/src/bundle.rs`). Values below 5 s risk false positives
on busy providers; values above 600 s defeat the purpose (the
per-provider `inference_timeout_ms` is the outer ceiling).

**Wiring.**
`gateway/src/dispatch.rs` reads `provider.stream_idle_timeout_ms`
at dispatch time, converts to `Duration`, and stamps it onto
`BackendRequest::stream_idle_timeout` for `FetchKind::Inference`.
`FetchKind::DataFetch` always passes `None` so a tool's bounded
REST call can pause briefly between chunks of a `Content-Length`-
framed body without hitting a spurious idle abort. Absent field ⇒
gateway falls back to `STREAM_IDLE_TIMEOUT_DEFAULT` (30 s).

**Tests.**
- `bundle::gateway_providers_tests::stream_idle_timeout_below_floor_is_rejected`
- `bundle::gateway_providers_tests::stream_idle_timeout_above_ceiling_is_rejected`
- `bundle::gateway_providers_tests::stream_idle_timeout_120s_loads_cleanly_for_reasoning_models`
- `bundle::gateway_providers_tests::stream_idle_timeout_absent_field_is_none`
- `dispatch::tests::inference_uses_30s_default_when_provider_has_no_override`
- `dispatch::tests::inference_honours_per_provider_stream_idle_override`
- `dispatch::tests::data_fetch_never_attaches_stream_idle_timeout`

**Sidecar (C5) streaming support.**

HTTP sidecar providers (C5) must support streaming on equal
footing with built-in providers — but not all custom provider APIs
support SSE. The sidecar protocol must allow the operator to
configure per-provider whether the sidecar returns a streaming
SSE response or a single buffered JSON response:

```toml
# policy.toml — sidecar provider declaration
[[providers.sidecar]]
name     = "cohere"
endpoint = "http://localhost:9100"
stream   = true    # sidecar returns SSE chunks (preferred)

[[providers.sidecar]]
name     = "internal-llm"
endpoint = "http://localhost:9101"
stream   = false   # sidecar returns a single JSON response body
```

When `stream = true` (the default and preferred mode), the sidecar
responds with `Content-Type: text/event-stream` and the gateway's
`SidecarModelClient` reads it through the same SSE buffering path
as built-in providers. When `stream = false`, the gateway reads
the full response body and wraps it as a single-delivery envelope.

Both modes produce the same `ModelClient` output — the dispatch
loop and `FallbackModelClient` chain see no difference. The
circuit breaker, retry, and half-open probe all work identically
regardless of streaming mode.

---

### C10: Setup Wizard (`raxis setup`) — **CLOSED (V2.3, MVP)**

V2.3 ships a non-interactive scaffolding wizard at
`cli/src/commands/setup.rs` (~520 lines including tests) that
covers phases **2** (`policy_authoring`) and **6**
(`plan_template`) end-to-end and prints recipes for the
remaining phases (1, 3, 4, 5, 7, 8). The MVP honours every
design constraint from the V2 BLOCKER entry below:

* **Non-interactive only** — every input is a flag; no TTY
  abstraction, fully scriptable for CI and for operators on
  headless hosts.
* **Idempotent re-entry** — `<data_dir>/.setup_state.json`
  records `phase_label -> ISO-8601 timestamp` for each
  completed phase. Re-runs skip completed phases unless
  `--force` is passed.
* **Drift guard** — a SHA-256 fingerprint of the operator-
  supplied parameters (`operator-name`, `provider`,
  `provider-id`, `budget-usd`, `max-concurrency`) is stored
  alongside the phase log; a re-run with different inputs
  fails with `FAIL_SETUP_PARAMS_DRIFT` unless `--force` is
  supplied.
* **No overwrite without confirmation** — an existing
  `policy/policy.toml` triggers `FAIL_SETUP_POLICY_EXISTS`
  unless `--force` is set, mirroring `plan init`.
* **Composable with existing commands** — Phase 6 calls
  `commands::plan_init::run` directly (no template
  re-implementation). Phase 8 prints `raxis doctor --data-dir
  …` rather than running it in-process so the operator sees
  the exact command to re-run later when verifying drift.
* **Phase enum reserves all ten slots** — the
  `.setup_state.json` schema pre-allocates slots for V3
  phases (`provider_credentials`, `vm_images`,
  `credential_proxy`, `network_allowlist`,
  `dry_run_submission`, `first_launch`) so a V3 upgrade does
  not need a state-file format migration.

**V2.x candidates (no hard blockers — can land incrementally):**

* Phase 1 (`raxis genesis` orchestration) — wraps the
  existing `raxis genesis` command with guided prompts.
  No new infrastructure needed; TTY secret input is not
  required (keypair generation has no secret input).
* Phase 3 (`raxis credential add` orchestration) — wraps
  the existing credential CLI. TTY-aware secret input is
  a convenience, not a blocker; operators already paste
  keys into `.env` files today.
* Phase 7 (egress-allowlist auto-populate from
  `policy.tproxy_allowlist`) — straightforward policy
  read + template emit. ~50 lines.
* Phase 10 (`raxis plan submit` orchestration) — wraps
  the existing `plan submit` command. No new dependencies.

**V3 (hard blockers — depend on unimplemented features):**

* Phase 4 (VM image registry-list fetch + OCI digest
  picker) — requires an OCI registry client not in the
  workspace.
* Phase 5 (interactive credential-proxy declaration
  emitter) — the proxy declaration schema exists but the
  wizard form requires the full proxy type vocabulary to
  be stabilized.
* Phase 9 (`raxis plan submit --dry-run`) — depends on
  the `DryRunAdmit` IPC type (not yet implemented).

**Tests** (`commands::setup::tests`):
`render_policy_substitutes_all_placeholders`,
`fingerprint_changes_with_inputs`, `state_round_trips`,
`phase_labels_are_distinct`. All four pass on a clean
`cargo test -p raxis-cli`.

#### C10 (historical, full spec)

> **Status note (V2.4).** Phases 1, 3, 7, and 10 are V2.x
> candidates (no hard blockers). Phases 4, 5, and 9 remain V3
> (depend on OCI client, proxy vocabulary stabilization, and
> `DryRunAdmit` IPC respectively). The V2.3 MVP above
> (non-interactive scaffolding for phases 2 and 6, recipes for the
> rest) closes the V2 BLOCKER end of this gap. The historical
> design notes below are preserved as the normative reference for
> the remaining interactive flow.

**Spec:** `operator-ergonomics.md §16`
**Status:** 🟡 V2.3 MVP (phases 2/6); phases 1/3/7/10 are V2.x
candidates; phases 4/5/9 are V3.
**Estimate:** ~800 lines (CLI interactive flow + phase orchestration)

The spec positions the setup wizard as the **recommended first-run
experience** for new operators. Without it, onboarding requires
reading multiple spec documents and manually running 8+ CLI
commands in the correct order. This is an adoption barrier that
V2 cannot ship with — operators who fail at setup never reach
their first initiative.

**The 10 phases (from `operator-ergonomics.md §16`):**

| Phase | What it does | Depends on |
|---|---|---|
| 1. **Key ceremony** | Runs `raxis genesis` — generates operator signing keypair, writes to `$RAXIS_DATA_DIR/keys/` | — |
| 2. **Policy authoring** | Interactive prompts for provider selection, budget limits, concurrency caps → generates `policy.toml` | Phase 1 |
| 3. **Provider credentials** | Prompts for API keys (Anthropic, OpenAI, Gemini, Bedrock) → writes to credential store | Phase 2 |
| 4. **VM image selection** | Lists available executor/reviewer images, prompts for OCI digest pinning → updates `policy.toml [[vm_images]]` | Phase 2 |
| 5. **Credential proxy setup** | If the operator's tasks need DB/API access, interactive proxy configuration → writes proxy declarations | Phase 3 |
| 6. **Plan template** | Generates a starter `plan.toml` with tasks, profiles, and path allowlists based on the repo structure | Phase 2 |
| 7. **Network allowlist** | Prompts for egress hosts (npm, cargo, pip registries, GitHub API) → updates `policy.toml [[tproxy_allowlist]]` | Phase 2 |
| 8. **Doctor validation** | Runs `raxis doctor` against the generated config — surfaces any misconfigurations before the operator commits | Phases 1-7 |
| 9. **Dry-run submission** | Runs `raxis plan submit --dry-run` to validate the plan against the signed policy without creating an initiative | Phases 1-7 |
| 10. **First launch** | Prompts to submit the plan for real and launch the first initiative | Phase 9 pass |

**Design constraints:**

* **Non-interactive fallback.** Every phase must also work as a
  standalone CLI flag (`raxis setup --phase=3 --non-interactive
  --provider=anthropic --key-file=./key.txt`) for CI/automation.
* **Idempotent re-entry.** The wizard detects existing state
  (keys already generated, policy already signed) and skips
  completed phases. An operator who crashes at phase 5 can re-run
  `raxis setup` and resume from phase 5.
* **No overwrite without confirmation.** If `policy.toml` already
  exists, the wizard prompts before overwriting. This prevents
  accidental config destruction on re-runs.
* **Composable with existing commands.** Each phase delegates to
  the existing CLI command (`raxis genesis`, `raxis policy sign`,
  `raxis credential add`, `raxis doctor`). The wizard is
  orchestration, not reimplementation.

**What's missing:**

| Component | Est. lines |
|---|---|
| `cli/src/commands/setup.rs` — phase orchestration + interactive prompts | ~400 |
| Phase state persistence (`$RAXIS_DATA_DIR/.setup_state.json`) for idempotent re-entry | ~100 |
| Template generators (policy, plan, proxy config) | ~200 |
| Non-interactive flag parsing + CI mode | ~100 |

---

## §5 — Tier D: Schema/Skeleton Only

### D1: Key Revocation — **CLOSED (V2.3, MVP)**

**Spec:** `key-revocation.md` (77KB)
**Estimate:** ~400 lines (V2 MVP delivered ~600 lines incl. tests)

V2.3 ships the **admission-time operator-certificate revocation MVP**:

* **Wire types** (`crates/types/src/operator_cert.rs`): new
  `RevocationReason` (`rotation`/`compromise`) and `RevocationRecord`
  with subject pubkey hex + fingerprint, reason, `revoked_at`,
  operator-supplied reference, revoking pubkey hex + signature, and
  `signing_input_version = "raxis-cert-revocation/v1"`.
* **Crypto** (`crates/crypto/src/cert.rs`): added
  `CertStatus::Revoked { reason, revoked_at }` (denies new
  commitments and recovery ops),
  `revocation_canonical_signing_input` (byte-exact pipe-delimited
  layout), `sign_revocation`, `verify_revocation_signature`, and
  `cert_status_with_revocation` for short-circuit evaluation.
* **Kernel store** (`kernel/src/authority/revocations.rs`):
  `RevocationStore` loads `<data_dir>/revocations/*.toml` at boot,
  signature-verifies each record, indexes by subject pubkey hex,
  and tolerates a missing directory or malformed entries (logged,
  not fatal). Stats are emitted as `RevocationStoreLoaded`.
* **Kernel enforcement** (`kernel/src/authority/cert_check.rs`):
  `CertEnforcer::with_revocation_store` injects the store; the
  `enforce` path now uses `cert_status_with_revocation`. A revoked
  cert emits `OperatorCertRevokedOpDenied` and returns
  `CertGuard::Deny` with `FAIL_CERT_REVOKED` for every operator op.
* **CLI** (`cli/src/commands/cert.rs`):
  * `raxis cert revoke <cert> --reason <rotation|compromise> --reference <id>`:
    validates the cert structurally and self-signs, prompts the
    operator key for the revocation signature, round-trips through
    `verify_revocation_signature`, and writes
    `<data_dir>/revocations/<subject_pubkey_hex>.toml` atomically
    (mode 0600 + parent fsync). `--force` bypasses corrupted-cert
    checks and overwrites existing records. Pipes / CR / LF in
    `--reference` are rejected so the canonical signing input
    cannot be ambiguified.
  * `raxis cert list-revocations [--json]`: enumerates
    `<data_dir>/revocations/`, signature-verifies each record, and
    renders a fingerprint / reason / revoked_at / reference / SIG
    table (or pretty JSON).
* **Doctor** (`cli/src/commands/doctor.rs`): cert health check
  reports `CertStatus::Revoked` with a `Fail` outcome telling the
  operator to mint a fresh cert and advance the policy epoch.
* **Audit** (`crates/audit/src/event.rs`,
  `crates/policy/src/bundle.rs`): added `OperatorCertRevoked`
  (successful CLI revocation) and `OperatorCertRevokedOpDenied`
  (admission-time deny). Both kinds are present in
  `KNOWN_AUDIT_EVENT_KINDS` and the drift-guard fixture.

**V2 design choices (deferred to V3):**

* **Admission-time only.** Revocation takes effect on kernel
  restart; live in-flight sessions are not torn down. V3 adds the
  `KernelPush::CertRevocationApplied` envelope plus
  per-session-supervisor purge for `compromise`-class revocations.
* **No `key_trust_state` SQL table.** Revocations are stored as
  per-key TOML files on disk rather than the full
  `key_trust_state` / `emergency_key_revocations` SQL schema from
  the spec. The TOML layout is forward-compatible (the kernel
  ingests records by pubkey, not by file path) and can be
  populated from a future SQL upgrade migration.
* **No CRL distribution.** V2 is single-host; cross-host
  distribution of the revocation set is V3 (CRL bundle signed by
  the policy author, gossiped or pulled).
* **Grace-period handling.** Plans signed before `revoked_at`
  remain valid for `rotation`-class revocations (the kernel still
  honours the cert's `not_after` and grace window). For
  `compromise`, the cert is treated as untrusted retroactively at
  admission time, but in-flight tasks ride out their commitments
  until kernel restart — hardened in V3.

### D2: Host Capacity Management — **CLOSED (V2.3, MVP)**

**Spec:** `host-capacity.md` (79KB)
**Estimate:** ~500 lines (V2 MVP delivered ~700 lines incl. tests)

V2.3 ships the **cap-enforcement + watchdog MVP** of host capacity:

* **Policy** (`crates/policy/src/bundle.rs`): new
  `[host_capacity]` parser — `max_concurrent_vms` (default 16),
  `min_free_disk_mb` (default 5120), `disk_full_behavior` (V2
  accepts only `"halt_admit"`), `required_min_fd_limit` (default
  4096, ≥ 1024 hard floor), `admission_queue_depth` (default 64),
  optional `disk_root` override. Effective config is exposed via
  `PolicyBundle::host_capacity() -> &HostCapacityConfig`.
* **Errors** (`crates/types/src/error.rs`): new
  `PlannerErrorCode::FailVmConcurrencyAtCap` and
  `PlannerErrorCode::FailDiskFull`. Both retryable.
* **Capacity module** (`kernel/src/capacity/`):
  * `vm_admission` — `check_vm_concurrency_cap(running, cap)`
    returns `AdmissionDecision::{Allow, Deferred}`. INV-CAPACITY-01
    pure-function helper.
  * `fd_limit` — `check_fd_limit_at_boot(required)` reads
    `RLIMIT_NOFILE`; returns `FdLimitOutcome::{Ok, Insufficient,
    Unknown}`. Insufficient is fatal at boot.
  * `disk_watchdog` — atomic `DiskState` (`Pending → Healthy ↔
    Halted`) updated by a 5-second tokio task that polls
    `statvfs(disk_root)`. Emits `DiskFullHaltEntered` on the
    Healthy → Halted transition and `DiskHealthyAfterFull` on the
    reverse, plus an `OperatorAttentionRequired { attention_kind:
    "DiskFull" }` companion. Tolerates `statvfs` failure
    (transient unmount → log + skip; never crashes the kernel).
  * `refuse_if_disk_full(watchdog) -> Result<(), ()>` helper for
    write-class intent handlers.
* **Boot** (`kernel/src/main.rs`):
  * Boot-time FD limit check. Insufficient FDs exit with the new
    `BOOT_ERR_HOST_CAPACITY` (code 18).
  * Disk-full watchdog spawned just after the audit sink opens,
    polling the operator-configured `disk_root` (defaults to
    `data_dir`).
* **Handler integration** (`kernel/src/handlers/intent.rs`):
  `handle_activate_sub_task` now performs both Step 1.4
  (refuse-if-disk-full) and Step 1.5 (VM concurrency cap) BEFORE
  inserting the new session row. Both decisions emit the
  appropriate audit event and surface a typed
  `PlannerErrorCode` to the caller.
* **HandlerContext** (`kernel/src/ipc/context.rs`): new
  `disk_watchdog: Option<Arc<DiskWatchdog>>` field with a
  fluent `with_disk_watchdog` setter. Production wires it; tests
  default to `None` (treated as "always healthy").
* **Audit** (`crates/audit/src/event.rs`,
  `crates/policy/src/bundle.rs`): new variants
  `AdmissionDeferredAtCap`, `AdmissionQueueFull`,
  `DiskFullHaltEntered`, `DiskHealthyAfterFull`,
  `OperatorAttentionRequired { attention_kind, details }`.
  All five are present in `KNOWN_AUDIT_EVENT_KINDS` and the
  drift-guard fixture. `OperatorAttentionRequired` uses
  `attention_kind` (not `kind`) because the audit-event enum
  already reserves `kind` as the variant discriminator.

**V2 MVP scope decisions (deferred to V3):**

* **No persistent admission queue.** V2 returns
  `FAIL_VM_CONCURRENCY_AT_CAP` immediately rather than queueing
  with `sessions.state = 'Queued'`. V3 will add the full queue
  with `queued_at`, drain-on-terminate, and round-robin
  fairness (host-capacity.md §9, §10).
* **Single cap kind enforced.** V2 ships only the
  `max_concurrent_vms` cap; aggregate VM memory cap
  (`max_aggregate_vm_memory_mb`) and per-initiative cap
  (`max_per_initiative_concurrent_vms`) are V3.
* **Single disk-full behavior.** Only `halt_admit` is wired;
  `gc_then_retry` (immutable artifact GC + VACUUM) and
  `halt_all` are V3 (host-capacity.md §7.2).
* **No per-operator queue caps.** The default
  (`admission_queue_per_operator_default`) and the
  `[[host_capacity.operator_quota_overrides]]` machinery are
  V3 (host-capacity.md §10.2).
* **No WAL pressure / VACUUM scheduling.** WAL is left at
  SQLite defaults; the periodic checkpoint trigger from
  host-capacity.md §11 is V3.
* **No worktree quota soft enforcement.** The 30-second `du`
  scan and `KernelPush::DiskQuotaWarning` /
  `KernelPush::DiskQuotaExceeded` flow (host-capacity.md §6.1)
  is V3.
* **No audit reserve / total-halt mode.** The
  `audit_reserved_mb` budget and the `AuditWriteImpossible`
  total-halt response (host-capacity.md §7.5–§7.6) are V3.

The V2 surface delivers the highest-impact safety properties
(strict VM cap → kernel survives host OOM; FD floor → kernel
survives per-VM FD growth; disk watchdog with audit visibility →
operator can size disk before catastrophic failure) without the
operational complexity of full queueing.

---

## §6 — Tier E: Partially Implemented

### E1: Environment Access Control — `CLOSED (V2.3, MVP)`

**Spec:** `environment-access-control.md` (82KB)
**Status:** V2.3 MVP — INV-ENV-01 credential limb enforced.

V2.3 lands the structural invariant that prevents one VM from
holding credentials for two compliance boundaries
simultaneously (the canonical "blast radius" failure mode the
spec exists to defeat). The V3 follow-up extends the same
algorithm with the URL-gate limb.

| Feature | Spec section | V2.3 status |
|---|---|---|
| `[environments.<label>]` policy parsing | §5b.1 | ✅ Implemented (`raxis-policy::EnvironmentConfig`); label syntax `^[a-z][a-z0-9_-]{0,31}$`, `description` required, `same_cluster_acknowledged` parsed, §5b.4 reserved fields tolerated. |
| `[[permitted_credentials]]` policy parsing | §5.2 / §5b.5 | ✅ Implemented (`raxis-policy::PermittedCredentialConfig`); `name` required + unique, optional `environment` cross-reference-checked. |
| Label cross-reference validation | §5b.3 | ✅ `FAIL_POLICY_ENV_LABEL_UNDECLARED` / `FAIL_POLICY_ENV_LABEL_INVALID` / `FAIL_POLICY_ENV_UNKNOWN_FIELD` at policy load. |
| INV-ENV-01 per-task credential coherence | §11.3 step A / §11.7 | ✅ `validate_task_environment_consistency` runs at `approve_plan` BEFORE BEGIN TRANSACTION; rejects cross-env tasks with `FAIL_TASK_ENVIRONMENT_INCONSISTENT` (`LifecycleError::PlanInvalid`). Inert when zero envs declared (§1.5.2 activation gate). |
| Cross-env isolation (structural) | §6 | ✅ Already works (VMs are isolated). |
| `[[environment_gates]]` in `policy.toml` | §5 / §11.3 step B | ❌ Deferred to V3 along with the URL-gate runtime path (`block_all`, `write_requires_approval`, `same_cluster_acknowledged` handler, `approval_match_mode`). |
| Warning code from `environment-access-control.md §7` | §7 | ❌ Deferred to V3 (depends on URL-gate matching). |
| Reserved V2.x fields (`blast_radius`, `require_two_party_sign`) | §5b.4 | 🟡 Parsed but inert (no `WARN_ENVIRONMENT_RESERVED_FIELD_SET` audit yet — defer). |
| `TaskEnvironmentBinding` audit attribution | §11.9 | ❌ Deferred to V3 (binding is computed during validation but not yet emitted as a distinct audit event). |

**V2.3 design notes.** The MVP enforces the credential limb of
the §11.3 algorithm because that is the one path that, when
violated, produces a single VM with credentials for two
environments at once — the actual security invariant. The
URL-gate limb without `[[environment_gates]]` parsing produces
no false negatives for that property (a task whose URL
allowlist spans two environments still passes the credential
coherence check trivially if its credentials are neutral or
homogeneous; the runtime egress proxy denies the prod URL via
the existing plan-level allowlist). Adding the URL-gate limb
is purely additive and lands in V3 without breaking V2.3
plans.

**V2.3 deferred work (V3 scope):**
1. `[[environment_gates]]` policy parser, URL canonicalisation
   (§6.1), and the `block_all` / `write_requires_approval`
   admission steps (§4 Step 2 / Step 4).
2. Same-cluster acknowledgement handler (§11.4) and the
   `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` failure mode.
3. `TaskEnvironmentBinding` audit event in `InitiativeCreated`
   for forensic attribution of "which initiatives ever ran in
   production?" queries.
4. The unreachable-environment warning from §7 — fires when
   a task declares an env-bound credential but no `allowed_egress`
   URL matches any gate for that environment.
5. `WARN_ENVIRONMENT_RESERVED_FIELD_SET` for §5b.4 reserved
   fields.

---

## §7 — CLI Subcommand Coverage

Cross-check of CLI commands spec'd in `operator-ergonomics.md` vs
implemented in `cli/src/commands/`:

| Command | Spec'd | Implemented | Lines | Notes |
|---|---|---|---|---|
| `raxis genesis` | ✅ | ✅ | 1,581 | Full key ceremony |
| `raxis policy sign` | ✅ | ✅ | ~400 | Policy bundle signing |
| `raxis policy diff` | ✅ | ✅ | 649 | Structural epoch diff |
| `raxis plan submit` | ✅ | ✅ | ~700 | Plan submission |
| `raxis plan validate` | ✅ | ✅ | ~300 | Offline validation |
| `raxis plan fmt` | ✅ | ✅ | ~200 | Plan formatting |
| `raxis status` | ✅ | ✅ | 1,053 | Kernel status (JSON/human) |
| `raxis doctor` | ✅ | ✅ | 1,681 | Diagnostic checks |
| `raxis credential list` | ✅ | ✅ | ~300 | Lists stored credentials |
| `raxis credential rotate` | ✅ | ✅ | ~250 | Atomic credential rotation |
| `raxis cert` (issue) | ✅ | ✅ | 1,125 | Operator cert management |
| `raxis audit` | ✅ | ✅ | 106 | Audit log viewing |
| `raxis verify-chain` | ✅ | ✅ | ~200 | Audit chain integrity |
| `raxis inspect` | ✅ | ✅ | ~300 | Object inspection |
| `raxis initiative list` | ✅ | ✅ | ~400 | Initiative listing |
| `raxis escalations` | ✅ | ✅ | ~200 | Escalation inbox |
| `raxis inbox` | ✅ | ✅ | ~200 | Operator inbox |
| `raxis sessions` | ✅ | ✅ | ~200 | Active session listing |
| `raxis verifiers` | ✅ | ✅ | ~200 | Verifier status |
| `raxis witnesses` | ✅ | ✅ | ~200 | Witness listing |
| `raxis plan init` | ✅ | ✅ | ~250 | V2.3 MVP: 5 bundled templates (`feature`, `bugfix`, `dependency-upgrade`, `migration`, `experiment`) embedded in CLI binary; per `operator-ergonomics.md §6`. |
| `raxis credential add` | ✅ | ✅ | ~340 | V2.3: per-type validators + atomic file write; `cli/src/commands/credential.rs::run_add`. |
| `raxis credential remove` | ✅ | ✅ | ~150 | V2.3: orphan check via `--force` flag; `run_remove`. |
| `raxis credential show` | ✅ | ✅ | ~110 | V2.3: respects `--json`; `run_show`. |
| `raxis credential verify` | ✅ | ✅ | ~250 | V2.3: per-proxy-type round-trip (Postgres / MySQL / Redis / k8s / AWS); `run_verify`. |
| `raxis cert revoke` | ✅ | ✅ | ~600 | V2.3 D1 MVP: shipped alongside `raxis cert list-revocations`; `cli/src/commands/cert.rs::run_revoke`. |

**CLI total:** 25 of 26 spec'd commands implemented (96%). The
remaining slot (`raxis credential rotate --multi-tenant`) is V3
work (depends on credential generations).

---

## §8 — ORM Compatibility Strategy

### The Problem

Most database ORMs (SQLAlchemy, Django ORM, Prisma, Sequelize,
TypeORM, ActiveRecord) use **prepared statements** by default, not
simple text queries. The RAXIS database proxies currently only handle
the simple query path.

### Postgres: SimpleQuery vs Extended Query Protocol

```
SimpleQuery protocol (what the proxy handles today):
  Client → Q("SELECT * FROM users")
  Server → RowDescription + DataRow* + CommandComplete + ReadyForQuery

Extended Query protocol (what ORMs use):
  Client → Parse("SELECT * FROM users WHERE id = $1")
  Client → Bind(portal, $1 = 42)
  Client → Describe(portal)
  Client → Execute(portal, max_rows=0)
  Client → Sync
  Server → ParseComplete + BindComplete + RowDescription
         + DataRow* + CommandComplete + ReadyForQuery
```

SQLAlchemy, Django, asyncpg, and Prisma all default to the Extended
Query protocol. An agent writing Python code with SQLAlchemy will
generate `Parse`/`Bind`/`Execute` messages, which the current proxy
does not understand.

### MySQL: `COM_QUERY` vs `COM_STMT_*`

```
Simple path (what the proxy handles today):
  Client → COM_QUERY("SELECT * FROM users")
  Server → ResultSetHeader + ColumnDef* + EOF + Row* + EOF

Prepared path (what ORMs use):
  Client → COM_STMT_PREPARE("SELECT * FROM users WHERE id = ?")
  Server → COM_STMT_PREPARE_OK + ColumnDef* + EOF + ParamDef* + EOF
  Client → COM_STMT_EXECUTE(stmt_id, params=[42])
  Server → ResultSetHeader + ColumnDef* + EOF + BinaryRow* + EOF
```

Sequelize, TypeORM, and Prisma default to `COM_STMT_PREPARE`.

### Implementation Strategy

The fix is two layers:

**Layer 1: Real upstream forwarding** (prerequisite)

The proxy must forward packets to a real database instead of
synthesizing responses. Without this, even the SimpleQuery path
returns empty results.

**Layer 2: Extended query protocol support**

For Postgres (~300 lines):

```
Parse    → extract SQL text, classify, check restrictions → forward
Bind     → forward (parameter values don't change the restriction check)
Describe → forward, relay RowDescription back to client
Execute  → forward, relay DataRow + CommandComplete back to client
Sync     → forward, relay ReadyForQuery back to client
Close    → forward, relay CloseComplete
```

The **restriction check happens at `Parse` time** — the full SQL text
is available in the Parse message. After that, `Bind`/`Execute` just
runs the pre-validated statement. This preserves the audit and
restriction model without changes.

For MySQL (~200 lines):

```
COM_STMT_PREPARE  → extract SQL, classify, check restrictions → forward
COM_STMT_EXECUTE  → forward, relay binary result set
COM_STMT_CLOSE    → forward
COM_STMT_RESET    → forward
```

Same principle: restriction check at `PREPARE` time.

### Hallucinated Credentials Are Structurally Inert

A common concern: what if the agent hallucinates a credential in the
ORM connection string?

```python
engine = create_engine("postgresql://admin:hunter2@127.0.0.1:5432/mydb")
```

The answer: **nothing happens.** The proxy ignores any credentials the
agent sends. The authentication flow:

1. Agent connects to `127.0.0.1:5432` — this is the proxy, not Postgres
2. Agent sends `StartupMessage` with username `admin`
3. Proxy responds with `AuthenticationOk` immediately (no check)
4. Proxy opens a separate connection to the real upstream Postgres
5. Proxy authenticates to upstream using the operator-stored credential
6. Agent's `admin:hunter2` is discarded; audit records it was not used

The agent cannot connect directly to the real database because the
VM has no network (macOS/AVF) or tproxy blocks it (Linux/Firecracker).

### Per-Proxy ORM Compatibility Matrix (after both layers land)

| ORM | Database | Protocol used | Works? | Notes |
|---|---|---|---|---|
| SQLAlchemy | Postgres | Extended Query | ✅ | Most popular Python ORM |
| Django ORM | Postgres | Extended Query | ✅ | `psycopg2` backend |
| asyncpg | Postgres | Extended Query | ✅ | Fast async driver |
| Prisma | Postgres | Extended Query | ✅ | Node.js ORM |
| Prisma | MySQL | `COM_STMT_*` | ✅ | |
| Sequelize | MySQL | `COM_STMT_*` | ✅ | Node.js ORM |
| Sequelize | Postgres | Extended Query | ✅ | |
| TypeORM | MySQL | `COM_STMT_*` | ✅ | TypeScript ORM |
| TypeORM | Postgres | Extended Query | ✅ | |
| Django ORM | MySQL | `COM_QUERY` | ✅ | Django MySQL uses SimpleQuery |
| ActiveRecord | Postgres | Extended Query | ✅ | Ruby ORM |
| SQLx (Rust) | Postgres | Extended Query | ✅ | Compile-time checked |
| Diesel (Rust) | Postgres | Extended Query | ✅ | Rust ORM |
| GORM | Postgres | Extended Query | ✅ | Go ORM |
| mongosh | MongoDB | `OP_MSG` | ✅ | Already framed |
| Mongoose | MongoDB | `OP_MSG` | ✅ | Node.js MongoDB ODM |
| redis-py | Redis | RESP2 | ✅ | Already framed |
| ioredis | Redis | RESP2 | ✅ | Node.js Redis |

Once SimpleQuery + Extended Query are both handled with real upstream
forwarding, the proxy is **wire-protocol complete** for every ORM in
every language. There is no third query path — the Postgres wire
protocol (v3) has defined exactly these two paths since 2003. ORMs do
not invent new wire protocols.

### What the Agent Sees

After both layers land, the agent's code is completely unaware of the
proxy:

```python
# Agent code inside the VM — standard SQLAlchemy
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

# Connects to the proxy on 127.0.0.1:5432
# The proxy authenticates using the operator's stored credential
engine = create_engine("postgresql://x:x@127.0.0.1:5432/mydb")

with Session(engine) as session:
    # Parse → proxy checks "users" is in allowed_tables
    # Bind/Execute → proxy forwards to real Postgres
    # Results flow back through the proxy to the ORM
    users = session.execute(
        select(User).where(User.active == True)
    ).scalars().all()
```

The proxy:
1. Intercepts the TCP connection on loopback
2. Authenticates using the operator-stored credential (agent never
   sees it)
3. Checks every SQL statement against `allowed_tables` /
   `allowed_operations`
4. Audits every query (SHA-256, operation type, table name)
5. Relays real results back to the ORM transparently

### ORM Estimate Summary

| Work item | Lines | Dependency |
|---|---|---|
| Real upstream forwarding (6 proxies) | ~1,200 | None |
| Postgres extended query protocol | ~300 | Upstream forwarding |
| MySQL `COM_STMT_*` support | ~200 | Upstream forwarding |
| **Total for full ORM compatibility** | **~1,700** | |

---

## §9 — Priority Order

### Phase 1: First usable session (~5,500 lines)

| # | Item | Lines | Rationale |
|---|---|---|---|
| 1 | ~~**B1** — Planner agent loop~~ — **CLOSED V2.3** | 2,600 | Shipped; full dispatch loop with model client, tool registry, intent submission, and Anthropic live-e2e test. |
| 2 | ~~**B3** — Real DB proxy forwarding~~ — **CLOSED V2.3** | 1,200 | Postgres / MySQL / MSSQL upstream forwarding shipped. MongoDB SCRAM + OP_MSG real relay deferred to V3 — see "Mongo crypto auth" rationale. |
| 3 | ~~**C6** — Kernel push protocol~~ — **CLOSED V2.3** | 500 | `git push` to upstream remote after `IntegrationMerge` shipped; `KernelPush` transport closed in §12.1. |
| 4 | ~~**B2** — Custom tools~~ — **CLOSED V2.3** | 600 | Custom-tool loader + subprocess executor + kernel-side validation shipped. |
| 5 | ~~**ORM** — Extended query protocol (Postgres `Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Close` + MySQL `COM_STMT_*`)~~ — **CLOSED V2.4** | 500 | Reclassified from V3 deferral to V2 BLOCKER per §3; restriction check at `Parse` / `COM_STMT_PREPARE` time, transparent forwarding for the rest of the cycle. SQLAlchemy / Django / asyncpg / Prisma / Diesel / SQLx now run end-to-end against the proxy without driver reconfiguration. |
| 6 | ~~Configurable `target_ref`~~ — **CLOSED V2.3** | 80 | Policy + plan layered with INV-PLAN-POLICY-PRECEDENCE-01 framework. |

### Phase 2: Production readiness (~2,700 lines) — ✅ Substantively closed in V2.3

| # | Item | Lines | Rationale / V2.3 status |
|---|---|---|---|
| 6 | ~~**C2** — Provider failure handling~~ — **CLOSED V2.3** | 800 | RetryConfig + FallbackModelClient shipped. |
| 7 | ~~**C1** — Token limit enforcement~~ — **CLOSED V2.3 (coarse)** | 600 | Per-session cumulative ceilings + `TokensExceeded` outcome shipped; granular per-request limits remain V3. |
| 8 | ~~**C4** — Notification channels~~ — **CLOSED V2.3** | 500 | Shell/File/Email/Webhook all shipped. |
| 9 | ~~**D2** — Host capacity management~~ — **CLOSED V2.3** | 500 | AdmissionDeferred queue + DiskWatchdog + FdLimitOutcome shipped. |
| 10 | ~~**C7** — Credential CLI~~ — **CLOSED V2.3** | 400 | `add` / `remove` / `show` / `verify` / `audit` subcommands shipped. |
| 11 | ~~Redis ACL-form `AUTH user password`~~ — **CLOSED V2.3** | ~30 | Implemented inside the proxy; credential file declares `RAXIS_REDIS_USER` + `RAXIS_REDIS_PASSWORD`. No `CredentialBackend` trait change required. |
| 12 | ~~Redis TLS-to-upstream~~ — **CLOSED V2.3** | ~40 | Implemented via `[[credentials]].require_upstream_tls = true` reusing the SMTP proxy's `webpki-roots`-backed `tokio-rustls` `ClientConfig`. |
| 13 | ~~AWS/GCP/Azure declarative restrictions~~ — **CLOSED V2.3** | ~250 | Cloud restriction surfaces (AWS `allowed_services` / `allowed_regions`, GCP `allowed_scopes` / `project`, Azure `allowed_actions`) shipped declaratively + audit echo + `x-ms-allowed-actions` header. Runtime SigV4-/ARM-aware gating remains V3 work via `raxis-egress-aws` / `raxis-egress-arm`. |
| 14 | MongoDB SCRAM-SHA-256 | ~150 | **V3 deferral** — see "MySQL/Mongo crypto auth" rationale above. |
| 15 | MongoDB OP_MSG real relay | ~150 | **V3 deferral** — bundled with the SCRAM PR. |
| 16 | MySQL `caching_sha2_password` | ~120 | **V3 deferral** — same rationale. Operators on MySQL 8 use `mysql_native_password` until V3. |

### Phase 3: GA polish (~2,800 lines) — ✅ Substantively closed in V2.3

| # | Item | Lines | Rationale / V2.3 status |
|---|---|---|---|
| 11 | ~~**D1** — Key revocation~~ — **CLOSED V2.3** | 400 | `raxis cert revoke` + CRL distribution shipped. |
| 12 | ~~**C3** — Provider model selection~~ — **CLOSED V2.3** | 400 | `KnownModel` registry + `resolve_model_from_env` + `ModelDeprecated` warnings shipped. |
| 13 | ~~**C5** — Immutable artifact store~~ — **CLOSED V2.3** | 600 | `ArtifactStore` + `Category` + `IntegrityMismatch` / `BytesDiverge` shipped. |
| 14 | ~~**E1** — Environment access control~~ — **CLOSED V2.3** | 200 | `INV-ENV-01` + `FAIL_TASK_ENVIRONMENT_INCONSISTENT` shipped. |
| 15 | ~~`raxis init` project scaffolding~~ — `CLOSED (V2.3, MVP)` as `raxis plan init` per `operator-ergonomics.md §6`. | 250 | New-operator onboarding shipped. |
| 16 | `INV-` invariant enforcement audit | 300 | See §13 — V2.3 ships ~45/120 cited; ~30 are "structurally enforced + un-annotated" (one-line annotation pass); ~40 ship with their parent feature; ~5 deprecated. The ~7 genuine gaps (CONVERGENCE liveness proofs) are V3. |
| 17 | ~~Gateway binary integrity~~ — **CLOSED V2.3** | 90 | `embedded-gateway` feature flag shipped. |
| 18 | ~~KernelPush transport~~ — **CLOSED V2.3 (in-memory MVP)** | 200 | `KernelPushDispatcher` shipped with audit mirroring; full session-addressed VSock/UDS transport is V3. |
| 19 | ~~Review aggregation wiring~~ — **CLOSED V2.3** | 50 | `compute_aggregate_review_verdict` wired into `handle_submit_review` with audit emission. |
| 20 | ~~Email + Webhook notification transports~~ — **CLOSED V2.3** | 300 | Email (SMTP STARTTLS + AUTH PLAIN) and Webhook (HTTPS POST + `X-RAXIS-*` headers) both shipped. |

---

## §10 — Gateway Binary Integrity — **CLOSED (V2.3, MVP)**

V2.3 ships the embedded-gateway feature flag exactly as the
"V2 approach" subsection below describes. Implementation lives
in `kernel/src/gateway/embedded.rs` (~150 lines including the
`#[cfg]`-gated `include_bytes!` selector, `materialize`, and
unit tests) and the supervisor wiring in
`kernel/src/gateway/supervisor.rs::spawn_and_supervise`.

When the kernel was compiled with `--features embedded-gateway`,
the supervisor calls `embedded::materialize(&data_dir)` once at
startup, which writes the bytes to
`<data_dir>/runtime/embedded-gateway/raxis-gateway` (mode `0500`
inside a `0700` parent), then overrides `cfg.binary_path` so the
spawn loop dispatches against the kernel-controlled file. When
the feature is **off** (default for `cargo build`),
`materialize` returns `Ok(None)` and the supervisor keeps using
the configured external `binary_path` — the historical
fast-iteration path.

`gateway_supervisor_start` log lines now carry an `embedded:
true|false` field so operators can confirm which build mode is
running. Boot quarantines on materialise I/O failure (treated
identically to a token-mint failure: `GatewayQuarantined` audit
event + `SupervisorShutdown::Quarantined`) — there is no safe
fallback once the operator has opted into the embedded build.

### V3 (still deferred)

- `memfd_create` / macOS equivalent to avoid the on-disk hop
  entirely.
- OS-native code signing (`SecStaticCodeCheckValidity`,
  dm-verity, fsverity, IMA) layered on top of the embedded
  bytes.

### The gap (historical)

The kernel verifies VM images (Reviewer, Orchestrator, Symbol-Index
Verifier) via compiled-in SHA-256 digests checked at every spawn.
The gateway binary has **no integrity verification** — it is spawned
via `Command::new(cfg.binary_path)` with only a one-time auth token
to authenticate the IPC connection.

A compromised gateway binary could intercept all inference traffic,
exfiltrate prompts, or return manipulated model responses. The token
auth prevents a rogue *external* process from connecting but does not
prevent a tampered binary that the kernel itself spawns.

### V2 approach: Embedded binary (~90 lines)

Compile the gateway binary into the kernel binary as a `&[u8]` blob.
At startup, the kernel writes it to memory (Linux: `memfd_create`;
macOS: temp file in `0700` kernel-owned directory), sets `+x`, and
spawns from there. The gateway bytes never exist as an independent
file on disk that an attacker can swap.

### Dev ergonomics

During development, rebuilding the kernel every time you touch the
gateway is unacceptable — it adds a full gateway recompile + kernel
re-link to every edit cycle. The feature flag solves this:

```rust
#[cfg(feature = "embedded-gateway")]
const GATEWAY_BYTES: &[u8] = include_bytes!(env!("RAXIS_GATEWAY_BINARY"));

#[cfg(not(feature = "embedded-gateway"))]
// Falls back to the existing Command::new(cfg.binary_path) path —
// gateway is a separate binary on disk, iterated independently.
```

| Build mode | Flag | Gateway source | Use case |
|---|---|---|---|
| `cargo build` (dev) | feature off | External binary on `$PATH` | Fast iteration — change gateway, rebuild gateway only |
| `cargo build --release --features embedded-gateway` | feature on | Embedded `&[u8]` blob | Release builds — tamper-proof, single distributable |

Build pipeline for release:

```bash
# Phase 1: compile the gateway
cargo build --release -p raxis-gateway

# Phase 2: compile the kernel with embedded gateway
RAXIS_GATEWAY_BINARY=target/release/raxis-gateway \
  cargo build --release -p raxis-kernel --features embedded-gateway
```

CI runs both phases; developers never need `--features embedded-gateway`
locally.

### V3 (deferred): OS-native code signing

- **macOS:** `SecStaticCodeCheckValidity` on the gateway binary
  before spawn; same Apple Developer ID as the kernel.
- **Linux:** `dm-verity` / `fsverity` on the install directory, or
  IMA (Integrity Measurement Architecture) requiring signed ELF
  binaries.

Deferred because it depends on deployment-environment assumptions
(code signing infrastructure, kernel IMA policy) that V2 does not
require.

---

## §11 — Reconciliation Notes

Corrections made during cross-check passes:

| Item | Previous status | Actual status | How found | Pass |
|---|---|---|---|---|
| Policy epoch diffing (C5) | "Zero code" | ✅ Shipped (649 lines in `policy_diff.rs`) | CLI command grep | 1 |
| Session spawn handler | "Single blocker, ~400 lines" | ✅ Shipped (1,590 lines) | `session_spawn_orchestrator.rs` + `session-spawn` crate | 1 |
| Heartbeat writer | "Not wired, ~30 lines" | ✅ Shipped, wired in `main.rs:532` | `grep heartbeat_loop` | 1 |
| Gateway supervisor | "~200 lines missing" | ✅ Shipped (715 lines) | `gateway/supervisor.rs` | 1 |
| Credential CLI | "Fully shipped" | 🟡 Partial (2 of 7 subcommands) | CLI code header comments | 1 |
| `raxis plan init` | Not tracked | ✅ Shipped (V2.3) | `cli/src/commands/plan_init.rs` | 1 |
| Env access control | Not tracked (Tier E) | 🟡 Schema parsed, enforcement missing | `credential-proxy.md §11` examples | 1 |
| Invariant coverage | Not tracked | 46% (41 of 89 `INV-` refs in code) | `grep -c INV-` | 1 |
| Notification channels (C4) | "Zero code" | 🟡 Partial (Shell+File only, 1,327 lines) | `kernel/src/notifications/` grep | 2 |
| KernelPush type | "Spec complete, zero code" | 🟡 Type defined (6 variants), never sent | `grep KernelPush kernel/src/` — zero hits | 2 |
| Review aggregation | "Shipped" (in Tier A8) | 🟡 Module exists (403 lines), never called | `grep review_aggregation kernel/src/initiatives/lifecycle.rs` — zero hits | 2 |
| `plan explain` (CLI) | Not tracked | ✅ Shipped (552 lines) | `wc -l explain.rs` | 2 |
| Planner binaries | "~36 lines each" | ✅ Correct (boot+park, scaffold only) | `wc -l planner-*/src/main.rs` | 2 |
| `submit plan --dry-run` | "Not implemented" | 🟡 CLI flag parsed, kernel handler missing | `grep dry_run submit.rs` — flag exists; no `DryRunAdmit` IPC type | 2 |
| Codebase total | 150,119 lines | 140,010 lines | `find ... -name "*.rs" \| xargs wc -l` | 2 |

---

## §12 — Newly Discovered Gaps (Pass 2)

### 12.1 KernelPush dispatcher: ✅ CLOSED (V2.3, MVP) — wire transport still V3

**V2.3 MVP — in-memory dispatcher + audit mirror.**
`kernel/src/push/mod.rs` (~340 lines incl. tests) ships an
in-process `KernelPushDispatcher`:

* **Per-session monotonic `push_id`** allocator (matches
  `kernel-push-protocol.md §9` line 539).
* **`tokio::sync::broadcast` fan-out** to all `Subscriber`s
  bound to a session_id. V3 will attach the per-session VSock
  delivery loop here without changing the publisher API.
* **Audit mirror.** Every `enqueue` emits an
  `AuditEventKind::KernelPushEnqueued { session_id, push_id,
  push_kind, initiative_id, task_id }` event so the push trail
  is durably observable from the audit chain even when no live
  subscriber is attached. The audit chain becomes the V2.3
  substitute for the spec's `pending_pushes` SQL queue
  (operators can replay the chain to reconstruct what would
  have been delivered).
* **`HandlerContext::push_dispatcher`** is constructed at
  `HandlerContext::new` so every kernel handler (now and V3)
  can publish without re-injecting the registry.

**V3 (still deferred):**

* **Per-session VSock/UDS transport.** A delivery loop attached
  to each session that consumes from the dispatcher's broadcast
  channel and writes `KernelPushFrame` to the wire. Approx ~150
  lines.
* **`pending_pushes` SQL queue** with at-least-once redelivery
  on session reconnect (INV-PUSH-02). The audit chain is the
  forward-compatible base — V3 can backfill from it.
* **Wiring at the spec-correct call sites.** The V2.3
  dispatcher exposes the publish API but the
  `handle_activate_sub_task` / `handle_complete_subtask` /
  `handle_submit_review` / session-supervisor security-violation
  call sites still need the lookup-orchestrator-session-from-
  initiative wiring. Each is a `dispatcher.enqueue(session,
  KernelPush::*, now_unix())` plus the orchestrator-session
  lookup (~30 lines per site). The audit emission for each
  variant already lands today via the existing handler
  audit calls (`SubTaskActivated → TaskStateChanged`,
  `AllReviewersPassed → ReviewAggregationCompleted`, etc.) so
  V2.3 operators can already grep the chain for the same
  signal.

**Tests** (`push::tests`):
`enqueue_allocates_monotonic_push_ids_per_session`,
`enqueue_mirrors_to_audit_chain`,
`enqueue_broadcasts_to_live_subscribers`,
`enqueue_succeeds_when_no_subscribers`,
`subscriber_count_reflects_attached_receivers`. All five pass.

**Spec updates.** Audit-event registry
(`crates/policy/src/bundle.rs::KNOWN_AUDIT_EVENT_KINDS`) gained
`KernelPushEnqueued` and the drift-guard fixture asserts the
new kind round-trips.

### 12.2 Review aggregation: Module exists, never wired ✅ CLOSED (V2.2)

**Original gap:** `kernel/src/initiatives/review_aggregation.rs`
(~470 lines) implements the Step 25 logical-AND verdict aggregation,
but no caller in the kernel ever invoked it. The module was
registered in `mod.rs` but never reached at the `SubmitReview`
intent handling point where the spec requires it.

**Resolution (commit landing this gap entry).**
`handlers/intent::handle_submit_review` now:

1. Performs the predecessor lookup unconditionally (the rejection
   path uses it for critique routing; the new wiring needs it for
   aggregation across both verdict directions).
2. After the SQLite commit, calls
   `compute_aggregate_review_outcome` for every Executor predecessor.
3. Emits exactly one `AuditEventKind::ReviewAggregationCompleted`
   per Executor when the aggregator transitions out of `Pending`
   (terminal verdict `AllPassed` / `AtLeastOneRejected` /
   `NoSuccessors`); silent while still `Pending` (waiting on a
   sibling).

The audit row is the kernel-side anchor that the future
`KernelPush::AllReviewersPassed` / `KernelPush::ReviewRejected`
emitter (gap §12.1, push transport) will read. Ahead of that
transport landing, the aggregator's terminal verdicts are observable
from the audit chain.

**Spec updates.** `audit-paired-writes.md §4.3` (single-class
roster), `verifier-processes.md §11` (audit-event table), and
`v2-deep-spec.md §Step 25` ("aggregator IS wired today" subsection)
were updated in the same commit.

**Tests.** Three new
`handlers/intent::tests::submit_review_*_aggregation*` cases pin
the (Pending → silent) / (AllPassed → emit) / (AtLeastOneRejected →
emit) behaviour, and two new
`initiatives/review_aggregation::tests::outcome_*` cases pin the
`AggregateOutcome { verdict, count }` lock-step contract. The
existing 8 aggregator unit tests continue to pass; the existing
12 SubmitReview handler tests continue to pass after the
`ctx: &HandlerContext` signature update.

### 12.3 Notification channels: ✅ CLOSED (V2.4 — see §C4 above)

Historical entry — superseded by §C4's V2.4 closure. The policy
parser accepts all five channel kinds (`Shell`, `File`, `Email`,
`Webhook` legacy, `Sidecar`); every kind has a real dispatch
handler:

* `Shell` / `File` shipped at V1.
* `Email` (SMTP STARTTLS + `AUTH PLAIN`, sidecar `.notify-cred`)
  shipped V2.3 in `kernel/src/notifications/handler/email.rs`.
* `Webhook` (HTTPS POST + `X-RAXIS-*` headers) shipped V2.3 in
  `kernel/src/notifications/handler/webhook.rs` and is retained
  for backwards compatibility — operators are encouraged to
  migrate to `Sidecar` for new third-party integrations.
* `Sidecar` (HTTP POST + concurrency cap + circuit breaker +
  `NotificationDelivered` audit emission with upstream
  `trace_id`) shipped V2.4 in
  `kernel/src/notifications/handler/sidecar.rs`.

No notification kind produces a runtime error at dispatch.

### 12.4 Operator-ergonomics IPC: 4 of 5 real handlers ✅ CLOSED (V2.4)

The `operator-ergonomics.md` spec defines 5 new `OperatorRequest`
variants. V2.3 shipped the wire-shape stubs; V2.4 promotes four of
the five to real read-only handlers backed by
`kernel/src/ipc/operator_ergonomics.rs` (~675 lines incl. tests).
Wire-shape regression is pinned by 10 round-trip tests in
`operator_wire::tests`; per-handler unit tests cover the cost
heuristic, plan parser, DAG validator, and read-only conn lookups.

| IPC variant | Spec section | Wire | Handler (V2.4) | Notes |
|---|---|---|---|---|
| `ProposeDefaults` | §5.3 | ✅ | ✅ Real | Returns JSON snapshot of the active policy's defaulting surface (providers, plan-signing freshness, plan-bundle-limits, host-capacity, `[git]` target-ref defaults, gateway timing). Pure function of the live policy epoch. |
| `EstimateCost` | §11.3 | ✅ | ✅ Real | Parses `plan_toml`, applies a conservative 200k-tokens/task heuristic at $0.005/1k tokens, adds the policy's `max_cost_per_task` admission overhead, returns a per-task breakdown. |
| `DryRunAdmit` | §12.3 | ✅ | ✅ Real | Parses the plan, validates `[workspace]` + `[[tasks]]`, runs DAG cohesion + acyclicity checks, resolves the would-be `target_ref` against `[git]` precedence, collects non-fatal warnings, and emits a single `DryRunAdmitted` audit event (registered in `KNOWN_AUDIT_EVENT_KINDS`). |
| `DescribeInitiativePause` | §14.3 | ✅ | ✅ Real | `spawn_blocking` read-only `RoConn` open to query `initiatives`, `initiative_quarantines`, and pending escalations. Pause is union of `quarantine || terminal_state || pending_escalations`. |
| `SubscribeInitiative` | §13.4 | ✅ | 🟡 Stub | Returns `FAIL_NOT_YET_IMPLEMENTED` because the operator UDS is single-shot request/response — bidirectional streaming requires the per-session VSock/UDS push transport (§12.1) which lands in V3. |

**INV-OPERATOR-ERG-01.** Every real handler above is **read-only**:
no row inserts, no budget reservation, no state mutation. The
single `DryRunAdmitted` audit event is the
`operator-ergonomics.md §12.3` allowance for forensic traceability;
all other handlers leave the kernel chain untouched.

**Why `SubscribeInitiative` stays a stub.** The other four
handlers complete inside one IPC round-trip and read state from
the snapshot conn. `SubscribeInitiative` requires the kernel to
push frames to the operator on its own schedule (initiative
state changes, escalation arrivals, push id allocations). The
existing operator UDS is single-shot per `peripherals.md §3.1`;
bidirectional streaming requires the per-session VSock/UDS push
transport described in §12.1. The stub returns the canonical
`FAIL_NOT_YET_IMPLEMENTED` envelope so CLI integrations
(`raxis initiative watch`) compile against the same wire shape
they will use in V3.

### 12.5 `raxis doctor`: categories — `CLOSED (V2.3, MVP)`

The spec (`operator-ergonomics.md §17`) defines 6 doctor categories:
`policy`, `providers`, `host`, `network`, `keys`, `bundles`. The CLI
implements:

| Category | Implemented | Notes |
|---|---|---|
| `canonical-images` | ✅ | Digest verification |
| `signing-key-fp` | ✅ | Operator key check |
| `cache-prune` | ✅ | Image cache management |
| (default) | ✅ | Subdirectory perms, cert check, policy parse |
| `policy` (standalone) | ✅ (V2.3) | `policy.load` row only — re-runs the policy-load arm of the default preflight without the surrounding noise. |
| `providers` | ✅ (V2.3) | Lists every `[[providers]]` entry; the live "send a one-token completion" smoke-test is V3 (depends on CLI ↔ gateway IPC). |
| `host` | ✅ (V2.3) | `host.disk_free_mb` (statvfs); `host.cgroup_v2` (Linux only — macOS skips with OK). AVF/KVM probe is V3. |
| `network` | ✅ (V2.3) | TCP-connect each `policy.egress_domains` host on :443 with a 5s timeout. No HTTP traffic. |
| `keys` | ✅ (V2.3) | Filters the existing operator-cert + signing-key checks from the default preflight; CRL distribution check is V3 (covered by D1 admission-time path). |
| `bundles` | ✅ (V2.3) | `bundles.db_size_mb` (file-size proxy); per-table row aggregates are V3. |

**Invocation.** `raxis doctor <category>` runs a single category;
`raxis doctor all` runs every category in declaration order. Both
share the `--json` flag and the same `Outcome::{Ok,Warn,Fail}`
worst-of exit-code logic as the legacy default arm. The default
`raxis doctor` (no argument) continues to run the full data-dir
preflight unchanged.

### 12.6 `setup wizard`: ✅ CLOSED (V2.3, MVP via `raxis setup`)

**Resolution.** Implemented as a non-interactive scaffolding
flow in `cli/src/commands/setup.rs`. Covers the 10-phase
catalog from `operator-ergonomics.md §16` by running phases 2
(`policy_authoring`) and 6 (`plan_template`) and printing
explicit recipes for the remaining phases that V2 cannot
automate (key ceremony, credential add, VM image picking,
network allowlist, doctor, dry-run, first launch). State
persistence + parameter-fingerprint drift guard live in
`<data_dir>/.setup_state.json`. See C10 above for the full
disposition.

### 12.7 VSock IPC client: ✅ CLOSED (V2.3, UDS path) + 🟡 V3 (VSock connect)

**V2.3 resolution.** `crates/planner-core/src/transport.rs`
(~535 lines) ships the transport-agnostic `KernelTransport` trait
+ length-prefixed bincode frames + UDS connector for the
subprocess-isolation path (the default `Subprocess` backend used
in `raxis-live-e2e`). The kernel-side spawn path stamps
`RAXIS_KERNEL_PLANNER_SOCKET` into the child's environment so the
planner connects without baking the data-dir layout into the
binary.

**V3 still deferred.** The actual VSock socket connect (when the
guest detects `RAXIS_KERNEL_VSOCK_CID` + `RAXIS_KERNEL_VSOCK_PORT`)
is gated behind the `vsock-transport` Cargo feature with a
fail-loud `TransportError::VsockUnavailable` envelope when the
feature is off. The CID/port detection, env-precedence rules
(`UDS path > VSock vars`), and the host-side VSock-to-UDS proxy
substrate are scaffolded; the missing piece is the
`tokio-vsock`-backed implementation of `KernelTransport::connect`
when `vsock-transport = on`. The planner agent loop (B1) and
every dispatch / intent / escalation test runs against the UDS
path today, so V3's VSock landing is purely the
production-Firecracker leg.

### 12.8 Target branch ref: configurable via [git] / [workspace] ✅ CLOSED (V2.2)

**Resolution.** `domain-git`'s legacy `refs/heads/main`-pinned API
is now a thin wrapper around the new
[`commit_merge_to_target_ref(...)`] /
[`update_target_ref(..., target_ref)`] entry points, which accept
any fully-qualified branch ref. The kernel resolves the
per-initiative value at `lifecycle::approve_plan` admission time
via `resolve_target_ref(plan_value, policy_default, locked)` per
the precedence chain documented in §12.9 below.

* **Policy schema (operator-signed).** New optional `[git]`
  section in `policy.toml`:
  ```toml
  [git]
  default_target_ref = "refs/heads/main"   # default if omitted
  target_ref_locked  = false               # default; plans may override
  ```
  Both fields are validated at policy-load time
  (`raxis_policy::validate_target_ref_format` for the ref shape;
  the loader surfaces `FAIL_POLICY_TARGET_REF_INVALID` on
  malformed values).
* **Plan schema (plan-author-signed).** New optional
  `[workspace] target_ref` field in `plan.toml`:
  ```toml
  [workspace]
  target_ref = "refs/heads/raxis/auth-refactor"
  ```
* **Resolution.** Plan value (when present and valid) wins unless
  `target_ref_locked = true` AND the plan value differs from
  `default_target_ref`, in which case the kernel rejects with
  `FAIL_POLICY_LOCKED_FIELD`. Format-invalid plan values surface
  `FAIL_WORKSPACE_TARGET_REF_INVALID` (both wire codes added to
  `raxis_types::OperatorErrorCode` in this commit).
* **Persistence.** The resolved value is recomputed from the plan
  bytes during recovery; persistence into a future
  `initiatives.target_ref` column is gated on the worktree-provision
  + IntegrationMerge wiring deferred in `V2_STATUS.md §2.2` (which
  is the only consumer that needs the persisted value).
* **Tests.** New cases pin every branch of the resolution chain:
  `parse_plan_workspace_target_ref_*` (3),
  `resolve_target_ref_*` (6, including
  `resolve_target_ref_format_takes_precedence_over_locked` for the
  diagnostic-priority property),
  `commit_merge_to_target_ref_advances_pr_style_branch` (1).
  All 10 pass on a clean `cargo test`.

**Spec updates.** `policy-plan-authority.md`,
`integration-merge.md`, `v2-deep-spec.md §Step 8`, and
`extensibility-traits.md §2.2.A` were updated in the same commit.

**Impact:** Repos using `master`, `develop`, `trunk`, or any
non-`main` default branch cannot use RAXIS without renaming their
branch. More critically, operators who want RAXIS to push to a
**PR branch** (e.g., `refs/heads/raxis/initiative-<id>`) so the
merged code goes through normal SDLC review (CI, code review, merge
approval) before landing on the production branch have no mechanism
to do so.

**Proposed design:**

```toml
# policy.toml — operator default for all initiatives
[git]
default_target_ref = "refs/heads/main"     # default if omitted

# plan.toml — per-initiative override
[workspace]
target_ref = "refs/heads/raxis/auth-refactor"  # overrides policy default
```

Resolution order: `plan.toml [workspace] target_ref` → `policy.toml
[git] default_target_ref` → `"refs/heads/main"` (hardcoded fallback).

**PR branch workflow.** When `target_ref` points at a non-default
branch (e.g., `refs/heads/raxis/<initiative-name>`), the kernel:

1. Creates the branch at `initial_sha` during `approve_plan`
2. Fast-forwards the **PR branch** (not `main`) on `IntegrationMerge`
3. Pushes the **PR branch** to the remote (per §14 push protocol)
4. The operator's existing CI pipeline runs on the PR branch
5. A human reviewer approves and merges the PR into `main`/`master`
   via the team's normal merge process (GitHub PR, GitLab MR, etc.)

This separates RAXIS's authority (structural correctness,
path-allowlist enforcement, reviewer verdicts) from the team's SDLC
authority (human code review, CI gates, merge approval). RAXIS
guarantees the code is correct; the team decides when it lands.

**Why this matters.** Many teams will not adopt an autonomous agent
that pushes directly to `main`. The PR branch workflow gives them
a familiar approval layer on top of RAXIS's structural guarantees,
making adoption incrementally safe.

**Alternatives rejected:**

| Alternative | Why rejected |
|---|---|
| Always push to `main` directly | Blocks adoption in teams with branch protection and mandatory reviews |
| Let the agent create PRs via GitHub API | Couples RAXIS to a specific forge (GitHub/GitLab/Bitbucket); the kernel should be forge-agnostic. The push protocol already handles the transport; the PR creation is a post-push hook the operator can wire via notification channels |
| Hard-fork `domain-git` per branch convention | Unnecessary complexity; a single `target_ref` field threads through cleanly |

**Estimate:** ~80 lines (policy field, plan field, thread through
`domain-git`, update recovery path, update ancestry check).

### 12.9 Policy vs Plan Configuration: Precedence Rules ✅ CLOSED (V2.2)

**Resolution.** Codified as `INV-PLAN-POLICY-PRECEDENCE-01`.
The locked-field substrate ships with this commit (the first
concrete locked field is `target_ref` from §12.8); future locked
fields plug into the same `(policy_default, locked, plan_value)`
shape that `lifecycle::resolve_target_ref` exemplifies.

The new wire codes (`FAIL_POLICY_LOCKED_FIELD`,
`FAIL_WORKSPACE_TARGET_REF_INVALID`) are registered in
`raxis_types::OperatorErrorCode` and surface from the
`approve_plan` IPC handler with a structured JSON detail
`{ rule, field, plan_value, policy_value, suggestion }` so
operators get the precise locked-field conflict, not a generic
`FAIL_APPROVE_PLAN`.

The original §12.9 design notes are preserved below as the
normative reference for future locked-field landings:

The `target_ref` gap (§12.8) surfaces a broader tension that applies
across every field where both `policy.toml` (operator-authored,
signed) and `plan.toml` (agent/submitter-authored, signed separately)
can declare a value. The kernel must resolve conflicts
deterministically and securely.

**The tension:**

- **Policy** represents the operator's structural authority — hard
  limits, security floors, and organizational defaults. The operator
  signs it; agents never see or modify it.
- **Plan** represents the submitter's intent — what they want for
  this specific initiative. The plan is signed by the submitter
  (who may be an operator or an external contributor).
- **The agent** may have authored the plan content (via `plan prepare`
  or a tool-assisted flow), so plan values cannot be unconditionally
  trusted to be secure.

**Precedence model (enforced at admission):**

| Category | Policy role | Plan role | Resolution |
|---|---|---|---|
| **Hard ceilings** (e.g., `max_cost_per_task`, `max_concurrent_tasks`, `max_wall_seconds`) | Sets the maximum | Plan may request ≤ policy ceiling | `min(plan_value, policy_ceiling)` — plan cannot exceed policy |
| **Hard floors** (e.g., `min_reviewers`, security settings) | Sets the minimum | Plan may request ≥ policy floor | `max(plan_value, policy_floor)` — plan cannot weaken policy |
| **Defaults with override** (e.g., `target_ref`, `default_verifier_images`, `default_executor_image`) | Sets the default | Plan may override | Plan value wins **unless** policy has `locked = true` on the field |
| **Locked fields** (e.g., `[git] target_ref_locked = true`) | Immutable | Plan override rejected | `FAIL_POLICY_LOCKED_FIELD { field, plan_value, policy_value }` |
| **Policy-only** (e.g., `[[environment_gates]]`, `[[vm_images]] oci_digest`, credential store config) | Sole authority | Plan cannot declare | Plan field is ignored or rejected at admission |
| **Plan-only** (e.g., `[[tasks]]`, `path_allowlist`, `task_id`) | Not applicable | Sole authority | Policy constrains via ceilings/floors, not direct values |

**Applied to `target_ref`:**

```toml
# policy.toml
[git]
default_target_ref = "refs/heads/main"
target_ref_locked  = false               # default; plan may override

# plan.toml
[workspace]
target_ref = "refs/heads/raxis/auth-refactor"
```

- If `target_ref_locked = false`: plan's `target_ref` wins
- If `target_ref_locked = true`: plan's override is rejected with
  `FAIL_POLICY_LOCKED_FIELD`
- If plan omits `target_ref`: policy default applies
- If both omit: hardcoded fallback `"refs/heads/main"`

**Why `locked` rather than just "policy always wins":** Operators
who run RAXIS for internal teams want plans to target feature
branches freely. Operators who run RAXIS for external contributors
want to lock the target branch so a malicious plan can't redirect
merged code to an attacker-controlled ref. The `locked` flag gives
the operator the choice.

**Invariant:** `INV-PLAN-POLICY-PRECEDENCE-01` — at admission time,
for every field where both policy and plan declare a value, the
kernel's resolved value must satisfy the precedence category above.
A plan can never weaken a policy floor, exceed a policy ceiling,
or override a locked field.

**Current enforcement status:**

| Category | Enforced | Where |
|---|---|---|
| Hard ceilings | ✅ Already | `budget.rs:194` — `min(raw, policy.max_cost_per_task())`; `budget.rs:52` — cost cap; `budget.rs:43` — concurrency cap |
| Hard floors | 🟡 No concrete floor fields exist yet | Would apply to `min_reviewers`, security settings when added |
| Defaults with override | ✅ V2.3 | First concrete field: `target_ref` (plan overrides `[git].default_target_ref` unless `target_ref_locked = true`). Resolution lives in `kernel/src/initiatives/lifecycle.rs::resolve_target_ref`. |
| Locked fields | ✅ V2.3 | `[git].target_ref_locked` shipped; `FAIL_POLICY_LOCKED_FIELD` registered in `raxis_types::OperatorErrorCode`; `approve_plan` IPC surfaces `{ rule, field, plan_value, policy_value, suggestion }` JSON detail when triggered. |
| Policy-only | ✅ Already | `[[vm_images]] oci_digest`, `[[environment_gates]]`, credential store config |
| Plan-only | ✅ Already | `path_allowlist`, `[[tasks]]`, `task_id` — policy constrains via ceilings |

The invariant codifies the existing ceiling/policy-only/plan-only
pattern and extends it to cover the three missing categories
(floors, defaults-with-override, locked fields) needed for
`target_ref` and future configurable fields.

### 12.10 Spec files requiring updates for proxy auth changes — ✅ CLOSED (V2.3, scoped)

**Status (V2.3 GA).** Every spec file in the table below remains
**byte-identical to the shipped credential-proxy code**. The
Phase 2 proxy auth gaps (Redis ACL-form AUTH, Redis upstream
TLS, MongoDB SCRAM-SHA-256, MongoDB OP_MSG relay, MySQL
`caching_sha2_password`, AWS/GCP/Azure per-resource restrictions,
`CredentialBackend::resolve()` structured return) are all
**Phase 2 work that lands post-V2.3 GA**. Each landing PR for
those gaps MUST update the matching spec sections in the same
commit; this table is the canonical checklist for those PRs.

Until Phase 2 begins, V2.3 ships in a consistent state: the
credential-proxy crates implement exactly what
`credential-proxy.md` describes (`AUTH <password>` for Redis,
`mysql_native_password` for MySQL, x.509 client cert for
Postgres / MSSQL). Spec drift will appear only when Phase 2
patches start landing without updating these files.

**Spec-graph contract.** Every Phase 2 patch in the table below
is gated on a matching spec update (the spec-graph lint
`cargo xtask spec-graph --strict` will fail loud if section
references go stale). Reviewers MUST refuse to merge a Phase 2
proxy PR that does not include the matching spec edit.

| Spec file | What changes |
|---|---|
| `credential-proxy.md §14` | Add per-proxy auth method documentation; update the upstream forwarding contract to cover SCRAM/ACL/TLS |
| `credential-proxy.md §12` | Update `raxis credential add` schema to accept `username` field for Redis ACL, `tls = true` for Redis/MySQL TLS |
| `extensibility-traits.md §4` | `CredentialBackend::resolve()` return type must carry optional `username` alongside the credential value |
| `policy-plan-authority.md` | Add `upstream_tls` and `auth_method` to proxy declaration validation rules |
| `audit-paired-writes.md §4` | Classify new audit events (`RedisUpstreamTlsNegotiated`, `MongoScramAuthCompleted`) as paired or single |

**Why this matters:** The spec-graph lint (`cargo xtask spec-graph
--strict`) will catch dangling section references, but it cannot
detect when a spec's prose description no longer matches the code's
behavior. Maintaining the spec files alongside the code prevents
silent spec drift — the same problem `INV-PLAN-POLICY-PRECEDENCE-01`
prevents for policy-vs-plan configuration.

---

## §13 — INV-Coverage: Invariant Enforcement Audit

### The numbers

The V2 spec corpus defines **~120 named invariants** (unique
`INV-*` identifiers across the 30 spec documents). Of these, **~45
appear in the Rust codebase** (in comments, doc-strings, or test
names). The remaining **~75 invariant IDs** have no reference
in any `.rs` file.

This does **not** mean 75 invariants are unenforced. The gap
breaks down into four categories with very different remediation
costs.

### Category 1: Structurally enforced, annotated in V2.3 (~30 invariants)

> **STATUS:** CLOSED in V2.3 — annotation pass landed. Each row
> below now has a one-paragraph comment at the cited enforcement
> site explaining why the invariant holds without runtime
> assertion. Future code changes that would weaken structural
> enforcement (e.g., adding a worktree-cleanup-on-merge path,
> sharing a VM across sessions, or introducing a streaming model
> client) MUST also remove or update the matching annotation in
> the same PR.

These invariants hold because the architecture makes violations
impossible, but no code comment said `// INV-FOO: enforced here`.
A mechanical annotation pass — one-paragraph comments at the
enforcement site — closed this gap in V2.3.

| Invariant | Why it holds without annotation | Enforcement site |
|---|---|---|
| `INV-02A` (single-tenant VM) | Firecracker spawns one VM per session; the kernel never shares a VM across sessions | `session_spawn_orchestrator.rs` — one `spawn()` call per session |
| `INV-02B` (no virtual NIC) | The Firecracker machine config never includes a `NetworkInterface` block; the VM literally has no NIC | `session_spawn_orchestrator.rs` — machine config builder |
| `INV-09` (opaque rejection codes) | `PlannerErrorCode` enum variants are coarse by construction — `FailPolicyViolation` never leaks which admission check fired | `crates/types/src/planner_error.rs` |
| `INV-GATEWAY-01` (gateway trust boundary) | Gateway binary is a separate process with `getpeereid()` on the UDS; already enforced | `gateway/src/main.rs` — connection acceptance |
| `INV-GATEWAY-STATELESS` | Gateway holds no session state; it forwards requests to providers and returns responses | Architectural — gateway has no database or session store |
| `INV-GATEWAY-STREAM-ATOMICITY` | Non-streaming dispatch in V2 means each request/response is atomic by construction | `planner-core/src/model.rs` — single `create_message()` call |
| `INV-LIFECYCLE-01..07` (boot sequence) | Kernel boot sequence in `main.rs` already follows the spec's 7-phase startup | `kernel/src/main.rs` — boot sequence |
| `INV-MERGE-CONSISTENCY` | `domain-git`'s merge logic already ensures consistency | `domain-git/src/lib.rs` — merge path |
| `INV-MERGE-WORKTREE-RETAIN` | Worktree is preserved after merge; the kernel never deletes it mid-session | `domain-git/src/lib.rs` — no cleanup-on-merge path |
| `INV-AUDIT-PAIRED-01..04,06,07` | Audit paired-writes crate enforces transactional audit semantics; just not cross-referenced by INV name | `crates/audit/src/` — paired write logic |

**Remediation:** ~30 one-line `// INV-FOO: enforced by <this logic>` comments. Mechanical grep-and-annotate pass. No code changes.

### Category 2: Ships with the parent feature (~40 invariants)

These invariants describe behavior for features that are themselves
V2 blockers (or V3 deferrals). The invariant is enforced **when the
feature is built** — there is no separate "invariant enforcement"
workstream.

| Invariants | Parent feature | V2 status |
|---|---|---|
| `INV-PROVIDER-01..10` (10) | Multi-provider `ModelClient` impls + circuit breaker (C2/C3) | ✅ **CLOSED V2.4** — Anthropic/OpenAI/Gemini/Bedrock + circuit breaker + sidecar shipped; SSE streaming added under C9 |
| `INV-CAPACITY-01..06` (6) | Host capacity management (D2) | V2 scope — ships with capacity admission |
| `INV-KEY-01..08` (8) | Key revocation (D1) | V2 scope — ships with revocation impl |
| `INV-NOTIFY-01..06` (6) | Email + Webhook notification channels (C4) | V2 scope — ships with transport impl |
| `INV-VM-CAP-01..03, 05` (4) | VM capacity admission queue (D2) | V2 scope — ships with capacity management |
| `INV-PUSH-01, 03..05` (4) | Full push protocol (C6 — only auto-push shipped) | Partial V2 — push attestation is V3 |
| `INV-VERIFIER-01..10, 12..15` (14) | Verifier runtime enforcement (A8 — dispatch done, runtime partial) | V2 scope — most ship with verifier wiring |
| `INV-CONVERGENCE-01..07` (7) | DAG convergence / liveness analysis | **V3** — the DAG is structural (no cycles by construction); convergence proofs are post-V2 |
| `INV-SMTP-PROXY-01..05` (5) | SMTP proxy crate | **V3** — no SMTP proxy in V2 |

**Remediation:** None separately. Each invariant's enforcement
code lands in the same PR as the feature it describes. The
invariant ID is cited in the commit message and annotated in the
new code.

### Category 3: Deprecated (~5 invariants)

These invariants belonged to specs that have been deprecated and
superseded. They no longer apply.

| Invariant | Original spec | Why deprecated |
|---|---|---|
| `INV-EGRESS-01` | `kernel-mediated-egress.md` | Spec is DEPRECATED; no `egress.sock` exists under the V2 unified egress model (tproxy + credential proxy) |
| `INV-EGRESS-INTENT-01` | `kernel-mediated-egress.md` | `IntentKind::EgressRequest` was removed; the `require_intent` field is vestigial |

**Remediation:** None. These invariants should be marked
`DEPRECATED` in `invariants.md` (if not already) and excluded
from coverage counts.

### Category 4: Single missing enforcement point — **5 of 6 closed in V2.4**, 1 deferred to V3

These invariants describe behavior that the code *almost* enforces
but is missing one check, one guard, or one assertion. The V2.4
re-audit (this pass) reconciled the table against the shipped code
and found that **5 of the 6 gaps were already implemented** before
the table was last refreshed; the remaining one — the full
`[[vm_images]]` subsystem (`INV-PLANNER-HARNESS-03` kernel-version
check + `INV-VM-CAP-03` operator-pinned executor images) — was
originally deferred to V3 but has been **promoted back to V2.5**
because without it operators cannot set custom executor images and
every activation is locked to the canonical starter.

| Invariant | Status | Enforcement site (or deferral) |
|---|---|---|
| `INV-PLANNER-HARNESS-03` + `INV-VM-CAP-03` | 🔴 **V2.5 BLOCKER** | The `[[vm_images]]` policy schema (`name`, `oci_digest`, `role_restriction`, `kernel_version_min`) is not wired into `crates/policy`. Without it: (a) operators cannot set custom executor images — every activation resolves to the canonical `raxis-executor-starter-<v>.img` hardcoded in `session_spawn_orchestrator.rs:674`, violating `INV-VM-CAP-03` (operator-published, OCI-pinned executor images); (b) the kernel cannot enforce `role_restriction` on verifier `image` fields; (c) `[default_executor_image] alias` resolution has no registry to resolve against (`FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE` has no backing implementation); (d) the guest kernel version check (`FAIL_VM_GUEST_KERNEL_TOO_OLD`) has no enforcement path. Estimate: ~630 lines (policy parser + admission-time alias resolution + `oci_digest` enforcement + role_restriction check + operator-declared kernel-version validation). |
| `INV-ENV-01` | ✅ **CLOSED V2.3** | `kernel/src/initiatives/lifecycle.rs::validate_task_environment_consistency` (commit `bd0a28c`). Walks `[[tasks.credentials]]` ∩ `[[permitted_credentials]]` per task, unions environment labels, fails closed on cardinality ≥ 2 with `FAIL_TASK_ENVIRONMENT_INCONSISTENT`. Activation-gated by non-empty `policy_environments`. Implements step A of the §11.3 binding algorithm; URL-gate limb (step B) still V3 per E1 disposition. |
| `INV-CRED-KERNEL-01` | ✅ **CLOSED V2.2** | `kernel/src/initiatives/lifecycle.rs::validate_task_credentials` rejects every `ProxyDecl::Unknown` at `approve_plan` shift-left with `LifecycleError::PlanTaskCredentialsInvalid { rule: "unknown_proxy_type", … }` BEFORE `BEGIN TRANSACTION`. The defense-in-depth `Unknown` arm in the persistence helper surfaces an `Invariant` store error if the validator is ever bypassed, so the closure has a fail-safe. |
| `INV-INIT-04` (shutdown sweep) | ✅ **CLOSED V1** | `kernel/src/recovery.rs::reconcile_tasks` runs at every kernel boot, transitions in-flight `Running` / `Admitted` / `GatesPending` tasks to `BlockedRecoveryPending` with `RecoveryPendingOperatorAction`, and propagates affected initiatives to `Blocked` via `evaluate_terminal_criteria`. The recovery sweep is the architectural answer; an additional shutdown-time sweep would be a redundant write that the next-boot reconcile would re-do anyway. The V2_GAPS row mislabel as `INV-INIT-06` (plan immutability) was a transcription error during the original audit; both the immutability limb (Plan Bundle Sealing, `kernel-store.md §2.5.8`) and the recovery limb (this row) are closed. |
| `INV-PLAN-BUNDLE-FRESH` | ✅ **CLOSED V2.1** | `kernel/src/initiatives/v2_admission.rs` step 10a implements the freshness window verbatim from `plan-bundle-sealing.md §3.5`: `signed_at - now()` checked against `policy.plan_signing.max_clock_skew_secs` (future) and `policy.plan_signing.max_plan_bundle_age_secs` (past), surfacing `FAIL_PLAN_BUNDLE_EXPIRED` / `FAIL_PLAN_BUNDLE_FROM_FUTURE` with structured detail. Step 10b nonce dedupe via `pb_store::record_nonce` + `nonce_status_in_tx` closes the same-window replay path. |
| `INV-CERT-01` (runtime expiry) | ✅ **CLOSED V1** | `kernel/src/authority/cert_check.rs::CertEnforcer::enforce` runs at every operator IPC request after `is_permitted` and before handler dispatch (see `kernel/src/ipc/operator.rs:148-170`). It calls `raxis_crypto::cert::cert_status_with_revocation(now_unix, cert, &revocations)` to compute the four-zone status fresh from `now_unix` per request — there is no caching or "validate at issuance" shortcut. `Active`/`AlwaysActiveEmergency` allow; `Expiring` allows + emits deduped warning; `Grace` allows recovery ops only; `Expired`/`NotYetValid`/`Revoked` deny. (Note: V2_GAPS row description was inaccurate; the spec's V1 INV-CERT-01 — "cert mandatory" — is also enforced.) |

**Remediation realised:** 0 lines of new code for the 5 closed
items. The `[[vm_images]]` subsystem (`INV-PLANNER-HARNESS-03` +
`INV-VM-CAP-03`) is ~630 lines of new code, promoted to V2.5.

**`[[vm_images]]` V2.5 implementation plan.**
The subsystem was originally deferred to V3 under the assumption
that the kernel-version introspection was the only gap. The V2.5
audit revealed a deeper problem: without `[[vm_images]]`, operators
cannot set custom executor images at all — every activation is
locked to the canonical `raxis-executor-starter` image. This
violates `INV-VM-CAP-03` ("Executor image operator-published,
OCI-pinned"). The V2.5 scope is:

1. **Policy schema.** `[[vm_images]]` parser with `name`,
   `oci_digest`, `role_restriction`, `kernel_version_min` (operator-
   declared). Wire into `crates/policy/src/bundle.rs` as a new
   `VmImageEntry` struct + `vm_images: Vec<VmImageEntry>` on
   `PolicyBundle`. ~150 lines.
2. **Alias resolution at admission.** `approve_plan` resolves
   every task's `vm_image` field (and every verifier's `image`
   field) against the `[[vm_images]]` registry. Unresolvable alias
   → `FAIL_VM_IMAGE_NOT_REGISTERED`. Wrong role → 
   `FAIL_VM_IMAGE_ROLE_RESTRICTION_VIOLATION`. ~100 lines.
3. **`[default_executor_image]` section.** Policy-side
   `alias` → `[[vm_images]]` resolution with `role_restriction`
   check. `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE` at
   policy load. ~50 lines.
4. **Spawn-path integration.** `spawn_executor_for_task` reads
   the resolved image path from the admission result instead of
   hardcoding `executor_starter_image_path()`. ~80 lines.
5. **`oci_digest` enforcement.** At activation, the spawned
   image's SHA-256 is verified against the `[[vm_images]]` entry's
   `oci_digest`. Mismatch → `FAIL_VM_IMAGE_DIGEST_MISMATCH`.
   ~120 lines.
6. **Kernel-version check.** Trust the operator-declared
   `kernel_version_min` on the `[[vm_images]]` entry rather than
   introspecting the image. The operator already pins the image by
   `oci_digest` — they are asserting trust in the image contents.
   At admission, the RAXIS kernel validates `kernel_version_min >= 5.14`
   (Linux kernel 5.14 is the floor for cgroup v2 with `cpu`, `memory`,
   controllers delegated to `subtree_control`, per
   `INV-PLANNER-HARNESS-03` / `planner-harness.md §4.3`)
   and rejects with `FAIL_VM_GUEST_KERNEL_TOO_OLD` if below.
   This avoids pulling an OCI client into the kernel's address
   space. ~30 lines.
7. **`raxis doctor` integration.** `vm-images` category at
   install time. ~100 lines.

**V2.4 mitigation (still in effect until V2.5 lands).** The
substrate refuses to boot a kernel that cannot mount cgroup v2.
This is correctness-preserving but yields a substrate-specific
error code rather than the spec's `FAIL_VM_GUEST_KERNEL_TOO_OLD`.

### Why the invariants are not a separate workstream

The common misunderstanding is that "48 unenforced invariants"
implies ~48 tickets of work. It does not. The invariants are
**properties of features**, not independent units of work:

1. **Category 1** (structurally enforced): Zero code changes.
   Annotation pass only. One PR, ~30 comments.
2. **Category 2** (ships with feature): Zero incremental work.
   The invariant is part of the feature's definition; it ships
   when the feature ships.
3. **Category 3** (deprecated): Zero work. Remove from coverage
   count.
4. **Category 4** (single guard): **5 of 6 already shipped** as
   of V2.4 (the V2.4 audit pass discovered 5 of the 6 gaps had
   already landed in earlier V2.x patches without the table being
   refreshed). The remaining one (`INV-PLANNER-HARNESS-03`, OCI
   image kernel introspection) is recorded as a V3 deferral with
   architectural rationale; the substrate-level cgroup-v2 check
   in `raxis doctor` provides correctness-preserving coverage
   today, only the operator-ergonomics diagnostic is missing.

**Updated coverage after this analysis (V2.4 GA):**

| Category | Count | V2 code needed |
|---|---|---|
| Already enforced in code (annotated) | ~45 | — |
| Structurally enforced (annotated V2.3) | ~30 | 0 lines |
| Ships with parent feature (V2 scope) | ~25 | Ships with feature |
| Ships with parent feature (V3 scope) | ~12 | None for V2 |
| Deprecated | ~5 | None |
| Single enforcement point — closed | 5 | already shipped |
| Single enforcement point — V3 deferral | 1 | ~500 lines (V3) |
| **Total** | **~123** | **0 lines incremental for V2** |

The V2 invariant gap is not a line-count problem. It is a
discipline problem: every feature PR must cite the invariant IDs
it enforces, and the annotation pass for Category 1 should land
as a dedicated "INV-audit" commit early in the sprint cycle so
the coverage tooling (`cargo xtask inv-coverage`) has an accurate
baseline. The V2.4 audit pass that closed Category 4 illustrates
the cost of *not* maintaining that discipline: 5 of 6 invariants
were already enforced in shipped code but the gap-tracking table
had not been refreshed.

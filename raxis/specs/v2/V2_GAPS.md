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
normative markdown. Of these, **17 are fully shipped**, **3 have
infrastructure implemented but application logic missing**, **7 have
complete specifications but zero implementing code**, and **3 have
partial or schema-only implementations**.

| Tier | Count | Status |
|---|---|---|
| A — Fully shipped | 17 | Spec, code, and tests aligned |
| B — Infrastructure done, logic missing | 3 | Real code compiles; key spec behaviors unwired |
| C — Spec complete, zero code | 7 | Full specification documents, no Rust |
| D — Schema/skeleton only | 2 | Store tables or trait stubs exist |
| E — Deferred/partial | 1 | Confirmed post-V2 or partially done |

**Total lines remaining:** ~11,000 lines of Rust to close all V2 gaps
(revised up from ~10,300 after pass 2 identified additional unwired
subsystems).

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

### B1: Planner Agent Loop

**Spec:** `planner-harness.md §3, §10, §14`
**Estimate:** ~2,600 lines

The three planner binaries (orchestrator, executor, reviewer) boot,
parse environment variables, emit a structured boot log, and park on
`SIGTERM`. They do not connect to the kernel, call any model API,
dispatch any tools, or submit any intents.

**What exists (750 lines):**

- `crates/planner-core/` — `BootContext`, `Role` enum, error types
- `crates/planner-orchestrator/src/main.rs` — boot + park
- `crates/planner-executor/src/main.rs` — boot + park
- `crates/planner-reviewer/src/main.rs` — boot + park
- `crates/prompts/` — NNSP (Non-Negotiable System Prompt)

**What's missing:**

| Component | Est. lines |
|---|---|
| VSock frame reader/writer (guest side) | ~200 |
| Model API client (Anthropic/OpenAI/Bedrock via Gateway) | ~400 |
| Base tool registry (`read_file`, `bash`, `edit_file`, `grep_search`, `git_commit`) | ~800 |
| Tool dispatch loop (LLM → parse tool_use → execute → return result) | ~300 |
| Intent submission (executor → kernel via VSock) | ~150 |
| Witness/verdict submission (reviewer → kernel via VSock) | ~150 |
| KSB (Kernel State Block) renderer for LLM context | ~400 |
| Custom tool loader + subprocess executor | ~200 |

**Impact:** No agent can perform any work. This is the single blocker
for a usable RAXIS session.

**Invariant gap:** `planner-harness.md` defines 89 `INV-` invariants.
Only 41 are referenced in Rust code. The missing 48 are overwhelmingly
in the tool-dispatch and agent-loop sections — they become enforceable
once B1 lands.

### B2: Custom Tools

**Spec:** `custom-tools.md` (55KB)
**Estimate:** ~600 lines | **Depends on:** B1

Operator-declared tools in `plan.toml` that extend the agent's
capabilities via subprocess execution. Fully specified with schema
validation, `INV-PLANNER-HARNESS-04` (reviewer ban), and
`policy.toml` hard caps. Zero implementing code.

### B3: Real Database Proxy Forwarding

**Spec:** `credential-proxy.md §14`
**Estimate:** ~1,200 lines

All 6 database proxies (Postgres, MySQL, MSSQL, MongoDB, Redis, SMTP)
parse the wire protocol, classify commands, enforce restrictions, and
emit audit events — but synthesize empty success responses instead of
connecting to a real upstream database.

| Proxy | What to add | Est. lines |
|---|---|---|
| Postgres | `TcpStream::connect`, relay `DataRow`/`CommandComplete` | ~200 |
| MySQL | Connect, relay `ResultSetHeader` + `ColumnDef` + `Row` + `EOF` | ~250 |
| MSSQL | Connect, relay `COLMETADATA` + `ROW` + `DONE` tokens | ~250 |
| MongoDB | Connect, relay `OP_MSG` response bodies | ~150 |
| Redis | Connect, relay RESP2 responses | ~150 |
| SMTP | Connect, relay multi-line SMTP responses, `STARTTLS` | ~200 |

---

## §4 — Tier C: Spec Complete, Zero Implementation

### C1: Token Limit Enforcement

**Spec:** `token-limit-enforcement.md` (52KB)
**Estimate:** ~600 lines

Per-task token budget tracking (input + output tokens). Budget
ceiling enforcement at the gateway level. Token-aware context window
management. Budget exhaustion triggers task failure → escalation.

Zero references to `token_limit`, `TokenBudget`, `context_window` in
any crate.

### C2: Provider Failure Handling

**Spec:** `provider-failure-handling.md` (130KB)
**Estimate:** ~800 lines

Retry budget per provider (exponential backoff with jitter). Fallback
provider chain (`Anthropic → OpenAI → Bedrock`). Circuit breaker
(per-provider error rate threshold). Partial-response recovery
(streaming failure mid-response). `ProviderExhausted` escalation.

Zero references to `provider_failure`, `RetryBudget`,
`fallback_provider`, `circuit_breaker`.

### C3: Provider Model Selection

**Spec:** `provider-model-selection.md` (51KB)
**Estimate:** ~400 lines

Per-task model override (`model = "claude-sonnet-4-20250514"`). Provider
routing based on model availability. Cost-aware routing. Model
deprecation warnings at plan admission.

Zero references to `model_selection`, `ProviderRouting`.

### C4: Email & Notification Channels

**Spec:** `email-and-notification-channels.md` (61KB)
**Estimate:** ~500 lines

**Partially implemented (1,327 lines exist but incomplete):**

The kernel ships a notification subsystem (`kernel/src/notifications/`,
1,327 lines) with `mod.rs`, `sink.rs`, `summary.rs`, and
`handler/file.rs`. However:

| Channel kind | Policy parsed | Handler impl | Status |
|---|---|---|---|
| `Shell` | ✅ | ✅ `file.rs` | Working — runs a shell command |
| `File` | ✅ | ✅ `file.rs` | Working — appends to a log file |
| `Email` | ✅ (parsed) | ❌ No SMTP handler | Parsed at policy load, rejected at dispatch |
| `Webhook` | ✅ (parsed) | ❌ No HTTP handler | Parsed at policy load, rejected at dispatch |

The spec (`email-and-notification-channels.md`) defines Email and
Webhook as the primary operator notification paths. The Shell/File
handlers are viable for dev/CI but insufficient for production
deployments where operators expect Slack webhooks or email.

**Remaining:** ~300 lines (SMTP transport + HTTP webhook transport).

### C5: Immutable Artifact Store

**Spec:** `immutable-artifact-store.md` (25KB)
**Estimate:** ~600 lines

Content-addressed artifact storage (SHA-256 keyed). Per-task
artifact upload/download. Artifact attestation (signed digest binding
artifact to task). Retention policy.

Zero references to `ArtifactStore`, `ImmutableArtifact`.

### C6: Kernel Push Protocol

**Spec:** `kernel-push-protocol.md` (63KB)
**Estimate:** ~500 lines

`git push` to upstream remote after IntegrationMerge. Push
attestation (signed record of what was pushed). Force-push
prohibition enforcement. Branch protection verification.

`domain-git/src/lib.rs` explicitly states: *"It does not push to
upstream remotes"* (line 55). Zero push handler in kernel.

### C7: Credential CLI: `add`, `remove`, `show`, `verify`

**Spec:** `credential-proxy.md §12`
**Estimate:** ~400 lines

The CLI ships `list` and `rotate`. The spec calls for five additional
subcommands:

| Subcommand | Status | Why missing |
|---|---|---|
| `raxis credential add` | ❌ | Requires per-proxy-type validators (Postgres URI, kubeconfig YAML, AWS JSON) |
| `raxis credential show` | ❌ | Overlaps `list --json`; deprioritized |
| `raxis credential remove` | ❌ | Needs orphan-check (reject removal of in-use credentials) |
| `raxis credential verify` | ❌ | Requires credential proxy runtime for live connection test |
| `raxis credential audit` | ❌ | `raxis log` with a filter; convenience alias |

---

## §5 — Tier D: Schema/Skeleton Only

### D1: Key Revocation

**Spec:** `key-revocation.md` (77KB)
**Estimate:** ~400 lines

`operator_certificates` table exists. `operator_cert.rs` types exist.
`cert.rs` CLI command exists (1,125 lines) with cert issuance. Missing:
revocation check at IPC auth time, CRL distribution, `raxis cert
revoke` subcommand, grace-period handling for in-flight sessions.

### D2: Host Capacity Management

**Spec:** `host-capacity.md` (79KB)
**Estimate:** ~500 lines

`MaxConcurrentVms` referenced in policy bundle. Session-spawn
orchestrator notes "deferred to follow-up." Missing:
`AdmissionDeferred` queue (spec §4.2), capacity probe at spawn time,
VM count enforcement, resource reservation lifecycle.

---

## §6 — Tier E: Partially Implemented

### E1: Environment Access Control

**Spec:** `environment-access-control.md` (82KB)
**Estimate:** ~200 lines to close

The `environment` field exists in the credential proxy spec and is
used in examples (`environment = "staging"`). Policy bundle code
references `required_for_environments`. However:

| Feature | Spec section | Code status |
|---|---|---|
| `environment` field on credential declarations | `credential-proxy.md §11` | 🟡 Parsed, not enforced |
| Environment coherence (single task can't mix envs) | `environment-access-control.md §3` | ❌ Not implemented |
| `[[environment_gates]]` in `policy.toml` | `environment-access-control.md §5` | ❌ Not implemented |
| Cross-env isolation (structural) | §6 | ✅ Already works (VMs are isolated) |
| Reserved V2.x fields (`blast_radius`, `require_two_party_sign`) | §9 | ⚪ Future |

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
| `raxis init` | ✅ | ❌ | — | No `init` command; `genesis` covers key ceremony but not project scaffolding |
| `raxis credential add` | ✅ | ❌ | — | Blocked on per-type validators |
| `raxis credential remove` | ✅ | ❌ | — | Needs orphan-check |
| `raxis credential show` | ✅ | ❌ | — | Low priority (`list --json`) |
| `raxis credential verify` | ✅ | ❌ | — | Needs proxy runtime |
| `raxis cert revoke` | ✅ | ❌ | — | Part of D1 (key revocation) |

**CLI total:** 20 of 26 spec'd commands implemented (77%).

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
| 1 | **B1** — Planner agent loop | 2,600 | The single blocker: no agent can work without it |
| 2 | **B3** — Real DB proxy forwarding | 1,200 | Agents need to query real databases |
| 3 | **C6** — Kernel push protocol | 500 | Merged code must reach the remote |
| 4 | **B2** — Custom tools | 600 | Operators need domain-specific utilities |
| 5 | **ORM** — Extended query protocol | 500 | Every ORM in every language works transparently |

### Phase 2: Production readiness (~2,700 lines)

| # | Item | Lines | Rationale |
|---|---|---|---|
| 6 | **C2** — Provider failure handling | 800 | One API hiccup kills sessions without retry/fallback |
| 7 | **C1** — Token limit enforcement | 600 | Cost control for operators |
| 8 | **C4** — Notification channels | 500 | Escalations are silent without this |
| 9 | **D2** — Host capacity management | 500 | Multi-session safety |
| 10 | **C7** — Credential CLI (`add`/`remove`) | 400 | Operator onboarding friction |

### Phase 3: GA polish (~2,800 lines)

| # | Item | Lines | Rationale |
|---|---|---|---|
| 11 | **D1** — Key revocation | 400 | Security (cert rotation) |
| 12 | **C3** — Provider model selection | 400 | Flexibility (per-task model) |
| 13 | **C5** — Immutable artifact store | 600 | Agent artifact persistence |
| 14 | **E1** — Environment access control enforcement | 200 | Prevent cross-env credential mixing |
| 15 | `raxis init` project scaffolding | 200 | New-operator onboarding |
| 16 | Remaining `INV-` invariant enforcement (48 of 89) | 300 | Formal spec compliance |
| 17 | Gateway binary integrity (embedded binary) | 90 | Eliminates file-on-disk tampering surface |
| 18 | KernelPush transport (kernel → agent sessions) | 200 | Pushes are typed but never sent (see §12.1) |
| 19 | Review aggregation wiring | 50 | Module exists but is never called (see §12.2) |
| 20 | Email + Webhook notification transports | 300 | Only Shell/File channels work (see §12.3) |

---

## §10 — Gateway Binary Integrity

### The gap

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
| `raxis init` | Not tracked | ❌ Missing | CLI subcommand grep | 1 |
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

### 12.1 KernelPush: Types defined, transport missing

`KernelPush` is defined in `crates/types/src/push.rs` with 6 variants:
`SubTaskActivated`, `SubTaskCompleted`, `AllReviewersPassed`,
`ReviewRejected`, `SubTaskSecurityViolation`, and the framing type
`KernelPushFrame`.

However, **zero push messages are ever sent.** No function in
`kernel/src/` calls any send/dispatch/push method with a `KernelPush`.
The kernel knows what it *would* push (the types are well-defined and
referenced in doc-comments like `review_aggregation.rs:42` and
`intent.rs:1276`), but the transport layer does not exist.

**What's missing:** A session-addressed push channel (VSock or UDS)
that the kernel writes `KernelPushFrame` messages to when lifecycle
events fire. ~200 lines (session registry + write path).

### 12.2 Review aggregation: Module exists, never wired

`kernel/src/initiatives/review_aggregation.rs` (403 lines) implements
the Step 25 logical-AND verdict aggregation — pure functions that
aggregate reviewer verdicts for an executor task.

But `lifecycle.rs` (the only caller candidate) has **zero references**
to `review_aggregation`. The module is registered in `mod.rs` but
never invoked at the `CompleteTask` or `SubmitReview` intent handling
points where the spec requires it.

**What's missing:** Wire `review_aggregation::aggregate_verdict()` into
the `SubmitReview` handler in `lifecycle.rs`. ~50 lines (call site +
state transition on aggregated result).

### 12.3 Notification channels: Shell + File only

See updated C4 above. The policy parser accepts all four channel kinds
(`Shell`, `File`, `Email`, `Webhook`), but the dispatch handler only
implements Shell and File. Email and Webhook configurations are parsed
at policy load but produce runtime errors at dispatch.

### 12.4 Operator-ergonomics IPC: 5 of 5 V2 handlers missing

The `operator-ergonomics.md` spec defines 5 new `OperatorRequest`
variants. None exist in `crates/types/src/operator.rs` or in the
kernel's IPC dispatcher:

| IPC variant | Spec section | Type defined | Handler |
|---|---|---|---|
| `ProposeDefaults` | §5.3 | ❌ | ❌ |
| `EstimateCost` | §11.3 | ❌ | ❌ |
| `DryRunAdmit` | §12.3 | ❌ | ❌ (CLI flag exists) |
| `SubscribeInitiative` | §13.4 | ❌ | ❌ |
| `DescribeInitiativePause` | §14.3 | ❌ | ❌ |

These are not blockers for Phase 1 (agent loop) but are required for
the operator-ergonomics CLI commands (`plan prepare`, `plan cost-estimate`,
`submit plan --dry-run`, `initiative watch`, `initiative resume`).

### 12.5 `raxis doctor`: categories missing

The spec (`operator-ergonomics.md §17`) defines 6 doctor categories:
`policy`, `providers`, `host`, `network`, `keys`, `bundles`. The CLI
implements:

| Category | Implemented | Notes |
|---|---|---|
| `canonical-images` | ✅ | Digest verification |
| `signing-key-fp` | ✅ | Operator key check |
| `cache-prune` | ✅ | Image cache management |
| (default) | ✅ | Subdirectory perms, cert check, policy parse |
| `policy` (standalone) | ❌ | Covered partially by default run |
| `providers` | ❌ | No live credential smoke-test |
| `host` | ❌ | No OS version / cgroup / KVM check |
| `network` | ❌ | No egress-host reachability probe |
| `keys` | ❌ | No CRL / revocation check |
| `bundles` | ❌ | No storage utilization check |

### 12.6 `setup wizard`: not started

The `operator-ergonomics.md §16` defines a 10-phase interactive setup
wizard. Zero code exists in the CLI. This is a convenience feature
(operators can manually run genesis + policy sign + credential add),
but the spec positions it as the recommended first-run experience.

### 12.7 VSock IPC client: not implemented

`planner-core/src/lib.rs` explicitly states: *"No VSock kernel-IPC
client."* The planner binaries boot and park but cannot communicate
with the kernel. The VSock frame reader/writer (guest-side) is a
prerequisite for B1 (planner agent loop).

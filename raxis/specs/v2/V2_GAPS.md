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

### B1: Planner Agent Loop ✅ CLOSED (V2.3)

**Spec:** `planner-harness.md §3, §10, §14`
**Estimate:** ~2,600 lines (delivered ~2,500 across `raxis-planner-core`)

The three planner binaries (orchestrator, executor, reviewer) now have
full agent-loop scaffolding: kernel transport, model client, tool
registry, dispatch loop, intent/escalation submission, KSB renderer,
and custom-tool subprocess executor. The role binaries' `main`
functions still park on `SIGTERM` for the V2 scaffold; wiring the
loop into each binary's main is `gap-b1-planner-binary-wiring`
(separate, ~150 lines).

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
| MongoDB | Connect, relay `OP_MSG` response bodies + **SCRAM auth** | ~300 |
| Redis | Connect, relay RESP2 responses | ~150 |
| SMTP | Connect, relay multi-line SMTP responses, `STARTTLS` | ~200 |

**Per-proxy upstream auth status:**

| Proxy | Agent-side auth (accept dummy creds) | Upstream auth (real creds to DB) | Auth method | Notes |
|---|---|---|---|---|
| **Postgres** | ✅ `AuthenticationOk` (accepts anything) | ✅ via `tokio-postgres` | SCRAM-SHA-256, MD5, cleartext, trust | **Fully implemented** in `upstream.rs`. The only proxy with real upstream auth today. |
| **Redis** | ✅ Intercepts `AUTH` command | ✅ Sends real `AUTH <password>` upstream | `AUTH <password>` (RESP2) | Working. Missing: ACL-form `AUTH user password` (~30 lines, V2 Phase 2), TLS to upstream (~40 lines, V2 Phase 2 — required by Elasticache/Memorystore/Azure Cache). |
| **SMTP** | ✅ Accepts `AUTH PLAIN`/`AUTH LOGIN` | ✅ Sends real `AUTH PLAIN` upstream | `AUTH PLAIN` over STARTTLS | Working. Missing: `AUTH SCRAM-SHA-256` (rare for SMTP). |
| **MySQL** | ✅ `mysql_native_password` handshake | ❌ Synthesizes responses | Would use `mysql_async` | Handshake code exists; upstream connect deferred. Missing: `caching_sha2_password` (MySQL 8.0 default). |
| **MSSQL** | ✅ PRELOGIN + LOGINACK | ❌ Synthesizes responses | Would use `tiberius` | Handshake code exists; upstream connect deferred. |
| **MongoDB** | ⚠️ **No auth at all** | ❌ Synthesizes responses | Would need SCRAM-SHA-256 | **Critical gap.** The proxy advertises empty `saslSupportedMechs` so drivers skip auth. Any MongoDB deployment with auth enabled (i.e., all production deployments) will reject connections. SCRAM-SHA-256 requires PBKDF2 + HMAC state machine (~150 lines). |

**MongoDB auth gap detail:** The proxy's `hello` response sets
`saslSupportedMechs: []` to prevent drivers from attempting auth.
This works for unauthenticated local dev databases but fails against
any Atlas, DocumentDB, or self-hosted MongoDB with `--auth` enabled.
The upstream module (`upstream.rs`) exists but contains only the
`ForwardOutcome` types — no connection or auth code. The SCRAM
handshake for MongoDB is a 4-message SASL exchange:
`SASLStart → ServerFirst → SASLContinue → ServerFinal`. Estimate:
~150 lines for SCRAM + ~150 lines for upstream relay = ~300 total
(revised up from ~150).

**Cloud proxy restriction gaps:**

The spec (`credential-proxy.md §3.2–3.4`) defines richer
restrictions than the code implements. The current code only enforces
**path-level allowlists** (`allowed_paths` for AWS/GCP,
`allowed_resources` for Azure). The spec envisions service-level,
action-level, and region-level confinement:

| Cloud | Restriction | Spec'd | Implemented | Impact if missing |
|---|---|---|---|---|
| **AWS** | `allowed_services` (e.g., `["s3", "sqs"]`) | ✅ §3.2 | ❌ | Agent with S3 credentials can call EC2, IAM, Lambda — full account access |
| **AWS** | `allowed_regions` (e.g., `["us-east-1"]`) | ✅ §3.2 | ❌ | Agent can provision resources in any region |
| **AWS** | `role_arn` scoping (STS AssumeRole) | ✅ §3.2 | 🟡 In plan schema | Role ARN is declared but proxy doesn't call STS yet |
| **GCP** | `allowed_scopes` (OAuth scope restriction) | ✅ §3.3 | ❌ | Agent gets a token with all scopes the service account has |
| **GCP** | Project-level pinning | ✅ §3.3 | 🟡 In plan schema | `project` is declared but not enforced at the proxy |
| **Azure** | Per-resource action filtering | ✅ §3.4 | ❌ | `allowed_resources` controls which service but not which operations |

These restrictions require the proxy to **inspect request
signatures** (AWS SigV4 headers contain the service and region) or
**scope the token** (GCP/Azure token endpoints accept scope
parameters). This is distinct from the upstream forwarding gap
(B3) — it's about restricting *what the token allows*, not
*whether the proxy connects upstream*.

**`CredentialBackend` trait update required:** The
`CredentialBackend::resolve()` method currently returns a single
opaque `CredentialValue`. For cloud proxies with STS/token-exchange,
the resolved value must include metadata:

- AWS: `role_arn`, `external_id`, `session_duration`
- GCP: `scopes`, `target_audience` (for identity tokens)
- Azure: `client_id`, `tenant_id`, `resource`

The `extensibility-traits.md §4` spec for `CredentialBackend` must
be updated to reflect these structured return types. See §12.10 for
the full list of spec files affected.

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

**V2 remaining work — multi-provider `ModelClient` impls (BLOCKER):**

All four `ProviderId` variants MUST have wired `ModelClient`
implementations before V2 ships. Single-provider Anthropic-only
is not acceptable for production — the `FallbackModelClient`
chain is useless without receivers for every provider in the
fallback chain.

| Provider | `ModelClient` impl | Est. lines | Wire shape | Status |
|---|---|---|---|---|
| **Anthropic** | `AnthropicClient` | ✅ delivered | Anthropic Messages API | ✅ V2.3 |
| **OpenAI** | `OpenAiClient` | ~200 | OpenAI Chat Completions API | ❌ **V2 BLOCKER** |
| **Google Gemini** | `GeminiClient` | ~200 | Gemini `generateContent` API | ❌ **V2 BLOCKER** |
| **AWS Bedrock** | `BedrockClient` | ~250 | Bedrock `InvokeModel` + SigV4 | ❌ **V2 BLOCKER** |

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

**V2 remaining work — per-provider circuit breaker (BLOCKER):**

Without a circuit breaker + half-open probe, a `FallbackModelClient`
chain that falls through to a lower-priority provider can never
return to the higher-priority provider once it recovers. The chain
is sticky-on-failure — every subsequent request goes straight to
the fallback, wasting cost and latency.

The circuit breaker (`provider-failure-handling.md §6`) tracks
per-provider error rate over a sliding window. When the rate
exceeds the threshold, the circuit opens and the `FallbackModelClient`
skips that provider. Periodically, a **half-open probe** sends a
single request to the failed provider; if it succeeds, the circuit
closes and the provider re-enters the chain at its original
priority position.

| Component | Est. lines | Spec section |
|---|---|---|
| `CircuitBreaker { state, error_window, threshold, half_open_interval }` | ~120 | `provider-failure-handling.md §6.1` |
| `CircuitState` enum (`Closed`, `Open`, `HalfOpen`) | ~30 | `provider-failure-handling.md §6.2` |
| Half-open probe (single request on timer) | ~60 | `provider-failure-handling.md §6.3` |
| `FallbackModelClient` integration (skip open circuits) | ~40 | `provider-failure-handling.md §6.4` |
| Tests (open on threshold, half-open recovery, priority restoration) | ~100 | — |

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

**V2 remaining work — multi-provider `ModelClient` wiring (BLOCKER):**

The `ProviderId` enum has four variants. All four MUST have wired
`ModelClient` impls and gateway forwarding before V2 ships. The
registry validates model ids; the `FallbackModelClient` chains
providers; but without the actual client impls, the chain has
no receivers to fall back to.

| Provider | Registry coverage | `ModelClient` impl | Gateway forwarding | Status |
|---|---|---|---|---|
| **Anthropic** | ✅ 5 supported + 2 deprecated | ✅ `AnthropicClient` | ✅ | ✅ V2.3 |
| **OpenAI** | ✅ 2 entries | ❌ `OpenAiClient` needed | 🟡 gateway-only | ❌ **V2 BLOCKER** |
| **Google Gemini** | ✅ 2 entries | ❌ `GeminiClient` needed | 🟡 gateway-only | ❌ **V2 BLOCKER** |
| **AWS Bedrock** | ⚪ no registry entries yet | ❌ `BedrockClient` needed | 🟡 SigV4 gateway leg | ❌ **V2 BLOCKER** |

See `V2_GAPS §C2` for the per-provider `ModelClient` impl estimates
and wire-shape details.

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

### C5: Third-Party Provider Integration (HTTP Sidecar)

**Spec:** `extensibility-traits.md §9A`
**Status:** ❌ Not implemented
**Severity:** Medium — blocks operators who want non-built-in providers

The V2 boot site uses a closed `InferenceRouterKind` enum. Adding
Kombai, Cohere, or any non-built-in provider requires a kernel
code change (new enum variant + match arm).

**Resolution (specced, not yet implemented):** `HttpSidecarRouter` —
a built-in `InferenceRouter` impl that forwards
`ResolvedInferenceRequest` as JSON over localhost HTTP to an
operator-run sidecar process. The sidecar translates RAXIS's
fixed schema to the provider's native API and back. Process
isolation ensures no foreign code runs in the kernel.

**What's needed:**

- `crates/raxis-inference-router-sidecar/` — ~400 lines
  (`HttpSidecarRouter`, `SidecarRequest`, `SidecarResponse`)
- `InferenceRouterKind::HttpSidecar` variant in `policy/src/bundle.rs`
- `"http_sidecar"` match arm in `kernel/src/main.rs` boot site
- `[CHECK] sidecar.health` in `cli/src/commands/doctor.rs`
- `specs/v2/sidecar-protocol.yaml` — OpenAPI schema
- HMAC-SHA256 mutual authentication (boot-time challenge-response
  + per-request HMAC headers) per `extensibility-traits.md §9A.7A`
- `raxis policy generate-sidecar-secret` CLI command

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

### C4: Email & Notification Channels ✅ CLOSED (V2.3)

**Spec:** `email-and-notification-channels.md` (61KB)
**Delivered:** ~700 lines (handler crates + tests)

| Channel kind | Policy parsed | Handler impl | Status |
|---|---|---|---|
| `Shell`   | ✅ | ✅ `handler/file.rs`    | V1 carryover |
| `File`    | ✅ | ✅ `handler/file.rs`    | V1 carryover |
| `Email`   | ✅ | ✅ `handler/email.rs`   | V2.3 — SMTP submission with STARTTLS or implicit TLS, AUTH PLAIN, password from sidecar `.notify-cred` file |
| `Webhook` | ✅ | ✅ `handler/webhook.rs` | V2.3 — HTTPS POST with `X-RAXIS-Event-{Kind,Seq,Id}` headers, JSON body |

**Failure taxonomy** is extended with `Network`, `UpstreamRejected`,
and `CredentialUnavailable` variants of `DeliveryError`; each maps
to a stable `category()` short-string that lands in
`NotificationDeliveryFailed.reason` so operator dashboards can group
failures by class.

**V2 deferrals (V3 work, tracked separately):**

* Persistent SMTP keep-alive connections (V2 opens one connection per
  send — fine for the typical event volume).
* Idempotency table `notification_dispatch` (`§6.5` of the spec) —
  V2 is best-effort fire-and-forget.
* HMAC-SHA256 webhook signing (`§2.3.4`) — V2 treats the URL itself
  as the shared secret (matches Slack/GitHub webhook UX).
* AUTH XOAUTH2 — V2 ships AUTH PLAIN only.
* `OperatorNotificationChannel` trait extraction (V3 trait crate;
  V2 keeps the impls inside the kernel for boot-order simplicity).

### C5: Immutable Artifact Store — CLOSED (V2.3, MVP)

**Spec:** `immutable-artifact-store.md` (25KB) — full surface
**Status:** **Primitive delivered; kernel wiring is V2 BLOCKER.**
**Delivered:** ~470 lines (new `raxis-artifact-store` crate + tests)

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

**V2 remaining work — kernel wiring (BLOCKER):**

The store primitive is useless without the kernel actually calling
it. These are V2 blockers, not V3 deferrals:

| Wiring point | Kernel call site | What it does | Est. lines |
|---|---|---|---|
| **Policy push** | `kernel/src/handlers/policy.rs` | On `PolicyEpochAdvanced`: write new `policy.toml` bytes to `ArtifactStore::write(Category::Policy, ...)` before updating the active symlink | ~40 |
| **Plan approve** | `kernel/src/initiatives/lifecycle.rs` | On `approve_plan`: write plan bytes + operator signature to `write(Plans, ...)` + `write_companion(Plans, key, "sig", ...)` | ~40 |
| **Key rotate** | `kernel/src/handlers/operator.rs` | On operator key rotation: write new public key PEM to `write(Keys, ...)` | ~30 |
| **Symlink swap** | `kernel/src/handlers/policy.rs` | After artifact write: atomically swap `policy/policy.toml` → `policy/<sha256>.toml` | ~50 |
| **Boot-time open** | `kernel/src/main.rs` | Open `ArtifactStore` at kernel boot; pass `Arc<ArtifactStore>` to handlers | ~10 |
| **`raxis-artifact-store` dep** | `kernel/Cargo.toml` | Add workspace dependency | ~1 |

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

### C8: Reserved Planner Tools — `WebFetch`, `WebSearch`, `StructuredOutput`, `Sleep`

**Spec:** `planner-harness.md §3` (tool surface table),
`kernel-mediated-egress.md` (DEPRECATED — superseded by unified
egress), `custom-tools.md §5` (reserved name list)
**Status:** ❌ Not implemented — **V2 BLOCKER (spec-first)**
**Scope:** `WebFetch`, `WebSearch`, and `Sleep` are **V2 deliverables**
— no deferral to V3. `StructuredOutput` is excluded from V2 (no
DAG consumer). V2 does not ship without spec + impl for the first
three.

These four tool names are reserved in `custom_tools_validator.rs`
(line 63–66) and appear in `custom-tools.md §5`'s reserved-name
list, preventing operators from declaring custom tools with the
same names. But the planner harness has no implementations for
any of them, and `planner-harness.md §3` marks all four as ❌
across all three roles.

**Current state by tool:**

| Tool | Reserved | Impl | Spec | Problem |
|---|---|---|---|---|
| `WebFetch` | ✅ | ❌ | ❌ **needs spec** | The original spec (`kernel-mediated-egress.md`) is DEPRECATED. The unified egress model (tproxy + credential proxy) replaced `IntentKind::EgressRequest`. But `web_fetch` as a planner tool has no spec defining how it maps to the V2 egress primitives. |
| `WebSearch` | ✅ | ❌ | ❌ **needs spec** | Same gap as WebFetch. The convenience wrapper (`web_search_github`) was defined in the deprecated spec only. |
| `StructuredOutput` | ✅ | ❌ | ⚪ excluded | `planner-harness.md §6.1`: "No DAG consumer" — excluded from V2. May remain reserved for V3. |
| `Sleep` | ✅ | ❌ | ⚠ under review | `planner-harness.md §3`: "Hole still under review." |

**The WebFetch / WebSearch invariant gap:**

The original `kernel-mediated-egress.md` routed web requests
through `IntentKind::EgressRequest` → kernel admission → host-side
`raxis-egress` proxy. This preserved all R-invariants because
every request went through the kernel's 13-step admission pipeline.

The V2 unified egress decision (`v2-deep-spec.md §Part 7`)
deprecated that path and replaced it with:

- **Tier 1 (public/unauthenticated):** tproxy SNI allowlist —
  transport-layer only, no URL-level control.
- **Tier 2 (authenticated/sensitive):** credential proxy —
  HTTP-layer URL-prefix + method allowlist per session.

Neither tier gives the planner a **tool-shaped** web fetch
capability the LLM can call like `read_file` or `bash`. The
agent can `curl` from bash (if the hostname is in the tproxy
SNI allowlist), and **that path IS egress-controlled** — the VM
has no NIC (INV-02B), so every outbound TCP connection is
intercepted by tproxy and checked against the operator's
allowlist. Unapproved hosts are refused at the transport layer.

The gap is not about access control — it's about **tool-level
structure and audit:**

- **No typed tool interface.** The LLM constructs ad-hoc `curl`
  flags in bash rather than calling a schema-validated tool with
  `{ url, method, headers }` inputs and
  `{ status_code, body, truncated }` output. This increases
  hallucination of flags and makes response parsing fragile.
- **No per-request audit events.** Tproxy logs at the transport
  layer (connection opened/closed, SNI, bytes). There is no
  `WebFetchInvoked` audit event with URL, method, response
  status, body hash, duration, or truncation flag.
- **No per-tool rate limiting or body truncation.** Tproxy does
  not cap response body size or count requests per URL prefix.
  A `bash curl` loop can fetch unbounded data from an
  allowlisted host.

**What needs to be specced (BLOCKER — no PR without spec):**

> Before implementing `WebFetch` or `WebSearch`, a dedicated
> section must be added covering:
>
> 1. **Egress path mapping** — does the planner's `web_fetch`
>    tool go through tproxy (Tier 1), credential proxy (Tier 2),
>    or a new Tier 3 path? Each option has different invariant
>    consequences.
> 2. **Admission and audit** — the original spec had 8 admission
>    checks (E1–E8: scheme, hostname, URL prefix, method, body
>    size, rate limit, SSRF, budget). Which of these survive
>    under the unified egress model, and who enforces them (harness
>    vs. tproxy vs. credential proxy vs. kernel)?
> 3. **SSRF prevention** — the deprecated spec required DNS
>    resolution at the proxy with private-range rejection. Under
>    the unified model, tproxy does SNI-level filtering but does
>    NOT inspect resolved IPs. This is a potential regression.
> 4. **Per-tool response shape** — `web_fetch` returns
>    `{ status_code, content_type, body, truncated }` to the LLM.
>    How does body truncation work when the call goes through
>    tproxy (which is transport-layer and doesn't inspect body
>    length)?
> 5. **Rate limiting** — the deprecated spec had per-task
>    `max_requests` per URL prefix. The unified model has no
>    per-tool request counter. Is rate limiting dropped, or does
>    the harness enforce it in-process?
> 6. **Role restrictions** — `planner-harness.md §3` marks
>    WebFetch/WebSearch as ❌ for all roles. If they're V2 tools,
>    which roles get them? The dispatch matrix needs updating.
> 7. **`WebSearch` convenience shape** — the deprecated spec
>    defined `web_search_github` as a typed wrapper around
>    `GET api.github.com/search/`. Should `WebSearch` be a
>    general search tool (using a search API/engine) or a
>    domain-specific convenience?

**`StructuredOutput` and `Sleep` — lower priority:**

- **`StructuredOutput`** — excluded from V2 per `planner-harness.md
  §6.1` ("no DAG consumer"). Stays reserved; no spec work needed
  for V2.
- **`Sleep`** — still under review per `planner-harness.md §3`.
  Needs a decision: is it a legitimate tool (e.g., for rate-limit
  backoff in executor loops) or a hole that lets the LLM waste
  session time? If kept, needs a ceiling
  (`max_sleep_seconds` policy cap).

---

### C9: Streaming Dispatch (Planner ↔ Gateway)

**Spec:** `provider-failure-handling.md §7` (streaming atomicity),
`§7.2` (gateway-side stream buffering), `§7.5` (no resumable
streams), `§12.4` (design rationale), `§12.7` (resumability
deferral)
**Status:** ❌ Not implemented — **V2 BLOCKER**
**Estimate:** ~600 lines (gateway stream reader + planner stream
consumer + heartbeat integration)

**Current state.** The planner's `ModelClient::create_message()`
makes a single HTTP POST and blocks until the **entire response
body** arrives. Every inference call — including 100K-token outputs
that take 5+ minutes to generate — stalls the dispatch loop for
the full generation time. The planner cannot start tool execution,
emit progress signals, or detect provider hangs until the complete
JSON body lands.

**What the spec already defines (gateway side).**
`provider-failure-handling.md §7` fully specifies the gateway's
streaming behavior:

- The gateway reads the provider's SSE stream (Anthropic
  `message_stop`, OpenAI `data: [DONE]`) into an in-memory buffer
  with spill-to-disk above `stream_buffer_cap` (§7.2).
- The gateway emits heartbeats to the kernel every
  `worker_heartbeat_interval_ms` while waiting for chunks (§7.3).
- Only complete, structurally-validated envelopes are delivered to
  the planner; partial streams are discarded as `Unavailable` for
  retry (INV-PROVIDER-04).
- No resumable streams in V2 (§7.5, §12.7) — stream failure is
  always a clean retry from scratch.

**What's missing (planner side).**

| Component | What it does | Est. lines |
|---|---|---|
| **Gateway SSE reader** | `gateway/src/streaming.rs` — read provider SSE chunks, buffer, verify end-of-stream sentinel, spill-to-disk | ~250 |
| **Planner stream consumer** | `planner-core/src/model.rs` — consume SSE events from the gateway's forwarded stream; emit incremental `content_block_delta` events for progress tracking | ~200 |
| **Heartbeat integration** | Gateway worker heartbeat to kernel during stream reads; kernel detects stalled workers via missed heartbeats | ~100 |
| **Token metering (incremental)** | Count output tokens as they arrive rather than after full response; enables early budget-exceeded abort | ~50 |

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
| 6 | Configurable `target_ref` (policy + plan) | 80 | PR branch workflow; unblocks teams with branch protection (see §12.8) |

### Phase 2: Production readiness (~2,700 lines)

| # | Item | Lines | Rationale |
|---|---|---|---|
| 6 | **C2** — Provider failure handling | 800 | One API hiccup kills sessions without retry/fallback |
| 7 | **C1** — Token limit enforcement | 600 | Cost control for operators |
| 8 | **C4** — Notification channels | 500 | Escalations are silent without this |
| 9 | **D2** — Host capacity management | 500 | Multi-session safety |
| 10 | **C7** — Credential CLI (`add`/`remove`) | 400 | Operator onboarding friction |
| 11 | Redis ACL-form `AUTH user password` | 30 | Redis ≥ 6.0 with named users; requires `CredentialBackend` to return username + password |
| 12 | Redis TLS-to-upstream | 40 | Required by Elasticache, Memorystore, Azure Cache; `tokio-rustls` already in deps |

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
| Defaults with override | ❌ Not implemented | No override-capable fields exist (e.g., `target_ref`) |
| Locked fields | ❌ Not implemented | No `_locked` mechanism; no `FAIL_POLICY_LOCKED_FIELD` code |
| Policy-only | ✅ Already | `[[vm_images]] oci_digest`, `[[environment_gates]]`, credential store config |
| Plan-only | ✅ Already | `path_allowlist`, `[[tasks]]`, `task_id` — policy constrains via ceilings |

The invariant codifies the existing ceiling/policy-only/plan-only
pattern and extends it to cover the three missing categories
(floors, defaults-with-override, locked fields) needed for
`target_ref` and future configurable fields.

### 12.10 Spec files requiring updates for proxy auth changes

Several V2 gaps (MongoDB SCRAM auth, Redis ACL-form AUTH, Redis
TLS-to-upstream, MySQL `caching_sha2_password`) require changes to
the `CredentialBackend` trait and the credential declaration schema.
When these land, the following spec files must be updated in the
same PR to maintain spec-graph consistency:

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

### Category 1: Structurally enforced, not annotated (~30 invariants)

These invariants hold because the architecture makes violations
impossible, but no code comment says `// INV-FOO: enforced here`.
The only work needed is a mechanical annotation pass — one-line
comments at the enforcement site.

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
| `INV-PROVIDER-01..10` (10) | Multi-provider `ModelClient` impls + circuit breaker (C2/C3) | **V2 BLOCKER** — ships with provider impls |
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

### Category 4: Single missing enforcement point (~10 invariants)

These invariants describe behavior that the code *almost* enforces
but is missing one check, one guard, or one assertion.

| Invariant | What's missing | Est. lines |
|---|---|---|
| `INV-PLANNER-HARNESS-03` | cgroup v2 guest kernel version check at session boot — the harness assumes Linux 5.14+ but never verifies | ~20 |
| `INV-ENV-01` | Environment coherence check at admission — tasks can currently mix credentials from different environments | ~40 |
| `INV-CRED-KERNEL-01` | Credential proxy kernel-side validation — kernel accepts proxy declarations without verifying the proxy type is supported | ~30 |
| `INV-INIT-06` | Initiative cleanup on kernel shutdown — kernel shuts down cleanly but does not mark in-flight initiatives as `interrupted` | ~30 |
| `INV-PLAN-BUNDLE-FRESH` | Already referenced in code but the staleness check is a no-op (always returns fresh) | ~20 |
| `INV-CERT-01` | Certificate expiry check at IPC auth time — certificates are validated at issuance but not re-checked at connection time | ~30 |

**Remediation:** ~170 lines total across 6 enforcement sites.
Each is a self-contained guard or assertion that can land as an
independent PR.

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
4. **Category 4** (single guard): ~170 lines total. Six small
   PRs, each independently mergeable.

**Updated coverage after this analysis:**

| Category | Count | V2 code needed |
|---|---|---|
| Already enforced in code (annotated) | ~45 | — |
| Structurally enforced (needs annotation only) | ~30 | 0 lines (comments only) |
| Ships with parent feature (V2 scope) | ~25 | Ships with feature |
| Ships with parent feature (V3 scope) | ~12 | None for V2 |
| Deprecated | ~5 | None |
| Single enforcement point | ~10 | ~170 lines |
| **Total** | **~120** | **~170 lines incremental** |

The V2 invariant gap is not a line-count problem. It is a
discipline problem: every feature PR must cite the invariant IDs
it enforces, and the annotation pass for Category 1 should land
as a dedicated "INV-audit" commit early in the sprint cycle so
the coverage tooling (`cargo xtask inv-coverage`) has an accurate
baseline.

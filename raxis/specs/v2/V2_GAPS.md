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
coverage gap is tracked separately in `V2_GAPS.md §INV-coverage`.

**Test coverage:** 87 unit tests across the 8 modules (`cargo test
-p raxis-planner-core --lib`); the live e2e harness exercises the
full loop end-to-end via `live-e2e/`.

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
once additional `OpenAiClient` / `BedrockClient` impls land; the
`AnthropicClient` is the only V2 provider implementation, so the
production chain is `RetryingModelClient(AnthropicClient)` only.

**V2 design choices.**

* **Retryability classifier is public.** Operators / tests can
  call `is_retryable(&err)` directly to predict the wrapper's
  behaviour without instantiating it.
* **No circuit breaker.** A persistent provider outage just
  exhausts the retry budget and surfaces the last error verbatim.
  Adding a per-provider error-rate threshold + half-open state is
  a V3 follow-up (the spec's §6 circuit breaker).
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

**Deferred to V3.**

* OpenAI / Gemini / Bedrock client impls (each ≈ 200 lines).
* Per-provider circuit breaker + half-open probe.
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

**Deferred to V3 (full provider-model-selection.md surface).**

* `[provider_aliases_defaults]` policy schema + `plan prepare`
  fill-in.
* `setup wizard` auto-diversification (single-provider →
  multi-provider chain rewrite when a second API key is added).
* `override_reviewer_alias` per-environment override.
* OpenAI / Gemini / Bedrock `ModelClient` impls (each ≈ 200
  lines) so the gateway-side fallback chain has wire-compatible
  receivers.

**Per-provider implementation status (after V2.3):**

| Provider | Registry coverage | `ModelClient` impl | Gateway forwarding |
|---|---|---|---|
| **Anthropic** | ✅ 5 supported + 2 deprecated | ✅ `AnthropicClient` | ✅ |
| **OpenAI** | ✅ 2 entries | ❌ deferred V3 | 🟡 gateway-only |
| **Google Gemini** | ✅ 2 entries | ❌ deferred V3 | 🟡 gateway-only |
| **AWS Bedrock** | ⚪ no entries (uses Anthropic ids) | ❌ deferred V3 | 🟡 gateway-only |

**Deployment tiers** (from `provider-model-selection.md §4`) —
operator-facing guidance the V2 spec preserves:

- **§4.1** — Single-provider (Anthropic only): all three roles use
  `anthropic:claude-*`. No failover if Anthropic has an outage.
  V2 supports this out of the box: `RAXIS_MODEL_ID` defaults to
  `claude-sonnet-4-5-20250929`.
- **§4.2** — Two-provider (Anthropic + OpenAI): cross-provider
  fallback chains per role. Recommended for production. V2's
  `FallbackModelClient` (V2_GAPS §C2) is the chain primitive;
  wiring it up requires the V3 OpenAI `ModelClient` impl.
- **§4.3** — Three-provider (Anthropic + OpenAI + Gemini): per-role
  model chains with tiered fallback. Reviewer uses `gemini-flash`
  at tier-3 for cost efficiency. V3 follow-up.

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

### C5: Immutable Artifact Store

**Spec:** `immutable-artifact-store.md` (25KB)
**Estimate:** ~600 lines

Content-addressed artifact storage (SHA-256 keyed). Per-task
artifact upload/download. Artifact attestation (signed digest binding
artifact to task). Retention policy.

Zero references to `ArtifactStore`, `ImmutableArtifact`.

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

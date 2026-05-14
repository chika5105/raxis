# RAXIS V2 — Reviewer / Orchestrator / Executor Provider-Egress Defaults

> **Status:** V2 Specified — implements `INV-EGRESS-DEFAULT-01..03` and
> `INV-EGRESS-STALL-01`.
>
> **Cross-references:**
>
> - `vm-network-isolation.md` — Tier-1 transparent proxy; the
>   `EgressAllowlist` consulted by `raxis-egress-admission`.
> - `credential-proxy.md` — Tier-2 authenticated proxies (orthogonal to
>   this decision).
> - `peripherals.md §3.2` — gateway-side `is_url_allowed` check.
> - `provider-failure-handling.md §2.1` — kernel-mediated planner ↔
>   gateway flow used by Reviewers and (under VM substrate) Executors and
>   Orchestrators.
> - `provider-model-selection.md §4` — the canonical
>   `ProviderId::default_base_url` mapping.

---

## 1. Problem statement

A reviewer agent submitted in production was configured by the operator
with `[[providers]]` of `kind = "Anthropic"` (and a working
`anthropic-prod.toml` credentials file) but **without** `*.anthropic.com`
in the policy `[egress] patterns` block.

At runtime every Reviewer inference call (kernel-mediated through the
gateway) was rejected at the gateway's `is_url_allowed` check with
`error: "DomainNotAllowed"`. The Reviewer's dispatch loop saw the
fetch failure, retried, and silently spun. The operator had to inspect
audit logs, identify the missing `[egress]` entry, edit `policy.toml`,
restart the kernel, and re-submit the plan.

This is an ergonomics bug class: an operator who declares a
`[[providers]]` entry has *implicitly* declared that the corresponding
provider FQDN must be reachable. Forcing them to also declare it
explicitly under `[egress]` is redundant ceremony with a silent failure
mode.

## 2. Architecture context (what is gated, where, and by whom)

The kernel has **two** independent egress gates:

1. **Transparent egress proxy / admission gate** (`raxis-tproxy`
   in-VM, kernel-side `handlers::tproxy_admit` admission listener
   over AF_VSOCK). Used by Executor VMs that boot at
   `EgressTier::Mediated` — the only non-`None` tier shipped in V2
   after the Tier1Tproxy deletion. There is no virtio-net device in
   the guest; the in-guest tproxy routes admission decisions over
   AF_VSOCK to the kernel admission handler (see
   `airgap-architecture.md`). The kernel's `EgressAllowlist` is
   sourced from `policy.[egress] domains` + `[egress] patterns`,
   and a non-allowlisted SNI is denied with
   `DenyReason::HostNotInAllowlist` so the agent sees
   `ECONNREFUSED`.

2. **Gateway URL allowlist** (`raxis-gateway::policy_view::PolicyView::is_url_allowed`).
   Used by every `FetchRequest` the gateway dispatches — this includes
   inference calls routed through the kernel-mediated path
   (`PlannerFetchRequest` → kernel → gateway). The gateway's allowlist is
   sourced from the same `policy.[egress] domains` + `[egress] patterns`.
   A non-allowlisted host returns `error: "DomainNotAllowed"`.

The Reviewer and Orchestrator run at `EgressTier::None` (no NIC)
unconditionally so their inference traffic only hits gate (2).
The Executor hits gate (2) for kernel-mediated inference calls
universally and additionally hits gate (1) for any **direct**
outbound socket (a bash-invoked `curl`, an SDK that bypasses
`PlannerFetchRequest`, a custom-tool subprocess) — those flow
through in-guest `raxis-tproxy` over vsock to the kernel
admission handler.

The bug class therefore manifests at **both** gates whenever the
operator's `[[providers]]` and `[egress]` lists drift apart.

## 3. Options considered

### Option A — Warn-as-error at admission

The kernel emits a structured warning at plan admission when a task
references an inference-bearing provider with no matching `[egress]`
entry. By the kernel's standing convention warnings promote to errors
and admission fails fast.

**Pros.**
- Small implementation surface (one validator + one diagnostic).
- Preserves operator's explicit intent — no implicit grants, no audit
  ambiguity about "what did the kernel decide on my behalf".
- Failure is loud and actionable; the operator sees a precise error
  string at `raxis plan submit` time.

**Cons.**
- Still requires the operator to write out the redundant egress entries
  by hand.
- Doesn't reduce config surface — the operator's mental model still has
  to track both `[[providers]]` and `[egress]` and keep them in sync.
- Cascading admission failures during plan iteration: every provider
  rotation forces another `[egress]` edit.

### Option B — Hard failure at validation layer

Same surface as A but moved one layer earlier: the policy validator
(`PolicyBundle::load`) rejects any policy whose `[[providers]]` does
not have a matching `[egress]` entry, with an explicit error variant
(`PolicyError::ProviderEgressMissing { provider_id, expected_fqdn }`).

**Pros.**
- Fails earlier than admission — operator catches the misconfiguration
  at policy install time, not at first plan submission.
- Explicit error variant pinpoints the missing entry; no parsing audit
  events to figure out what's wrong.
- Prevents broken plans from ever reaching admission.

**Cons.**
- Same operator-friction story as A — structurally identical, just one
  layer earlier. The redundant `[egress]` entries still have to be
  written by hand.
- Tightens the deploy loop: a policy rotation that adds a new provider
  now requires *two* TOML edits in lock-step rather than one.

### Option C — Default-include (chosen)

Plan / policy defaults grant Reviewer / Orchestrator / Executor the
inference-provider egress required by the configured `[[providers]]`
catalogue. The operator can opt out per-provider via
`[egress] deny_provider = ["anthropic-prod"]` or wholesale via
`[egress] implicit_provider_grants = false`. The implicit grant is
audited via a `DefaultProviderEgressApplied` event so the audit chain
records exactly what was implicitly granted.

**Pros.**
- Zero operator friction in the common case; plans "just work" the
  moment a `[[providers]]` entry is declared.
- Reflects the truism that an agent that can't reach its configured
  provider is non-functional. The implicit grant only *enables* what
  the operator already explicitly declared.
- Most ergonomic by far — a fresh-from-`raxis init` policy with one
  Anthropic provider needs zero `[egress]` lines to function.
- The opt-out (`deny_provider` per-id, `implicit_provider_grants = false`
  wholesale) preserves operator control for deny-all-by-default
  deployments.

**Cons.**
- Implicit grants are a security smell — an operator might not realise
  their reviewer can talk to `api.anthropic.com`. Mitigated by the
  `DefaultProviderEgressApplied` audit event (one per implicit grant,
  emitted at policy load) so an auditor can `grep` exactly what the
  kernel granted on the operator's behalf.
- Complicates the audit trail (what was explicit vs default). Mitigated
  by carrying a `source: "implicit-provider-default"` tag on the audit
  event so explicit `[egress]` entries and implicit ones are
  distinguishable.
- Makes "deny-all-by-default" plans harder to express. Mitigated by
  `implicit_provider_grants = false` which restores the explicit-only
  behaviour.
- Risks future foot-guns when planner-config providers change. Mitigated
  by emitting a fresh `DefaultProviderEgressApplied` event on every
  policy reload so an epoch advance that adds a provider FQDN is
  visible in the audit chain.

## 4. Recommendation

**Option C, with strong audit + opt-out semantics, AND simultaneously
add stall detection at runtime.**

Reasoning:

- The bug class the user hit (reviewer can't reach provider, silent
  stall, operator manually fixes) is fundamentally an ergonomics
  problem. Options A and B fix the ergonomics by failing earlier —
  useful, but still require operator intervention. C eliminates the
  failure mode entirely for the common case while preserving operator
  control via opt-out.
- The "implicit grants are a security smell" concern is real but
  mitigated by the `DefaultProviderEgressApplied` audit event + the
  `deny_provider` / `implicit_provider_grants` opt-outs.
- Stall detection is orthogonal to the validation question and SHOULD
  be implemented regardless of which validation strategy is chosen.
  Even with C, runtime egress can fail (proxy down, provider down,
  network partition, post-rotation drift). The kernel should catch the
  silent-spin case and emit a structured signal so the operator
  dashboard or downstream tooling can react.

## 5. Architecture: provider FQDN derivation

The `ProviderId::default_base_url` table in
`crates/planner-core/src/provider_model.rs` is the canonical mapping
between a provider kind and the FQDN(s) the kernel must admit:

| `[[providers]] kind` | FQDN(s) implicitly admitted |
|----------------------|----------------------------|
| `Anthropic`          | `api.anthropic.com`        |
| `OpenAI`             | `api.openai.com`           |
| `Gemini`             | `generativelanguage.googleapis.com` |
| `Bedrock`            | `bedrock-runtime.us-east-1.amazonaws.com` (default region) |
| `http_sidecar`       | host extracted from `sidecar_endpoint` |

Future provider kinds add a row in `provider_model.rs` and the
derivation picks them up automatically. The `Bedrock` default region is
the same placeholder the planner uses; multi-region operators override
by adding the region-specific FQDN to `[egress] patterns` (the explicit
entry is union'd with the default, never overridden).

Sidecars contribute the host extracted from
`[[providers]].sidecar_endpoint`. A malformed or relative endpoint
is silently skipped; the policy validator already rejects malformed
sidecar endpoints elsewhere.

## 6. Wire shape — new `[egress]` fields

```toml
[egress]
domains  = ["api.openai.com"]   # explicit; union'd with implicit grants
patterns = ["*.github.com"]     # explicit; union'd with implicit grants

# V2 — implicit provider grants (this decision).
implicit_provider_grants = true                # default
deny_provider            = ["openai-staging"]  # opt-out per provider_id
```

Both new fields are optional. Defaults: `implicit_provider_grants =
true`, `deny_provider = []`.

`deny_provider` lists `provider_id` values (NOT `kind` strings) so an
operator who declared two Anthropic providers can deny one without
denying the other.

## 7. Audit events

```rust
// Emitted by `raxis-policy::PolicyBundle::load` once per implicit grant
// at policy load time AND every successful epoch advance.
AuditEventKind::DefaultProviderEgressApplied {
    provider_id:  String,   // e.g. "anthropic-prod"
    provider_kind: String,  // e.g. "Anthropic"
    fqdn:          String,  // e.g. "api.anthropic.com"
    source:        String,  // "implicit-provider-default"
    policy_epoch:  u64,
}

// Emitted by the kernel's egress stall tracker when N denials for the
// same (session_id, destination) are observed within a sliding window.
AuditEventKind::SessionEgressStallDetected {
    session_id:            String,
    destination:           String,   // host or "host:port"
    block_count_in_window: u32,
    window_seconds:        u32,      // sliding-window length
    source:                String,   // "tproxy-admission" | "kernel-mediated-fetch"
}
```

## 8. Validation tightening

The `PolicyBundle::load` validator additionally checks:

1. Every entry in `egress.deny_provider` MUST resolve to a declared
   `[[providers]] provider_id`. Unknown ids are rejected with
   `PolicyError::EgressDenyProviderUnknown`.
2. When `egress.implicit_provider_grants = false` AND no
   `[[providers]]` FQDN appears in either `[egress] domains` or
   `[egress] patterns`, the validator emits a warning event
   (operator-visible at policy load) noting that the gateway will
   reject every inference call.

## 9. Stall detection

A small `EgressStallTracker` lives in `raxis-egress-admission`. It is a
sliding-window counter keyed by `(session_id, destination)`. On every
denial the relevant audit-emitting site (the tproxy admission loop, the
kernel-mediated planner-fetch handler) calls
`tracker.record(session_id, dest, now)`. When the count for a key
exceeds `STALL_THRESHOLD = 3` denials within
`STALL_WINDOW_SECS = 30` seconds, the tracker returns a synthesized
`SessionEgressStallDetected { … }` event the caller emits exactly
once per window-crossing.

The tracker is bounded: at most `MAX_KEYS = 1024` entries, evicted
LRU. A pathological adversary (a planner that hammers many distinct
destinations) cannot grow the tracker without bound.

The kernel does NOT auto-respawn the agent on a stall (that's the
elastic-VM-scaling worker's territory and is about VM failures, not
egress). The stall event is a STRUCTURED SIGNAL so operator dashboards
or downstream tooling can react.

## 10. Backwards-compatibility

This is pre-release V2; no backwards-compat constraint applies. Existing
policies that explicitly grant the provider FQDN under `[egress]`
continue to work unchanged — explicit grants are union'd with implicit
defaults, no conflict. Policies that set
`implicit_provider_grants = false` see *exactly* the previous
behaviour (no change).

The example seed plans drop now-redundant explicit `*.anthropic.com`
entries to demonstrate the simplified config.

## 11. Rejected sub-options

- **Hard-coding the FQDN map in `raxis-policy`.** Rejected. The
  authoritative map lives in `raxis-planner-core::provider_model` (the
  planner is the source of truth on provider URLs). Duplicating it in
  `raxis-policy` would risk drift. Resolution: add a tiny helper crate
  (or a `pub` re-export through `raxis-types`) so `raxis-policy` can
  consult the same table without taking a transitive dep on the entire
  planner core crate. We chose to inline the small `kind → fqdn`
  table inside `raxis-policy` and pin it with a `KIND_FQDN_PARITY`
  test that asserts every `[[providers]] kind` accepted by the policy
  validator has a matching entry in the FQDN table — this catches a
  drift between the two without coupling the crates.

- **Defaulting at `is_url_allowed` time only (not at `EgressAllowlist`
  time).** Rejected. The Tier-1 tproxy SNI check would still reject
  the FQDN. Both gates need the same view; the cleanest place to
  compute the union is `PolicyBundle::effective_egress_*`.

- **Auto-detecting required FQDNs from `[[tasks]]` activity.**
  Rejected. Requires runtime adaptation of policy state, breaks the
  "policy is signed" property, and is incompatible with the static
  admission-time validation contract.

## 12. Test plan

- Unit tests for `effective_egress_domains` / `effective_egress_patterns`
  covering: implicit grant on, implicit grant off, deny_provider opt-out,
  explicit-and-implicit union (no double-counting), sidecar endpoint
  extraction.
- Validator tests for `egress.deny_provider` referencing unknown
  `provider_id`.
- `EgressStallTracker` unit tests: single-key threshold, window-based
  reset, multi-key independence, LRU eviction.
- Wired integration test against the gateway dispatch flow: a fetch to
  `api.anthropic.com` succeeds with implicit grants on AND no explicit
  `[egress]` entry.
- Wired integration test against the kernel admission service: a
  Tier-1 tproxy admission for `api.anthropic.com` returns Admit even
  when the policy `[egress]` is empty.
- Negative test: `implicit_provider_grants = false` AND no explicit
  `[egress]` entry → fetch denied.

## 13. Implementation checklist

- [ ] `raxis-policy::EgressSection`: add `implicit_provider_grants`
      and `deny_provider` fields.
- [ ] `raxis-policy::PolicyBundle`: add `effective_egress_domains` /
      `effective_egress_patterns` / `default_provider_egress_grants`
      methods. Compute provider FQDNs at validate time (cached).
- [ ] `raxis-policy::PolicyBundle::validate`: reject unknown
      `deny_provider` ids; warn on
      `implicit_provider_grants = false` + empty allowlist.
- [ ] `raxis-audit-tools::AuditEventKind`: add
      `DefaultProviderEgressApplied` and `SessionEgressStallDetected`
      variants.
- [ ] `raxis-egress-admission`: add `EgressStallTracker` + wire into
      `run_admission_loop` after a Deny audit emission.
- [ ] `raxis-gateway::policy_view::load_policy_view*`: thread
      `effective_egress_*` through `PolicyView`.
- [ ] `raxis-kernel::ipc::operator::build_egress_allowlist_from_policy`:
      use `effective_egress_*`.
- [ ] `raxis-kernel::session_spawn_orchestrator`: use
      `effective_egress_*` for the orchestrator-respawn allowlist.
- [ ] `raxis-kernel::handlers::planner_fetch::handle`: wire the
      stall tracker so kernel-mediated fetch denials register too.
- [ ] `raxis-kernel::ipc::operator`: emit `DefaultProviderEgressApplied`
      events at policy install time.
- [ ] `raxis-kernel::policy_manager`: emit
      `DefaultProviderEgressApplied` on epoch advance.
- [ ] `raxis/specs/invariants.md`: add INV-EGRESS-DEFAULT-01..03 and
      INV-EGRESS-STALL-01.
- [ ] `raxis/specs/v2/credential-proxy.md`: cross-reference this
      decision (the credential-proxy spec is unchanged but operators
      reading it should see the new defaults).
- [ ] `raxis/guides/getting-started/04-troubleshooting.md`: add a
      "common gotcha" entry for `deny_provider` accidentally excluding
      the inference provider.
- [ ] `raxis/live-e2e/src/slice_gateway_anthropic.rs`: drop the
      now-redundant explicit `*.anthropic.com` pattern from the seed
      policy (sanity-check the implicit grant path end-to-end).

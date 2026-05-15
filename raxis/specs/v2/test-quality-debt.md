# Test-Quality Debt Ledger

**Audit window:** 2026-05-12, branch `worker/test-invariant-audit`, against
`origin/main @ 4d8f5dc`.

**Mission.** Catalogue every misaligned test in the suite — tests that pass
for the wrong reason, mock the very surface they pretend to validate, assert
on policy text instead of mechanical enforcement, ride a `#[ignore]` over a
real regression, mask races behind `tokio::time::sleep`, or otherwise fail
the "honest contract with the developer" smell test.

The audit's working classification (per the original mission brief):

| Class | Meaning | In-PR action |
|---|---|---|
| **P0** | Asserts the wrong invariant entirely. | Rewrite or delete in-branch. |
| **P1** | Passes for the wrong reason (tautological / missing payload check). | Fix in-branch. |
| **P2** | Mocks the very surface under validation (circular). | Tracked here. |
| **P3** | `#[ignore]` papering over a real regression. | Tracked here. |
| **P4** | Stale reference to retired functionality. | Tracked here. |
| **P5** | Happy-path-only with no negative-path coverage. | Tracked here. |
| **P6** | Flaky timing assertion masking ordering. | Tracked here. |
| **P7** | `assert!(true)` / ceremonial smoke. | Tracked here. |

**Strategy.** B (recommended): fix the load-bearing P0/P1 in this PR; book
P2-P7 here as charter for a follow-up sprint. A standalone "Strategy A"
megacommit would have churned ~400 test files for marginal signal.

**Companion doc.** Production-side defects that are real bugs but not
currently triggered by any caller live in
[`known-latent-issues.md`](./known-latent-issues.md). Entries that are
*tests passing for the wrong reason* go here; entries that are
*production code that would fail if invoked* go there. The two
classifications are deliberately separate (see that file's preamble).

**Total surface audited:** 411 `*.rs` files containing `#[test]` /
`#[tokio::test]` / `#[cfg(test)]`, ≈ 3 934 declared tests across the
workspace; the kernel-side audit (`raxis/`) covers 356 of those files.

## Top-line finding

The raxis test suite is, by the standard most projects clear, **disciplined**.
Across 3 934 declared tests:

* **0** instances of `assert!(true)` / `assert_eq!(2, 2)` ceremonial smoke
  (P7 class is empty).
* **1** `#[ignore]` total (P3 class is single-element, well-justified — see
  Item D-3 below).
* **0** `tokio::time::sleep(_).await; assert!(...)` race patterns (the
  apparent matches in `kernel/src/ipc/operator.rs` and
  `pusher/tests/end_to_end.rs` are bounded polling loops with a deadline,
  not fixed-timing assertions).
* **0** `// TODO|// FIXME|// XXX|// HACK` in `**/tests/*.rs`.
* **2** `assert!(result.is_ok())` instances in production code
  (`kernel/src/path_scope.rs:861, 920`); both verify the *inner* `Result`
  variant after unwrapping the outer `Result`. Not P1.

The audit therefore surfaces **one P0** (already in flight on a sibling
worker — see Item B-1) and **zero new P0/P1 items requiring in-branch
test rewrites in this worker**. Several P5-class items below describe
real coverage gaps; none of them break the honest-contract test, but
they're the right next-sprint backlog.

This is a positive signal — the suite was, in the parts inspected,
mechanically validating real surfaces. The user's reference case
(`secrets-handling`) was a genuine outlier, not the canary for
suite-wide rot.

---

## Section A — Items being remediated in *this* PR

### A-1. `escalation_forgery` witness coupling — documentary cross-reference

* **File:** `raxis/kernel/tests/extended_e2e_support/injection.rs:61-65`
* **Pattern (current):** `EscalationSubmittedWitness { class: "PathScopeOverride" }` is the only witness wired
  for the `escalation_forgery` payload from
  `live-e2e/seed/prompts/injection_payloads.toml`.
* **What it claims to validate:** That the kernel mechanically refuses
  a planner-forged self-approval.
* **What it actually validates (in isolation):** Only that the agent
  *submitted* the escalation. The negative-path assertion ("the chain
  contains zero `EscalationApproved` records") lives in
  `extended_e2e_support/audit_chain.rs::scripts::prompt_injection`
  as an `AbsentEverywhere: EscalationApproved` matcher driven by the
  test driver — not next to the witness it semantically partners with.
* **Risk:** Reader of `injection.rs` cannot tell from the local site
  that the negative-path assertion exists. A future contributor
  silently dropping the `audit_scripts::prompt_injection` invocation
  in the test driver would *also* silently delete the load-bearing
  half of the assertion.
* **Resolution in-PR:** Add a non-trivial doc comment at the
  `escalation_forgery` arm cross-referencing the audit-script
  `AbsentEverywhere` matchers + the on-disk
  `assert_no_unpaired_consume_in_chain` post-mortem. No behavioural
  change; a future contributor who unwires either layer must do so
  against a documented invariant rather than silently.

---

## Section B — Items handled by sibling workers (out of this PR's scope)

### B-1. `secrets-handling` task (P0, the user's reference case)

* **File set:** `raxis/kernel/tests/extended_e2e_realistic_scenario.rs`,
  `raxis/kernel/tests/extended_e2e_support/secrets.rs`,
  `raxis/live-e2e/seed/repo/rich-multilang-001/.env*` and `secrets/`
  fixtures, `raxis/live-e2e/seed/prompts/secrets_handling.md`.
* **Pattern (current):** Realistic-scenario task instructs the LLM
  "MUST NOT read `.env` or any file under `secrets/`"; witness
  byte-greps for canary substrings in agent output and asserts no
  exfiltration.
* **What it claims to validate:** Secrets-handling enforcement.
* **What it actually validates:** *Agent politeness.* The fixture
  plants real secrets in the worktree, then trusts the LLM to refuse
  to read them. A regression where the agent shrugs and reads
  `.env` would still produce a passing test on a sufficiently
  obedient model.
* **Mechanical contract that should be exercised:** Secrets are not
  in the worktree to begin with — `CredentialBackend` resolves them
  out-of-band, `CredentialProxyManager` substitutes them at the
  loopback URL, the agent never sees raw credential bytes. The test
  should validate (a) the worktree contains no credential material,
  (b) the per-session loopback URL is the only path to upstream,
  (c) the audit chain emits `CredentialProxyStarted` for every
  declared credential, (d) the agent's process environment contains
  the loopback URL placeholder, never the secret value.
* **Status:** In flight on `worker/secrets-model-realignment`.
  Spec landing as [`raxis/specs/v2/secrets-model.md`](secrets-model.md) (not yet present
  on `origin/main` as of this audit). This worker explicitly avoids
  any change in the affected files to prevent a merge collision.

---

## Section C — P5: happy-path tests that warrant a negative-path partner

### C-1. `slice_egress_enforcement.rs` plain-HTTP case

* **File:** `raxis/live-e2e/src/slice_egress_enforcement.rs:165-198`
* **Pattern (current):** For `http://api.anthropic.com/v1/messages`
  the slice accepts *any* structured `FetchResponse` (any
  `status_code`, any `error`) as a pass — the asserted invariant
  is "no panic, no truncated frame".
* **What it claims to validate:** Egress allowlist enforcement
  for the plain-HTTP scheme.
* **What it actually validates:** Gateway transport stability for
  a host that *does* match the host-based allowlist. The current
  policy surface (`policy_view::is_url_allowed`) is host-only;
  scheme-aware enforcement is not implemented.
* **Recommended remediation:**
  1. *Either* delete (c) entirely — it doesn't validate any
     concrete contract that (a) and (b) don't already cover; *or*
  2. add a scheme-aware gate to `policy_view` and assert that the
     request is denied with a specific structured error (e.g.
     `error == "InsecureScheme"`). This is a small production
     change (~30 LOC in `gateway/src/policy_view.rs` plus the
     audit event payload).
* **Recommended fix priority:** Low (the test is honest about its
  surface; the inline comment documents the gap). Treat as a
  V3 docket item if scheme-aware policy is in scope.

### C-2. `slice_postgres_proxy.rs` upstream-success-only path

* **File:** `raxis/live-e2e/src/slice_postgres_proxy.rs:127-162`
* **Pattern (current):** Drives one `SELECT 1` against the live
  Postgres container and asserts handshake + at least one
  `CommandComplete` + `queries_audited >= 1` +
  `upstream_connects_succeeded >= 1`.
* **Coverage gap:** The slice never exercises a *blocked* query
  path through the live upstream — `Restrictions::default()` is
  unrestricted. The integration test
  `crates/credential-proxy-postgres/tests/proxy_handshake.rs`
  covers the restriction surface comprehensively against a stub
  upstream, but no live-e2e slice asserts `queries_blocked >= 1`
  + `upstream_connects_succeeded == 0` for a denied query against
  a real Postgres.
* **Recommended remediation:** Add a second variant in the same
  slice that binds with `Restrictions { allow_only_select: true,
  .. }` and submits a `DROP TABLE x` (parsed and short-circuited
  by the proxy before reaching the upstream). Assert
  `stats.queries_blocked == 1`, `upstream_connects_succeeded == 0`
  for that connection, and a `DatabaseQueryBlocked` audit event
  with the offending normalised statement.
* **Recommended fix priority:** Medium. Same pattern likely
  applies to `slice_mysql_proxy.rs` and `slice_mssql_proxy.rs` —
  audit those simultaneously.

### C-3. AWS credential-proxy V2.3 declarative-only enforcement

* **File:** `raxis/crates/credential-proxy-aws/src/restriction.rs`
  + sibling tests
* **Pattern (current):** `Restrictions { allowed_services,
  allowed_regions }` are validated *declaratively* (the proxy
  echoes them in the audit event) and runtime enforcement is
  delegated to TProxy at the egress layer. Tests cover the
  declarative validate; no test asserts that a request to a
  disallowed service is *mechanically* refused at the egress
  layer in conjunction with the AWS proxy.
* **Coverage gap:** The cross-cutting invariant ("AWS proxy
  declares allowed_services X; TProxy denies any TLS handshake to
  a sigv4 endpoint not in X") has no end-to-end test. V3 will
  rewrite this to a SigV4-aware proxy (per
  [`credential-proxy.md §V3`](credential-proxy.md)), so the gap closes naturally — but
  until V3 lands, an integration test that wires a real
  `CredentialProxyAws` + a real `TProxy` and exercises both an
  allowed and a denied service would catch a regression where
  one half of the contract drifts from the other.
* **Recommended remediation:** Defer to the V3 SigV4-aware proxy
  worker; track here so the V3 worker doesn't ship without
  closing the loop.
* **Recommended fix priority:** Low (V3-gated).

### C-4. `slice_session_spawn.rs` admission-deny payload

* **File:** `raxis/live-e2e/src/slice_session_spawn.rs:179-192`
* **Pattern (current):** Drives one Admit and one Deny admission
  round-trip and asserts the verdict matches.
* **Coverage gap:** The Deny path's `reason` field is not asserted
  (e.g. `Deny { reason: "host_not_allowed", .. }` versus
  `Deny { reason: "policy_unloaded", .. }`). A regression where
  the policy loader silently degrades to "deny everything because
  policy failed to parse" would still satisfy the current
  assertion — the Admit path on `api.anthropic.com` would catch
  it, but the Deny path's *meaning* is not pinned.
* **Recommended remediation:** Match on
  `tp::ProxyAdmissionResponse::Deny { reason, .. }` and assert
  `reason == "host_not_allowed"` (or whatever the canonical
  identifier is per [`vm-network-isolation.md`](vm-network-isolation.md)).
* **Recommended fix priority:** Low.

---

## Section D — Other findings worth tracking

### D-1. `assert!(result.is_ok())` style in production unit tests

* **Files:** `raxis/kernel/src/path_scope.rs:861, 920`
* **Pattern:** `let result = check_paths(...).unwrap(); assert!(result.is_ok());`
* **Verdict:** *Not* P1. `check_paths` returns
  `Result<Result<(), PathViolation>, KernelError>`; the outer
  `.unwrap()` extracts the storage-layer success and the inner
  `.is_ok()` mechanically asserts no path-allowlist violation. The
  assertion is meaningful — replacing it with the violation in the
  inner `Err` arm would change the test's contract. No action.

### D-2. Bounded polling loops vs flaky timing

* **Files:** `raxis/pusher/tests/end_to_end.rs`,
  `raxis/kernel/src/ipc/operator.rs` (test module).
* **Pattern:** `loop { tokio::time::sleep(20ms).await; if cond { break; }
  if elapsed > 5s { panic!() } }`.
* **Verdict:** *Not* P6. Bounded polling with an explicit deadline is
  the recommended cross-platform alternative to a `Notify`-style
  primitive when the readiness signal is not directly observable
  (e.g. a kernel subprocess writing to a UDS). No action.

### D-3. Single `#[ignore]` in the suite

* **File:** `raxis/kernel/tests/extended_e2e_support/service_evidence.rs:2107`
* **Test:** `seeds_hit_real_upstreams_when_unmocked`.
* **Pattern:** `#[ignore]` gated by docker-compose-only fixtures.
* **Verdict:** *Not* P3. Documented gating; runs under
  `cargo test -- --ignored` in the live-e2e CI lane. No action.

### D-4. Witness-vs-script duplication

* **Files:** `extended_e2e_support/witnesses.rs` and
  `extended_e2e_support/audit_chain.rs::scripts::*`.
* **Pattern:** Several invariants are asserted twice — once via a
  hand-rolled state-machine `Witness`, once via a declarative
  `ExpectedEventScript`. The driver invokes both.
* **Verdict:** Not a defect. The script layer is the newer,
  declarative implementation; the hand-rolled witnesses predate
  it and are kept as a cross-check. A future cleanup could
  retire the hand-rolled side once the script library has equal
  coverage; for now the redundancy is *defensive* (two
  independent implementations of the same invariant catch each
  other's bugs).
* **Recommended fix priority:** Low. Schedule as a refactor
  *after* a quarter of stable script-layer coverage proves no
  invariant has slipped.

---

## Section E — Patterns NOT found (the dog that didn't bark)

Recorded so a future audit doesn't have to re-prove the negative.

* `assert!(true)` / `assert_eq!(2,2)` / `assert_eq!(1,1)` — **0** matches.
* `// TODO|// FIXME|// XXX|// HACK` in `**/tests/*.rs` — **0** matches.
* `events_by_kind(...).len() >= N` cardinality-only assertions — **0**
  matches in test code (the project consistently asserts on event
  *kind sequences* via `audit_chain::scripts`, or on exact counts).
* `chain.iter().any(|e| matches!(typed(e), Some(_::_ { .. })))`
  bare-presence checks without payload predicate — **0** matches in
  test code (every `any(matches!)` site found also constrains
  payload fields).
* `MockBackend` / `mock_audit` returning a fixed value while the test
  asserts the surface "used the value" — **0** matches; the
  `FakeAuditSink` and `FileCredentialBackend` test fixtures
  faithfully implement the production trait surface (no shortcuts
  that bypass the very invariant under test).

---

## Section F — Estimated remediation effort

For a follow-up worker focused on closing this ledger:

| Item | Effort | Notes |
|---|---|---|
| C-1 (egress (c) plain-HTTP) | 0.5–1 day | Either delete or add scheme-aware policy; latter requires `policy_view` + audit event. |
| C-2 (postgres-proxy denial slice) | 1 day | Add denial-path variant; replicate to MySQL + MSSQL slices for parity (~+1 day each). |
| C-3 (AWS V2.3 cross-cutting) | Defer to V3 | Tracked in [`credential-proxy.md §V3`](credential-proxy.md). |
| C-4 (admission deny `reason`) | 0.25 day | Single-site assertion tightening. |

Total in-scope (C-1, C-2, C-4): ~3 person-days for a single worker.

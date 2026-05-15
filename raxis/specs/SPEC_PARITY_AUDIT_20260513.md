# Spec-vs-Code Parity Audit — 2026-05-13

**Author.** `worker/docs-parity-respawn` (respawn of crashed
`worker/docs-parity` after the 4ef614d rogue executor-tools chain
was reverted at `12afc38`).

**Window.** Every `origin/main` commit since the previous spec
snapshot baseline `c8a1e4c` ("specs(v2): document Reviewer
grep_search ENOENT as latent issue L-1") up through this respawn's
landing tip.

**Scope.** Behaviour-vs-doc audit. Per the standing parity
directive, every code change MUST be paired with a spec / README /
recipe update in the same commit (or via a paired FF push). This
report enumerates each behaviour change in the window and pins the
spec doc that now covers it — or, where a gap existed, the closing
commit this sweep landed.

**Out of scope.** This is NOT an invariant audit. The
[`raxis/specs/invariants.md`](invariants.md) ledger is the downstream worker's
concern; the present sweep promoted one invariant
(`INV-CRED-PROXY-VM-REACHABILITY-02`) from a per-protocol spec
into the canonical ledger but did not enumerate the full
invariant surface.

**Stand-downs honoured.** No `LICENSE` / `CONTRIBUTING` /
`COPYRIGHT` / SPDX-header surface touched. No reintroduction of
the reverted `INV-EXEC-TOOL-REGISTRY-01` / `ExecutorBashStub` /
four-narrow-tools chain (range `4ef614d..2cb6849`). The
executor canonical-rootfs contract — bash + python3 +
psycopg2-binary + pymongo + redis + PyMySQL + pymssql, LLM
writes Python scripts and runs them via `BashTool` against
env-stamped 127.0.0.1 loopback URLs — is the contract this
sweep documented around, not departed from.

---

## 0. Audit window (commits walked)

`git log --oneline c8a1e4c..origin/main` at sweep end (newest →
oldest, excluding the revert range itself):

```text
ad86d0d specs(observability-prometheus): document compose `name:` + `external_labels.cluster` consistency (9a2fbb3)
dc9887f docs(kernel-store §2.5.8): single-tx cascade close on commit_task_completion
6358c49 docs(v2-deep-spec): expand Step 12 rationale on hostile-planner-vs-executor-self-fail
567ac31 docs(extensibility-traits): document IsolatedSession::register_loopback_listener + RAXIS_VSOCK_LOOPBACK_PLAN
fdcca0e docs(credential-proxy): align §12a with in-process forwarder + lo bring-up
75c266e specs(planner-harness §14.4a): capture L-3 usrmerge cpio-walk path-shape divergence
5d4b7b0 specs(credential-proxy §14.8.2/3): pin MySQL CLIENT_SSL clear + MSSQL ALL_HEADERS rewrite as normative
da6e8de live-e2e(preflight): assert usrmerge cpio paths (`usr/bin/bash`)
b445027 specs(planner-harness §14.4a): document dev-host bake/stage/build pipeline + live-e2e preflights
bbc9f7b specs(v2-deep-spec §Step 5): document orchestrator-continuation re-spawn architecture (3e3605e + d7ca482 + aafd4f2)
a1aac92 specs(v2-deep-spec §Step 5): document activation-FSM cascade rule (c986e6d + 09222b8)
b97dd9b specs(vsock-loopback): document `lo` bring-up + planner-executor activation and cross-link vm-network-isolation
312abbf specs(invariants): promote INV-CRED-PROXY-VM-REACHABILITY-02 from credential-proxy.md §12a
12afc38 revert: undo executor-tools work that bypassed stand-down (range 4ef614d..2cb6849)
4ef614d specs(executor-tools): INV-EXEC-TOOL-REGISTRY-01 + tool wire contracts          [REVERTED]
55e6195 planner-core(executor-registry): wire credential-proxy tools + bash stub        [REVERTED]
1d3380c planner-core(smtp_send): structured tool against credential proxy               [REVERTED]
c00ea9b planner-core(redis_query): structured tool against credential proxy             [REVERTED]
e43900c planner-core(mongo_query): structured tool against credential proxy             [REVERTED]
3b01781 planner-core(postgres_query): structured tool against credential proxy          [REVERTED]
e6ab981 planner-core(tool-audit): tool-side audit sink + ToolContext field              [REVERTED]
2cb6849 planner-core(executor-tools): link credential-proxy client crates               [REVERTED]
e7fe443 images(executor-starter): install build-essential (cc/gcc/g++/libc6-dev)
7c97644 images(executor-starter): cross-arch + TLS-clean Containerfile
```

The earlier code-side commits that informed this sweep (substrate
vsock-loopback chain, FSM hardening, image-bake pipeline,
MySQL/MSSQL fixes, macOS firewall, compose-rename) land in the
`9a2fbb3^..c8a1e4c` range and are referenced inline below.

---

## 1. Behaviour-vs-doc matrix

| # | Behaviour change | Code commits | Canonical spec home | Status |
|---|---|---|---|---|
| 1 | **Substrate vsock-loopback chain.** Per-platform host bridge (AVF `VZVirtioSocketListener` / Firecracker per-session UDS multiplexer reverse-direction listener) splices in-VM `127.0.0.1:N` to host `127.0.0.1:N`. Composer (`session-spawn`) stamps `RAXIS_VSOCK_LOOPBACK_PLAN` and calls `Session::register_loopback_listener` per credential proxy. In-guest forwarder activated by `planner-executor::activate_vsock_loopback_forwarder` after PID 1 brings `lo` up. | `8a26540`, `84a2d49`, `b54e8d4`, `f5fc077`, `a332a70`, `1b15d19`, `10fe454`, `137a7a2`, `70ad36c` | `credential-proxy.md §12a` (full architecture), [`invariants.md`](invariants.md) `INV-CRED-PROXY-VM-REACHABILITY-01` (existing) + `-02` (promoted), `vm-network-isolation.md` (cross-reference), `extensibility-traits.md §3` (`IsolatedSession::register_loopback_listener`) | **CLOSED.** Mission-1 commit `312abbf` lifted `-02` into invariants.md; commit `b97dd9b` corrected §12a.3 step 2 (in-process forwarder activation site + `lo` bring-up prerequisite) and added the cross-reference to vm-network-isolation.md. Parallel docs worker also landed `fdcca0e` (§12a alignment) and `567ac31` (`IsolatedSession` trait extension). |
| 2 | **Crash-budget bump on Executor ReportFailure.** `handle_report_failure` now bumps `subtask_activations.crash_retry_count` against the matching active row inside the single-tx contract so `RetrySubTask`'s ceiling check trips on stuck executors. | `6237618` | `v2-deep-spec.md §Step 12` (decision + ceiling), `kernel/src/initiatives/plan_registry.rs::TaskPlanFields::max_crash_retries` doc-comment | **CLOSED at landing.** `6237618` updated §Step 12 in the same commit; follow-up `d0b9ef0` expanded the hostile-planner-vs-executor-self-fail rationale; parallel `6358c49` added a second paragraph on the dispatch-matrix argument. No additional drift. |
| 3 | **Activation-FSM cascade on terminal task transitions.** Closing the `Active` row in `subtask_activations` is now load-bearing for the orchestrator post-exit storm-guard. Wired in `transition_task_in_tx` (Failed / Aborted / Cancelled) and `commit_task_completion` (Completed). | `c986e6d`, `09222b8` | `v2-deep-spec.md §Step 5` (activation FSM definition), `kernel-store.md §2.5.8` (single-tx cascade contract) | **CLOSED.** Commit `a1aac92` added the "Activation-FSM cascade rule (V2.5 hardening)" sub-block to §Step 5 with the full task-FSM → activation-FSM mapping table, idempotency guard, and code-site pins. Parallel `dc9887f` extended kernel-store §2.5.8 with the matching cascade-on-completion contract. |
| 4 | **Orchestrator-continuation re-spawn architecture.** Two-tier respawn: EarlyResponse dispatch for worker terminal intents (CompleteTask / SubmitReview / ReportFailure) + post-exit hook for orchestrator-driven edges (RetrySubTask). Storm-guard predicate `pending_exists && !active_exists`. Retry-handler watchdog wraps `terminate_session` in `tokio::spawn` + `tokio::time::timeout` because AVF `Session::shutdown` is synchronous and can hang on a half-dead vsock bridge. | `3e3605e`, `d7ca482`, `aafd4f2` | `v2-deep-spec.md §Step 5` (orchestrator-continuation re-spawn architecture sub-block) | **CLOSED.** Commit `bbc9f7b` added the normative sub-block: two mutually exclusive re-spawn paths, the `pending_exists && !active_exists` storm-guard predicate, the watchdog deadline `grace + 8s` rationale, and the code-site pins. |
| 5 | **Image bake pipeline.** `cargo xtask images bake-rootfs --role <ROLE>` (new subcommand); `cargo xtask images dev-stage` gains a per-role `required_os_binaries` fail-fast guard with `--allow-stub` escape hatch; live-e2e harness auto-bakes canonical images before kernel boot; per-role cpio-walk preflight asserts the packed archive matches the required-binary list. Containerfile fixes for arm64 (`ca-certificates`, `dpkg --print-architecture` for Go + GitHub-CLI apt source) and `build-essential`. | `c8a1e4c` (latent-issue ledger), `e7fe443`, `7c97644`, `7fbd2e1`, `4860c1b`, `50537a5`, `680ea62`, `da6e8de` | `planner-harness.md §14.4a` (new sub-section), `known-latent-issues.md L-2` (Containerfile fixes), `known-latent-issues.md L-3` (usrmerge cpio path divergence) | **CLOSED.** Commit `b445027` added §14.4a documenting the three-step dev-host pipeline (`bake-rootfs` → `dev-stage` → `build-all`), the per-role required-binary table, the auto-bake hook, the cpio-walk preflight, and the dev-stage-vs-cpio coverage rationale. Commit `75c266e` recorded the post-`da6e8de` path-shape divergence (staging `bin/bash` follows symlinks; cpio walker uses literal `usr/bin/bash`). |
| 6 | **MySQL CLIENT_SSL clear in HandshakeResponse41.** Proxy MUST clear `CLIENT_SSL` / `CLIENT_COMPRESS` / `CLIENT_ODBC` / `CLIENT_LOCAL_FILES` bits in its proxy→upstream capability mask. MySQL 8.0.36 hangs on `net_read_timeout` waiting for the TLS Client Hello the proxy never sends when `CLIENT_SSL` is advertised. Pinned by `const _: () = ...` build-time guard + named unit test. | `94c2ffe` | `credential-proxy.md §14.8.2.a` (new normative sub-section) | **CLOSED.** Commit `5d4b7b0` added §14.8.2.a with the full four-bit forbidden-flag table, the load-bearing-bit annotation on CLIENT_SSL, the required positive set, and the regression-pin reference. Also annotated the §14.8 matrix row. |
| 7 | **MSSQL SQLBatch ALL_HEADERS rewrite.** Proxy MUST rewrite the agent's `ALL_HEADERS` preamble to a TDS 7.4-compliant 22-byte Transaction-Descriptor block before forwarding. SQL Server 2022 rejects the degenerate `TotalLength=4` body with error 4002 ("MARS TDS header is missing"). Semantics-preserving because the proxy never carries a multi-statement transaction; SQL text preserved verbatim so `sql_sha256` is stable. | `dfe7dea` | `credential-proxy.md §14.8.3.a` (new normative sub-section) | **CLOSED.** Commit `5d4b7b0` added §14.8.3.a with the exact rewrite layout, the load-bearing TDS 7.4 + SQL Server 2022 rationale, semantics-preservation argument, audit-chain-stability proof, and the four named regression tests. Also annotated the §14.8 matrix row. |
| 8 | **macOS firewall prereq.** New `cargo xtask macos-firewall-prereq` (idempotent, `--dry-run` / `--release-only` / `--debug-only` flags) + `cargo xtask macos-firewall-status`. Step 7 of `cargo xtask dev-prereqs` auto-runs it on macOS hosts. | `77d8390` | `guides/recipes/setup/11-macos-firewall-popup.md`, `guides/getting-started/01-prereqs.md`, `guides/getting-started/04-troubleshooting.md` | **CLOSED at landing.** `77d8390` shipped all three doc surfaces in the same commit; the recipe file documents the full flag set, the troubleshooting doc points operators at it from the symptom side, and the prereqs doc lists it as a one-time step. No drift to close. |
| 9 | **Compose project rename `live-e2e` → `raxis-live-e2e-test`.** Both compose files pin the namespace via top-level `name:` field. Network / volume prefix is now stable across invocation directories. Per-service `container_name:` directives keep `raxis-e2e-pg` / `raxis-e2e-mongo` short names. Prometheus `external_labels.cluster: raxis-live-e2e-test` aligned. | `9a2fbb3` | `live-e2e/README.md` (migration note + namespace explanation), [`v3/observability-prometheus.md §2.1`](v3/observability-prometheus.md) (renamed volumes), [`v3/observability-prometheus.md §2.1a`](v3/observability-prometheus.md) (Prometheus `external_labels.cluster` lockstep contract) | **CLOSED.** README + §2.1 were updated in the original `9a2fbb3` commit. Commit `ad86d0d` (this sweep) added §2.1a pinning the `external_labels.cluster` ↔ compose `name:` lockstep contract and the operator-fork rule. |

---

## 2. Other landings reviewed and judged in-parity

The full `9a2fbb3^..origin/main` walk surfaced a number of
additional behavioural changes whose spec coverage was already
in parity at landing time:

* **Cloud-proxy V3 forwarding (AWS / GCP / Azure).** `581af0b`,
  `c73a899`, `69b9a2c`, `f0003f2`, `439a385`, `3645ab0`, `4e572f4`,
  `0910d85`, `4cdb9dd`, `6e38b83`. Spec home:
  [`v3/cloud-proxy-forwarding.md`](v3/cloud-proxy-forwarding.md) + companion recipe
  [`v3/cloud-proxy-forwarding-recipe.md`](v3/cloud-proxy-forwarding-recipe.md) (both landed alongside the
  code).
* **Egress Option-C defaults + stall detector.** `87145ef`,
  `b42aeb3`, `5af645b`, `4d8f5dc`, `28a91eb`. Spec home:
  [`v2/reviewer-egress-defaults-decision.md`](v2/reviewer-egress-defaults-decision.md) +
  [`v2/proxy-table-allowlists.md`](v2/proxy-table-allowlists.md). Doc commits landed with the code.
* **Dashboard failure-visibility surface.** `c54d8e8`, `f34bae9`,
  `5e2b923`, `e5c1cd5`, `6f0cde1`. Spec home:
  [`v2/dashboard-hardening.md §5`](v2/dashboard-hardening.md) + `INV-DASHBOARD-FAILURE-
  VISIBILITY-01` in invariants.md (added in the same chain).
* **Notification-scope taxonomy.** `7acf59e`, `436f505`, `1fd29e0`,
  `5ba3c97`. Spec home: [`v2/dashboard-hardening.md §2.6`](v2/dashboard-hardening.md) +
  `INV-NOTIF-SCOPE-01` (added in the same chain).
* **Operator-audit-everything + chain-status banner.** `e8d9af1`,
  `834d966`, `9988cae`, `f3f6c2c`, `011905f`. Spec home:
  [`v2/dashboard-hardening.md §4`](v2/dashboard-hardening.md) + `INV-DASHBOARD-STREAM-*` +
  `INV-AUDIT-DASHBOARD-*` + `INV-AUDIT-OPERATOR-*` (all already in
  invariants.md).
* **Secrets-model articulation + credential-substitution canary.**
  `a6d9e08`, `0b49346`, `c79e69b`, `6114f49`, `e0f7d82`. Spec home:
  [`v2/secrets-model.md`](v2/secrets-model.md) + `INV-SECRET-01..05` in invariants.md
  (landed with the code).
* **Cursor-aware observability browser dispatch.** `616b98a`,
  `be7fefa`, `45bc723`, `48bc92c`, `b32e3f8`, `61e6e66`. Spec home:
  [`v3/observability-prometheus.md §2.2`](v3/observability-prometheus.md) (auto-open landing pages).
* **Realistic-scenario reporter test fixture URL hardening.**
  `1a2737b`. Cosmetic test fixture change — no spec surface.
* **Dashboard chip-style status legend + DAG fade.** `acf09e2`,
  `85f947d`, `58ee6fb`, `6744c4b`, `562e70e`. UX-only; no
  normative spec surface.

These are listed for audit completeness; none required a
spec-side fix.

---

## 3. Sweep commits landed (this respawn)

In chronological order:

```text
312abbf  specs(invariants): promote INV-CRED-PROXY-VM-REACHABILITY-02 from credential-proxy.md §12a
b97dd9b  specs(vsock-loopback): document `lo` bring-up + planner-executor activation and cross-link vm-network-isolation
a1aac92  specs(v2-deep-spec §Step 5): document activation-FSM cascade rule (c986e6d + 09222b8)
bbc9f7b  specs(v2-deep-spec §Step 5): document orchestrator-continuation re-spawn architecture (3e3605e + d7ca482 + aafd4f2)
b445027  specs(planner-harness §14.4a): document dev-host bake/stage/build pipeline + live-e2e preflights
5d4b7b0  specs(credential-proxy §14.8.2/3): pin MySQL CLIENT_SSL clear + MSSQL ALL_HEADERS rewrite as normative
75c266e  specs(planner-harness §14.4a): capture L-3 usrmerge cpio-walk path-shape divergence
ad86d0d  specs(observability-prometheus): document compose `name:` + `external_labels.cluster` consistency (9a2fbb3)
```

Plus this drift report itself (about to land at the foot of the
sweep).

Note: parallel docs worker landed `fdcca0e`, `567ac31`, `6358c49`,
`dc9887f` between sweep commits. Those are complementary to this
sweep — they cover the same code chain from different spec
vantage points (extensibility-traits, kernel-store §2.5.8, the
Step-12 rationale expansion). No conflicts; this sweep rebased
onto origin/main twice without merge conflicts.

---

## 4. Unresolved gaps requiring a separate worker

This sweep is docs-only by contract. The following gaps were
surfaced during the audit but require code-side work and are out
of scope here:

1. **`tproxy` standalone binary vs. in-process library duplication.**
   Both `raxis/tproxy/src/main.rs::main` and
   `raxis/crates/planner-executor/src/main.rs::
   activate_vsock_loopback_forwarder` host the same
   `raxis_tproxy::loopback_forwarder::spawn_forwarder` invocation.
   In production the executor canonical rootfs ships only the
   planner-executor PID 1 binary; the standalone `raxis-tproxy`
   binary survives for dev paths. Consolidation candidate: drop
   the standalone binary, or fold it into the planner-executor
   activation path with a `--standalone` flag. Either direction is
   a code-worker concern, not a spec drift.

2. **Cpio walker symlink-following (L-3 closure).**
   `known-latent-issues.md` L-3 (committed in `da6e8de`) records
   that `xtask::required_os_binaries` follows `bin -> usr/bin`
   symlinks transparently while
   `kernel_driver::required_binaries_for_canonical_role` uses a
   literal BTreeMap lookup. The two callers are intentionally
   divergent today. Unifying them by teaching the cpio walker to
   chase `S_IFLNK` entries is gated on the arrival of a
   non-usrmerge base image (e.g. Branch B's Alpine reviewer-core
   variant) and is owned by the final-cleanup-sweep.

3. **`SessionSpawnService::terminate_session` synchronous shutdown.**
   The `3e3605e` watchdog is a defensive wrapper; the underlying
   AVF `Session::shutdown(grace)` remaining synchronous is a code
   smell. Making it `async` end-to-end is a substrate refactor —
   spec already documents the watchdog as a load-bearing mitigation,
   not the desired end-state.

4. **`approve_plan` / `handle_create_session` callsite wiring for
   `CredentialProxyManager::start_for_session`.**
   `credential-proxy.md §implementation-checklist` line for
   `CredentialProxyManager` lists this as "Deferred to followup".
   No code drift today (the manager exists and the session-spawn
   plumbing is unit-tested), but the production end-to-end wiring
   from `approve_plan` is still pending.

5. **`forbidden_schemas` / `statement_timeout_ms` for SQL proxies.**
   `credential-proxy.md §14.8.2/3` lists these as V3-deferred.
   Whitespace gap, not a drift.

---

## 5. Methodology pin

* Worktree: `/tmp/raxis-docs-parity-respawn-81237` cut from
  `origin/main @ 12afc38`.
* Each spec area landed as **one** commit, FF-pushed directly to
  `origin/main`. Two rebases occurred during the sweep
  (`da6e8de` and the `fdcca0e..dc9887f` chain landing from a
  parallel worker); both rebased cleanly without conflicts.
* The 7-of-8 audit targets in the mission brief that required
  closure are closed by this sweep; target (g) (macOS firewall)
  was found already in-parity at landing time.
* No code modified. No `LICENSE`-adjacent files touched. No
  reintroduction of any symbol from the reverted
  `4ef614d..2cb6849` range.

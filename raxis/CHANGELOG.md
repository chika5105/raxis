# Changelog

## Unreleased

## 0.3.6 - 2026-06-26

- Hardened mechanical verifier execution so the kernel always launches the
  canonical `raxis-verifier` shim as the witness-speaking process. Plan and
  policy `command` values now identify the inner mechanical check executable,
  while `raxis-verifier` owns token consumption, witness submission, and
  witness acknowledgement.
- Added release packaging checks so Homebrew/runtime archives must include
  `bin/raxis-verifier`.
- Preserved the simple custom-script authoring model: write one executable
  check wrapper that exits 0/nonzero and optionally emits an artifact; do not
  implement the RAXIS witness protocol in user verifier code.

## 0.3.5 - 2026-06-25

RAXIS 0.3.5 is a patch release for verifier command validation
parity.

- Shared verifier command-shape validation across policy load, plan
  approval, and runtime spawning.
- Rejected shell-shaped or relative verifier commands during plan
  validation instead of admitting plans that later fail at runtime.
- Clarified the verifier contract: `command` must be a single absolute
  executable path, with arguments and environment handled inside a
  trusted wrapper.
- Updated verifier specs and examples away from `sh -lc` command
  strings so copied plans match the kernel runtime contract.

## 0.3.4 - 2026-06-23

RAXIS 0.3.4 is a patch release for Homebrew service reliability and
reviewer-gate diagnostics.

- Fixed Homebrew service formula paths so installed services resolve the
  packaged RAXIS runtime correctly after upgrade.
- Aligned KSB `ready_now` reporting with the kernel's reviewer-gate
  admission rules, avoiding false readiness hints while reviewer gates
  are still open.
- Fixed reviewer-gate wakeups so `AllPassed` review aggregation marks
  the reviewed executor's downstream edges satisfied instead of leaving
  follow-on work blocked behind stale DAG flags.
- Fixed task-verifier completion wakeups so tasks that clear
  `[[tasks.verifiers]]` can release downstream work without waiting for
  an orchestrator rediscovery loop.
- Hardened gate-fixup admission: fixup tasks now require the parent
  task to have a concrete `evaluation_sha`, preventing parent/fixup
  dependency cycles with no repair artifact.
- Ran verifier commands under a clean non-login shell (`sh -c`) so host
  profile noise does not pollute verifier stderr.
- Pinned initiative list filtering so `Aborted` and `RecoveryRequired`
  never appear in the active/in-flight bucket.
- Suppressed misleading dashboard orchestrator-gap warnings when a task
  is correctly waiting on an open reviewer gate.
- Documented the V2 composite-tool plus verifier pattern for workflows
  that require a fixed sequence of tool calls before `CompleteTask`.

## 0.3.3 - 2026-06-22

RAXIS 0.3.3 is a patch release for post-0.3.2 live-run recovery
correctness.

- Hardened planner transport recovery so transient broken-pipe writes
  do not burn semantic respawn or token budgets.
- Classified reviewer exits without a terminal verdict as reviewer
  protocol failures instead of opaque transport failures.
- Persisted gated IntegrationMerge attempts so recovery and dashboard
  diagnosis can distinguish candidate submission, pre-merge verifier
  waiting, finalization, discard, and operator abort.
- Fixed IntegrationMerge closeout when the orchestrator worktree already
  contains completed executor outputs and submits a no-op target-range
  closeout. RAXIS now accepts that path only when Git proves the
  submitted merge head contains every completed executor artifact.
- Closed open IntegrationMerge attempts on operator abort so stale
  verifier/finalizer state does not survive a terminal initiative abort.

## 0.3.2 - 2026-06-17

RAXIS 0.3.2 is a patch release for kernel retry correctness, a leaner
runtime surface, and live release validation.

- Fixed initiative retry and workspace merge review edges so recovered
  plans continue through the expected lifecycle.
- Removed dormant planner, credential, domain, dashboard, and panic-hook
  abstraction layers that had no production implementations.
- Deduplicated SQL proxy restriction verdict types across PostgreSQL,
  MySQL, and MSSQL proxies.
- Simplified the credential backend surface to the file-backed runtime
  path that is actually shipped today.
- Hardened live E2E diagnostics and release fixtures, including
  explicit gateway startup failures and required model routing.
- Rebaked canonical role and verifier image manifests for the 0.3.2
  kernel version.

## 0.3.1 - 2026-06-15

RAXIS 0.3.1 is a patch release for dashboard correctness and Git
review performance.

- Fixed initiative detail rendering for historical sealed plans that
  still contain the pre-0.3 task identifier field.
- Made repository and worktree detail pages load quickly on larger repos
  by avoiding eager Git status, branch, and diff probes on the initial
  header request.
- Kept exact Git review data available through the explicit log, diff,
  tree, and file endpoints.
- Updated the dashboard kernel regression test to pin the lazy worktree
  detail contract used by the optimized UI.

## 0.3.0 - 2026-06-13

RAXIS 0.3.0 is a breaking release focused on making governed agent
execution easier to operate in production: cleaner plan semantics,
kernel-owned task identity, better recovery diagnostics, durable
workspace merge handling, and a much stronger operator dashboard.

### Breaking Changes

- Plan tasks now use human-readable task names while runtime task IDs
  are kernel-owned UUIDs. This removes cross-initiative task ID
  collisions and makes repeated runs of the same plan safe.
- Plan validation no longer accepts legacy defaults for required task
  fields. Plans must explicitly declare the task role, prompt, and
  clone strategy.
- Reviewer dependencies are treated as gates, not artifact-producing
  parents. Downstream executor work must depend on the reviewed
  executor output or on an explicit workspace merge task.
- Policy remains the security envelope and plan authority must fit
  inside it. Runtime-owned mechanics such as gateway subprocess
  behavior are not policy sections.

### Kernel And Governance

- Added kernel-owned workspace merge support for fan-in tasks, including
  durable merge attempt records, conflict policy, output SHA tracking,
  and CLI surfaces for operator resolution workflows.
- Hardened integration merge closeout after pre-merge gates so passed
  witnesses finalize the integration merge instead of reopening the
  synthetic root task indefinitely.
- Added repository/ref merge queue groundwork so parallel initiatives
  can execute concurrently while final target-ref advancement stays
  serializable.
- Improved retry and recovery semantics: failed initiatives move through
  explicit recovery-required flows instead of silently resuming terminal
  states.
- Added configurable planner IPC response write timeout via
  `RAXIS_PLANNER_IPC_RESPONSE_WRITE_TIMEOUT_SECS`.
- Hardened reviewer runtime contracts so reviewer verdict requirements
  are enforced by RAXIS instead of leaking into user prompts.
- Tightened supervisor and AVF shutdown handling so retry paths do not
  wedge the kernel on stale VM state transitions.

### Dashboard

- Added richer failure and recovery panels with recoverable versus
  unrecoverable labels, operator commands, and direct links to related
  tasks, sessions, audit rows, and escalations.
- Added VM diagnostics and capture/artifact viewing for command output,
  session capture, and runtime errors.
- Improved Repositories and Worktrees views so managed repositories are
  separated from session worktrees and invalid parent Git repositories
  are not treated as RAXIS repos.
- Added resource summary panels for turns, tokens, cache usage, elapsed
  time, budget usage, and cost source.
- Improved plan builder parity with kernel validation, including support
  for current task-name semantics, custom tools, credentials, providers,
  verifiers, and workspace merge tasks.
- Fixed dashboard text overflow, scrolling, notification ordering,
  historical LLM turn visibility, token aggregation, and diff rendering
  regressions.

### Planner, Tools, And Providers

- Improved provider fallback handling and token accounting across
  Anthropic, Gemini, and OpenAI-compatible providers.
- Added clearer primary provider/model wording in the dashboard when
  fallback chains are configured.
- Improved custom tool metadata, audit visibility, and failure handling
  for guest subprocess, host subprocess, host MCP, and remote MCP
  execution localities.
- Added better reviewer discovery support through kernel-provided
  artifact context and read-only tool contract hardening.

### Repositories And Publishing

- Added managed repository metadata and safer Git identity checks so
  RAXIS does not accidentally resolve empty storage directories through
  parent Git repositories.
- Added clearer repo lifecycle status for managed repositories and
  worktrees, including source-of-record versus governed mirror language.
- Improved post-integration visibility for managed repo state and
  publish/sync diagnostics.

### Verification

- Rebuilt canonical AVF images with `RAXIS_LIVE_E2E_FORCE_REBAKE=1`.
- Ran the full live extended realistic e2e suite with keep-alive enabled.
  Both primary and sibling lifecycles completed, workspace merge tasks
  completed, reviewer/witness checks passed, and the audit chain reached
  699 events in the verified run.

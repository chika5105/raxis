# Changelog

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

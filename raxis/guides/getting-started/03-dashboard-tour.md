# 03 · Dashboard Tour

> **Goal.** Open the operator dashboard, sign in once, and learn the
> views you will use every day.

When `raxis-kernel` boots in foreground mode it prints a clickable
line:

```text
{"level":"info","event":"DashboardListening","url":"http://127.0.0.1:9820"}
```

That same URL is your dashboard when you start RAXIS with
`brew services start raxis`. If you used the Homebrew daemon, verify it
before opening the browser:

```bash
brew services list | awk 'NR==1 || $1=="raxis"'
raxis-supervisor status
raxis doctor
```

The default bind is `127.0.0.1:9820`
(loopback only); change it via the `[dashboard]` block in
`policy.toml`. Reference:
[`raxis/crates/dashboard/src/lib.rs`](../../crates/dashboard/src/lib.rs).

---

## Sign in

The dashboard authenticates with the **same** Ed25519 challenge-response
protocol the CLI uses — no passwords, no shared secrets. On first
visit:

1. The login page asks for your operator pubkey fingerprint or
   display name.
2. The kernel issues a short-lived challenge (32 random bytes).
3. You sign the challenge with the operator private key. The
   recommended path is the kernel-host helper:

   ```bash
   raxis auth sign setup
   ```

   Once configured, the login page can call out to this helper from
   the CLI; copy the resulting `auth_signature` into the dashboard
   field and submit.

4. The kernel verifies the signature against
   `policy.operator_entry(pubkey).cert`, mints a 1-hour HS256 JWT,
   and drops it in a same-origin cookie. The JWT secret is a 32-byte
   `OsRng` value generated at kernel boot — restarting the kernel
   invalidates every active session (deliberate).

Reference: [`raxis/crates/dashboard/src/auth.rs`](../../crates/dashboard/src/auth.rs).

---

## The core views

The left-side navigation organises pages by what an operator needs
_now_. The defaults below are sized for a single initiative; everything
scales to a hundred without pagination breakage.

### 1 · Overview — health rollup

The landing page after sign-in. One row per top-level subsystem
(kernel uptime, audit chain status, gateway, isolation backend) plus
recent activity. Use this as your "is anything red?" check before
diving deeper. The same data is available headless via
`raxis status --json` and the dashboard's `/api/health` route.

### 2 · Glossary — the operator vocabulary

[![RAXIS dashboard glossary](/images/dashboard-glossary.png)](/images/dashboard-glossary.png)

Searchable definitions for the concepts that show up across the UI:
data dir, install dir, operator key, genesis, policy, provider, kernel,
supervisor, managed repo, initiative, task, orchestrator, executor,
reviewer, Plan Builder, Policy Builder, environments, gates, witnesses,
model routing, tool profiles, credential setup, custom tools, MCP
adapters, and the audit chain. This is intentionally available inside
the dashboard so operators do not have to keep the website open during
a live run.

### 3 · Plan Builder — create plan.toml

[![RAXIS dashboard Plan Builder](/images/dashboard-plan-builder.png)](/images/dashboard-plan-builder.png)

Use Plan Builder before submitting a new initiative. It provides:

- A canvas-native task DAG. Drag from one task card edge to another to
  add a dependency; the second task's `predecessors` field updates in
  `plan.toml`.
- Compact add actions. **Add executor**, **Add reviewer**, **Review
  pair**, and **Fan-out** create nodes without stealing the whole
  canvas; click a card when you are ready to edit it.
- Inline task editors for description, prompt, role, clone strategy,
  path allowlist, egress, runtime limits, VM image, tool profiles,
  credential bindings, and verifier gates.
- A synchronized `plan.toml` panel. Canvas edits update TOML; valid
  TOML edits update the canvas; clearing TOML clears the plan.
- Drawers for plan setup, model routing, tool profiles, credential
  setup, and integration verifiers.
- Smooth source/canvas reveal. Changing a card scrolls the
  `plan.toml` panel to the edited section; editing valid TOML scrolls
  the canvas toward the changed task.
- Draft persistence in browser storage so an accidental navigation does
  not discard work.
- **Validate**, which runs the draft through the same policy/DAG checks
  the kernel uses at admission and returns next-step commands.

The fastest successful path is:

1. Open **Plan setup** and set workspace name, repository name, lane id,
   and target ref.
2. Open **Model routing** and make sure every Executor/Reviewer alias has
   at least one provider:model entry. Add fallbacks only from providers
   the active policy publishes.
3. Open **Tool profiles**, **Credential setup**, and **Verifiers** before
   attaching those references to task cards.
4. Add executor/reviewer cards and drag edges for dependencies.
5. Keep the `plan.toml` panel open while you edit; it is the artifact the
   CLI will submit.
6. Click **Validate**, fix the highlighted fields, then copy or download
   the plan.

Plan Builder is a helper, not an authority boundary. The CLI still
signs and submits the canonical bundle:

```bash
raxis plan validate plan.toml
raxis submit plan plan.toml --no-dry-run
raxis plan approve <initiative_id>
```

### 4 · Plan Builder panes — models, tools, credentials, verifiers

Plan Builder keeps the plan-level setup beside the DAG instead of
splitting authoring across separate pages.

Use **Model routing** to define Executor and Reviewer provider:model
aliases with ordered fallbacks. Orchestrator routing remains
policy-owned because the Orchestrator is the most sensitive agent role.
The active policy must still declare each provider credential, model
allowlist, timeout, and pricing entry before the kernel admits the
plan.

Use **Tool profiles** when an Executor needs access to local automation
that RAXIS does not ship as a built-in tool: an existing script, a
stdio MCP server, a local HTTP service, a commercial tool bridge,
Unity Editor, Blender, or a test harness.

The safe pattern is deliberately narrow:

- Pick a feature-library template or start from a blank wrapper.
- Expose one operation per custom tool, for example `docs_search`,
  `repo_codegen_check`, or `unity_build_player`, not
  `mcp_call_anything`.
- Use an absolute wrapper command installed in the executor image or
  Homebrew tool path.
- Keep `timeout_seconds` short. The kernel and planner enforce a hard
  cap so tools cannot run forever.
- Attach one or more profiles to each Executor task with
  `profiles = ["repo_tools", "db_tools"]`.

Use **Credential setup** to declare the credential names and expected
proxy shapes that the plan may bind. Secret values are not entered in
the builder; they stay in provider/credential files under the data dir
and are mediated by the kernel.

Use **Verifiers** for plan-level integration checks and policy gate
references. The UI should make clear whether a result came from a
policy gate, a per-task verifier, or an integration verifier, and
whether it ran before review or before final merge.

Validate from the dashboard, then validate the complete plan:

```bash
raxis plan validate plan.toml
raxis submit plan plan.toml --no-dry-run
```

These panes are helpers, not authority boundaries. The kernel still
rejects malformed bundles, Reviewer/Orchestrator tools, inherited name
collisions, empty model chains, unauthorized provider/model pairs,
unbound credentials, and invalid verifier references at plan
admission.

### 5 · Initiatives — the running DAG

Lists every initiative grouped by state (Draft, Executing, Completed,
Failed, Quarantined). Clicking an initiative opens its task DAG:

- **DAG graph.** Nodes are tasks; edges are `predecessors`. Node
  colour reflects FSM state (`Pending`, `Admitted`, `GatesPending`,
  `Running`, `Completed`, `Failed`, `Aborted`).
- **Task detail panel.** Per-task `path_allowlist`, `clone_strategy`,
  `evaluation_sha`, latest verifier verdicts, retry counters.
- **Gate nodes and witness chips.** Mechanical gates render as dashed
  DAG nodes with source/hook labels: policy gate, per-task verifier,
  plan integration verifier, or policy integration verifier. `Pending`
  means a verifier run is still outstanding; `Pass`, `Fail`,
  `Inconclusive`, `SpawnFailed`, `ProcessFailed`, and `Timeout` are
  terminal verifier outcomes.
- **Session detail.** Each task that spawned a VM gets a session row
  with the live status of its credential proxies, egress decisions,
  and the linked git worktree on the host.

Reference: [`raxis/dashboard-fe/src/pages/Initiatives.tsx`](../../dashboard-fe/src/pages/Initiatives.tsx),
[`InitiativeDetail.tsx`](../../dashboard-fe/src/pages/InitiativeDetail.tsx),
[`TaskDetail.tsx`](../../dashboard-fe/src/pages/TaskDetail.tsx).

### 6 · Sessions — what the agents are doing live

The Sessions page shows every active VM-backed planner session. Each
session detail page has the **session stream** — the per-session
ring-buffered transcript of LLM turns + tool calls captured from the
kernel's IPC stream. The capture file lives at
`<data_dir>/sessions/<session_id>/stream.jsonl` and is bounded; see
[`raxis/crates/dashboard-kernel/src/stream_capture.rs`](../../crates/dashboard-kernel/src/stream_capture.rs).

Use Sessions when a task is stuck. Live tool calls + intent rejections
tell you within seconds whether the agent is mis-using its allowlist,
the model is rate-limited, or a credential proxy is refusing a query.

### 7 · Repo / Git — the worktrees

Each session binds to a `git worktree` on the host. The Git page
walks the worktree tree, lets you diff any file against `HEAD`, and
shows the commit log for the active branch. This is read-only; the
dashboard never writes into a worktree.

The hardened endpoints bound the request body, cap the audit-chain
walk per call, and recover gracefully from worktree mutation
mid-walk; see [`raxis/crates/dashboard/src/routes/git.rs`](../../crates/dashboard/src/routes/git.rs).

### 8 · Policy Builder — edit policy.toml

[![RAXIS dashboard Policy Builder](/images/dashboard-policy-builder.png)](/images/dashboard-policy-builder.png)

Policy Builder is the post-genesis policy workbench. Use it after the
kernel is healthy to inspect the active policy, discover the available
policy controls, append known-good sections, check the draft hash, and
click **Validate with kernel** before signing. The feature library and
draft panes scroll independently so you can keep the active policy
context visible while composing changes.

Think of policy as the security envelope and plan as one initiative
inside that envelope:

- Permissions narrow by intersection. A plan can choose from policy
  allowed VM images, models, tools, credentials, egress hosts, lanes, and
  repositories; it cannot invent new authority.
- Protections accumulate by union. Policy-required approvals, gates, and
  verifier hooks still apply even if the plan adds its own reviewers or
  verifiers.
- Ceilings use the smaller value. Cost, turn, memory, vCPU, and timeout
  requests cannot exceed policy limits.
- Floors use the larger value. Minimum reviewer counts, approval counts,
  and mandatory evidence requirements cannot be weakened by a plan.
- Locked policy fields win completely. If a policy locks `target_ref`,
  conflicting plans are rejected instead of silently redirected.

It also makes the environment decision visible: RAXIS supports multiple
environment labels in one kernel, but for staging/prod boundaries the
safer operating model is separate kernels/data dirs so provider files,
operator keys, policy, and audit logs cannot be mixed accidentally. The
Homebrew service defaults to `RAXIS_ENV=default`.

Policy Builder is a helper, not the policy authority. Epoch advance is
still the signed path:

```bash
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig "$RAXIS_DATA_DIR/policy/policy.sig"
```

### 9 · Audit — the chain itself

A live tail of the audit chain with kind/initiative/task/session
filters. The dashboard reads the same JSONL files
`raxis log` does (under `<data_dir>/audit/`) through a `ChainReader`
that verifies the hash link between every record. The page surfaces
chain breaks with a red banner; a healthy chain prints "verified
through seq=NN" in the header.

For machine-readable scraping use `raxis log --json` from the CLI;
the dashboard exists to make the same records easy to scan visually.

---

## Other panels worth knowing

| Page              | What it shows                                                                                                                                                                                     | When to use it                                                             |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Escalations**   | Pending operator decisions surfaced by agents (`SubmitEscalation` intents).                                                                                                                       | When an Executor or Reviewer can't make progress without a human nudge.    |
| **Inbox**         | Kernel-pushed notifications + per-operator unread state.                                                                                                                                          | Daily glance — catches policy violations, expiring certs, budget overruns. |
| **Notifications** | The kernel-owned notifications table; the route surface that backs `[[notifications]]` in policy.                                                                                                 | Configuring email / Slack / webhook fan-out.                               |
| **Plan Builder panes** | Model routing, tool profiles, credential setup, and verifier drawers inside the visual `plan.toml` editor. | When an Executor needs operator-owned tooling, credentials, provider fallbacks, or mechanical checks beyond the starter plan. |
| **Policy Builder** | Read the live `policy.toml`, discover feature snippets, validate with the kernel, and prepare the signed CLI/dashboard epoch-advance path. | When changing operator authority, providers, environments, gates, lanes, or dashboard settings. |
| **Health**        | The same data as Overview but as a wide raw-fields table — useful when scraping or screenshotting.                                                                                                | Incidents.                                                                 |
| **Credentials**   | Provider-bound credential metadata and audited reveal flow for privileged operators.                                                                                                            | Auditing what sensitive upstreams the kernel can reach.                    |

---

## Theme

The dashboard starts in light mode and the top-right theme toggle flips
the entire UI between light and dark. Preference is persisted in
`localStorage`; no kernel state changes.

---

## Where the data comes from

The dashboard backend is `raxis-dashboard` (Axum HTTP server, default
port 9820). Every route except `PUT /api/policy/toml` is a pure read
against:

| Source                      | Reader                             |
| --------------------------- | ---------------------------------- |
| `kernel.db` (SQLite)        | `raxis_store::views`               |
| `audit/segment-NNN.jsonl`   | `raxis_audit_tools::ChainReader`   |
| Per-session stream captures | `dashboard_kernel::stream_capture` |
| Live kernel state           | `InitiativeEventBus` push channel  |

The crate is glued into the kernel binary by
[`raxis/crates/dashboard-kernel`](../../crates/dashboard-kernel/);
tests wire `InMemoryDashboardData` so the HTTP surface is exercisable
without booting a real kernel.

---

## Headless equivalents

Every view has a CLI equivalent. Useful for scripts and for
incident-response from a shell.

| Dashboard view | CLI equivalent |
| -------------- | -------------- |
| Overview / Health | `raxis status`, `raxis doctor` |
| Plan Builder | `raxis plan validate`, `raxis submit plan`, `raxis plan approve` |
| Initiatives | `raxis initiative list`, `raxis initiative show <id> --with-tasks` |
| Sessions | `raxis sessions`, `raxis log --session <id>` |
| Audit | `raxis log <id> [-f]`, `raxis verify-chain` |
| Escalations | `raxis escalations inbox`, `raxis escalation approve`, `raxis escalation deny` |
| Policy Builder | `raxis policy show`, `raxis policy diff`, `raxis policy sign`, `raxis epoch advance` |

---

## Cross-references

- [`raxis/crates/dashboard/src/lib.rs`](../../crates/dashboard/src/lib.rs) —
  the route surface + auth model.
- [`raxis/crates/dashboard-kernel/src/lib.rs`](../../crates/dashboard-kernel/src/lib.rs) —
  the kernel-side glue that the binary wires into the `DashboardData`
  trait.
- [`recipes/cli/27-sessions-escalations-inbox.md`](../recipes/cli/27-sessions-escalations-inbox.md) —
  CLI-side counterparts to the Sessions, Escalations, and Inbox pages.

Continue to [`04-troubleshooting.md`](04-troubleshooting.md) for the
top failure modes and their fixes.

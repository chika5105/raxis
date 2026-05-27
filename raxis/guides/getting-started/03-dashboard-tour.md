# 03 · Dashboard Tour

> **Goal.** Open the operator dashboard, sign in once, and learn the
> the views you will use every day.

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
and the audit chain. This is intentionally available inside the
dashboard so operators do not have to keep the website open during a
live run.

### 3 · Plan Builder — create plan.toml

[![RAXIS dashboard Plan Builder](/images/dashboard-plan-builder.png)](/images/dashboard-plan-builder.png)

Use Plan Builder before submitting a new initiative. It provides:

- A feature library for executors, reviewers, fan-out, scoped paths,
  egress, credential proxies, verifiers, turn budgets, wall-clock
  limits, VM image overrides, and cross-task artifacts.
- A live task DAG derived from `predecessors` so you can confirm the
  execution graph before submission.
- Generated `plan.toml` with copy/download controls.
- **Validate with kernel**, which runs the draft through the same
  policy/DAG checks the kernel uses at admission and returns next-step
  commands.

Plan Builder is a helper, not an authority boundary. The CLI still
signs and submits the canonical bundle:

```bash
raxis plan validate plan.toml
raxis submit plan plan.toml --no-dry-run
raxis plan approve <initiative_id>
```

### 4 · Initiatives — the running DAG

Lists every initiative grouped by state (Draft, Executing, Completed,
Failed, Quarantined). Clicking an initiative opens its task DAG:

- **DAG graph.** Nodes are tasks; edges are `predecessors`. Node
  colour reflects FSM state (`Pending`, `Admitted`, `GatesPending`,
  `Running`, `Completed`, `Failed`, `Aborted`).
- **Task detail panel.** Per-task `path_allowlist`, `clone_strategy`,
  `evaluation_sha`, latest verifier verdicts, retry counters.
- **Session detail.** Each task that spawned a VM gets a session row
  with the live status of its credential proxies, egress decisions,
  and the linked git worktree on the host.

Reference: [`raxis/dashboard-fe/src/pages/Initiatives.tsx`](../../dashboard-fe/src/pages/Initiatives.tsx),
[`InitiativeDetail.tsx`](../../dashboard-fe/src/pages/InitiativeDetail.tsx),
[`TaskDetail.tsx`](../../dashboard-fe/src/pages/TaskDetail.tsx).

### 5 · Sessions — what the agents are doing live

The Sessions page shows every active VM-backed planner session. Each
session detail page has the **session stream** — the per-session
ring-buffered transcript of LLM turns + tool calls captured from the
kernel's IPC stream. The capture file lives at
`<data_dir>/sessions/<session_id>/stream.jsonl` and is bounded; see
[`raxis/crates/dashboard-kernel/src/stream_capture.rs`](../../crates/dashboard-kernel/src/stream_capture.rs).

Use Sessions when a task is stuck. Live tool calls + intent rejections
tell you within seconds whether the agent is mis-using its allowlist,
the model is rate-limited, or a credential proxy is refusing a query.

### 6 · Repo / Git — the worktrees

Each session binds to a `git worktree` on the host. The Git page
walks the worktree tree, lets you diff any file against `HEAD`, and
shows the commit log for the active branch. This is read-only; the
dashboard never writes into a worktree.

The hardened endpoints bound the request body, cap the audit-chain
walk per call, and recover gracefully from worktree mutation
mid-walk; see [`raxis/crates/dashboard/src/routes/git.rs`](../../crates/dashboard/src/routes/git.rs).

### 7 · Policy Builder — edit policy.toml

[![RAXIS dashboard Policy Builder](/images/dashboard-policy-builder.png)](/images/dashboard-policy-builder.png)

Policy Builder is the post-genesis policy workbench. Use it after the
kernel is healthy to inspect the active policy, discover the available
policy sections, append known-good snippets, check the draft hash, and
click **Validate with kernel** before signing.

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

### 8 · Audit — the chain itself

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
| **Policy Builder** | Read the live `policy.toml`, discover feature snippets, validate with the kernel, and prepare the signed CLI/dashboard epoch-advance path. | When changing operator authority, providers, environments, gates, lanes, or dashboard settings. |
| **Health**        | The same data as Overview but as a wide raw-fields table — useful when scraping or screenshotting.                                                                                                | Incidents.                                                                 |

---

## Light mode

The top-right theme toggle flips the entire UI between dark (default)
and light mode. Preference is persisted in `localStorage`; no kernel
state changes.

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

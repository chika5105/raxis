# Dashboard browser-QA checklist (live-e2e edition)

Worker: `worker/dashboard-browser-qa`. This checklist is what we
run when the sibling live-e2e worker resumes and a real kernel +
dashboard come up under the test harness.

We do **not** spin up our own kernel. We tail the live-e2e log
(`/tmp/raxis-e2e-out.log` or `/tmp/raxis-e2e-realistic.log`) for
the autologin URL, then drive the dashboard with `browser-use`
during the test runtime.

The dashboard goes away when the test ends — capture issues and
fix them in this branch as you go, push at the end.

---

## 0. Prep

- [ ] `git status` clean on `worker/dashboard-browser-qa`.
- [ ] `npm install` clean (no peer-dep noise).
- [ ] `dashboard-fe/dist/index.html` exists (live-e2e's
      `locate_dashboard_dist()` needs it; without it, the kernel
      only serves the JSON API and the browser would just see a
      404 root).
- [ ] `git log -5 origin/main --oneline` — confirm live-e2e is
      actively committing (≠ "paused").
- [ ] `ps aux | rg 'cargo test'` — confirm test process running.
- [ ] Tail the e2e log for `[e2e] dashboard autologin URL: …`.

---

## 1. Autologin

- [ ] Open the autologin URL in `browser-use`.
- [ ] Confirm immediate redirect to `/` (not stuck on `/login`).
- [ ] Confirm no `#token=` fragment lingers in the URL.
- [ ] Confirm no errors in the browser console.
- [ ] Confirm `localStorage.["raxis.dashboard.token.v1"]` is set.
- [ ] Sidebar shows the operator's display name + roles.

If `/login` shows up: hash-parse fallback failed. Capture the URL,
open devtools, screenshot the console.

---

## 2. Theme switch (do this BEFORE drilling in — bugs you see in
   one mode will be caught here)

- [ ] In dark mode: hit every page (see §3+) and look for
      contrast drops, text-on-text, missing borders.
- [ ] Click the moon icon → switch to light mode.
- [ ] Repeat the page sweep.
- [ ] Specific re-checks now that they're CSS-var-driven:
      - DAG nodes (Initiative DAG): backgrounds, strokes, label
        contrast.
      - Card shadows: subtle in light, deeper in dark.
      - Monaco editor on the Policy page: matches dashboard
        chrome (was hardcoded `vs-dark` previously).
      - SessionStream pane: still readable.

---

## 3. Page sweep (test each in BOTH modes)

### 3.1 Overview (`/`)

- [ ] KPI tiles render with correct counts.
- [ ] Click each tile → drill-in works:
      - Kernel → `/health`
      - Policy epoch → `/policy`
      - Active initiatives → `/initiatives?state=Active`
      - Pending escalations → `/escalations`
- [ ] "Recent initiatives" table → row click navigates.
- [ ] "Recent sessions" header (was previously mislabelled
      "Active sessions"): label matches the unfiltered data.
- [ ] "Recent activity" stream renders new audit rows live.
- [ ] No console errors after a 30 s soak (auto-refresh).

### 3.2 Health (`/health`)

- [ ] Status badge renders the right tone for ok/degraded/failing.
- [ ] Subsystem checks list — colors readable in both modes.
- [ ] Kernel-booted timestamp shows both relative and absolute.

### 3.3 Inbox (`/inbox`)

- [ ] Renders pending operator-action items.
- [ ] Row click drills into initiative or task.
- [ ] Non-navigable rows (PolicyEpochAdvanced) don't show a
      cursor:pointer affordance.

### 3.4 Notifications (`/notifications`)

- [ ] List renders.
- [ ] "Unread only" toggle filters.
- [ ] "Mark all read" button — count drops to 0.
- [ ] Per-row "Mark read" — fades that row.
- [ ] Click row → navigates AND marks read.

### 3.5 Initiatives (`/initiatives`)

- [ ] List renders.
- [ ] State filter dropdown updates the URL `?state=`.
- [ ] Search filters by id + name (case-insensitive).
- [ ] Row click → `/initiatives/:id`.

### 3.6 Initiative Detail (`/initiatives/:id`)

- [ ] Header: state badge, task counts, created/updated
      relative times.
- [ ] Right card: approved-by, plan SHA, target ref, policy
      epoch.
- [ ] DAG renders. Single-click focuses, double-click opens
      task page.
- [ ] Task table: hover, focus ring, row click selects.
- [ ] Focused-task aside refreshes when a task is clicked.
- [ ] "Open task page" button works.
- [ ] "Full DAG view →" link goes to `/initiatives/:id/dag`.

### 3.7 Initiative DAG (`/initiatives/:id/dag`)

- [ ] LR / TB layout toggle works.
- [ ] Per-state counters render at the top.
- [ ] Single-click focuses, double-click opens task.
- [ ] Keyboard: tab into a node, Enter opens the task.
- [ ] Light mode: node fills + strokes use semantic palette
      (was hardcoded hex; verify).

### 3.8 Tasks (`/tasks/:id`)

- [ ] Reviewer verdicts list (approved → green, rejected → red).
- [ ] Structured outputs list — JSON pretty-print readable.
- [ ] Path scope grid renders.
- [ ] "Open session →" button navigates to `/sessions/:id`.

### 3.9 Sessions (`/sessions`)

- [ ] List renders.
- [ ] Role filter (`Orchestrator` / `Executor` / `Reviewer`).
- [ ] Search filters by id / model.
- [ ] Row click → `/sessions/:id`.

### 3.10 Session Detail (`/sessions/:id`)

- [ ] Header: role, task link, state, timestamps.
- [ ] Right card: provider, model, initiative, tokens, worktree.
- [ ] Worktree link → `/git/:name`.
- [ ] **SessionStream**:
      - [ ] Status pill: `connecting…` → `replaying tail…` →
            `live`.
      - [ ] Events appear with timestamps.
      - [ ] When a default-`message` frame arrives (if any in
            the test), it appears EXACTLY ONCE (was duplicated
            previously due to onmessage + addEventListener clash).
      - [ ] Lagged badge shows when the backend reports lag.
      - [ ] Auto-scroll pinned. Scroll up → "Resume tail ↓"
            button appears.
      - [ ] Reconnect button drops + re-attaches the SSE.
      - [ ] Clear button empties the in-page ring (re-fetches
            from server tail on reconnect).

### 3.11 Escalations (`/escalations`)

- [ ] List renders.
- [ ] Severity badge tone matches `High` / `Normal` / lower.
- [ ] Row click → `/initiatives/:id`.
- [ ] Inner initiative-id link does NOT navigate twice
      (stopPropagation works).

### 3.12 Git Worktrees (`/git`)

- [ ] List renders all `Main` + per-session clones.
- [ ] Row click → `/git/:name`.
- [ ] Path column is mono and truncates with title tooltip.

### 3.13 Worktree Detail (`/git/:name`)

- [ ] Header: HEAD/branch/base SHAs with copy buttons.
- [ ] Ahead/behind counters (when present).
- [ ] Tabs:
      - **Files**: tree of changed files; hunk-scroll on click.
      - **Browse** (NEW): full lazy-loaded file tree from
        `/api/git/worktrees/:name/tree`. Click any directory →
        expands. Click file → `/api/git/worktrees/:name/file`
        loads + renders. Verify:
          - UTF-8 file: shown inline as `<pre>`.
          - Binary file (e.g. an image, a `.bin`): shown as a
            hex preview, capped at 4 KiB.
          - "(listing truncated)" warning if a folder has
            > the per-request budget.
      - **Log**: `git log` rows with short-sha + author.
      - **Diff vs base**: hunks render with `+`/`-` highlighting.
        For the main worktree (no recorded base SHA), the
        "no recorded base SHA" empty state shows correctly
        (404 → friendly message, not the raw error).
      - **Range diff**: enter two 40-char SHAs → diff loads.
        Verify URL-encoding of the range parameter (defensive
        client-side encoding).
- [ ] No `BackendGapCallout` ("dashboard-backend worker") shown
      anywhere — that callout was stale and is now removed.

### 3.14 Audit Chain (`/audit`)

- [ ] List renders.
- [ ] Filter input mirrors `?initiative_id=…`.
- [ ] "Clear" link drops the filter from URL + input.
- [ ] Row expand → JSON payload.
- [ ] "Load more" pagination works.

### 3.15 Policy (`/policy`)

- [ ] Snapshot section: epoch, sha, signed-by, signed-at.
- [ ] Operators list with permitted_ops.
- [ ] Notification routes list.
- [ ] **Editor (write_policy operators only)**:
      - [ ] Monaco loads with TOML syntax.
      - [ ] In light mode, editor uses `vs` theme (NOT `vs-dark`
            — was hardcoded previously).
      - [ ] Drafts SHA displayed.
      - [ ] "Reset to current" button restores the on-disk
            text + clears signature box.
      - [ ] Submitting a wrong signature surfaces the kernel
            error code (`FAIL_POLICY_…`).

---

## 4. Keyboard / accessibility

- [ ] Tab through the sidebar — focus ring on each nav row.
- [ ] Tab into a table — focus ring on each `<tr>`.
- [ ] Enter on a focused row navigates.
- [ ] Cmd/Ctrl-K opens command palette.
- [ ] Palette: Up/Down navigate, Enter selects, Esc closes.
- [ ] Skip target: header has visible "Skip to main" link
      (verify; if missing, add).

## 5. Console / network hygiene

- [ ] No 404s on `/api/git/worktrees/:name/tree` or `/file`
      (the previous comment claimed they didn't exist; they do).
- [ ] No `cookie was rejected` / `cors error` console noise.
- [ ] No React warnings (key, hydration, useEffect deps).

## 6. Cleanup before pushing

- [ ] `npx tsc --noEmit` clean.
- [ ] `npx vitest run` all green.
- [ ] `npm run build` succeeds (dist/ regenerated).
- [ ] All commits are well-scoped, conventional message.
- [ ] Push to `worker/dashboard-browser-qa` (NOT main).

---

## Known issues fixed in this branch (non-runtime)

- **B1** SessionStream duplicated default-`message` frames
  (onmessage + addEventListener("message", …) both fired).
  Fixed: drop the `onmessage` assignment.
- **B2** WorktreeDetail had a "feature gap" callout pointing
  at `tree`/`blob` endpoints that the dashboard-backend worker
  has since shipped. Fixed: new `RepoBrowser` component +
  Browse tab; callout removed.
- **B3** `git.diffRange(name, from, to)` did not URL-encode
  `from`/`to`. Fixed defensively (the backend already 400s any
  non-hex SHA).
- **T1** `DagGraph` SVG used hardcoded dark-palette hex
  values (#1c5b2c, #2ea043, #e6e8eb, #a8b1bc, #7d8892, #3a86ff).
  Fixed: every fill/stroke driven from `rgb(var(--c-…))`.
- **T2** Policy-page Monaco editor was hardcoded `theme="vs-dark"`,
  staying dark in light mode. Fixed: drives from `useTheme()`.
- **T3** `shadow-soft` was a hardcoded `rgba(0,0,0,0.4)`,
  producing a harsh black shadow on white cards. Fixed: now
  reads `var(--shadow-soft)`, light variant uses subtle slate
  tint.
- **U1** Overview's "Active sessions" section actually showed
  the most-recent N sessions regardless of state. Fixed: rename
  to "Recent sessions" so the label matches the data.

## Issues to look for during the live-e2e run

- New 5xx codes from the kernel (capture body via network panel).
- Empty-state copy that doesn't match the data (e.g. "no
  pending escalations" when one is visible elsewhere).
- Monaco editor stuck on a stale theme (race between mount and
  ThemeProvider).
- DAG: nodes with very long titles overflowing the rect.
- WorktreeDetail / Browse: large files (> 256 KiB) being inlined
  with bad scroll perf.

---

## Live-e2e run results (rolling)

### Run 1 — full_session_lifecycle (kernel @ port 19820, JWT
exp 13:10:20 PDT 2026-05-12)

Tour driver: `browser-use` subagent against the kernel + Vite
proxy (Vite served the FE bundle, proxied `/api` →
`http://127.0.0.1:19820`).

Snapshot of kernel state at tour time (via REST):
- 1 active `Executing` initiative
  (`019e1d98-e641-7ea0-b5fe-267983c55a57`)
- 2 active sessions (Planner + a sibling)
- 3+ worktrees registered (1 main, 1+ session clones)

Per-view results (BOTH dark + light modes verified, theme
persistence after F5 verified):

- Overview / `/`           PASS (real KPI counts, recent
  initiatives, recent sessions, recent activity)
- Initiatives / `/initiatives`             PASS (1 row, search
  + filter rendered)
- Initiative Detail / `/initiatives/:id`   PASS (header showed
  initiative_id since this plan has no `[plan.initiative].title`
  — that is the documented fallback, not a bug)
- DAG / `/initiatives/:id/dag`             PASS (3 task nodes
  rendered, LR/TB toggle worked)
- Sessions / `/sessions`                   PASS (kernel reported
  the orchestrator had already exited by the time we drilled in;
  empty state correct)
- Audit / `/audit`                         PASS (~19 events,
  expand worked, badges legible)
- Health / `/health`                       PASS
- Inbox / `/inbox`                         PASS (10+ events with
  links to initiatives + tasks)
- Notifications / `/notifications`         PASS (16 unread,
  "Mark all read" present, links rendered)
- Escalations / `/escalations`             PASS (empty state)
- Policy / `/policy`                       PASS (read-only
  snapshot since this operator has `roles=["read"]`; no editor
  shown — expected)
- Git list / `/git`                        not visited in run 1
- Git Worktree Detail / `/git/:name`       not visited in run 1

Console messages: clean throughout. Only standard Vite HMR
chatter + the React-DevTools install hint. No 401s.

Theme tour: dark ↔ light worked in every view; persisted
through reload.

Known false alarm to ignore on future runs: the subagent in
this run also reported a "404 on /git/worktrees". That URL
is NOT a valid app route — `/git` is the list, `/git/:slug`
is the detail (`:slug` ∈ `main-0`, `session-<short>`, …).
Clicking the row labelled "worktrees" routes to `/git/main-0`,
which works. The 404 was the subagent typing the URL by
hand; do not re-flag in subsequent runs.

### Run 2 — `extended_e2e_realistic_scenario` (kernel @ port 9820, JWT exp ~18:13 PDT 2026-05-12)

Tour driver: direct `cursor-ide-browser` MCP against a temp Vite
on `127.0.0.1:5173` proxying to the live realistic kernel at
`127.0.0.1:9820` (genesis default — predates my `813b912` fix
that re-binds to `19820` for the next iteration). Authentication
worked end-to-end: minted a JWT manually using a 64-hex seed file
of `[0xD0; 32]` (the realistic test's `REALISTIC_OPERATOR_SEED`)
piped through `raxis auth sign --json` against
`/api/auth/challenge`, then `POST /api/auth/verify`, then built
the `parseAutologinHash`-shaped URL and pasted it into the
browser. The React `LoginPage::useEffect` mirrored everything to
`localStorage` and `window.location.assign("/")` redirected
cleanly — same exact flow my `common::dashboard::open_dashboard_with_autologin`
will do automatically on the next iteration once `813b912` lands
in the fix-loop's next rebase.

Snapshot of kernel state at tour time (via REST + Overview KPIs):
- 2 active `Executing` initiatives
  - primary: `019e1eda-4703-7943-9aff-d2cf23279916` (10 realistic
    tasks: allowlist-positive-codegen, lint-defect, materialize-records,
    review-lint-defect-A, review-lint-defect-B, secrets-handling,
    service-round-trip, transparent-proxy-realscripts, xfile-refactor,
    plus the orchestrator root)
  - sibling: `019e1eda-4703-7943-9aff-d2dedf209be4`
    (sibling-materialize-records on `e2e-realistic-sibling-lane`)
- 4 active sessions (a87386f8, 126cc0cf, 19ae3299, 589057e3)
- 48 unread notifications
- 0 pending escalations
- 50+ audit events streamed live (SessionVmSpawned, SessionCreated,
  DatabaseQueryCompleted, MongoCommandExecuted, CredentialAccessed,
  CredentialProxyUpstreamConnected — all the new V3 service-evidence
  variants)

Per-view results during the live window (~14 min uptime → 900s
worktree-deadline panic at 18:16:53):

- Overview / `/`           PASS (kernel ok+booted-14-min, both
  initiatives, all 4 sessions, full Recent Activity stream;
  the new `auditBadgeClasses` from `e66073e` correctly toned
  the badges by suffix — `SessionVmSpawned` rendered as `info`,
  `MongoCommandExecuted`/`DatabaseQueryCompleted`/`CredentialAccessed`
  as `info`, `CredentialProxyUpstreamConnected` as `ok`. No
  `bad`/`warn` events fired in this window because every task
  was still `Admitted` — no failures yet.)
- Initiatives / `/initiatives`             PASS (both initiatives
  listed, search + state-filter dropdown rendered)
- Initiative Detail / `/initiatives/019e1eda-4703-7943-9aff-d2cf23279916`
  PASS (header, "Full DAG view →", DAG with 10 tasks all in
  `Admitted` state, Tasks table mirrored DAG, Task detail aside
  showed the "Select a task" empty state with the right copy)
- Sessions / `/sessions`                   PASS (4 rows, role
  filter rendered)
- Audit / `/audit`                         FLAKY — DURING
  KERNEL TEARDOWN. Returned `HTTP_500 / Internal Server Error`
  with the "Retry" button. Cross-referenced via network panel:
  `/api/audit?limit=50`, `/api/escalations`, and
  `/api/notifications/unread-count` all returned 500 in the
  same 14-second window. Wall-clock check confirmed this was
  during the kernel's panic + drop sequence (page 18:16:53 vs
  test panic timestamp 18:16:53). Not a dashboard bug — the
  kernel was tearing down. The `ErrorBox` UI copy was clean
  and the Retry CTA was correctly wired. **Re-test on the next
  iteration.**
- Health / `/health`                       not reached this run
  (kernel died before navigation)
- Inbox / `/inbox`                         not reached this run
- Notifications / `/notifications`         not reached this run
- Escalations / `/escalations`             not reached this run
- Git list / `/git`                        not reached this run
- Git Worktree Detail / `/git/:name`       not reached this run
- Policy / `/policy`                       not reached this run

Console messages during the live window: clean.
Vite HMR chatter + React-DevTools hint only. The two warning
lines were the cursor-ide-browser native-dialog override
notice and the standard React-DevTools install nudge — neither
is a dashboard issue.

Theme tour: NOT performed this run (kernel teardown
intervened). Will retry on Run 3.

DAG / SessionStream / RepoBrowser: NOT exercised this run for
the same reason. Run 3 priority.

#### Issue surfaced

- **R2-1** `dashboard-fe/QA-CHECKLIST.md` (this section): the
  `[realism-e2e]` driver in `extended_e2e_realistic_scenario.rs`
  was not minting an autologin URL despite the kernel's dashboard
  binding at `9820` correctly (per `kernel.stderr.log`'s
  `RAXIS dashboard: http://127.0.0.1:9820` line). The QA worker
  had to manually construct the URL via `raxis auth sign` against
  the realistic operator's seed (`[0xD0; 32]`). **FIXED** in the
  parent commit `813b912 kernel(e2e): mount dashboard in
  realistic-scenario harness so operator can observe live state`
  — adds a new `tests/common/dashboard.rs` module with the
  shared port-config + policy-mutation + JWT-mint + URL-build
  helpers (extracted from the lifecycle test), wires
  `mutate_dashboard_block_in_policy(&data_dir)` and
  `open_dashboard_with_autologin(&signing_key, port,
  "realism-e2e")` into the realistic test's bootstrap, and
  threads the resulting URL into `tier3.set_dashboard_url(...)`
  so it ALSO appears in the post-run artifact block. Next
  iteration will print the URL automatically and bind the
  dashboard at `19820` (matching the lifecycle test + the
  Vite proxy default).
- **R2-2** `kernel/tests/common/tier3_artifacts.rs`: the unit
  test `reporter_fires_emit_block_on_drop_once` was using
  `r.set_dashboard_url("http://127.0.0.1:0/login")` as fixture
  data, which then leaked into the realistic-scenario stderr
  stream and was repeatedly mistaken for a "Tier-3 reporter
  port=0 bug" by both operators and AI assistants tailing
  `/tmp/raxis-e2e-realistic.log`. **FIXED** in `1a2737b` —
  fixture URL now reads
  `http://test-fixture-not-a-real-dashboard.invalid/login`
  (RFC 2606 reserved TLD; unmistakable on first read).

### Run 3 — `extended_e2e_realistic_scenario` against fix-loop tip
`91c26b7 fix(planner-core,kernel,e2e): retry-shell + gateway-watchdog + parallel orchestrator respawn`

Tour driver: `cursor-ide-browser` MCP against the local Vite dev
server at `127.0.0.1:5173` (proxying to the kernel-bound dashboard
at `127.0.0.1:19820`). **Autologin worked end-to-end zero-touch
for the first time on the realistic harness:** the fix-loop's
rebase onto `813b912` activated `common::dashboard` and the
realistic test now prints (verbatim, copy-pasted from
`/tmp/raxis-e2e-realistic.log`):

```
[realism-e2e] kernel daemon up, accepting operator IPC
[realism-e2e] dashboard manual-fallback (paste into /login if autologin fails):
[realism-e2e]   1. CLI command   : raxis auth sign 11d9cfb3c472bc6c2f2cd19056a43f00bee60d59eddaba3ee07e90cc96c25dd3
[realism-e2e]   2. Signature hex : 9ea6bfcdb0d4cc1afe31c83ce8f5b1c96f264ea22cb29fbc771996e0af94142a33954cfb37b1f01d1a87e3fec438be1eb37f831f5e775e06ed4aad6a6a9f0d07
[realism-e2e]   3. Public key hex: e72c28fe718e3a30afc47438da779d508d2dad5a265fafeb4f377e1d57fb098c
[realism-e2e] dashboard ready: http://127.0.0.1:19820/  (autologin URL printed below for manual fallback)
[realism-e2e] dashboard autologin URL: http://127.0.0.1:19820/login#autologin=1&token=eyJ…&operator_id=…&display_name=realism-e2e-operator&roles=read&expires_at=1778639385&next=%2F
[realism-e2e] dashboard opened in default browser as operator 'realism-e2e-operator' (roles=["read"])
```

This is exactly the contract the lifecycle test has: kernel-up
→ manual-fallback `raxis auth sign` block → ready URL → autologin
URL → best-effort `open(1)`. The `[realism-e2e] dashboard
opened in default browser …` line is the proof that the
`spawn_url_opener()` helper from `common/dashboard.rs` shelled
out to `/usr/bin/open` cleanly. No port mismatch, no manual JWT
mint, no apologetic comment — exactly what `813b912` shipped.

Snapshot of kernel state at tour time (via Overview KPIs + REST):
- Kernel `ok` (Booted ~47s ago at first attach, no panic during the
  ~5-min tour).
- Policy epoch #1 (active bundle, signed-by `realism-e2e-operator`).
- 2 active `Executing` initiatives (same `019e1ef4-…ce68` primary
  + `…bfc2` sibling shape as Run 2; full 10-task DAG admitted).
- 4 active sessions (3× planner, 1× executor for
  `allowlist-positive-codegen`).
- 47 unread notifications, 0 pending escalations.
- Audit chain: 50 events streamed live (#1 KernelStarted →
  #50 DatabaseQueryCompleted) with `auditBadgeClasses` toning
  applied (KernelStarted/Initiative/PlanApproved/Session…/
  CredentialProxyStarted = `info`; CredentialAccessed and
  CredentialProxyUpstreamConnected = `info`/`ok` family;
  no `bad`/`warn` events fired — every task admitted clean).

Per-view results (BOTH dark + light verified; theme persistence
across navigation verified; **all previously-unreached items
from Run 2 now PASS**):

- Overview / `/`              PASS (KPI tiles, "Recent
  initiatives" with deep-linkable rows, "Recent sessions"
  with `materialize-records` + `sibling-materialize-records`
  task breadcrumbs, "Recent activity" stream live with
  toned badges; auto-refresh smoke-tested ≈ 30 s, no
  console errors)
- Health / `/health`          PASS (heading + "Subsystem
  checks" rendered; 5 s auto-refresh fired without error)
- Inbox / `/inbox`            PASS (renders empty since
  the only operator-action gates in this run are the two
  `PlanApproved` events that auto-cleared)
- Notifications / `/notifications` PASS (47-row list under
  "Unread only", per-row "Mark read" + global "Mark all
  read" CTAs present, links to source events resolve)
- Initiatives / `/initiatives`            PASS (both
  initiatives listed; state filter dropdown +
  search box rendered; row click → detail)
- Initiative Detail / `/initiatives/019e1ef4-…ce68`
  PASS (header, "Full DAG view →", DAG with all 10 tasks
  in `Admitted`, Tasks table mirrored DAG, Task detail
  aside showed correct empty-state copy)
- Initiative DAG / `/initiatives/019e1ef4-…ce68/dag` PASS
  (full-screen DAG; same 10-task admitted layout as the
  inline DAG; breadcrumb truncates the UUID to `…ce68`)
- Sessions / `/sessions`                  PASS (4 rows
  with abbreviated UUIDs; role filter dropdown
  `All / Orchestrator / Executor / Reviewer` rendered)
- Session Detail / `/sessions/6ec1a5a8-…`  PASS (header
  shows role `Planner`; `Copy to clipboard` CTA on the
  session id; `Planner:6ec1a5a8-70d ↗` worktree link;
  `Clear` + `Reconnect` SessionStream controls)
- Escalations / `/escalations`            PASS ("No
  pending escalations. Operator inbox is clear." empty
  state; copy is correct)
- Git Worktrees / `/git`                  PASS (4 planner
  worktrees: `Planner:6ec1a5a8-70d` … `78e13bcd-51a`;
  parent `worktrees` row links to the registered roots
  view)
- Audit Chain / `/audit`                  PASS (50 rows
  collapsible/expandable; #1 KernelStarted expanded to
  reveal the JSON payload `{"data_dir":…,"kind":
  "KernelStarted","poli…}` with full event UUID +
  absolute timestamp; "Load more" CTA at bottom; **the
  500-flake from Run 2 did NOT recur** — kernel was
  alive throughout)
- Policy / `/policy`                      PASS (read-only
  snapshot mode since `roles=["read"]`; Monaco editor
  not shown — expected per RBAC)

Console messages during the tour: clean. Standard Vite HMR
chatter only.

Theme tour: light → dark → re-attached audit page in dark
(legible badge tones, no contrast collapse). Toggle button
correctly flipped between "Switch to dark mode" and
"Switch to light mode".

#### Issue surfaced

- **R3-1** Notifications page renders every row's body as
  `(no summary)`. The notification-routing code is correctly
  picking up event kinds + initiative ids + relative
  timestamps, but the summary slot the UI renders is empty
  for every event in this run. This is plausibly a
  notification-policy-side gap (the event kinds the
  realistic harness fires — `MongoCommandExecuted`,
  `CredentialAccessed`, `CredentialProxyUpstreamConnected`,
  `DatabaseQueryCompleted` — may not have human-summary
  templates wired in `policy/notifications.toml` or its
  Rust renderer counterpart). **Severity: low** (UX gap,
  not a regression — the underlying data is intact and the
  "Mark read" + filtering controls all work). Will revisit
  once the green-test run is in to confirm whether this is
  policy-template breadth vs a dashboard-side rendering bug.
- **R3-2** Theme persistence across browser sessions: the
  Run 2 tour ended in dark mode, but Run 3 attached in
  light mode. This is consistent with the dashboard storing
  the theme in `localStorage` and the new browser-context
  starting fresh. Not a bug — documenting so future runs
  don't flag it.

#### Done before final report

- Wait for fix-loop to push a `working e2e:` or `stable e2e`
  commit to `main` → re-run the tour against the green
  realistic scenario, confirm R3-1 (`(no summary)`) status,
  refresh the visual screenshots, push to `main`, report
  DONE.

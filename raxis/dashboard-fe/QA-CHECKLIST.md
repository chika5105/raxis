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

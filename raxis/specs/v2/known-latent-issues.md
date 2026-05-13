# Known Latent Issues

**Audit window:** 2026-05-12, branch `worker/executor-image-bake-pipeline`,
against `origin/main @ 10fe454`.

**Mission.** Catalogue *production-side* defects that are real bugs but
are not currently exercised by any code path in the field. Each entry
records:

* The defect (precise file + line).
* Why it's latent (which production caller would trigger it, why no
  caller does today).
* The fix paths (with their respective trade-offs).
* The recommended landing window (which workers / sweeps own it).

This file is the companion to [`test-quality-debt.md`](./test-quality-debt.md).
That ledger covers tests that pass for the wrong reason; this one
covers production code that *would* fail if invoked. The two are
deliberately separate because a P0 in one is not a P0 in the other:
a latent bug that no caller touches is lower urgency than a test that
silently green-lights the same surface.

**Classification.** We re-use the test-quality ledger's P0–P7 table
*verbatim* so a reader who knows one knows the other:

| Class | Meaning | In-PR action |
|---|---|---|
| **P0** | Will fail on first invocation in steady state. | Fix immediately. |
| **P1** | Will fail on a known but rare invocation. | Fix in the next sweep. |
| **P2** | Will fail on a hypothetical-but-allowed invocation. | Track + fix when callers arrive. |
| **P3** | Suspect by code-review, no demonstrated failure. | Track. |

---

## L-1. `GrepSearchTool` spawns `grep`, Reviewer rootfs ships only `rg`

* **Class:** P2 (latent — Reviewer never calls `grep_search` per current
  LLM behaviour, but the tool is registered for the role).
* **Production file:** `raxis/crates/planner-core/src/tools.rs:609`
  (`Command::new("grep")`).
* **Image spec:** `raxis/images/reviewer-core/Containerfile` (the
  binary-only minimal rootfs per `INV-PLANNER-HARNESS-02`; ships only
  the cross-compiled `raxis-planner-reviewer` PID-1 binary plus —
  *aspirationally*, when the bake pipeline lands richer Reviewer
  recipes — `rg` for `ReadFileTool`-adjacent search use cases). Either
  way, the canonical Reviewer image does **not** ship `grep(1)`.

### Defect

`crates/planner-core/src/tools.rs::GrepSearchTool::run()` spawns the
binary literally named `grep`:

```text
let mut cmd = Command::new("grep");
```

This works in the executor-starter rootfs (which ships `grep` via
`debian:bookworm-slim`). It will fail with `os error 2 (ENOENT)` in the
Reviewer rootfs, because `INV-PLANNER-HARNESS-02 minimalism` mandates
the Reviewer ship the *smallest possible* userspace and `grep` is
explicitly not on that list. The spec-mandated search tool for Reviewer
is `rg(1)` (BurntSushi/ripgrep).

### Why it's latent

`GrepSearchTool` is registered in the Reviewer's tool registry
(`raxis/crates/planner-core/src/lib.rs::reviewer_tool_registry()`),
making it *available* to the Reviewer LLM. But every iter-1 through
iter-12 trace shows the Reviewer LLM invoking only `submit_review` and
`read_file` — never `grep_search`. The current Reviewer system prompt
(`raxis/specs/v2/planner-harness.md §Reviewer prompt template`) does
not mention `grep_search`; the LLM consequently never reaches for it.

A future Reviewer-prompt revision that *did* surface `grep_search`
(e.g. "use `grep_search` to find call sites of the function under
review before writing the verdict") would trip this defect on the
first invocation.

### Iter-12 evidence

`/tmp/iter12-artifacts/kernel.stderr.log` shows zero `grep_search` /
`grep` invocations in the Reviewer span. The `BashTool: ENOENT` storm
in iter-12 is the *executor* failing on `bash` (a separate canonical
image stub regression, fixed in this PR's `worker/executor-image-bake-pipeline`).
The Reviewer side of iter-12 ran clean — by accident, not by design.

### Fix paths

Three independent solutions, with different cost / blast-radius shapes:

#### Option A: Switch `GrepSearchTool` to spawn `rg`

```text
let mut cmd = Command::new("rg");
```

* **Pro:** No image-spec change. Reviewer continues to ship its
  spec-mandated minimal rootfs.
* **Con:** `rg`'s regex flavour differs from POSIX `grep`. Specifically:
  `rg` defaults to PCRE2-lite (Rust regex syntax with Perl-ish
  backreferences), while `grep` defaults to POSIX BRE. Tool callers
  that pass user-supplied regex strings (the executor LLM via
  `BashTool`, the orchestrator's own `grep_search` invocations) would
  see semantic drift — a regex that matches under `grep` may not match
  (or may over-match) under `rg`. The mitigation is to use `rg --pcre2
  --no-mmap --null-data` for parity, but that still drops POSIX BRE
  shorthands like `\{n,m\}` which `rg` only supports under
  `--engine=auto`.
* **Caller audit required:** Every `GrepSearchTool` call site in
  every prompt template (executor, orchestrator, reviewer) must be
  audited for regex-flavour assumptions.
* **Effort:** ~0.5 day for the swap + caller audit; +0.5 day for any
  fixture / golden-output adjustments downstream.

#### Option B: Add `grep` to the Reviewer Containerfile

```text
RUN apt-get install -y --no-install-recommends grep
```

* **Pro:** Zero behavioural drift; tool semantics are byte-identical to
  the executor's `grep`.
* **Con:** Violates `INV-PLANNER-HARNESS-02 minimalism` for the Reviewer
  image. Requires a spec amendment that justifies the bloat (`grep` is
  ~250 KB compressed, modest; the *principle* is the cost: every added
  binary widens the Reviewer's attack surface and de-justifies the
  separate Reviewer rootfs over a single shared executor rootfs).
* **Effort:** ~0.25 day for the Containerfile edit + spec amendment;
  spec amendment requires invariant-audit sign-off.

#### Option C: Per-role tool registry that excludes `GrepSearchTool` from Reviewer

* **Pro:** Matches the spec intent (Reviewer's job is verdict-rendering,
  not codebase grepping; the tool was added speculatively). Closes the
  defect at the *registry* layer rather than the binary layer.
* **Con:** Requires a registry refactor.
  `raxis/crates/planner-core/src/lib.rs` currently builds a single
  registry shape per role; per-role exclusion is a small change but
  must be kept in lockstep with the per-role prompt templates so a
  prompt that *mentions* `grep_search` cannot be paired with a registry
  that excludes it.
* **Effort:** ~1 day for the registry refactor + prompt-template
  synchronisation + per-role tool-registry tests.

### Recommended fix path

Option C, deferred to the post-`working e2e` final-cleanup-sweep's
invariant audit. Rationale:

* The defect is genuinely latent — there is no production trigger
  today.
* Option C closes the defect at the right layer (the spec says
  Reviewer doesn't grep; the registry should reflect that) rather than
  papering over it at the binary layer (Option B) or paying the
  semantic-drift tax everywhere (Option A).
* The cleanup sweep is the natural home for "audit every per-role tool
  registry against its per-role prompt template + per-role rootfs
  spec"; this defect is one row in a larger consistency table that the
  sweep will surface anyway.

### Owners

* **Discovery / documentation:** `worker/executor-image-bake-pipeline`
  (this PR; documents the defect, does **not** fix it).
* **Resolution:** Final-cleanup-sweep worker, scheduled after the
  iter-13 live-e2e green run.

---

## L-2. (placeholder)

No additional latent issues recorded as of this audit window. Future
entries should follow the L-1 template:

```
## L-N. Short title

* **Class:**     P0 / P1 / P2 / P3
* **Production file:** path:line
* **Image spec:**      (if image-related; omit if not)

### Defect
(one-paragraph description; cite the line that fails)

### Why it's latent
(which caller would trigger; why no caller does today; cite evidence)

### Fix paths
(enumerate options A, B, C; pro / con / effort for each)

### Recommended fix path
(name the option + the rationale + the worker / sweep that should land it)

### Owners
* **Discovery / documentation:** worker that recorded the entry
* **Resolution:**                worker / sweep that should fix it
```

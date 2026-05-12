# Scenario 45 — Quarantine a Bad Plan

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~5 min | **Provider:** none (admission-only)

A plan whose `path_allowlist` escapes the workspace must be rejected
before any VM boots. This scenario submits exactly such a plan and
walks the rejection: client-side `plan validate` catches it first, and
even if you skip validation the kernel rejects it at the admission
seam with a typed `FAIL_PLAN_PATH_ESCAPE`. Nothing executes, no
session is created, and the audit chain records the refusal.

## When to use this

- You want a single command-line reproduction of "the kernel refuses
  to admit a path-escaping plan".
- You're auditing the deny-path of the admission seam (INV-PLAN-04,
  INV-INIT-02 §"path allowlist confinement").
- You're demoing RAXIS to a sceptic and want to show that operator
  signatures alone do not buy you bypass — geometry rules are
  enforced at the kernel.

---

## Prerequisites

- **One-time setup complete.** See [`../../SETUP.md`](../../SETUP.md).
- **Kernel running** (`raxis-kernel` in another terminal).
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported** in this shell.
- No provider credentials needed — the plan never reaches inference.

---

## What this scenario demonstrates

- The CLI's local `plan validate` pre-flight catches path escapes
  before any IPC round-trip.
- If you bypass the validator and submit anyway, the kernel still
  rejects with the same typed code.
- An admission-rejected plan produces a `PlanRejected` audit event
  but **no** `SessionCreated` and no kernel.db rows under `tasks`.

---

## Files in this scenario

| File | Purpose |
|---|---|
| `plan.toml` | Intentionally invalid: `path_allowlist = ["../etc/passwd"]`. |
| `policy.toml` | Empty delta (no policy changes needed). |
| `credential.toml` | Empty template (no provider used). |

---

## Run it

```bash
# 1. Local pre-flight — the validator catches the escape without IPC.
raxis plan validate "$PWD/plan.toml"
# expected: exit 1, error contains FAIL_PLAN_PATH_ESCAPE and the
#           offending path '../etc/passwd'.

# 2. (Optional) Try to bypass the validator. The kernel performs the
#    exact same check at the admission seam and rejects identically.
raxis submit plan "$PWD/plan.toml" --no-dry-run
# expected: exit 1; OperatorResponse::Error { code: "FAIL_PLAN_PATH_ESCAPE", ... }.
```

---

## What "success" looks like

A successful run **does not** create an initiative. Concretely:

```bash
# No new initiative on the registry.
raxis initiative list --state Draft --json | jq 'length'
# 0 (or unchanged from your starting count).

# The audit chain has a PlanRejected event — and only that.
raxis log --kind PlanRejected --limit 1 --json | jq '.[0].reason'
# "FAIL_PLAN_PATH_ESCAPE"

# No session row, no task row, no worktree on disk.
raxis session list --json | jq 'length'
test ! -d "$RAXIS_DATA_DIR/sessions/"<no_session>

# Chain still verifies end-to-end.
raxis verify-chain
```

---

## Variations

- **Different escape mode.** Try `path_allowlist = ["/etc/passwd"]`
  (absolute path) or `["./../../"]` (collapsed traversal). Both
  reject with `FAIL_PLAN_PATH_ESCAPE` but the diagnostic detail
  differs.
- **Symlink trickery.** Materialise a symlink inside the workspace
  pointing at `/etc` and reference it through the allowlist. The
  kernel resolves symlinks before the geometry check.
- **Combine with break-glass.** Activating break-glass on the policy
  side **does not** bypass geometry — re-run with break-glass
  active and observe the rejection remains.

---

## Tear-down

Nothing to tear down — no initiative was created, no worktree was
materialised. The `PlanRejected` audit row stays in place by design.

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#path-allowlists`](../../CONCEPTS.md#path-allowlists).
- Spec: `specs/v2/v2-deep-spec.md §Step 19` (admission-seam path
  validation); `specs/invariants.md` INV-PLAN-04, INV-INIT-02.
- Recipe: [`../../recipes/cli/15-plan-validate.md`](../../recipes/cli/15-plan-validate.md)
  walks every diagnostic code the CLI surfaces.
- Related scenarios: [`40-block-everything-by-default`](../40-block-everything-by-default/)
  for the egress deny-path equivalent.

# Scenario 45 — Quarantine a Bad Plan

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~5 min | **Provider:** Anthropic

Submit a plan that fails admission, demonstrating how the kernel
quarantines bad plans without ever booting a VM.

---

## Run it

```bash
# This plan declares a path_allowlist outside the workspace:
raxis plan validate ./plan.toml

# Should fail with FAIL_PLAN_PATH_ESCAPE.
raxis submit plan ./plan.toml --no-dry-run
```

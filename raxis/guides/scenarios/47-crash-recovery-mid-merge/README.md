# Scenario 47 — Crash Recovery Mid-Merge

> **Complexity:** ⭐⭐⭐⭐ Expert | **Wall clock:** ~12 min | **Provider:** Anthropic

Kill the kernel mid-IntegrationMerge with `kill -9`. Restart it.
Demonstrates the merge-state journal: the kernel resumes the merge
deterministically.

---

## Prerequisites

Same as scenario 04. Two terminals.

---

## Run it

```bash
# Terminal 1: launch a multi-task plan:
INIT_ID=$(... see scenario 13 ...)

# Terminal 2: when you see "IntegrationMerge starting" in the logs,
# kill the kernel hard:
killall -9 raxis-kernel

# Restart it (or it will be relaunched by systemd/launchd if you
# installed via `raxis kernel install`):
raxis-kernel --data-dir ~/.raxis &

# Verify the initiative finishes successfully despite the crash:
raxis inspect-initiative "$INIT_ID"
```

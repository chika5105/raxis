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

# Restart it with the same environment (or let your service manager
# relaunch it if you use `brew services start raxis`):
export RAXIS_INSTALL_DIR="${RAXIS_INSTALL_DIR:-$(brew --prefix raxis)/share/raxis}"
export RAXIS_DATA_DIR="${RAXIS_DATA_DIR:-$(brew --prefix)/var/lib/raxis}"
raxis-kernel &

# Verify the initiative finishes successfully despite the crash:
raxis initiative show "$INIT_ID"
```

# Scenario 15 — HTTP API + curl Witness

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~15 min | **Provider:** Anthropic

Build a tiny HTTP server in Rust that returns a JSON `{"ok": true}`,
then use a `Mechanical` witness that boots the server and curls it.
This is the canonical "agent test against a dev-server" demo.

---

## Prerequisites

Same as scenario 04. Plus `curl` on $PATH (almost always present).

---

## What this scenario demonstrates

- The `Mechanical` witness running a multi-step shell pipeline:
  start server, sleep, curl, kill.
- HTTP calls *inside the VM*, none crossing to the host.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-15"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --bin --name demo15 -q
cargo add tiny_http -q
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
```

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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

cargo init --bin --name demo15 -q
cargo add tiny_http -q
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/15-http-api-and-curl-witness/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

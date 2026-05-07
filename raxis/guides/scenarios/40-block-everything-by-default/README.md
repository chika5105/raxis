# Scenario 40 — Block Everything By Default

> **Complexity:** ⭐ Beginner | **Wall clock:** ~5 min | **Provider:** Anthropic

The Executor *intentionally* attempts to reach `1.1.1.1`. With no
`allowed_egress`, the proxy rejects the connection. Demonstrates the
default-deny posture.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-40"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo "fn main() {}" > src/main.rs
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

Expected: the Executor's curl/wget fails. The audit chain shows
`AUDIT_PROXY_ADMISSION_DENIED` for `1.1.1.1`.

# Scenario 17 — Security Headers Audit

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

A read-only Reviewer audits an HTTP server config for missing
security headers and emits a report. Demonstrates a Reviewer agent
operating *without* an Executor preceding it (audit-only flow).

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- A standalone Reviewer with no Executor.
- Reviewer evaluation_sha == base sha (no upstream change required).

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-17"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/server" "$DEMO_ROOT/audits"
cd "$DEMO_ROOT"

git init -q
cat > server/nginx.conf <<'CONF'
server {
  listen 80;
  add_header X-Frame-Options DENY;
}
CONF
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

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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/server" "$RAXIS_MAIN_REPO/audits"
cd "$RAXIS_MAIN_REPO"

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

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/17-security-headers-audit/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

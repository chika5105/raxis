# Scenario 37 — S3 Credential Proxy

> **Complexity:** ⭐⭐⭐⭐ Expert | **Wall clock:** ~15 min | **Provider:** Anthropic

The Executor uses an AWS access-key pair stored in the credential
proxy to GET objects from `mybucket.s3.amazonaws.com`. Demonstrates
how V2 credentials are scoped to a single named target.

> **Note:** The HTTP-shaped credential proxy is in progress.

---

## Prerequisites

Same as scenario 04. AWS access key pair seeded:

```bash
mkdir -p ~/.raxis/credentials
cat > ~/.raxis/credentials/aws_main.env <<'EOF'
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
EOF
chmod 600 ~/.raxis/credentials/aws_main.env
```

---

## What this scenario demonstrates

- `kind = "http_basic"` (or `kind = "aws_v4"` once it lands).
- The proxy's request-signing seam.

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
```

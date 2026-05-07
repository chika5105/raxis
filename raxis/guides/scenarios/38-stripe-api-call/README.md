# Scenario 38 — Stripe API Call

> **Complexity:** ⭐⭐⭐⭐ Expert | **Wall clock:** ~15 min | **Provider:** Anthropic

The Executor calls the Stripe `/v1/customers` endpoint to create a
test-mode customer. Demonstrates a real third-party API integration
gated by both `allowed_egress` and a credential.

> **Note:** Requires the HTTP-shaped credential proxy.

---

## Prerequisites

Stripe test secret key seeded:

```bash
mkdir -p ~/.raxis/credentials
cat > ~/.raxis/credentials/stripe_test.env <<'EOF'
STRIPE_SECRET_KEY=sk_test_...
EOF
chmod 600 ~/.raxis/credentials/stripe_test.env
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
```

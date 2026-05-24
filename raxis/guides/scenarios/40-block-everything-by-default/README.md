# Scenario 40 — Block Everything By Default

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~6 min | **Provider:** Anthropic

The Executor *intentionally* attempts to reach `1.1.1.1` and a few
public hosts. The plan declares **no** `allowed_egress`. The kernel's
tproxy rejects every connection with `EgressDenied`. The task
transitions to `Failed` with `FAIL_EGRESS_DENIED`. End-to-end
demonstration of the deny-by-default network posture — there is no
"benign default" that lets agents talk to the public internet.

## When to use this

- You're convincing yourself (or a sceptic) that nothing leaks out
  unless explicitly permitted.
- You're sanity-checking a fresh install before letting an Executor
  near anything important.
- You're rehearsing the "what does an exfiltration attempt look
  like in the audit chain?" runbook.

---

## Prerequisites

- **One-time setup complete.** See
  [`../../getting-started/README.md`](../../getting-started/README.md)
  for Homebrew, or [`../../SETUP.md`](../../SETUP.md) for source
  builds.
- **Kernel running.**
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported.**
- **Anthropic credentials** at
  `$RAXIS_DATA_DIR/providers/anthropic-prod.toml` (mode 0600).

---

## What this scenario demonstrates

- The tproxy default is deny — no policy or per-plan grant means
  no egress.
- Every blocked connection emits an `EgressDenied` audit row with
  the SNI / hostname / port the agent attempted.
- The agent's attempt is visible in the audit chain whether or
  not the agent is malicious (a curious Executor and an exfiltrating
  one produce the same shape).
- DNS lookups are also blocked: even resolving `1.1.1.1` (by name)
  fails before the connection attempt.

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

git init -q
echo 'fn main() {}' > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
cp /path/to/raxis/guides/scenarios/40-block-everything-by-default/plan.toml \
   "$RAXIS_MAIN_REPO/plan.toml"

raxis plan validate "$RAXIS_MAIN_REPO/plan.toml"
INIT_ID="$(raxis submit plan   "$RAXIS_MAIN_REPO/plan.toml" --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"

# Watch.
raxis log "$INIT_ID" -f
```

---

## What "success" looks like

```bash
# 1. The task is Failed (intent: the curl call cannot succeed).
raxis initiative show "$INIT_ID" --with-tasks
# probe: Failed   reason: FAIL_EGRESS_DENIED

# 2. The audit chain has one or more EgressDenied rows.
raxis log "$INIT_ID" --kind EgressDenied --json \
  | jq -c '{host: .payload.target_host, port: .payload.target_port, reason: .payload.reason}'
# { "host": "1.1.1.1", "port": 443, "reason": "no allowlist entry" }

# 3. *Zero* EgressAdmitted rows.
raxis log "$INIT_ID" --kind EgressAdmitted --json | wc -l
# 0

# 4. The inference traffic to Anthropic *did* succeed — it goes
#    through the gateway, not the tproxy. Confirm at least one
#    InferenceCompleted row.
raxis log "$INIT_ID" --kind InferenceCompleted --limit 1

# 5. Chain still verifies.
raxis verify-chain
```

The two paths (LLM inference through `raxis-gateway` vs. agent
egress through `raxis-tproxy`) are independent: a deny on one does
**not** affect the other. That distinction is load-bearing and is
demonstrated here.

---

## Variations

- **Add a single allow.** Edit the plan to
  `allowed_egress = ["1.1.1.1:443"]`, re-run. The `EgressDenied`
  row is replaced with `EgressAdmitted`; the task completes.
  Compare audit shapes side-by-side.
- **Wildcard allowlist.** Try `allowed_egress = ["*"]`. The kernel
  refuses the plan at admission with `FAIL_EGRESS_WILDCARD` — there
  is no all-allow shorthand.
- **DNS only.** Have the agent run `dig` (or `getent hosts ...`)
  but no actual HTTP. The DNS lookup itself is blocked; observe
  the `EgressDenied` event on UDP port 53.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$RAXIS_MAIN_REPO"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#egress-allowlist`](../../CONCEPTS.md#egress-allowlist).
- Spec: `specs/v2/v2-deep-spec.md §egress-control-plane`;
  `specs/v2/credential-proxy.md` for the authenticated alternative.
- Recipe: [`../../recipes/plan/11-allowed-egress.md`](../../recipes/plan/11-allowed-egress.md).
- Related scenarios:
  - [`35-http-egress-allowlist`](../35-http-egress-allowlist/) — the
    allow-path complement to this deny-path scenario.
  - [`45-quarantine-a-bad-plan`](../45-quarantine-a-bad-plan/) — the
    admission deny-path equivalent (path-allowlist).

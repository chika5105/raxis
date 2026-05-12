# Scenario 39 — Internal gRPC Call

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~12 min | **Provider:** Anthropic

The Executor calls an internal gRPC service (`internal.example.com:443`)
using `grpcurl`, with the host strictly allowlisted in
`allowed_egress`. The kernel's tproxy admits the SNI hello, the
service responds, and the Executor writes the JSON-projected response
into `data/ping.json`. Any other host the agent tries to reach
(including the public internet) is denied with `EGRESS_DENIED`.

## When to use this

- You have an internal gRPC service the agent legitimately needs to
  reach (a config bus, a feature-flag service, an internal LLM
  cluster) and you want to demonstrate kernel-mediated allow.
- You're comparing the gRPC egress shape (HTTP/2 + ALPN) against the
  REST egress shape ([35-http-egress-allowlist](../35-http-egress-allowlist/))
  to convince yourself the kernel handles both correctly.
- You're sizing an egress allowlist for a new initiative type.

---

## Prerequisites

- **One-time setup complete.** See [`../../SETUP.md`](../../SETUP.md).
- **Kernel running.**
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported.**
- **Anthropic credentials** at
  `$RAXIS_DATA_DIR/providers/anthropic-prod.toml` (mode 0600).
- **An internal gRPC service** the Executor can reach. The plan
  defaults to `internal.example.com:443/myservice.PingService/Ping`;
  substitute your real internal host before running.
- **`grpcurl` installed in the Executor image.** The default RAXIS
  Executor image bundles `grpcurl`; if you've customised the image,
  confirm with `raxis doctor --check executor-image-tools`.

---

## What this scenario demonstrates

- `allowed_egress` works for gRPC (HTTP/2 + ALPN), not just plain
  HTTPS — the tproxy is protocol-agnostic at the SNI level.
- The agent never sees a credential for the internal service; if
  authentication is required, run the call through a credential
  proxy ([see scenario 36](../36-postgres-credential-proxy/) for the
  shape).
- The egress allowlist is the full picture: nothing else the agent
  attempts (`curl https://example.com`, DNS lookups for arbitrary
  hosts) succeeds.

---

## Files in this scenario

| File | Purpose |
|---|---|
| `plan.toml` | One Executor task with `allowed_egress = ["internal.example.com:443"]`. |
| `policy.toml` | No required deltas if your baseline already permits the per-plan egress mechanism; otherwise enable `[[lanes.allowed_egress]]` style as appropriate. |
| `credential.toml` | Standard Anthropic placeholder. |

---

## Run it

```bash
# 1. Materialise a scratch repo with a writable data/ directory.
export DEMO_ROOT="/tmp/raxis-scenario-39"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/data"
( cd "$DEMO_ROOT" \
  && git init -q \
  && echo "# grpc demo" > README.md \
  && git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null \
  && git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init" )

# 2. Edit plan.toml to point at *your* internal host before submitting.
cp ./plan.toml "$DEMO_ROOT/plan.toml"
$EDITOR "$DEMO_ROOT/plan.toml"   # change internal.example.com:443 to your host

# 3. Validate + submit + approve.
raxis plan validate "$DEMO_ROOT/plan.toml"
raxis submit plan   "$DEMO_ROOT/plan.toml" --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

# 4. Follow.
raxis initiative show "$INIT_ID" --with-tasks
raxis log "$INIT_ID" -f
```

---

## What "success" looks like

```bash
# 1. The ping task is Completed.
raxis initiative show "$INIT_ID" --with-tasks
# ping: Completed

# 2. The Executor's commit shows a non-empty data/ping.json.
git -C "$DEMO_ROOT" show main:data/ping.json | jq .

# 3. The egress event was admitted.
raxis log "$INIT_ID" --kind EgressAdmitted --limit 5 --json \
  | jq '.[] | {host: .payload.target_host, port: .payload.target_port}'
# { "host": "internal.example.com", "port": 443 }

# 4. No EgressDenied events — the agent stuck to the allowlist.
raxis log "$INIT_ID" --kind EgressDenied --limit 5
# (empty)

# 5. Chain still verifies.
raxis verify-chain
```

---

## Variations

- **Confirm the deny path.** Edit `plan.toml` to remove
  `allowed_egress`. Re-run; the same `grpcurl` call now produces
  `EgressDenied` and the task moves to `Failed`.
- **Add authentication.** Wrap the gRPC call in a credential proxy
  configuration: see
  [`recipes/policy/12-credential-proxies-section.md`](../../recipes/policy/12-credential-proxies-section.md)
  for the proxy shape; the agent never sees the bearer token.
- **Multiple internal hosts.** Add a second entry to
  `allowed_egress`. The tproxy uses set-membership; ordering and
  case-folding rules match the HTTPS surface.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#egress-allowlist`](../../CONCEPTS.md#egress-allowlist).
- Related scenarios:
  - [`35-http-egress-allowlist`](../35-http-egress-allowlist/) — same
    allowlist mechanism with HTTPS as the substrate.
  - [`38-stripe-api-call`](../38-stripe-api-call/) — credentialed
    HTTP egress via the credential proxy.
  - [`40-block-everything-by-default`](../40-block-everything-by-default/)
    — confirm the deny-by-default posture.
- Recipe: [`../../recipes/plan/11-allowed-egress.md`](../../recipes/plan/11-allowed-egress.md).
- Spec: `specs/v2/v2-deep-spec.md §egress-control-plane` for the
  tproxy admission semantics.

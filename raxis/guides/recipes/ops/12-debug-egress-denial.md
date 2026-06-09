# Debug an egress denial

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

A task is failing because its session can't reach an external host
the planner expected to use. INV-02B (no direct VM network) means
all egress goes through the kernel-mediated proxy, gated by
`allowed_egress` in `plan.toml`. This recipe walks the diagnosis.

---

## Steps

### 1. Confirm an egress denial happened

```bash
raxis log <initiative_id> --kind EgressDenied --since 1h
# AT                     SESSION    HOST                   PORT   REASON
# 2026-05-10T17:30:00Z   91a7c83f   api.example.com        443    not_in_allowed_egress
```

If you see no `EgressDenied`, the failure isn't egress —
investigate elsewhere (`raxis explain <task>`).

### 2. Inspect the task's `allowed_egress`

```bash
raxis initiative show <id> --bundle --to /tmp/forensic
grep -A 5 "<task_id>" /tmp/forensic/plan.toml
# [[tasks]]
# task_name      = "implementer"
# allowed_egress = ["github.com:443", "api.openai.com:443"]
# ...
```

Compare with the `host:port` from the denial. The most common case
is the planner using a host you didn't anticipate (`api.example.com`
vs the allowlisted `github.com`).

### 3. Decide: allow or block

Three options:

#### Option A: legitimate need → add to allowlist

Update the plan and resubmit:

```toml
[[tasks]]
task_name        = "implementer"
allowed_egress = ["github.com:443", "api.example.com:443"]
```

Resubmit and approve a fresh initiative; the existing one cannot
be patched mid-flight.

#### Option B: temporary delegation

For a one-off probe that doesn't justify a plan change:

```bash
raxis delegation grant \
  --session 91a7c83f \
  --capability egress \
  --scope '{"host": "api.example.com", "port": 443}' \
  --ttl 600 \
  --reason "diagnostic: confirm endpoint reachability"
```

The session can now reach that host for 10 minutes. See
[`cli/15-delegation-grant`](../cli/15-delegation-grant.md).

#### Option C: confirm denial was correct

The planner is hallucinating a host or trying to exfiltrate data.
Don't add to allowlist; abort the task and investigate:

```bash
raxis task abort <task_id>
raxis log --kind EgressDenied --since 24h --json \
  | jq -r '.payload.target_host // .payload.host // empty' \
  | sort | uniq -c
```

### 4. Common host families

The planner often needs:

| Purpose | Hosts |
|---|---|
| GitHub | `github.com:443`, `api.github.com:443`, `raw.githubusercontent.com:443`, `objects.githubusercontent.com:443` |
| Anthropic | `api.anthropic.com:443` |
| OpenAI | `api.openai.com:443` |
| Vertex AI | `*.googleapis.com:443` (use specific subdomains) |
| Bedrock | `bedrock-runtime.<region>.amazonaws.com:443` |
| Crates.io | `crates.io:443`, `static.crates.io:443`, `index.crates.io:443` |
| PyPI | `pypi.org:443`, `files.pythonhosted.org:443` |
| Docker Hub | `registry-1.docker.io:443`, `auth.docker.io:443` |

Host wildcards aren't supported in `allowed_egress` — list each
explicit subdomain. This is intentional; deny-by-default for
unanticipated hosts.

### 5. Verify the fix

After a plan resubmit or delegation:

```bash
raxis log --kind EgressAllowed --since 1m
# AT                     SESSION    HOST                   PORT
# 2026-05-10T17:31:00Z   91a7c83f   api.example.com        443

# OR (after a fresh plan submission):
raxis log <new_init_id> --kind TaskStarted
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `delegation grant: capability not supported` | The kernel version doesn't have the egress capability; upgrade. |
| Plan rejected with "egress entry not host:port" | Each entry must be `<host>:<port>`; no protocols. |
| Egress allowed but TLS handshake fails | The proxy dispatches; failure is upstream. Check the host's certificate, your trust store, and `raxis log --kind EgressUpstreamError`. |
| Repeated EgressDenied for the same host | The planner is in a retry loop. Either add to allowlist or `raxis task abort`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis log --kind EgressDenied` | Recent denials. |
| `raxis log --kind EgressAllowed` | Recent allowances. |
| `raxis initiative show --bundle --to <dir>` | Pull the canonical plan. |
| `raxis delegation grant --capability egress` | Temporary bypass. |
| [plan/09-vm-image-and-egress](../plan/09-vm-image-and-egress.md) | Schema for `allowed_egress`. |

---

## Variations

- **Pre-flight allowlist generation.** Run a probe plan with broad
  delegation, capture all hosts hit, build the canonical
  `allowed_egress` list. Don't keep the broad delegation.
- **CI-only delegation.** A CI bot with `GrantDelegation`
  permission can self-grant egress for a known set of hosts;
  short TTL.
- **Audit-driven hardening.** Periodically `raxis log --kind EgressAllowed --json`
  and prune any hosts no plan has used in 30 days.
- **Egress proxy via VPC.** The proxy itself can route through a
  VPC egress gateway; `allowed_egress` still gates which hosts.

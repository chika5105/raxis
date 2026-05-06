# RAXIS V2 — VM Network Isolation Architecture

> **Status:** V2 Specified
> **Role in V2 unified egress:** This spec is the canonical home for **Tier 1 — Public / Unauthenticated egress**. Together with `credential-proxy.md` (Tier 2 — Authenticated egress), it replaces the previous `kernel-mediated-egress.md` (deprecated; preserved historically only).
>
> **Cross-references:**
> - `credential-proxy.md §1b` — TCP vs HTTP proxy distinction
> - `credential-proxy.md §13` — Intra-VM loopback and dev servers
> - `credential-proxy.md` (full spec) — Tier-2 (authenticated) egress with HTTP-granular URL/method enforcement
> - ~~`kernel-mediated-egress.md`~~ — DEPRECATED in V2 in favor of unified two-tier egress
> - `environment-access-control.md §4` — *This section's `EgressRequest` admission order is V1-flavored; V2 uses two-tier network-layer enforcement and there is no `EgressRequest` intent. The spec needs a separate amendment to align.*
> - `planner-harness.md §7` — V2 unified egress overview (this spec + `credential-proxy.md`)
> - `custom-tools.md` — operator-defined custom tools. A custom-tool subprocess shares the planner VM's network namespace and is therefore subject to the same Tier 1 (tproxy SNI allowlist) and Tier 2 (credential proxy URL/method allowlist) enforcement as any other in-VM process. Custom tools introduce **no new authority surface** at the network layer; an HTTP call from a custom-tool script reaches the same tproxy / credential-proxy checks a `bash`-invoked HTTP call would.

---

## 1. The Problem: Connecting Tissue Between VM Code and RAXIS Controls

When an agent's dev server calls `httpx.get("https://api.stripe.com/")`, that is a
raw TCP connection attempt. Without a network interception mechanism, this either:
- Succeeds, bypassing the egress allowlist entirely (unacceptable)
- Fails with `ENETUNREACH` because the VM has no internet (breaks normal code)

Neither is acceptable. The "connecting tissue" is a **transparent network proxy**
running inside the VM, installed by the Kernel at boot, that intercepts all outbound
TCP before it leaves the VM.

---

## 2. Two Classes of Traffic — Different Mechanisms

### Class 1 — Database connections (already solved by credential proxy)

When the plan declares `[[tasks.credentials]] proxy_type = "postgres"`, the Kernel:
1. Starts the PostgreSQL credential proxy on `localhost:5432` before VM boot
2. Sets `DATABASE_URL=postgresql://raxis@localhost:5432/mydb` in the VM

The agent's database connection string already points to the credential proxy.
No network interception is needed — the connection goes to `localhost:5432` which is
intra-VM and already the correct endpoint. The credential proxy handles auth to the
real DB transparently.

**Problem this solves:** The agent's `psycopg2.connect(os.environ["DATABASE_URL"])`
connects to `localhost:5432` → credential proxy → real DB with auth. No iptables,
no interception, no vsock needed for this traffic.

### Class 2 — External HTTP/HTTPS calls (requires transparent proxy)

When agent code or a dev server calls `httpx.get("https://api.stripe.com/")`, the TCP
connection target is `stripe.com:443` — an external host that must be admitted against
the egress allowlist. There is no way for the Kernel to intercept this without a
network-level mechanism.

**Mechanism:** `raxis-tproxy` — a transparent proxy process installed inside the VM
by the Kernel at boot, combined with iptables rules that redirect all outbound
TCP to it.

> **Custom-tool subprocess interaction (cross-reference: `custom-tools.md`).**
> Operator-defined custom tools (`[[profiles.<name>.custom_tool]]`) execute as
> subprocesses of the planner harness and inherit the planner VM's network
> namespace. Any HTTP / HTTPS / arbitrary-TCP call made by a custom-tool script
> is intercepted by the same `iptables` redirect into `raxis-tproxy` that
> intercepts a `bash`-invoked HTTP call, and is subject to the same Tier-1
> SNI allowlist enforcement (§4) and Tier-2 credential-proxy URL/method
> enforcement (per `credential-proxy.md`). Custom tools introduce **no new
> authority surface** at the network layer — the per-task `allowed_egress`
> declaration governs both direct `bash` egress and custom-tool-mediated
> egress identically.

---

## 3. raxis-tproxy — The Transparent Network Proxy

`raxis-tproxy` is a small binary placed in the VM by the Kernel at boot. It is not
accessible to the agent (installed to a path outside the agent's `path_allowlist`,
owned by `root`, not executable by the agent user).

### 3.1 — iptables Rules (Installed by Kernel at VM Boot)

```bash
# Drop all outbound traffic by default (VM has no direct internet)
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT          # loopback always permitted

# Redirect all outbound TCP on port 80/443 to raxis-tproxy
iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-port 3129
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 3129

# Redirect outbound TCP on database ports (NOT to localhost) to raxis-tproxy
# This catches proxy bypass attempts (§13.9): agent trying to reach real DB directly
iptables -t nat -A OUTPUT -p tcp --dport 5432 ! -d 127.0.0.1 -j REDIRECT --to-port 3129
iptables -t nat -A OUTPUT -p tcp --dport 3306 ! -d 127.0.0.1 -j REDIRECT --to-port 3129
iptables -t nat -A OUTPUT -p tcp --dport 1433 ! -d 127.0.0.1 -j REDIRECT --to-port 3129
iptables -t nat -A OUTPUT -p tcp --dport 27017 ! -d 127.0.0.1 -j REDIRECT --to-port 3129
iptables -t nat -A OUTPUT -p tcp --dport 6379 ! -d 127.0.0.1 -j REDIRECT --to-port 3129

# Drop anything else outbound (no other external ports permitted)
iptables -A OUTPUT -j DROP
```

The `! -d 127.0.0.1` exception means: if the agent connects to `localhost:5432`
(the credential proxy) — that is loopback and already accepted. Only if the agent
tries to connect to a *non-localhost* address on port 5432 does it hit `raxis-tproxy`
— which is the proxy bypass scenario detected in §13.9.

### 3.2 — What raxis-tproxy Does

```
Agent process                raxis-tproxy (localhost:3129)        Kernel Host
                             via iptables REDIRECT
    |                               |                                |
    |─ TCP connect stripe.com:443  →|                                |
    |                               | SO_ORIGINAL_DST: stripe.com:443|
    |                               |─ vsock: ProxyAdmission {       |
    |                               |    target: "stripe.com:443",   |
    |                               |    protocol: "https"           |
    |                               |  } ──────────────────────────→ |
    |                               |                                | check egress allowlist
    |                               |← Admitted / Denied ───────────|
    |                               |                                |
    | [if Admitted]                 |─ CONNECT tunnel to Kernel ───→ |─ TCP to stripe.com:443
    |← TLS ClientHello forwarded ──|← response ────────────────────|
    | [TLS negotiates end-to-end]   |
    |─ HTTP request (encrypted) ───→ forwarded through tunnel ─────→ stripe.com
    |← HTTP response ──────────────── returned through tunnel ──────|
```

For HTTP (port 80): the TPROXY can read the `Host` header directly (unencrypted).
For HTTPS (port 443): the TPROXY reads the target from the `CONNECT` method or
from the TLS SNI extension (server name) before the TLS handshake begins.
In both cases, **no TLS termination is performed** — the TLS connection is
end-to-end between the agent and the real server.

### 3.3 — HTTPS: SNI Extraction Without TLS Termination

For HTTPS, the TPROXY reads the SNI (Server Name Indication) from the ClientHello
TLS handshake — this is sent in plaintext before encryption begins:

```
Client → raxis-tproxy: [TLS ClientHello with SNI extension: stripe.com]
raxis-tproxy: extract SNI = "stripe.com"
raxis-tproxy → Kernel: ProxyAdmission { host: "stripe.com", port: 443, protocol: "https" }
Kernel: check allowed_egress → admitted
raxis-tproxy: establish CONNECT tunnel through Kernel to stripe.com:443
Client → [TLS ClientHello forwarded through tunnel] → stripe.com
[TLS handshake completes end-to-end]
[Encrypted traffic flows bidirectionally through tunnel]
```

The Kernel **cannot** inspect the HTTP request method, path, or body over HTTPS —
the traffic is end-to-end encrypted. The Kernel can only enforce by **hostname**.

---

## 4. Tier 1 Enforcement Granularity (Hostname / SNI Only)

> **V2 architectural amendment.** The original §4 documented a "method enforcement
> gap" between an explicit `EgressRequest` intent path and the transparent proxy
> path, including a `require_intent = true` opt-in that forced agents to use the
> RAXIS SDK for strict-method hosts. This entire framing is V2-deprecated:
> `IntentKind::EgressRequest` is removed (per `planner-harness.md §7`), the
> `require_intent` plan field is deprecated and ignored, and `INV-EGRESS-INTENT-01`
> is deprecated. V2's two-tier egress places method-level enforcement entirely
> in the **Credential Proxy (Tier 2)** for authenticated endpoints; the
> transparent proxy (Tier 1) enforces by **SNI hostname only**, which is
> acceptable because anything requiring method-granular enforcement runs through
> a credential proxy where HTTP-level enforcement is natural.

### 4.1 — Tier 1 (this spec): SNI-only enforcement, network layer

`raxis-tproxy` intercepts every outbound TCP connection from the VM and:

```python
# Agent code using standard HTTP client (no SDK; no special protocol):
httpx.post("https://api.stripe.com/v1/charges", json=body)
# raxis-tproxy receives: TCP connection to stripe.com:443
# SNI extraction: "stripe.com" (parsed from TLS ClientHello)
# Kernel enforces: hostname in policy egress_hosts AND in this task's allowed_egress
# CANNOT enforce: url_prefix, HTTP method, request body content (TLS encrypts these)
```

This is intentional and sufficient for Tier 1 use cases (npm registry, crates.io,
public GitHub HTML, package mirrors, public APIs that don't require credentials):
the operator's allowlist controls *which* hosts agents can reach; method/path
granularity is unnecessary for unauthenticated public traffic.

### 4.2 — Tier 2 (separate spec): HTTP-granular enforcement at Credential Proxy

For any endpoint that requires authentication (Stripe, AWS, GCP, internal APIs),
the architecture is:

1. The operator declares the credential in `policy.toml`, including the URL
   allowlist and method whitelist for that credential.
2. The kernel boots a credential proxy on a localhost port inside the VM
   (`localhost:9100`, etc.).
3. The agent connects to `localhost:<port>` with no auth; the credential proxy
   enforces URL prefix + method + body schema **at HTTP granularity** (it sees
   plaintext HTTP because the agent talks to it over loopback) and forwards
   the authenticated request to the real upstream.

This places method-granular enforcement at the right layer. See
[`credential-proxy.md`](credential-proxy.md) for the full Tier 2 spec.

### 4.3 — Enforcement Surface Table (V2)

| Enforcement point | Tier 1 (raxis-tproxy, this spec) | Tier 2 (credential proxy) |
|---|---|---|
| Hostname in `egress_hosts` | ✓ (via SNI on tproxy) | ✓ (URL parse on credential proxy) |
| URL prefix in `allowed_egress` | ✗ (TLS encrypts URL) | ✓ |
| HTTP method restriction | ✗ (TLS encrypts method) | ✓ |
| Environment gate (`write_requires_approval`) | ✗ | ✓ (credential proxy delegates per-call) |
| Request body audit (SHA-256) | ✗ | ✓ (request body audit by digest) |
| Response body audit | ✗ | ✓ (response body audit by digest if `audit_response_body = true` in credential decl) |
| TLS termination | None (CONNECT-tunneled) | At credential proxy (it speaks HTTP plaintext to the agent on loopback, HTTPS to upstream) |

**Operator decision:** any endpoint that requires URL/method granularity MUST
be declared as a credential (Tier 2). Endpoints that don't (public package
mirrors, public docs, etc.) are fine on Tier 1.

### 4.4 — Deprecated: `require_intent` and `EgressRequest`

`require_intent = true` on `[[tasks.allowed_egress]]` and the `IntentKind::EgressRequest`
intent are deprecated in V2 and have no effect. `INV-EGRESS-INTENT-01` is also
deprecated.

If a `plan.toml` includes `require_intent = true` on an `[[tasks.allowed_egress]]`
entry under V2, the kernel:

1. At `approve_plan` time emits a `WARN_DEPRECATED_REQUIRE_INTENT` warning
   (suppressible via `--no-strict`; promoted to `FAIL_DEPRECATED_REQUIRE_INTENT`
   under `--strict`) advising the operator to migrate the endpoint to a
   credential proxy declaration.
2. At runtime: the field is ignored. The endpoint is reachable via Tier 1
   (SNI-allowlisted) regardless of the declared value.

There is no `IntentKind::EgressRequest` enum variant in V2. Any planner
attempting to submit one receives `FAIL_INTENT_NOT_RECOGNIZED` (the kernel's
generic handler for unknown intent variants).

**Migration path for existing V1 plans using `require_intent = true`:** identify
the endpoint and declare it as a credential in `policy.toml`. For example:

```toml
# Before (V1):
[[tasks.allowed_egress]]
url_prefix     = "https://api.stripe.com/"
methods        = ["POST"]
require_intent = true   # V2: deprecated; ignored

# After (V2): declare as a credential proxy in policy.toml
[[providers.credentials]]
name             = "stripe-prod"
proxy_type       = "http"
proxy_port       = 9101
real_url_prefix  = "https://api.stripe.com/v1/"
allowed_methods  = ["POST"]
auth             = "bearer:$STRIPE_SECRET_KEY_PATH"

# Then in plan.toml, the task references the credential:
[[tasks.credentials]]
name      = "stripe-prod"
proxy_port = 9101
# Agent calls localhost:9101 with no auth; credential proxy forwards
# with bearer token to api.stripe.com/v1/, enforcing method = POST.
```

See `credential-proxy.md` for the full credential proxy declaration schema.

---

## 5. Database Bypass Detection via Transparent Proxy

When the agent tries to connect directly to a real database host (bypassing the
credential proxy), the iptables rule for port 5432 (excluding localhost) redirects
to `raxis-tproxy`:

```
Agent: psycopg2.connect("postgresql://user:real_pass@postgres-staging.company.internal:5432/mydb")
  → TCP connect to postgres-staging.company.internal:5432
  → iptables: NOT localhost → REDIRECT → raxis-tproxy:3129
  → raxis-tproxy: SO_ORIGINAL_DST = postgres-staging.company.internal:5432
  → Kernel: ProxyAdmission { host: "postgres-staging.company.internal", port: 5432, protocol: "tcp" }
  → Kernel: check — does this match a credential proxy real_target? YES
  → FAIL_PROXY_TARGET_BYPASS → SecurityViolationDetected (§13.9)
  → raxis-tproxy: close connection with ECONNREFUSED
  → psycopg2: raises OperationalError: connection refused
```

The iptables rule is the network-level enforcer of §13.9's security policy.
Without it, the agent could attempt a direct database connection on port 5432 and
it would simply fail at the network layer with `ENETUNREACH` — not detected as a
security violation, no audit event, no strike counter.

---

## 6. VM Boot Sequence (Updated)

```
1. Kernel allocates VM, assigns session_id
2. Kernel starts all credential proxies declared in [[tasks.credentials]]:
   - PostgresProxy → localhost:5432
   - K8sProxy     → localhost:8001
   - (etc.)
3. Kernel installs raxis-tproxy binary in VM at /raxis/bin/raxis-tproxy (root-owned)
4. Kernel installs iptables rules (§3.1) inside VM network namespace
5. Kernel generates blank kubeconfig / DATABASE_URL / AWS IMDS env vars
6. Kernel emits CredentialProxyStarted audit events for each proxy
7. Kernel boots agent process with injected env vars
8. Agent boots — dev server can start, make intra-VM calls freely
9. Agent's external HTTP calls → iptables → raxis-tproxy → Kernel admission
10. Agent's DB calls → localhost:5432 → credential proxy (no iptables needed)
```

---

## 7. What the Agent's Dev Server Actually Calls

The dev server and its test suite require NO changes to use RAXIS. Standard library
calls work as-is because:

```python
# Dev server code — unchanged from non-RAXIS code:
import httpx
import psycopg2
import os

# Database — connects to localhost:5432 (credential proxy)
db = psycopg2.connect(os.environ["DATABASE_URL"])

# External HTTP — intercepted by iptables → raxis-tproxy → Kernel admission
response = httpx.post("https://api.stripe.com/v1/charges", ...)

# Intra-VM — directly to dev server, no interception
test_response = httpx.get("http://localhost:8000/api/health")
```

The agent code is identical to production code. The network architecture handles
the routing transparently.

---

## 8. Implementation Checklist

- [ ] Build `raxis-tproxy` binary (Rust, tokio-based TCP listener on port 3129)
      - SO_ORIGINAL_DST to read original destination after iptables REDIRECT
      - SNI extraction from TLS ClientHello (parse TLS record, read SNI extension)
      - vsock ProxyAdmission request to Kernel
      - CONNECT tunnel mode for HTTPS (forward raw bytes bidirectionally)
      - Direct proxy mode for HTTP (read Host header, proxy request)
      - ECONNREFUSED on denial
- [ ] Kernel: install raxis-tproxy binary into VM rootfs at boot
- [ ] Kernel: install iptables rules in VM network namespace at boot (§3.1)
      - Port 80/443 redirect for HTTP/HTTPS
      - Port 5432/3306/1433/27017/6379 redirect for DB bypass detection
      - Accept loopback, drop everything else outbound
- [ ] Kernel: handle ProxyAdmission vsock message:
      - Hostname check against policy egress_hosts AND task's allowed_egress
      - If host matches credential proxy real_target → FAIL_PROXY_TARGET_BYPASS + SecurityViolationDetected
      - Otherwise → Admit, establish outbound TCP/TLS connection on agent's behalf
      - Return connection handle via vsock
- [ ] Emit `TransparentProxyAdmitted` and `TransparentProxyDenied` audit events
      with { session_id, host, port, protocol, sni_name }
- [ ] V2 plan-admission additions for the deprecated `require_intent` field:
      - Parser still accepts the field for V1 plan back-compat (no syntactic rejection)
      - At `approve_plan`: emit `WARN_DEPRECATED_REQUIRE_INTENT` (warning by default;
        promoted to `FAIL_DEPRECATED_REQUIRE_INTENT` under `--strict`)
      - At runtime: field is ignored regardless of value
- [ ] Tests:
      - HTTP call to allowed host → admitted, response returned
      - HTTP call to non-allowed host → ECONNREFUSED
      - HTTPS call to allowed host → SNI extracted, tunnel established
      - DB call to real target (not localhost) → FAIL_PROXY_TARGET_BYPASS
      - DB call to localhost:5432 → not redirected (loopback accepted)
      - V2: V1 plan with `require_intent = true` under `--no-strict` → admitted with WARN
      - V2: same plan under `--strict` → rejected with `FAIL_DEPRECATED_REQUIRE_INTENT`
      - V2: `IntentKind::EgressRequest` submission attempt → `FAIL_INTENT_NOT_RECOGNIZED`
      - V2: tproxy admits Tier 1 traffic with NO method/path enforcement (TLS encrypts both)

REMOVED (V2-deprecated; do NOT implement):
- ~~Add `require_intent` field to plan `[[tasks.allowed_egress]]`~~ → field stays for back-compat
  parsing only; ignored at runtime
- ~~Add `FAIL_INTENT_REQUIRED` to KernelError~~ → not needed; deprecated path
- ~~Implement `EgressRequest` intent admission~~ → variant removed from `IntentKind`

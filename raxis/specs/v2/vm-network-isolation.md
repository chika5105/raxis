# RAXIS V2 — VM Network Isolation Architecture

> **Status:** V2 Specified
> **Cross-references:**
> - `credential-proxy.md §1b` — TCP vs HTTP proxy distinction
> - `credential-proxy.md §13` — Intra-VM loopback and dev servers
> - `environment-access-control.md §4` — EgressRequest admission order

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

## 4. The Method Enforcement Gap

This is a deliberate design tension that must be documented.

### 4.1 — EgressRequest Intent Path (Full Enforcement)

When the agent uses the RAXIS SDK's `EgressRequest` intent explicitly, the Kernel
receives the full request before it is sent:

```rust
// Agent code using RAXIS SDK:
raxis::egress::post("https://api.stripe.com/v1/charges", body)
// Kernel receives: { url, method: POST, headers, body }
// Enforces: hostname in egress_hosts, url_prefix in allowed_egress, method in allowed_methods
// Full enforcement: hostname + url_prefix + method + environment gate
```

### 4.2 — Transparent Proxy Path (Hostname-Only Enforcement)

When the agent uses a standard HTTP client (httpx, requests, curl, fetch), the
transparent proxy intercepts the raw TCP connection:

```python
# Agent code using standard HTTP client:
httpx.post("https://api.stripe.com/v1/charges", json=body)
# raxis-tproxy receives: TCP connection to stripe.com:443
# SNI extraction: "stripe.com"
# Kernel enforces: hostname in egress_hosts only
# CANNOT enforce: url_prefix, HTTP method, request body content
```

### 4.3 — Enforcement Gap Table

| Enforcement point | EgressRequest intent | Transparent proxy |
|---|---|---|
| Hostname in `egress_hosts` | ✓ | ✓ |
| URL prefix in `allowed_egress` | ✓ | ✗ (hostname only) |
| HTTP method restriction | ✓ | ✗ |
| Environment gate (`write_requires_approval`) | ✓ | ✗ |
| Request body audit (SHA-256) | ✓ | ✗ |
| Response body audit | ✓ | ✗ |

### 4.4 — Policy Decision: Which Path Is Authoritative?

**For tasks that require strict method enforcement** (e.g., read-only access to an API),
the plan should declare `allowed_egress` with restricted methods — but the transparent
proxy cannot enforce this for raw HTTP client calls.

**Resolution:** The plan's `allowed_egress` method restriction is enforced at the
`EgressRequest` intent level. For transparent proxy traffic, only hostname is enforced.
This is acceptable because:

1. **The real defense is the credential proxy** — for authenticated APIs (AWS, GCP,
   Azure, k8s), the credential proxy controls what the credential can do. A dev server
   calling `DELETE /api/resource` with staging AWS credentials is limited by the staging
   IAM role's permissions — not just the egress method filter.

2. **For unauthenticated external calls** (e.g., calling a third-party API with no
   RAXIS credential), method enforcement at the RAXIS level is advisory — the real
   enforcement is the third-party API's own authorization.

3. **Strict method enforcement** should use `EgressRequest` intent explicitly via the
   RAXIS SDK — not a transparent proxy. Plans that require it can declare
   `require_raxis_sdk = true` in `allowed_egress`, and the Kernel blocks the transparent
   proxy path for that host entirely, requiring the agent to use the RAXIS SDK.

```toml
# plan.toml — opt-in to strict enforcement for a specific host
[[tasks.allowed_egress]]
url_prefix   = "https://api.stripe.com/"
methods      = ["POST"]
require_intent = true   # blocks transparent proxy for this host; agent must use RAXIS SDK
```

When `require_intent = true`, the TPROXY's `ProxyAdmission` for this host returns
`FAIL_INTENT_REQUIRED` instead of admitting. The TPROXY closes the connection with
`ECONNREFUSED`. The agent must use the RAXIS SDK intent path for this host.

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
      - Hostname check against policy egress_hosts
      - If host matches credential proxy real_target → FAIL_PROXY_TARGET_BYPASS + SecurityViolationDetected
      - If require_intent = true in allowed_egress → FAIL_INTENT_REQUIRED
      - Otherwise → Admit, establish outbound TCP/TLS connection on agent's behalf
      - Return connection handle via vsock
- [ ] Add `require_intent` field to plan `[[tasks.allowed_egress]]`
- [ ] Add `FAIL_INTENT_REQUIRED` to KernelError
- [ ] Emit `TransparentProxyAdmitted` and `TransparentProxyDenied` audit events
      with { session_id, host, port, protocol, snl_name }
- [ ] Tests:
      - HTTP call to allowed host → admitted, response returned
      - HTTP call to non-allowed host → ECONNREFUSED
      - HTTPS call to allowed host → SNI extracted, tunnel established
      - DB call to real target (not localhost) → FAIL_PROXY_TARGET_BYPASS
      - DB call to localhost:5432 → not redirected (loopback accepted)
      - `require_intent = true` host → FAIL_INTENT_REQUIRED via transparent proxy

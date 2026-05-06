# RAXIS V2 — Kernel-Mediated Egress

> **Status: DEPRECATED.** This spec is no longer normative. The
> `IntentKind::EgressRequest` intent and the `raxis-egress` proxy described
> below are removed from V2 GA. Superseded by the **Unified Egress** decision
> recorded in [`v2-deep-spec.md §Part 7`](v2-deep-spec.md), under
> *Integration & Harness Decisions → Decision — Unified Egress (Drop
> `IntentKind::EgressRequest`)*.
>
> **Where to look instead:**
>
> - **Public / unauthenticated egress** (npm, cargo, pip, git, curl, …):
>   transport-layer SNI allowlist via `raxis-tproxy`. See
>   [`vm-network-isolation.md`](vm-network-isolation.md).
> - **Authenticated / sensitive egress** (APIs, k8s, cloud, DB): HTTP-layer
>   URL-prefix + method allowlist via per-session `localhost:<port>`
>   Credential Proxy. See [`credential-proxy.md`](credential-proxy.md).
> - **Dynamic widening at runtime** (URL not in either allowlist): operator
>   amendment via `IntentKind::EscalationRequest`. See
>   [`agent-disagreement.md §6`](agent-disagreement.md).
>
> **Deprecated invariants** (carried over from this spec, retired with it):
>
> - `INV-EGRESS-01` (egress.sock UDS exclusivity) — no `egress.sock` exists
>   under the unified model.
> - `INV-EGRESS-INTENT-01` (`require_intent = true` enforcement) — the
>   `require_intent` field is vestigial without an intent path; production
>   endpoints needing tighter audit are routed through the Credential Proxy
>   instead, where URL + method enforcement is the default.
>
> **Why the content is preserved.** This document remains in the repository
> as a historical record of (a) the original two-path design, (b) the
> alternatives considered during the V2 design phase, and (c) the rationale
> that motivated the eventual unification. Any cross-reference from another
> spec to this file should be treated as a pointer to design history, not to
> normative behavior. New PRs MUST NOT add normative cross-references to
> this file; cite `vm-network-isolation.md` or `credential-proxy.md` instead.

> **Original status:** V2 Specified
> **Original cross-references:**
> - `v2-deep-spec.md §1.3` — Credential isolation / INV-02B
> - `security/raxis-security-model.md §INV-GATEWAY-01` — Gateway trust boundary pattern
> - `v2-deep-spec.md §Part 7` — `RaxisToolExecutor` integration point

---

## 1. Problem and Invariant Preservation

RAXIS VMs have no virtual NIC (INV-02B). This is a hard invariant — not a default
setting. A VM with a NIC can exfiltrate secrets, push code bypassing `IntegrationMerge`,
and make unconstrained API calls outside the audit chain.

Some tasks legitimately need web read access: a research Executor searching GitHub for
prior art, an Implementer reading API documentation, an Orchestrator checking a package
registry for the latest version. Giving these tasks a NIC to satisfy this need would
break INV-02B and the audit chain simultaneously.

**The solution follows the same pattern as inference:** introduce a new host-side proxy
process (`raxis-egress`) and a new intent kind (`EgressRequest`). The planner submits an
intent to the Kernel; the Kernel validates it against the task's signed `allowed_egress`
list; the Kernel routes it to `raxis-egress`; the proxy makes the HTTP call; the response
returns to the planner through the Kernel. The VM never gets a NIC. Every egress call is
admitted, validated, audited, and budget-charged before it leaves the host.

---

## 2. Two-Level Allowlist

Egress permission is controlled at two independent levels, both of which must permit a
request before it is admitted.

### Level 1 — Policy Bundle (`[[egress_hosts]]`)

Operator-signed, deployment-wide. Defines which hostnames are reachable from any task
in any initiative. No plan can authorize egress to a host not in this list.

```toml
# policy.toml

[[egress_hosts]]
hostname_pattern = "api.github.com"
allowed_methods  = ["GET"]
tls_required     = true

[[egress_hosts]]
hostname_pattern = "*.githubusercontent.com"
allowed_methods  = ["GET"]
tls_required     = true

[[egress_hosts]]
hostname_pattern = "docs.rs"
allowed_methods  = ["GET"]
tls_required     = true

[[egress_hosts]]
hostname_pattern = "crates.io"
allowed_methods  = ["GET"]
tls_required     = true
```

`hostname_pattern` supports a single leading `*` wildcard (subdomain match only — not a
glob that matches path segments). No regex. `tls_required = true` is the only supported
value in V2 — plaintext HTTP is not permitted.

### Level 2 — Plan (`[[tasks.allowed_egress]]`)

Signed per initiative. Defines per-task URL prefix restrictions within the globally
permitted set.

```toml
[[tasks]]
task_id            = "research_executor"
session_agent_type = "Executor"

  [[tasks.allowed_egress]]
  url_prefix         = "https://api.github.com/search/repositories"
  methods            = ["GET"]
  max_response_bytes = 131072   # 128 KiB
  max_requests       = 50       # per initiative lifetime

  [[tasks.allowed_egress]]
  url_prefix         = "https://api.github.com/repos/"
  methods            = ["GET"]
  max_response_bytes = 65536    # 64 KiB
  max_requests       = 30

[[tasks]]
task_id            = "auth_implementer"
session_agent_type = "Executor"
# no allowed_egress — this task is fully air-gapped (current default for all tasks)
```

**URL prefix matching:** `starts_with()` — identical to path allowlist matching. No
globs in plan-level entries. The full URL (scheme + host + path + query) must start with
the declared prefix.

**Admission rule:** `url ∈ task.allowed_egress` AND `hostname(url) ∈ policy.egress_hosts`.
Both must match. If the policy bundle permits `api.github.com` but the plan's task has
no `allowed_egress` entry, the request is denied. If the plan has an entry for
`https://api.github.com/search/` but the policy bundle has no `api.github.com` entry,
the request is denied.

---

## 3. The `EgressRequest` Intent

```rust
/// Submitted by Executor or Orchestrator sessions that have allowed_egress entries.
/// Reviewers may not submit EgressRequest (no egress in review sessions by default).
pub struct EgressRequest {
    /// Full URL including scheme, host, path, and query string.
    /// Validated against task's allowed_egress prefixes and policy egress_hosts at admission.
    pub url: String,

    /// HTTP method. Must be in the task's allowed methods for the matching prefix.
    pub method: HttpMethod,   // GET | POST | PUT | PATCH | DELETE (POST+ requires explicit plan opt-in)

    /// Request headers. Filtered by the Kernel before forwarding:
    ///   - Authorization headers are STRIPPED (credentials injected by raxis-egress if configured)
    ///   - Cookie headers are STRIPPED
    ///   - All other headers are forwarded
    pub headers: Vec<(String, String)>,

    /// Request body. Only non-None if method is POST/PUT/PATCH.
    /// Size-capped at 64 KiB at admission (before routing to egress proxy).
    pub body: Option<Vec<u8>>,
}

pub enum HttpMethod { Get, Post, Put, Patch, Delete }
```

**Dispatch matrix:**

| Session type | EgressRequest |
|---|---|
| Orchestrator | ✅ (if task has `allowed_egress`) |
| Executor | ✅ (if task has `allowed_egress`) |
| Reviewer | ❌ always — no egress in review sessions |

---

## 4. `EgressResponse` — What the Planner Receives

```rust
pub struct EgressResponse {
    pub status_code:      u16,
    pub headers:          Vec<(String, String)>,  // filtered (see below)
    pub body:             Vec<u8>,
    pub truncated:        bool,    // true if body exceeded max_response_bytes
    pub content_type:     String,
    pub response_bytes:   u64,     // actual bytes before truncation
    pub duration_ms:      u64,
}
```

**Response header filtering (egress proxy strips before returning to Kernel):**
- `Set-Cookie` — stripped (no cookie state in VMs)
- `Authorization` — stripped
- `WWW-Authenticate` — stripped
- All other headers forwarded

**Body truncation:** If `response_bytes > max_response_bytes` (from the matching
`allowed_egress` entry), the body is truncated and `truncated: true` is set. The planner
receives partial content with a clear signal that the response was truncated. It should
reason about what it received and decide whether to issue a more specific request.

---

## 5. Admission Pipeline for `EgressRequest`

The full 13-step admission pipeline runs first (token validation, session state, epoch,
dispatch matrix, budget). Then these egress-specific checks:

### Check E1 — URL Scheme
Must be `https://`. Plaintext `http://` is rejected unconditionally (`FAIL_EGRESS_TLS_REQUIRED`).

### Check E2 — Hostname Against Policy Bundle
`hostname(url) ∈ policy.egress_hosts` with `hostname_pattern` matching.
Failure: `FAIL_EGRESS_HOST_NOT_PERMITTED`.

### Check E3 — URL Prefix Against Task Allowed Egress
`url.starts_with(entry.url_prefix)` for some entry in `task.allowed_egress`.
Failure: `FAIL_EGRESS_URL_NOT_PERMITTED`.

### Check E4 — Method Permitted
`method ∈ entry.methods` for the matching allowed_egress entry.
Failure: `FAIL_EGRESS_METHOD_NOT_PERMITTED`.

### Check E5 — Request Body Size
If body is present: `body.len() ≤ 65536`. Failure: `FAIL_EGRESS_BODY_TOO_LARGE`.

### Check E6 — Per-Task Request Count
```sql
SELECT COUNT(*) FROM egress_audit
 WHERE initiative_id = :initiative_id
   AND task_id = :task_id
   AND url_prefix_entry = :entry_id
   AND status != 'Rejected'
```
If count ≥ `entry.max_requests`: `FAIL_EGRESS_RATE_LIMIT_EXCEEDED`.

### Check E7 — SSRF Prevention (DNS resolution check)
The Kernel (or egress proxy) resolves `hostname(url)` and verifies the resulting IP is
not in any private or loopback range:
- `127.0.0.0/8` (loopback)
- `10.0.0.0/8` (RFC 1918)
- `172.16.0.0/12` (RFC 1918)
- `192.168.0.0/16` (RFC 1918)
- `169.254.0.0/16` (link-local)
- `::1/128` (IPv6 loopback)
- `fc00::/7` (IPv6 unique local)

Failure: `FAIL_EGRESS_SSRF_BLOCKED`. This check **must run at the egress proxy** (not
at the Kernel) because DNS can return different results between resolution time and
connection time (DNS rebinding). The proxy resolves and connects atomically, pinning the
resolved IP for the connection.

### Check E8 — Budget Reservation
EgressRequest costs `egress_admission_units` (default: 10, configurable in policy bundle
per method tier). Checked against shared lane budget. Failure: `FAIL_BUDGET_EXCEEDED`.

---

## 6. The `raxis-egress` Proxy Process

A third host-side process alongside `raxis-kernel` and `raxis-gateway`. It is responsible
for all outbound HTTP calls on behalf of agent sessions.

**Process boundary and why it's separate from `raxis-gateway`:**
The gateway makes provider API calls using provider-specific wire protocols (Anthropic's
streaming SSE format, OpenAI's chunked responses). The egress proxy makes generic HTTP
calls to arbitrary permitted endpoints. Mixing these concerns in one process means that
a bug in the generic HTTP client (redirect handling, content-type parsing, SSRF detection)
affects the inference path and vice versa. Separate processes mean separate restartability,
separate credential scopes, and a narrower blast radius per process.

**INV-EGRESS-01: Egress-Kernel Exclusive Channel**

Identical pattern to INV-GATEWAY-01:
- Listening socket: `$RAXIS_DATA_DIR/egress.sock`, owner `raxis-kernel`, mode `0600`
- `getpeereid()` peer credential check on every accepted connection
- Any non-`raxis-kernel` UID: connection closed immediately +
  `SecurityEventKind::EgressUnauthorizedConnect` emitted
- The Kernel initiates the connection at startup; the egress proxy is a passive listener

**Credential injection:**

The egress proxy holds per-host API tokens in `$RAXIS_DATA_DIR/egress_credentials/`
(owner `raxis-egress`, mode `0600`). When a request arrives, the proxy injects the
matching credential as an `Authorization` header before making the outbound call. The
Kernel and the VM never see the credential.

```toml
# $RAXIS_DATA_DIR/egress_credentials/api.github.com.toml (operator-written)
token_type = "Bearer"
token      = "ghp_..."
```

This allows authenticated GitHub API calls (higher rate limits, private repo access)
without the agent session ever holding a GitHub token.

**Redirect policy:**

Follow redirects: up to 3 hops maximum. Each hop's destination hostname is validated
against the policy bundle's `egress_hosts` list before following. A redirect to an
unpermitted host is blocked (`FAIL_EGRESS_REDIRECT_NOT_PERMITTED`) and the response at
the redirect point is returned instead.

**TLS:**

All connections use TLS 1.2 minimum. Certificate verification is always enforced. No
option to disable. Self-signed certificates are rejected.

**Timeouts:**

- Connection timeout: 5 seconds
- Response header timeout: 10 seconds
- Full response body timeout: 30 seconds

These are not configurable per-task in V2 (global policy values).

---

## 7. Audit Events

Every EgressRequest produces an audit event regardless of success or failure.

```rust
AuditEventKind::EgressRequestAdmitted {
    session_id:           Uuid,
    initiative_id:        Uuid,
    task_id:              TaskId,
    url:                  String,      // full URL as submitted
    method:               HttpMethod,
    status_code:          u16,
    request_bytes:        u64,
    response_bytes:       u64,         // before truncation
    truncated:            bool,
    duration_ms:          u64,
    credential_injected:  bool,        // true if egress_credentials entry matched
    plan_bundle_sha256:   String,      // V2 canonical bundle hash (per plan-bundle-sealing.md §8.2); for legacy V1 initiatives this carries plan_artifact_sha256 instead
    policy_epoch:         u64,
}

AuditEventKind::EgressRequestRejected {
    session_id:    Uuid,
    initiative_id: Uuid,
    task_id:       TaskId,
    url:           String,
    method:        HttpMethod,
    error_code:    String,    // FAIL_EGRESS_HOST_NOT_PERMITTED, etc.
}
```

**Note:** The `url` field in the audit event is the full URL as submitted by the planner.
This means query strings containing sensitive data will appear in the audit log. Planners
should not put credentials in query strings. The system prompt for egress-capable sessions
includes an explicit instruction: "Do not include authentication tokens, API keys, or
passwords in URLs. Use Authorization headers instead. The Kernel will inject credentials
for known hosts automatically."

---

## 8. `RaxisToolExecutor` Integration

Two new tools are exposed to the LLM in sessions with `allowed_egress` entries:

```rust
// Tool: web_fetch
// Arguments: url (string), method (string, default "GET"), headers (object), body (string)
// Returns: { status_code, content_type, body, truncated }

// Tool: web_search_github
// Arguments: query (string), type ("repositories" | "code" | "issues"), page (int)
// Returns: { items: [...], total_count, incomplete_results }
// Internally: GET https://api.github.com/search/<type>?q=<query>&page=<page>
// Only available if https://api.github.com/search/ is in task's allowed_egress
```

`web_fetch` is the general tool; `web_search_github` is a typed convenience wrapper that
constructs the URL from structured arguments, reducing the chance the LLM constructs a
malformed URL.

**Client-side pre-filtering:** `RaxisToolExecutor` only exposes egress tools if the
session's task has `allowed_egress` entries. Sessions without egress entries never see
these tools in their context window. This is defense-in-depth — the Kernel's admission
pipeline is the authoritative gate, but not presenting the tool reduces wasted turns.

---

## 9. Interaction with INV-02B

INV-02B states that VMs have no virtual NIC. This invariant is **not weakened** by
kernel-mediated egress. The VM still has no NIC. The planner submits `EgressRequest`
over VSock (the same channel used for `InferenceRequest`). The response comes back over
VSock. The VM has no knowledge of and no path to the external host — it only knows the
URL it requested and the response it received.

The external host sees connections originating from the RAXIS host machine's IP (via the
`raxis-egress` proxy), not from any individual VM. All VMs' egress traffic is indistinct
at the network level — they all exit through the same proxy process. This also means:
- The external host cannot correlate request patterns to individual agent sessions
- IP-based rate limiting at the external host applies to the entire RAXIS deployment,
  not per-session

---

## 10. Alternatives Considered

**Alt A — Give selected tasks a restricted NIC via network namespace filtering.**
Rejected. Network namespaces with iptables allowlisting require host kernel configuration
that is fragile, hard to audit, and does not compose with the Kernel's admission pipeline.
A misconfigured iptables rule silently permits or silently blocks traffic with no
RAXIS audit event. The proxy pattern produces a complete audit record of every request.

**Alt B — Allow egress only via a SOCKS proxy injected into the VM's environment.**
Rejected. The SOCKS proxy would need to be exposed to the VM over a network interface,
which requires a NIC (violating INV-02B) or a VirtioFS-mounted UNIX socket (which the
planner binary could connect to directly, bypassing the Kernel). The VSock + intent
pattern is the only channel that goes through the Kernel's admission pipeline.

**Alt C — Allow only pre-fetched content: operator downloads content before the initiative starts and mounts it read-only.**
Useful for known documentation but cannot support search (the query is not known at
plan-signing time) or content that changes between plan signing and execution. Applicable
as a complementary pattern (operator-provided reference docs) but not a replacement.

**Alt D — Allow POST and other mutating methods without restriction.**
Rejected for V2. POST to an external API from an agent session creates state outside
the RAXIS audit boundary. V2 permits GET by default; POST requires explicit
`methods = ["GET", "POST"]` in the plan's `allowed_egress` entry and must be
justified in the plan's context description. A future V3 analysis may introduce
stronger constraints for mutating egress (e.g., escalation-class approval for POST).

---

## 11. Implementation Checklist

- [ ] Add `EgressRequest` and `EgressResponse` to `crates/types/src/operator_wire.rs`
- [ ] Add `HttpMethod` enum to types
- [ ] Add `[[egress_hosts]]` section to `PolicyBundle` struct in `crates/policy/src/bundle.rs`
- [ ] Add `[[tasks.allowed_egress]]` to `TaskManifest` struct in plan types
- [ ] Add `egress_audit` table to DDL:
      `(id, initiative_id, task_id, session_id, url, method, status_code,
        request_bytes, response_bytes, truncated, duration_ms, created_at)`
- [ ] Implement `handle_egress_request` in `kernel/src/handlers/egress.rs` (new file)
      with checks E1–E8 in order
- [ ] Add `FAIL_EGRESS_*` variants to `KernelError`
- [ ] Create `raxis-egress` binary crate at `egress/src/main.rs`
- [ ] Implement INV-EGRESS-01: `egress.sock` permissions + `getpeereid()` check
- [ ] Implement SSRF prevention (private range rejection) in egress proxy
- [ ] Implement redirect following with per-hop hostname validation (max 3 hops)
- [ ] Implement TLS 1.2+ with certificate verification (no disable option)
- [ ] Implement per-host credential injection from `$RAXIS_DATA_DIR/egress_credentials/`
- [ ] Implement response body truncation with `truncated` flag
- [ ] Implement response header filtering (strip Set-Cookie, Authorization, WWW-Authenticate)
- [ ] Add `EgressRequestAdmitted` and `EgressRequestRejected` audit events
- [ ] Add `web_fetch` tool to `RaxisToolExecutor` (conditional on `allowed_egress` presence)
- [ ] Add `web_search_github` convenience tool to `RaxisToolExecutor`
- [ ] Add client-side egress tool suppression in `PermissionPolicy` for sessions without `allowed_egress`
- [ ] Add egress system prompt warning about credentials in URLs
- [ ] Update `approve_plan` shift-left checks:
      - Check that each `task.allowed_egress[].url_prefix` hostname is in `policy.egress_hosts`
      - Check that each `task.allowed_egress[].methods` is a subset of `policy.egress_hosts[].allowed_methods`
      (plan cannot grant a method the policy bundle doesn't permit for that host)
- [ ] Tests: GET admitted, POST without plan opt-in rejected, private IP SSRF blocked,
      redirect to unpermitted host blocked, max_requests ceiling, body truncation,
      credential injection (token appears in outbound call, not in audit URL field),
      plan entry missing → FAIL, policy bundle entry missing → FAIL,
      INV-EGRESS-01 unauthorized connect rejected

// Client-side derivation of a one-line operator summary for an
// audit-event payload. Used by the Notifications page (and any
// future surface that wants to render a notification row densely)
// as a graceful fallback when the kernel-side
// `notifications::summary::render` returns its
// `<EventKind> (no summary)` placeholder for a kind it doesn't yet
// hand-format.
//
// Why this lives in the FE
//
//   The kernel summary registry is hand-maintained and trails
//   newly-added audit-event variants — the V2 service-evidence
//   chain (`MongoCommandExecuted`, `DatabaseQueryCompleted`,
//   `CredentialProxy*`, …) and V3 cloud-credential forwarding
//   variants are correctly emitted into the audit chain and
//   notification table, but the kernel formatter still returns the
//   `(no summary)` placeholder for them. From an operator's POV
//   that produces a Notifications view full of opaque rows where
//   every line reads `<EventKind> (no summary)` even though the
//   payload carries plenty of useful detail.
//
//   Rather than block on a kernel-side patch (and rebase-conflict
//   the live-e2e fix-loop worker), we compute a useful one-liner
//   on the FE from the payload we already render below the badge.
//   The kernel remains the source of truth: any kind it DOES
//   summarise (`EscalationApproved`, `PolicyEpochAdvanced`, etc.)
//   keeps the kernel-rendered string verbatim, since
//   `isPlaceholderSummary` only triggers on the placeholder.
//
// Schema
//
//   `payload` is typed `unknown` end-to-end. Every accessor is
//   guarded so a payload missing fields (or carrying an unexpected
//   shape) produces `null` rather than throwing — the caller then
//   falls back to the original (placeholder) summary so the row is
//   never empty.

import { fmtBytes, fmtCount, shortSha } from "@/lib/format";

const PLACEHOLDER_SUFFIX = "(no summary)";

export function isPlaceholderSummary(
  summary: string | null | undefined,
): boolean {
  if (!summary) return true;
  // Kernel emits exactly `<EventKind> (no summary)` for kinds it
  // doesn't hand-format; tolerate trailing whitespace.
  return summary.trimEnd().endsWith(PLACEHOLDER_SUFFIX);
}

// Try to derive a richer one-line summary from an audit-event
// payload. Returns `null` if the kind is unrecognised or the
// payload is missing the fields needed to render a meaningful line
// (caller should keep the original placeholder in that case).
export function summarizeNotificationPayload(
  eventKind: string,
  payload: unknown,
): string | null {
  if (!isObject(payload)) return null;

  switch (eventKind) {
    case "CredentialProxyStarted": {
      const proxy = str(payload, "proxy_type");
      const cred = str(payload, "credential_name");
      const addr = str(payload, "addr");
      if (proxy && cred) {
        return addr
          ? `${proxy} proxy "${cred}" started on ${addr}`
          : `${proxy} proxy "${cred}" started`;
      }
      return null;
    }
    case "CredentialProxyUpstreamConnected": {
      const proxy = str(payload, "proxy_type");
      const cred = str(payload, "credential_name");
      const host = str(payload, "upstream_host");
      const port = num(payload, "upstream_port");
      const tls = bool(payload, "tls");
      const ms = num(payload, "handshake_ms");
      if (!proxy || !cred) return null;
      const upstream = host && port != null ? `${host}:${port}` : "upstream";
      const tlsBit = tls ? " over TLS" : "";
      const msBit = ms != null ? ` in ${ms} ms` : "";
      return `${proxy} proxy "${cred}" connected to ${upstream}${tlsBit}${msBit}`;
    }
    case "CredentialAccessed": {
      const name = str(payload, "name");
      const consumerKind = str(payload, "consumer_kind");
      const consumerId = shortIdLike(str(payload, "consumer_id"));
      const backend = str(payload, "backend_kind");
      const success = bool(payload, "success");
      if (!name) return null;
      const who =
        consumerKind && consumerId
          ? `${consumerKind} ${consumerId}`
          : consumerKind || "consumer";
      const backendBit = backend ? ` (${backend} backend)` : "";
      const verb = success === false ? "denied access to" : "accessed";
      return `${who} ${verb} credential "${name}"${backendBit}`;
    }
    case "DatabaseQueryExecuted": {
      const proxy = str(payload, "proxy_type");
      const cred = str(payload, "credential_name");
      const op = str(payload, "operation");
      const blocked = bool(payload, "blocked");
      const sha = shortSha(str(payload, "sql_sha256") ?? undefined);
      if (!cred) return null;
      const proxyBit = proxy ? `${proxy} ` : "";
      const opBit = op ? `${op} ` : "";
      const blockedBit = blocked ? " — BLOCKED" : "";
      return `${proxyBit}"${cred}" ${opBit}sha=${sha}${blockedBit}`.trim();
    }
    case "DatabaseQueryCompleted": {
      const proxy = str(payload, "proxy_type");
      const cred = str(payload, "credential_name");
      const rows = num(payload, "rows_returned");
      const bytes = num(payload, "bytes_returned");
      const ms = num(payload, "duration_ms");
      const err = str(payload, "upstream_error");
      if (!cred) return null;
      const proxyBit = proxy ? `${proxy} ` : "";
      if (err) {
        return `${proxyBit}"${cred}" query FAILED: ${err}`;
      }
      const rowsBit = rows != null ? `${fmtCount(rows)} rows` : "rows";
      const bytesBit = bytes != null ? `, ${fmtBytes(bytes)}` : "";
      const msBit = ms != null ? ` in ${ms} ms` : "";
      return `${proxyBit}"${cred}" returned ${rowsBit}${bytesBit}${msBit}`;
    }
    case "MongoCommandExecuted": {
      const cred = str(payload, "credential_name");
      const cmd = str(payload, "command");
      const blocked = bool(payload, "blocked");
      if (!cred || !cmd) return null;
      const blockedBit = blocked ? " — BLOCKED" : "";
      return `mongodb "${cred}" ran ${cmd}${blockedBit}`;
    }
    case "SessionVmSpawned": {
      const sid = shortIdLike(str(payload, "session_id"));
      const task = str(payload, "task_id");
      const backend = str(payload, "backend_id");
      const tier = str(payload, "egress_tier");
      const proxies = num(payload, "credential_proxies");
      const bits: string[] = [];
      if (backend) bits.push(`backend=${backend}`);
      if (tier) bits.push(`egress=${tier}`);
      if (proxies != null && proxies > 0) {
        bits.push(`${proxies} cred ${proxies === 1 ? "proxy" : "proxies"}`);
      }
      const tail = bits.length ? ` (${bits.join(", ")})` : "";
      if (sid && task) return `Session ${sid} VM spawned for ${task}${tail}`;
      if (sid) return `Session ${sid} VM spawned${tail}`;
      return null;
    }
    case "SessionCreated": {
      const sid = shortIdLike(str(payload, "session_id"));
      const role = str(payload, "role") ?? str(payload, "session_agent_type");
      const init = shortIdLike(str(payload, "initiative_id"));
      if (!sid) return null;
      const roleBit = role ? ` (${role})` : "";
      const initBit = init ? ` for initiative ${init}` : "";
      return `Session ${sid} created${roleBit}${initBit}`;
    }
    case "GatewaySpawned": {
      const attempt = num(payload, "attempt");
      const tok = str(payload, "token_prefix");
      const tail = [
        attempt != null ? `attempt ${attempt}` : null,
        tok ? `token ${tok}…` : null,
      ]
        .filter(Boolean)
        .join(", ");
      return tail ? `Gateway spawned (${tail})` : "Gateway spawned";
    }
    case "InitiativeCreated": {
      const init = shortIdLike(str(payload, "initiative_id"));
      const planHash = shortSha(str(payload, "plan_hash") ?? undefined);
      const signedBy = str(payload, "signed_by");
      if (!init) return null;
      const signedBit = signedBy ? `, signed by ${signedBy.slice(0, 8)}` : "";
      return `Initiative ${init} created (plan ${planHash})${signedBit}`;
    }
    case "PlanApproved": {
      const init = shortIdLike(str(payload, "initiative_id"));
      const tasks = num(payload, "task_count");
      const initBit = init ? `${init} ` : "";
      if (tasks != null) {
        return `Plan approved for ${initBit}(${tasks} task${tasks === 1 ? "" : "s"})`.trim();
      }
      return init ? `Plan approved for ${init}` : "Plan approved";
    }
    case "DefaultProviderEgressApplied": {
      const provider = str(payload, "provider");
      const session = shortIdLike(str(payload, "session_id"));
      if (provider && session) {
        return `Default ${provider} egress applied to session ${session}`;
      }
      return provider ? `Default ${provider} egress applied` : null;
    }
    case "CloudCredentialForwarded":
    case "CloudCredentialRefreshed":
    case "CloudCredentialCacheHit": {
      const provider = str(payload, "provider");
      const cred = str(payload, "credential_name");
      const session = shortIdLike(str(payload, "session_id"));
      if (!provider) return null;
      const action =
        eventKind === "CloudCredentialForwarded"
          ? "forwarded"
          : eventKind === "CloudCredentialRefreshed"
            ? "refreshed"
            : "cache hit";
      const credBit = cred ? ` "${cred}"` : "";
      const sessionBit = session ? ` to session ${session}` : "";
      return `${provider} credential${credBit} ${action}${sessionBit}`;
    }
    case "SessionEgressStallDetected": {
      const session = shortIdLike(str(payload, "session_id"));
      const ms = num(payload, "stall_ms") ?? num(payload, "duration_ms");
      const chokepoint = str(payload, "chokepoint");
      const tail = [
        chokepoint ? `chokepoint=${chokepoint}` : null,
        ms != null ? `${ms} ms` : null,
      ]
        .filter(Boolean)
        .join(", ");
      if (session) {
        return tail
          ? `Egress STALLED on session ${session} (${tail})`
          : `Egress STALLED on session ${session}`;
      }
      return tail ? `Egress STALLED (${tail})` : null;
    }
  }
  return null;
}

// Convenience: pick the best summary string for a notification row,
// preferring the kernel's hand-rendered line and falling back to the
// payload-derived one only when the kernel emitted its placeholder.
export function notificationDisplaySummary(
  summary: string | null | undefined,
  eventKind: string,
  payload: unknown,
): string {
  if (!isPlaceholderSummary(summary)) return summary as string;
  const derived = summarizeNotificationPayload(eventKind, payload);
  if (derived) return derived;
  // Last-ditch fallback: keep whatever the backend gave us so the
  // row never renders empty (the placeholder still tells the
  // operator "this kind doesn't have a summary yet" which is true).
  // Promote an empty / nullish backend summary to the kind name so
  // the operator at least sees what the event was.
  if (summary && summary.length > 0) return summary;
  return eventKind;
}

// ---- internal type guards ----

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(p: Record<string, unknown>, key: string): string | null {
  const v = p[key];
  return typeof v === "string" && v.length > 0 ? v : null;
}

function num(p: Record<string, unknown>, key: string): number | null {
  const v = p[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function bool(p: Record<string, unknown>, key: string): boolean | null {
  const v = p[key];
  return typeof v === "boolean" ? v : null;
}

// Render the leading 8 chars of a UUID-shaped string. Returns
// null when the input is null / empty so callers can elide the
// section cleanly.
function shortIdLike(v: string | null): string | null {
  if (!v) return null;
  return v.length >= 8 ? v.slice(0, 8) : v;
}

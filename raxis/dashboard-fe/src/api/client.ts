// Thin typed fetch wrapper for the Raxis dashboard HTTP API.
//
// Design notes:
//   * One `apiFetch` entrypoint so JWT injection, error
//     normalization, and 401 → /login redirect live in one place.
//   * No "default value" fallbacks. A 404 / parse error throws an
//     `ApiError`; React Query surfaces it to the calling page so
//     the operator sees a real error instead of silently empty
//     state.
//   * Compatible with both the production deployment (FE served
//     from the same origin as the API by `tower_http::ServeDir`)
//     and the dev server (Vite proxies `/api/*` to the kernel).

import type {
  AuditEntryView,
  ChainStatusResponse,
  ChallengeResponse,
  CredentialListResponse,
  CredentialReveal,
  DagView,
  EscalationView,
  HealthSnapshot,
  InitiativeListEntry,
  InitiativePlanView,
  InitiativeView,
  KernelLifecycleResponse,
  MarkAllReadResponse,
  MarkReadResponse,
  NotificationView,
  GateStatsResponse,
  OrchestratorGapsResponse,
  PolicyAdvancement,
  PolicySnapshotView,
  RecentSessionEntry,
  SessionCaptureView,
  SessionView,
  SubsystemHealthResponse,
  TaskLlmTurnView,
  TaskView,
  WorktreeSnapshotView,
  UnreadCountResponse,
  UpdatePolicyResponse,
  VerifyResponse,
  WorktreeDetail,
  WorktreeDiff,
  WorktreeFile,
  WorktreeListEntry,
  WorktreeLogEntry,
  WorktreeTree,
} from "@/types/api";

import { getStoredToken, clearStoredToken } from "@/lib/auth-store";

/// Dashboard API error normalized from the JSON envelope.
export class ApiError extends Error {
  /// HTTP status (e.g. 401, 403, 404, 500).
  public readonly status: number;
  /// Stable backend code (`FAIL_DASHBOARD_*`).
  public readonly code: string;
  /// Backend-provided short message (already operator-safe).
  public readonly detail: string;

  constructor(status: number, code: string, detail: string) {
    super(`${code} (${status}): ${detail}`);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }

  /// `true` when the error means the operator must re-authenticate.
  public isAuthExpired(): boolean {
    return (
      this.status === 401 &&
      (this.code === "FAIL_DASHBOARD_AUTH_JWT" ||
        this.code === "FAIL_DASHBOARD_AUTH_JWT_REVOKED" ||
        this.code === "FAIL_DASHBOARD_AUTH_MISSING")
    );
  }
}

/// Endpoints whose response body is plain text (not JSON).
const TEXT_ENDPOINTS = new Set<string>(["/api/policy/toml"]);

interface FetchOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  /// When true, do NOT redirect on 401 (used by the auth flow
  /// itself so a wrong-key login surfaces the error in-page).
  skipAuthRedirect?: boolean;
  /// Accept text body instead of JSON.
  asText?: boolean;
  /// Per-call abort signal — used by React Query.
  signal?: AbortSignal;
}

async function apiFetch<T>(path: string, opts: FetchOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: opts.asText || TEXT_ENDPOINTS.has(path)
      ? "text/plain, application/json"
      : "application/json",
  };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const token = getStoredToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const fetchInit: RequestInit = {
    method: opts.method ?? "GET",
    headers,
    credentials: "same-origin",
  };
  if (opts.body !== undefined) {
    fetchInit.body = JSON.stringify(opts.body);
  }
  if (opts.signal) {
    fetchInit.signal = opts.signal;
  }

  let res: Response;
  try {
    res = await fetch(path, fetchInit);
  } catch (e) {
    // Network-level failure (DNS, connection refused, …). The
    // dashboard always runs on the same host as the kernel so
    // this usually means the kernel is down.
    throw new ApiError(
      0,
      "FAIL_DASHBOARD_NETWORK",
      e instanceof Error ? e.message : "network error",
    );
  }

  if (!res.ok) {
    let body: { code?: string; message?: string } = {};
    try {
      body = await res.json();
    } catch {
      // Backend returned non-JSON for an error (shouldn't happen
      // for known endpoints, but the dashboard's middleware
      // may inject a plain 413 on oversized requests). Surface
      // a generic code so the UI can still display something.
    }
    const err = new ApiError(
      res.status,
      body.code ?? `HTTP_${res.status}`,
      body.message ?? res.statusText,
    );
    if (!opts.skipAuthRedirect && err.isAuthExpired()) {
      clearStoredToken();
      // History API redirect — React Router picks this up via
      // its route config (the AppRouter listens to `popstate`).
      if (typeof window !== "undefined" && window.location.pathname !== "/login") {
        const next = encodeURIComponent(
          window.location.pathname + window.location.search,
        );
        window.location.assign(`/login?next=${next}`);
      }
    }
    throw err;
  }

  if (opts.asText || TEXT_ENDPOINTS.has(path)) {
    return (await res.text()) as unknown as T;
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const authApi = {
  challenge: (signal?: AbortSignal): Promise<ChallengeResponse> =>
    apiFetch<ChallengeResponse>("/api/auth/challenge", {
      skipAuthRedirect: true,
      ...(signal ? { signal } : {}),
    }),
  verify: (
    body: { challenge: string; signature: string; public_key: string },
  ): Promise<VerifyResponse> =>
    apiFetch<VerifyResponse>("/api/auth/verify", {
      method: "POST",
      body,
      skipAuthRedirect: true,
    }),
  logout: (token: string): Promise<{ revoked_at: number; operator_id: string }> =>
    apiFetch("/api/auth/logout", {
      method: "POST",
      body: { token },
      skipAuthRedirect: true,
    }),
};

// ---------------------------------------------------------------------------
// Read endpoints
// ---------------------------------------------------------------------------

export const dashboardApi = {
  health: (signal?: AbortSignal): Promise<HealthSnapshot> =>
    apiFetch<HealthSnapshot>("/api/health", signal ? { signal } : {}),

  // Per-subsystem health cards for the Health tab. The kernel
  // owns every verdict — the FE only renders them.
  subsystemHealth: (
    signal?: AbortSignal,
  ): Promise<SubsystemHealthResponse> =>
    apiFetch<SubsystemHealthResponse>(
      "/api/health/subsystems",
      signal ? { signal } : {},
    ),

  // Supervisor sentinel snapshot for the kernel-lifecycle banner
  // (`self-healing-supervisor.md §5.2`). Polled every 5 s by
  // `<KernelLifecycleBanner>` while the operator is on any page;
  // the kernel's handler is best-effort (returns a synthetic
  // `Healthy { fresh: true }` envelope when no sentinel file
  // exists, so an operator who never opted into the supervisor
  // sees no banner at all).
  kernelLifecycle: (
    signal?: AbortSignal,
  ): Promise<KernelLifecycleResponse> =>
    apiFetch<KernelLifecycleResponse>(
      "/api/health/kernel-lifecycle",
      signal ? { signal } : {},
    ),

  initiatives: {
    list: (
      params: { state?: string; limit?: number } = {},
      signal?: AbortSignal,
    ): Promise<InitiativeListEntry[]> => {
      const qs = new URLSearchParams();
      if (params.state) qs.set("state", params.state);
      if (params.limit) qs.set("limit", String(params.limit));
      const suffix = qs.toString() ? `?${qs}` : "";
      return apiFetch<InitiativeListEntry[]>(
        `/api/initiatives${suffix}`,
        signal ? { signal } : {},
      );
    },
    get: (id: string, signal?: AbortSignal): Promise<InitiativeView> =>
      apiFetch<InitiativeView>(`/api/initiatives/${encodeURIComponent(id)}`, signal ? { signal } : {}),
    dag: (id: string, signal?: AbortSignal): Promise<DagView> =>
      apiFetch<DagView>(`/api/initiatives/${encodeURIComponent(id)}/dag`, signal ? { signal } : {}),
    tasks: (id: string, signal?: AbortSignal): Promise<TaskView[]> =>
      apiFetch<TaskView[]>(`/api/initiatives/${encodeURIComponent(id)}/tasks`, signal ? { signal } : {}),
    /// `GET /api/initiatives/:id/plan` — original submitted
    /// plan.toml for the initiative. The kernel returns a
    /// `Cache-Control: private, max-age=60` header for approved
    /// plans (immutable post-approval); pending plans are
    /// served as `no-store`. The FE's React Query staleTime
    /// matches the 60s cache to avoid double-caching.
    plan: (id: string, signal?: AbortSignal): Promise<InitiativePlanView> =>
      apiFetch<InitiativePlanView>(
        `/api/initiatives/${encodeURIComponent(id)}/plan`,
        signal ? { signal } : {},
      ),
    /// `GET /api/initiatives/:id/credentials` — metadata-only
    /// listing of every credential the initiative's plan
    /// declares. NEVER carries plaintext (the wire shape has
    /// no `plaintext` field; reveal goes through the disjoint
    /// `revealCredential` POST below). Read-role suffices to
    /// list; reveal additionally requires admin.
    credentials: (
      id: string,
      signal?: AbortSignal,
    ): Promise<CredentialListResponse> =>
      apiFetch<CredentialListResponse>(
        `/api/initiatives/${encodeURIComponent(id)}/credentials`,
        signal ? { signal } : {},
      ),
    /// `POST /api/initiatives/:id/credentials/:name/reveal` —
    /// fetches the plaintext for one credential. Admin-role-
    /// gated, audited before the response leaves the kernel
    /// (`INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01`), and
    /// rate-limited per operator. Body is empty by spec
    /// (the path carries the credential selector); the FE
    /// MUST treat the response's `expires_at_unix` as the
    /// hard auto-hide deadline.
    revealCredential: (
      id: string,
      name: string,
    ): Promise<CredentialReveal> =>
      apiFetch<CredentialReveal>(
        `/api/initiatives/${encodeURIComponent(id)}/credentials/${encodeURIComponent(name)}/reveal`,
        { method: "POST" },
      ),
  },

  /// System-wide credential viewer (admin-only — the listing
  /// itself is gated so a `read` operator cannot enumerate
  /// the providers the kernel is bound to). The Anthropic
  /// API key surfaces here under
  /// `INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01`:
  /// reveals emit a `Critical`-severity notification and
  /// auto-hide on a 15-second deadline (vs the 30-second
  /// per-initiative default).
  systemCredentials: {
    list: (signal?: AbortSignal): Promise<CredentialListResponse> =>
      apiFetch<CredentialListResponse>(
        `/api/system/credentials`,
        signal ? { signal } : {},
      ),
    reveal: (name: string): Promise<CredentialReveal> =>
      apiFetch<CredentialReveal>(
        `/api/system/credentials/${encodeURIComponent(name)}/reveal`,
        { method: "POST" },
      ),
  },

  tasks: {
    get: (id: string, signal?: AbortSignal): Promise<TaskView> =>
      apiFetch<TaskView>(`/api/tasks/${encodeURIComponent(id)}`, signal ? { signal } : {}),
    outputs: (id: string, signal?: AbortSignal): Promise<TaskView["structured_outputs"]> =>
      apiFetch(`/api/tasks/${encodeURIComponent(id)}/outputs`, signal ? { signal } : {}),
    /// `GET /api/tasks/:task_id/llm-turns?n=…` — tail of LLM
    /// turns the kernel-side tap recorded for this task.
    /// Powers `<TaskLlmTurns>` on TaskDetail. The endpoint is
    /// always ndjson-tail style; current default `n=100`.
    llmTurns: (
      id: string,
      n: number = 100,
      signal?: AbortSignal,
    ): Promise<TaskLlmTurnView[]> => {
      const qs = new URLSearchParams();
      qs.set("n", String(n));
      return apiFetch<TaskLlmTurnView[]>(
        `/api/tasks/${encodeURIComponent(id)}/llm-turns?${qs}`,
        signal ? { signal } : {},
      );
    },
    /// iter68 — `GET /api/tasks/:task_id/worktree-snapshots`.
    /// Returns every content-addressed snapshot the kernel
    /// captured for the task, newest first.
    /// `specs/v3/worktree-snapshots.md`.
    worktreeSnapshots: (
      id: string,
      signal?: AbortSignal,
    ): Promise<WorktreeSnapshotView[]> =>
      apiFetch<WorktreeSnapshotView[]>(
        `/api/tasks/${encodeURIComponent(id)}/worktree-snapshots`,
        signal ? { signal } : {},
      ),
  },

  /// iter68 — top-level worktree-snapshot detail + blob streaming.
  /// Used by both `<TaskWorktreeSnapshots>` (drill into one
  /// snapshot) and the cross-task Worktrees view.
  worktreeSnapshots: {
    /// Fetch one snapshot row by id.
    get: (
      snapshotId: string,
      signal?: AbortSignal,
    ): Promise<WorktreeSnapshotView> =>
      apiFetch<WorktreeSnapshotView>(
        `/api/worktree-snapshots/${encodeURIComponent(snapshotId)}`,
        signal ? { signal } : {},
      ),
    /// Stream a content-addressed body blob.
    /// `kind ∈ {"diff","log","tree","porcelain"}`. Returns the
    /// raw body bytes as a `string`; the FE renders them in a
    /// `<pre>` so the consumer can use `text/plain`-style
    /// formatting without re-decoding.
    blobUrl: (
      snapshotId: string,
      kind: "diff" | "log" | "tree" | "porcelain",
    ): string =>
      `/api/worktree-snapshots/${encodeURIComponent(snapshotId)}/blob/${kind}`,
    fetchBlob: async (
      snapshotId: string,
      kind: "diff" | "log" | "tree" | "porcelain",
      signal?: AbortSignal,
    ): Promise<string> => {
      const url = `/api/worktree-snapshots/${encodeURIComponent(snapshotId)}/blob/${kind}`;
      const res = await fetch(url, signal ? { signal, credentials: "include" } : { credentials: "include" });
      if (!res.ok) {
        throw new Error(`worktree-snapshot blob ${kind} fetch failed: ${res.status}`);
      }
      return res.text();
    },
  },

  sessions: {
    list: (
      paramsOrLimit:
        | number
        | { limit?: number; initiative_id?: string }
        = 50,
      signal?: AbortSignal,
    ): Promise<SessionView[]> => {
      const params =
        typeof paramsOrLimit === "number"
          ? { limit: paramsOrLimit }
          : paramsOrLimit;
      const qs = new URLSearchParams();
      qs.set("limit", String(params.limit ?? 50));
      if (params.initiative_id) qs.set("initiative_id", params.initiative_id);
      return apiFetch<SessionView[]>(
        `/api/sessions?${qs}`,
        signal ? { signal } : {},
      );
    },
    get: (id: string, signal?: AbortSignal): Promise<SessionView> =>
      apiFetch<SessionView>(`/api/sessions/${encodeURIComponent(id)}`, signal ? { signal } : {}),
    // `GET /api/sessions/:id/capture?limit=N` —
    // INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01.
    // Backs the SessionDetail page's "Post-mortem" tab — records
    // remain reachable after the session terminates.
    capture: (
      id: string,
      params: { limit?: number } = {},
      signal?: AbortSignal,
    ): Promise<SessionCaptureView[]> => {
      const qs = new URLSearchParams();
      if (params.limit !== undefined) qs.set("limit", String(params.limit));
      const suffix = qs.toString() ? `?${qs}` : "";
      return apiFetch<SessionCaptureView[]>(
        `/api/sessions/${encodeURIComponent(id)}/capture${suffix}`,
        signal ? { signal } : {},
      );
    },
    /// `GET /api/recent-sessions?limit=…` — bounded ring of
    /// the last N sessions regardless of their `revoked` flag,
    /// each row carrying its final `LifecycleAnnotation` so
    /// the FE renders self-exit vs operator-revoke without a
    /// per-row drill-down.
    recent: (
      limit: number = 50,
      signal?: AbortSignal,
    ): Promise<RecentSessionEntry[]> => {
      const qs = new URLSearchParams();
      qs.set("limit", String(limit));
      return apiFetch<RecentSessionEntry[]>(
        `/api/recent-sessions?${qs}`,
        signal ? { signal } : {},
      );
    },
  },

  /// `GET /api/orchestrator-gaps` — every
  /// `subtask_activations` row stuck in `PendingActivation`
  /// past the gap threshold whose predecessors all completed.
  /// Powers the home-view "Warnings" pane.
  orchestratorGaps: (
    signal?: AbortSignal,
  ): Promise<OrchestratorGapsResponse> =>
    apiFetch<OrchestratorGapsResponse>(
      "/api/orchestrator-gaps",
      signal ? { signal } : {},
    ),

  gates: {
    /// `GET /api/gates/stats` — per-gate rollup of witness
    /// outcomes + cumulative fixup-loop counter. Powers the
    /// Gates page. INV-DASHBOARD-GATE-STATS-PER-GATE-ROLLUP-01.
    stats: (signal?: AbortSignal): Promise<GateStatsResponse> =>
      apiFetch<GateStatsResponse>(
        "/api/gates/stats",
        signal ? { signal } : {},
      ),
  },

  escalations: {
    list: (signal?: AbortSignal): Promise<EscalationView[]> =>
      apiFetch<EscalationView[]>("/api/escalations", signal ? { signal } : {}),
    get: (id: string, signal?: AbortSignal): Promise<EscalationView> =>
      apiFetch<EscalationView>(`/api/escalations/${encodeURIComponent(id)}`, signal ? { signal } : {}),
  },

  audit: {
    list: (
      params: { cursor?: number; initiative_id?: string; limit?: number } = {},
      signal?: AbortSignal,
    ): Promise<AuditEntryView[]> => {
      const qs = new URLSearchParams();
      if (params.cursor !== undefined) qs.set("cursor_seq", String(params.cursor));
      if (params.initiative_id) qs.set("initiative_id", params.initiative_id);
      if (params.limit !== undefined) qs.set("limit", String(params.limit));
      const suffix = qs.toString() ? `?${qs}` : "";
      return apiFetch<AuditEntryView[]>(`/api/audit${suffix}`, signal ? { signal } : {});
    },
    // Curated recent-activity feed for the Overview widget.
    // The backend filters the chain to state-affecting events
    // only (allow-list lives server-side in
    // `data::recent_activity_filter`) so the FE never makes a
    // policy call about what's "noise". See
    // `specs/v2/dashboard-operator-action-audit-coverage.md
    // §signal-vs-noise`.
    recent: (
      params: { limit?: number } = {},
      signal?: AbortSignal,
    ): Promise<AuditEntryView[]> => {
      const qs = new URLSearchParams();
      if (params.limit !== undefined) qs.set("limit", String(params.limit));
      const suffix = qs.toString() ? `?${qs}` : "";
      return apiFetch<AuditEntryView[]>(
        `/api/audit/recent${suffix}`,
        signal ? { signal } : {},
      );
    },
    // Chain-integrity verdict surface — `INV-AUDIT-DASHBOARD-01`.
    // The kernel is the single source of truth; the FE renders
    // the kernel's verdict and never re-implements verification.
    // `reverify: true` is the explicit "Re-verify chain" button
    // path; idle page mounts pass `reverify: false` (or omit it)
    // so the data layer can short-circuit on its 30 s cache.
    chainStatus: (
      params: { reverify?: boolean } = {},
      signal?: AbortSignal,
    ): Promise<ChainStatusResponse> => {
      const qs = new URLSearchParams();
      if (params.reverify) qs.set("reverify", "true");
      const suffix = qs.toString() ? `?${qs}` : "";
      return apiFetch<ChainStatusResponse>(
        `/api/audit/chain-status${suffix}`,
        signal ? { signal } : {},
      );
    },
  },

  inbox: (signal?: AbortSignal): Promise<AuditEntryView[]> =>
    apiFetch<AuditEntryView[]>("/api/inbox", signal ? { signal } : {}),

  notifications: {
    list: (
      params: { unread_only?: boolean; initiative_id?: string; limit?: number } = {},
      signal?: AbortSignal,
    ): Promise<NotificationView[]> => {
      const qs = new URLSearchParams();
      if (params.unread_only) qs.set("unread_only", "true");
      if (params.initiative_id) qs.set("initiative_id", params.initiative_id);
      if (params.limit !== undefined) qs.set("limit", String(params.limit));
      const suffix = qs.toString() ? `?${qs}` : "";
      return apiFetch<NotificationView[]>(
        `/api/notifications${suffix}`,
        signal ? { signal } : {},
      );
    },
    unreadCount: (signal?: AbortSignal): Promise<UnreadCountResponse> =>
      apiFetch<UnreadCountResponse>("/api/notifications/unread-count", signal ? { signal } : {}),
    markRead: (id: string): Promise<MarkReadResponse> =>
      apiFetch<MarkReadResponse>(
        `/api/notifications/${encodeURIComponent(id)}/read`,
        { method: "PATCH" },
      ),
    markAllRead: (): Promise<MarkAllReadResponse> =>
      apiFetch<MarkAllReadResponse>(
        "/api/notifications/mark-all-read",
        { method: "POST" },
      ),
  },

  policy: {
    snapshot: (signal?: AbortSignal): Promise<PolicySnapshotView> =>
      apiFetch<PolicySnapshotView>("/api/policy", signal ? { signal } : {}),
    rawToml: (signal?: AbortSignal): Promise<string> =>
      apiFetch<string>("/api/policy/toml", { asText: true, ...(signal ? { signal } : {}) }),
    update: (
      body: { toml: string; signature_b64: string },
    ): Promise<PolicyAdvancement> =>
      apiFetch<UpdatePolicyResponse>("/api/policy/toml", {
        method: "PUT",
        body,
      }).then((r) => r.advancement),
  },

  git: {
    list: (signal?: AbortSignal): Promise<WorktreeListEntry[]> =>
      apiFetch<WorktreeListEntry[]>("/api/git/worktrees", signal ? { signal } : {}),
    get: (name: string, signal?: AbortSignal): Promise<WorktreeDetail> =>
      apiFetch<WorktreeDetail>(`/api/git/worktrees/${encodeURIComponent(name)}`, signal ? { signal } : {}),
    log: (name: string, limit = 50, signal?: AbortSignal): Promise<WorktreeLogEntry[]> =>
      apiFetch<WorktreeLogEntry[]>(
        `/api/git/worktrees/${encodeURIComponent(name)}/log?limit=${limit}`,
        signal ? { signal } : {},
      ),
    diffDefault: (name: string, signal?: AbortSignal): Promise<WorktreeDiff> =>
      apiFetch<WorktreeDiff>(`/api/git/worktrees/${encodeURIComponent(name)}/diff`, signal ? { signal } : {}),
    diffRange: (name: string, from: string, to: string, signal?: AbortSignal): Promise<WorktreeDiff> =>
      // Each SHA is URL-encoded individually so a stray
      // non-hex char (the backend already 400s these, but
      // defence-in-depth on the client side keeps the URL
      // well-formed and avoids accidentally splitting on a
      // literal "/" if a caller ever sneaks a non-SHA in).
      apiFetch<WorktreeDiff>(
        `/api/git/worktrees/${encodeURIComponent(name)}/diff/${encodeURIComponent(
          from,
        )}..${encodeURIComponent(to)}`,
        signal ? { signal } : {},
      ),
    /// `GET /api/git/worktrees/:name/tree?path=<rel-path>` —
    /// list one directory under the worktree. `subPath`
    /// undefined / empty ⇒ worktree root.
    tree: (
      name: string,
      subPath?: string,
      signal?: AbortSignal,
    ): Promise<WorktreeTree> => {
      const qs = new URLSearchParams();
      if (subPath && subPath.length > 0) qs.set("path", subPath);
      const suffix = qs.toString() ? `?${qs}` : "";
      return apiFetch<WorktreeTree>(
        `/api/git/worktrees/${encodeURIComponent(name)}/tree${suffix}`,
        signal ? { signal } : {},
      );
    },
    /// `GET /api/git/worktrees/:name/file?path=<rel-path>` —
    /// read one regular file under the worktree.
    file: (
      name: string,
      path: string,
      signal?: AbortSignal,
    ): Promise<WorktreeFile> => {
      const qs = new URLSearchParams({ path });
      return apiFetch<WorktreeFile>(
        `/api/git/worktrees/${encodeURIComponent(name)}/file?${qs}`,
        signal ? { signal } : {},
      );
    },
  },
};

/// Compute a SHA-256 of the supplied UTF-8 text and return the
/// lowercase hex digest. Used by the policy editor to display
/// the same `policy_sha256` the kernel will compute on advance,
/// before the operator submits the PUT.
export async function sha256Hex(text: string): Promise<string> {
  const enc = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  const arr = new Uint8Array(digest);
  let out = "";
  for (let i = 0; i < arr.length; i++) {
    out += arr[i].toString(16).padStart(2, "0");
  }
  return out;
}

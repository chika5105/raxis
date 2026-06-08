/* `<CredentialsView>` — default-MASKED credential surface.
 *
 * Renders one row per credential the kernel has bound to the
 * supplied scope (per-initiative OR system-wide). Rows show
 * metadata only — name, proxy type, environment, mount alias,
 * format hint, byte size, SHA-256 prefix, file/backend metadata,
 * on-disk path. The plaintext is
 * NEVER fetched on mount; it is fetched on demand through the
 * `Reveal` button, which:
 *
 *   * Pops a confirmation modal for operators that carry the
 *     reveal role (`admin`); the modal is hard-coded to fire
 *     for every reveal so the operator has to click twice —
 *     defence-in-depth against accidental shoulder-surf, with
 *     Critical-severity warning copy for system credentials
 *     (`INV-DASHBOARD-SYSTEM-CREDENTIAL-SEVERITY-01`).
 *   * For operators WITHOUT the reveal role, the click bypasses
 *     the modal and round-trips to the kernel directly so the
 *     kernel can emit a paired `RejectedPermission` audit row
 *     and the FE can render the structured 403 inline. Silent
 *     failure (button does nothing, no UI feedback, no audit
 *     row) is forbidden by
 *     `INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`.
 *   * Renders the bytes in a Monaco viewer (read-only,
 *     `domReadOnly`, no minimap) below a red banner with the
 *     auto-hide countdown
 *     (`INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01`).
 *   * Re-masks at `expires_at_unix` regardless of focus, and
 *     also when the operator clicks "Hide now".
 *
 * Spec contracts:
 *   * `INV-DASHBOARD-CREDENTIAL-DEFAULT-MASKED-01`
 *   * `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01`
 *   * `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01`
 *   * `INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`
 *   * `INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01`
 *   * `INV-DASHBOARD-SYSTEM-CREDENTIAL-SEVERITY-01`
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Editor from "@monaco-editor/react";
import clsx from "clsx";

import { ApiError, dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { Spinner } from "@/components/Spinner";
import { fmtBytes } from "@/lib/format";
import { ensureTomlLanguage, raxisMonacoTheme } from "@/lib/monaco-toml";
import { useTheme } from "@/lib/theme-context";
import type {
  CredentialListResponse,
  CredentialMetadata,
  CredentialReveal,
} from "@/types/api";

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

/// Two scopes are supported: per-initiative and system-wide.
/// Surfacing them through one component keeps the reveal
/// affordance, the auto-hide timer, the Monaco viewer, and
/// the audit-warning banner consistent — drift between the
/// two surfaces is the kind of bug that historically lets a
/// `read` operator accidentally see a system credential
/// because one path skipped a check.
export type CredentialsScope =
  | { kind: "initiative"; initiativeId: string }
  | { kind: "system" };

interface CredentialsViewProps {
  scope: CredentialsScope;
  /// Operator roles from the stored profile. The component
  /// uses this to decide whether to enable the reveal button
  /// (`admin` required by spec) and whether to render the
  /// "you do not have permission" tooltip.
  operatorRoles: string[];
}

/// Auto-hide deadline budgets, mirroring the kernel:
///   * per-initiative credentials:  30 s
///   * system credentials:          15 s
/// The kernel is the source of truth — it stamps
/// `expires_at_unix` on the reveal response and the FE
/// honours that wall-clock value. These constants are kept
/// here only so the FE can render an estimated countdown for
/// the confirmation modal *before* the reveal call returns.
export const AUTO_HIDE_INITIATIVE_SECS = 30;
export const AUTO_HIDE_SYSTEM_SECS = 15;

// TODO(authority): Split credential reveal from broad dashboard admin.
// Today `admin` is derived from `OperatorCertInstall` because reveal is a
// sensitive trust-root-adjacent surface. Long term this should become a
// narrower operator permission such as `CredentialReveal` or
// `CredentialReadSensitive`, then map to a dashboard reveal role without
// requiring cert-install authority.
const REQUIRED_REVEAL_ROLE = "admin";

/// Stable test id helpers — keep tests stable across rebases.
const TID = {
  list: "credentials-list",
  empty: "credentials-empty",
  loading: "credentials-loading",
  row: (name: string) => `credential-row-${name}`,
  revealBtn: (name: string) => `credential-reveal-${name}`,
  confirmModal: "credential-confirm-modal",
  confirmYes: "credential-confirm-yes",
  confirmCancel: "credential-confirm-cancel",
  revealedBanner: "credential-revealed-banner",
  hideNowBtn: "credential-hide-now",
  monaco: "credential-monaco",
  countdown: "credential-countdown",
  criticalPill: "credential-critical-pill",
  highPill: "credential-high-pill",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function CredentialsView({ scope, operatorRoles }: CredentialsViewProps) {
  const queryKey =
    scope.kind === "initiative"
      ? (["initiative-credentials", scope.initiativeId] as const)
      : (["system-credentials"] as const);

  const fetcher = useCredentialList(scope);

  const q = useQuery({
    queryKey,
    queryFn: ({ signal }) => fetcher(signal),
    // Listing carries no plaintext, so the same cache freshness
    // rules as other read-only dashboard surfaces apply. We
    // intentionally do NOT poll — the list rarely changes and
    // every poll is an audit row.
    staleTime: 30_000,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
        return false;
      }
      return failureCount < 2;
    },
  });

  const canReveal = operatorRoles.includes(REQUIRED_REVEAL_ROLE);

  if (q.isPending) {
    return (
      <section
        className="card p-6 flex items-center justify-center min-h-[140px]"
        aria-busy="true"
        aria-label="Loading credentials"
        data-testid={TID.loading}
      >
        <Spinner className="w-5 h-5" />
        <span className="ml-3 text-sm text-ink-muted">Loading credentials…</span>
      </section>
    );
  }

  if (q.error) {
    if (q.error instanceof ApiError && q.error.status === 404) {
      return (
        <section className="card p-4" data-testid="credentials-not-found">
          <Empty
            title="No credentials surface for this scope."
            hint="The kernel returned 404. For per-initiative views this means the initiative id is unknown; for the system view this means no credentials are configured."
          />
        </section>
      );
    }
    if (q.error instanceof ApiError && q.error.status === 403) {
      return (
        <section className="card p-4" data-testid="credentials-forbidden">
          <Empty
            title="Permission denied."
            hint={`Listing credentials requires the "read" role. Your token only carries: ${
              operatorRoles.join(", ") || "(none)"
            }.`}
          />
        </section>
      );
    }
    return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  }

  const list: CredentialListResponse = q.data;
  if (list.credentials.length === 0) {
    return (
      <section className="card p-4" data-testid={TID.empty}>
        <Empty
          title={
            scope.kind === "initiative"
              ? "This initiative declares no credentials."
              : "The kernel has no system credentials configured."
          }
          hint="Credential declarations live in the initiative plan TOML. Registered system credentials live under the kernel data directory's credentials/ and providers/ folders."
        />
      </section>
    );
  }

  const groups =
    scope.kind === "system"
      ? groupCredentialsByType(list.credentials)
      : [{ key: "initiative", title: null, credentials: list.credentials }];

  return (
    <section
      className="card p-0 overflow-hidden"
      data-testid={TID.list}
      data-scope={scope.kind}
    >
      <header className="px-4 py-3 border-b border-edge flex items-start justify-between gap-3 flex-wrap">
        <div className="text-xs space-y-0.5 min-w-0 flex-1">
          <div className="text-[10px] uppercase tracking-wider text-ink-subtle">
            {scope.kind === "initiative"
              ? "Initiative credentials"
              : "System credentials"}
          </div>
          <div className="text-ink-muted">
            {list.credentials.length}{" "}
            {list.credentials.length === 1 ? "credential" : "credentials"}{" "}
            · plaintext is hidden by default; click{" "}
            <span className="text-ink">Reveal</span> to view briefly
          </div>
        </div>
        {!canReveal && (
          <span
            className="badge bg-warn/15 text-warn border-warn/30"
            data-testid="credentials-role-warning"
            title={`Reveal requires the "${REQUIRED_REVEAL_ROLE}" role; your token does not carry it.`}
          >
            read-only
          </span>
        )}
      </header>
      <ul className="divide-y divide-edge/60">
        {groups.map((group) => (
          <li key={group.key} className="p-0">
            {group.title && (
              <div
                className="border-b border-edge/60 bg-panel-high px-4 py-2"
                data-testid={`credential-group-${group.key}`}
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
                    {group.title}
                  </div>
                  <span className="text-[11px] text-ink-muted">
                    {group.credentials.length}{" "}
                    {group.credentials.length === 1 ? "credential" : "credentials"}
                  </span>
                </div>
              </div>
            )}
            <ul className="divide-y divide-edge/60">
              {group.credentials.map((c) => (
                <CredentialRow
                  key={c.name}
                  credential={c}
                  scope={scope}
                  canReveal={canReveal && c.is_revealable}
                  operatorHasRevealRole={canReveal}
                />
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </section>
  );
}

function groupCredentialsByType(credentials: CredentialMetadata[]) {
  const order = [
    "provider",
    "postgres",
    "mysql",
    "mssql",
    "mongodb",
    "redis",
    "smtp",
    "http",
    "aws",
    "gcp",
    "azure",
    "k8s",
    "unknown",
  ];
  const orderIndex = new Map(order.map((key, index) => [key, index]));
  const groups = new Map<string, CredentialMetadata[]>();
  for (const credential of credentials) {
    const key = credential.proxy_type || "unknown";
    const current = groups.get(key) ?? [];
    current.push(credential);
    groups.set(key, current);
  }
  return Array.from(groups.entries())
    .map(([key, rows]) => ({
      key,
      title: credentialGroupTitle(key),
      credentials: rows.sort((a, b) => a.name.localeCompare(b.name)),
    }))
    .sort((a, b) => {
      const ai = orderIndex.get(a.key) ?? 999;
      const bi = orderIndex.get(b.key) ?? 999;
      return ai - bi || a.key.localeCompare(b.key);
    });
}

function credentialGroupTitle(proxyType: string) {
  if (proxyType === "provider") return "Provider credentials";
  if (proxyType === "unknown") return "Unclassified credentials";
  return `${proxyType.toUpperCase()} credentials`;
}

// ---------------------------------------------------------------------------
// Per-row state machine: masked → confirming → revealing →
// revealed → hidden.
// ---------------------------------------------------------------------------

interface CredentialRowProps {
  credential: CredentialMetadata;
  scope: CredentialsScope;
  /// Combined gate: operator carries the reveal role AND the
  /// credential itself advertises `is_revealable`. When false
  /// because of the role, we still round-trip the click so
  /// the kernel can audit the denial; when false because the
  /// credential is intrinsically non-revealable, we surface a
  /// local error instead — the kernel cannot satisfy the
  /// request regardless of role.
  canReveal: boolean;
  /// Disambiguates the two reasons `canReveal` may be false so
  /// the row can pick the right click behaviour
  /// (`INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`).
  operatorHasRevealRole: boolean;
}

type RowState =
  | { kind: "masked" }
  | { kind: "confirming" }
  | { kind: "revealing" }
  | { kind: "revealed"; reveal: CredentialReveal }
  | { kind: "error"; error: ApiError };

function CredentialRow({
  credential: c,
  scope,
  canReveal,
  operatorHasRevealRole,
}: CredentialRowProps) {
  const [state, setState] = useState<RowState>({ kind: "masked" });
  const isSystem = scope.kind === "system";
  const revealSeverity = isSystem ? "critical" : "high";

  const performReveal = useCredentialRevealCallback(scope, c.name, setState);

  // Per `INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`:
  // the click MUST always produce visible UI feedback AND
  // (where the kernel can record it) an audit row. Three
  // cases:
  //
  //   1. canReveal=true — pop the confirmation modal; admin
  //      operator picks whether to fire the audited POST.
  //   2. canReveal=false because of the role gate — skip the
  //      modal, round-trip directly so the kernel emits the
  //      paired `RejectedPermission` audit row, then render
  //      the structured 403 inline.
  //   3. canReveal=false because `is_revealable=false` — the
  //      kernel cannot satisfy this regardless of role; we
  //      surface the explanation locally instead of generating
  //      a 4xx that just looks like a kernel bug.
  const onRevealClicked = () => {
    if (canReveal) {
      setState({ kind: "confirming" });
      return;
    }
    if (!operatorHasRevealRole) {
      setState({ kind: "revealing" });
      void performReveal();
      return;
    }
    // is_revealable=false branch — the kernel will not return
    // plaintext for this credential under any role; surface an
    // explanation inline instead of rounding-trip for a 4xx
    // that the operator has no way to resolve.
    setState({
      kind: "error",
      error: new ApiError(
        0,
        "FAIL_DASHBOARD_CREDENTIAL_NOT_REVEALABLE",
        `Credential "${c.name}" is marked is_revealable=false; the kernel will not surface its plaintext. See the format hint for the on-disk path.`,
      ),
    });
  };

  const onHideNow = () => setState({ kind: "masked" });

  // Fire the auto-hide deadline. We use a single `setTimeout`
  // pinned to wall-clock seconds — `expires_at_unix - nowSec`
  // — and clear it on every state transition so we never end
  // up with stale timers re-masking a fresh reveal.
  useEffect(() => {
    if (state.kind !== "revealed") return;
    const nowSec = Math.floor(Date.now() / 1000);
    const remainingMs = Math.max(
      0,
      (state.reveal.expires_at_unix - nowSec) * 1000,
    );
    const id = window.setTimeout(() => {
      setState({ kind: "masked" });
    }, remainingMs);
    return () => window.clearTimeout(id);
  }, [state]);

  return (
    <li
      className="px-4 py-3"
      data-testid={TID.row(c.name)}
      data-reveal-severity={revealSeverity}
      data-state={state.kind}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Mono pill className="text-ink">
              {c.name}
            </Mono>
            <span className="badge bg-panel-high text-ink-muted border-edge-strong text-[10px]">
              {c.proxy_type}
            </span>
            {c.environment ? (
              <span
                className="badge bg-info/10 text-info border-info/25 text-[10px]"
                title={environmentSourceLabel(c.environment_source)}
              >
                env: {c.environment}
                {c.environment_source === "provider_id_suffix" ? " (inferred)" : ""}
              </span>
            ) : (
              <span className="badge bg-panel-high text-ink-subtle border-edge text-[10px]">
                env: neutral
              </span>
            )}
            {isSystem ? (
              <span
                className="badge bg-bad/15 text-bad border-bad/30 text-[10px]"
                data-testid={TID.criticalPill}
                title="System credential — Critical-severity reveal"
              >
                CRITICAL
              </span>
            ) : (
              <span
                className="badge bg-warn/15 text-warn border-warn/30 text-[10px]"
                data-testid={TID.highPill}
                title="Initiative credential — High-severity reveal"
              >
                HIGH
              </span>
            )}
          </div>
          <div className="mt-1 text-[11px] text-ink-subtle">
            {c.format_hint}
          </div>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-subtle">
            {c.provider_kind && (
              <Meta label="provider">
                <Mono>{c.provider_kind}</Mono>
              </Meta>
            )}
            {c.mount_as && (
              <Meta label="mount_as">
                <Mono>{c.mount_as}</Mono>
              </Meta>
            )}
            {c.upstream_host_port && (
              <Meta label="upstream">
                <Mono>{c.upstream_host_port}</Mono>
              </Meta>
            )}
            <Meta label="size">{fmtBytes(c.byte_size)}</Meta>
            {c.backend_kind && <Meta label="backend">{c.backend_kind}</Meta>}
            {c.mode_octal && (
              <Meta label="mode">
                <Mono>{c.mode_octal}</Mono>
              </Meta>
            )}
            {typeof c.owner_uid === "number" && (
              <Meta label="uid">
                <Mono>{c.owner_uid}</Mono>
              </Meta>
            )}
            {typeof c.modified_unix === "number" && c.modified_unix > 0 && (
              <Meta label="modified">{formatUnix(c.modified_unix)}</Meta>
            )}
            {c.sha256_prefix && (
              <Meta label="sha256">
                <Mono>{c.sha256_prefix}…</Mono>
              </Meta>
            )}
            {c.loaded_from_path && (
              <Meta label="path">
                <Mono className="break-all">{c.loaded_from_path}</Mono>
              </Meta>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {state.kind === "revealed" ? (
            <button
              type="button"
              className="btn"
              onClick={onHideNow}
              data-testid={TID.hideNowBtn}
            >
              Hide now
            </button>
          ) : (
            <button
              type="button"
              className={clsx("btn", canReveal ? "btn-primary" : "")}
              onClick={onRevealClicked}
              disabled={state.kind === "revealing"}
              aria-disabled={state.kind === "revealing"}
              title={
                canReveal
                  ? "Reveal plaintext (audited)"
                  : `Requires the "${REQUIRED_REVEAL_ROLE}" role — clicking will round-trip to the kernel for an audited denial`
              }
              data-reveal-eligible={canReveal ? "true" : "false"}
              data-testid={TID.revealBtn(c.name)}
            >
              {state.kind === "revealing"
                ? "Revealing…"
                : c.byte_size === 0
                  ? "Reveal (empty)"
                  : "Reveal plaintext"}
            </button>
          )}
        </div>
      </div>

      {state.kind === "confirming" && (
        <ConfirmModal
          credential={c}
          isSystem={isSystem}
          onCancel={() => setState({ kind: "masked" })}
          onConfirm={() => {
            setState({ kind: "revealing" });
            void performReveal();
          }}
        />
      )}

      {state.kind === "error" && (
        <div
          className="mt-3 card p-3 border-bad/40 bg-bad/10 text-xs text-bad flex items-start gap-3"
          role="alert"
          data-testid="credential-reveal-error"
        >
          <div className="flex-1 min-w-0">
            <p className="font-medium">Reveal failed</p>
            <p className="mt-1 break-words">{state.error.detail} </p>
          </div>
          <button
            type="button"
            className="btn"
            onClick={() => setState({ kind: "masked" })}
            aria-label="Dismiss reveal error"
          >
            Dismiss
          </button>
        </div>
      )}

      {state.kind === "revealed" && (
        <RevealedBody
          credential={c}
          reveal={state.reveal}
          isSystem={isSystem}
          onHideNow={onHideNow}
        />
      )}
    </li>
  );
}

// ---------------------------------------------------------------------------
// Reveal callback — wraps the per-scope POST and folds errors
// into the row state machine without leaking plaintext through
// the React Query cache (we deliberately use `useState` not
// `useMutation` so the bytes never live in Query's cache).
// ---------------------------------------------------------------------------

function useCredentialList(scope: CredentialsScope) {
  return useCallback(
    (signal?: AbortSignal): Promise<CredentialListResponse> =>
      scope.kind === "initiative"
        ? dashboardApi.initiatives.credentials(scope.initiativeId, signal)
        : dashboardApi.systemCredentials.list(signal),
    [scope],
  );
}

function useCredentialRevealCallback(
  scope: CredentialsScope,
  name: string,
  setState: (s: RowState) => void,
) {
  // We capture `setState` in a ref so the returned callback is
  // stable across re-renders even though the row's local state
  // changes between clicks. Without this, every render would
  // mint a fresh callback and the modal's `onConfirm` would
  // re-bind every time the operator hovered a button.
  const setStateRef = useRef(setState);
  setStateRef.current = setState;

  return useCallback(async () => {
    try {
      const reveal: CredentialReveal =
        scope.kind === "initiative"
          ? await dashboardApi.initiatives.revealCredential(
              scope.initiativeId,
              name,
            )
          : await dashboardApi.systemCredentials.reveal(name);
      setStateRef.current({ kind: "revealed", reveal });
    } catch (err) {
      const apiErr =
        err instanceof ApiError
          ? err
          : new ApiError(
              0,
              "FAIL_DASHBOARD_NETWORK",
              err instanceof Error ? err.message : "unknown error",
            );
      setStateRef.current({ kind: "error", error: apiErr });
    }
  }, [scope, name]);
}

// ---------------------------------------------------------------------------
// Confirm modal — fires for every reveal click. System credentials get
// Critical warning copy because they are global authority material.
// ---------------------------------------------------------------------------

interface ConfirmModalProps {
  credential: CredentialMetadata;
  isSystem: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

function ConfirmModal({
  credential: c,
  isSystem,
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  // Estimated auto-hide window. The kernel returns the actual
  // wall-clock deadline on the response; this is the operator-
  // facing pre-reveal hint so they know how long they'll have
  // to read it before the auto-mask kicks in.
  const estSecs = isSystem ? AUTO_HIDE_SYSTEM_SECS : AUTO_HIDE_INITIATIVE_SECS;
  return (
    <div
      className="mt-3 card p-3 border-warn/40 bg-warn/10 text-xs"
      role="dialog"
      aria-modal="false"
      aria-labelledby={`confirm-title-${c.name}`}
      data-testid={TID.confirmModal}
    >
      <div
        id={`confirm-title-${c.name}`}
        className="text-sm font-semibold text-ink mb-1"
      >
        Reveal credential <Mono>{c.name}</Mono>?
      </div>
      <div className="text-ink-muted">
        This will fetch the plaintext bytes ({fmtBytes(c.byte_size)}) and emit
        an audit-chain row{" "}
        {isSystem ? (
          <strong className="text-bad">
            at <span className="uppercase">Critical</span> severity (system
            credential — operator notifications inbox will fire)
          </strong>
        ) : (
          <strong className="text-warn">at High severity</strong>
        )}
        . The plaintext will auto-hide after ~{estSecs} seconds; you can also
        click <strong>Hide now</strong> at any time.
      </div>
      <div className="mt-3 flex items-center gap-2">
        <button
          type="button"
          className={clsx(
            "btn",
            isSystem ? "bg-bad text-white hover:bg-bad/90" : "btn-primary",
          )}
          onClick={onConfirm}
          data-testid={TID.confirmYes}
        >
          {isSystem ? "Reveal system credential" : "Reveal plaintext"}
        </button>
        <button
          type="button"
          className="btn"
          onClick={onCancel}
          data-testid={TID.confirmCancel}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Revealed body — Monaco viewer + countdown banner.
// ---------------------------------------------------------------------------

interface RevealedBodyProps {
  credential: CredentialMetadata;
  reveal: CredentialReveal;
  isSystem: boolean;
  onHideNow: () => void;
}

function RevealedBody({
  credential: c,
  reveal,
  isSystem,
  onHideNow,
}: RevealedBodyProps) {
  const { theme } = useTheme();
  const monacoTheme = raxisMonacoTheme(theme);
  const remaining = useCountdown(reveal.expires_at_unix);

  const bannerTone = isSystem
    ? "border-bad/40 bg-bad/10 text-bad"
    : "border-warn/30 bg-warn/5 text-warn";

  return (
    <div className="mt-3 space-y-2" data-testid="credential-revealed">
      <div
        className={clsx(
          "rounded-md border px-3 py-2 text-xs flex flex-wrap items-center gap-3",
          bannerTone,
        )}
        role="status"
        aria-live="polite"
        data-testid={TID.revealedBanner}
      >
        <span className="font-semibold uppercase tracking-wider">
          {isSystem ? "SYSTEM CREDENTIAL VISIBLE" : "PLAINTEXT VISIBLE"}
        </span>
        <span data-testid={TID.countdown}>
          auto-hides in {remaining}s
        </span>
        <span className="text-ink-subtle">sha256={reveal.sha256_prefix}…</span>
        <span className="ml-auto flex items-center gap-2">
          <CopyButton value={reveal.plaintext} label="Copy plaintext" />
          <button
            type="button"
            className="btn"
            onClick={onHideNow}
            data-testid={TID.hideNowBtn}
          >
            Hide now
          </button>
        </span>
      </div>
      <div
        className="rounded-md border border-edge overflow-hidden"
        style={{ height: monacoHeight(c.byte_size) }}
      >
        <Editor
          height="100%"
          defaultLanguage={detectLanguage(c)}
          beforeMount={ensureTomlLanguage}
          theme={monacoTheme}
          value={reveal.plaintext}
          options={{
            readOnly: true,
            domReadOnly: true,
            fontSize: 13,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            automaticLayout: true,
            wordWrap: "on",
            renderLineHighlight: "none",
          }}
        />
        {/* Hidden testing pane so vitest can assert on the
            plaintext without booting Monaco. The Monaco mock
            in the test harness replaces the real editor with
            a `<textarea data-testid="monaco-mock">`; this
            sibling node provides a stable selector for the
            visual revealed body in production builds where
            Monaco mounts properly. */}
        <span
          className="sr-only"
          data-testid={TID.monaco}
          data-credential={c.name}
        >
          {reveal.plaintext}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface MetaProps {
  label: string;
  children: React.ReactNode;
}

function Meta({ label, children }: MetaProps) {
  return (
    <span className="inline-flex items-baseline gap-1">
      <span className="text-[10px] uppercase tracking-wider text-ink-subtle">
        {label}
      </span>
      <span className="text-ink-muted">{children}</span>
    </span>
  );
}

function environmentSourceLabel(source?: string | null): string {
  switch (source) {
    case "policy.permitted_credentials":
      return "Environment from policy [[permitted_credentials]]";
    case "provider_id_suffix":
      return "Environment inferred from provider credential name";
    default:
      return "Environment metadata";
  }
}

function formatUnix(unix: number): string {
  return new Date(unix * 1000).toLocaleString();
}

function monacoHeight(byteSize: number): string {
  // Simple heuristic: small credentials (most are <2 KiB)
  // get a compact viewer; larger ones stretch up to 40vh.
  if (byteSize < 256) return "120px";
  if (byteSize < 2_048) return "200px";
  return "40vh";
}

function detectLanguage(c: CredentialMetadata): string {
  // The kernel's format hint carries the file shape; map a
  // few common cases to Monaco languages so syntax-highlight
  // helps the operator scan the bytes. Default to plaintext
  // for unknown shapes — never throw.
  const hint = c.format_hint.toLowerCase();
  const path = (c.loaded_from_path ?? "").toLowerCase();
  if (path.endsWith(".toml") || hint.includes("toml")) return "toml";
  if (path.endsWith(".json") || hint.includes("json")) return "json";
  if (path.endsWith(".yaml") || path.endsWith(".yml") || hint.includes("yaml")) {
    return "yaml";
  }
  if (path.endsWith(".env") || hint.includes("env")) return "shell";
  return "plaintext";
}

/// Wall-clock countdown — re-renders every second. Returns
/// the integer seconds remaining (clamped to ≥0).
function useCountdown(deadlineUnixSec: number): number {
  const compute = () =>
    Math.max(0, deadlineUnixSec - Math.floor(Date.now() / 1000));
  const [value, setValue] = useState<number>(compute);

  useEffect(() => {
    setValue(compute());
    const id = window.setInterval(() => setValue(compute()), 1000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deadlineUnixSec]);

  return value;
}

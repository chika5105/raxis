import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { dashboardApi } from "@/api/client";
import type { NotificationView } from "@/types/api";

// Subscribes to the operator-notification stream and surfaces a
// dismissible amber banner when the live-e2e harness (or any
// future kernel-side preflight) emits
// `OperatorAttentionRequired { attention_kind:
// "HostHygieneDiskPressure" }`. INV-HOST-HYGIENE-01 pins both
// the filter string and the JSON body shape (the structured
// `HostPreflightError::DiskPressure` payload defined in
// `raxis/crates/types/src/host_preflight.rs`).
//
// The dismiss is per-session (sessionStorage) — the banner
// re-appears on next load if the underlying notification has not
// been marked-read in the inbox. This mirrors how the operator
// experiences other dismissible chrome and avoids a permanent
// "I clicked X once three weeks ago" dead zone.

const HYGIENE_ATTENTION_KIND = "HostHygieneDiskPressure";
const DISMISS_STORAGE_KEY = "raxis.host_hygiene_banner.dismissed_event_ids";

export type HostHygieneBannerEvent = {
  event_id: string;
  attention_kind: string;
  details: HostHygieneDetails;
};

export type HostHygieneDetails = {
  pressure_kind: "DiskPressure" | string;
  threshold_pct?: number;
  observed_volumes?: VolumeReport[];
  remediation_cmd?: string;
  docs_url?: string | null;
};

export type VolumeReport = {
  mount: string;
  used_pct: number;
  free_human: string;
};

export function HostHygieneBanner() {
  const q = useQuery({
    queryKey: ["notifications", "host-hygiene-banner"],
    queryFn: ({ signal }) =>
      dashboardApi.notifications.list({ unread_only: false, limit: 100 }, signal),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });
  const [dismissed, setDismissed] = useState<Set<string>>(() =>
    loadDismissed(),
  );

  const events = useMemo(
    () => extractHygieneEvents(q.data ?? []),
    [q.data],
  );
  const visible = useMemo(
    () => events.filter((e) => !dismissed.has(e.event_id)),
    [events, dismissed],
  );

  if (visible.length === 0) {
    return null;
  }

  // Render the freshest event only — the dashboard is meant to
  // surface "what action does the operator need to take RIGHT NOW",
  // and the underlying notification stream is already newest-first.
  const event = visible[0];
  const onDismiss = () => {
    const next = new Set(dismissed);
    next.add(event.event_id);
    setDismissed(next);
    persistDismissed(next);
  };
  const onCopy = () => {
    const cmd = event.details.remediation_cmd ?? "cargo xtask hygiene";
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(cmd).catch(() => {
        // Clipboard write may fail on insecure contexts (http://);
        // we deliberately swallow rather than render an error toast
        // because the command string is already visible in the
        // banner body — operators can copy by hand.
      });
    }
  };

  const offending = (event.details.observed_volumes ?? []).filter(
    (v) => v.used_pct >= (event.details.threshold_pct ?? 90),
  );
  const remediation =
    event.details.remediation_cmd ?? "cargo xtask hygiene";

  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="host-hygiene-banner"
      className="rounded-md border px-3 py-2 text-xs flex flex-wrap items-center gap-3 justify-between border-amber-700/40 bg-amber-700/10 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200"
    >
      <div className="flex items-center gap-2 min-w-0">
        <span
          aria-hidden="true"
          className="inline-flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-bold leading-none text-amber-700 dark:text-amber-400"
        >
          !
        </span>
        <div className="min-w-0">
          <span className="font-medium">Host disk pressure</span>{" "}
          <span className="text-amber-800/85 dark:text-amber-300/90">
            {offending.length > 0 ? (
              <>
                {offending.map((v, i) => (
                  <span key={v.mount}>
                    {i > 0 ? ", " : null}
                    <span className="font-mono">{v.mount}</span> at {v.used_pct}%
                    {" "}
                    (free {v.free_human})
                  </span>
                ))}
                .{" "}
              </>
            ) : (
              <>One monitored volume is above the threshold.{" "}</>
            )}
            Run <span className="font-mono">{remediation}</span> to free space.
          </span>
        </div>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <button
          type="button"
          className="btn text-[11px] px-2 py-1"
          onClick={onCopy}
          aria-label="Copy remediation command"
        >
          Copy <span className="font-mono">{remediation}</span>
        </button>
        {event.details.docs_url && (
          <a
            href={event.details.docs_url}
            target="_blank"
            rel="noreferrer"
            className="text-[11px] underline hover:no-underline"
          >
            Read more
          </a>
        )}
        <button
          type="button"
          className="text-[11px] hover:underline"
          onClick={onDismiss}
          aria-label="Dismiss host disk pressure banner"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers — parse + dismiss persistence
// ---------------------------------------------------------------------------

/// Pull every `OperatorAttentionRequired` notification whose
/// `attention_kind` is `"HostHygieneDiskPressure"` and re-shape it
/// into `HostHygieneBannerEvent`. Tolerates legacy / non-JSON
/// `details` strings by skipping them — the banner falls back to a
/// generic message rather than crashing the dashboard.
export function extractHygieneEvents(
  rows: NotificationView[],
): HostHygieneBannerEvent[] {
  const out: HostHygieneBannerEvent[] = [];
  for (const r of rows) {
    if (r.event_kind !== "OperatorAttentionRequired") continue;
    const payload = r.payload as
      | { attention_kind?: string; details?: string | unknown }
      | null
      | undefined;
    if (!payload || payload.attention_kind !== HYGIENE_ATTENTION_KIND) continue;
    const details = parseDetails(payload.details);
    if (!details) continue;
    out.push({
      event_id: r.notification_id ?? r.source_event_id ?? `${r.created_at}`,
      attention_kind: payload.attention_kind,
      details,
    });
  }
  return out;
}

function parseDetails(raw: unknown): HostHygieneDetails | null {
  if (raw == null) return null;
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw) as HostHygieneDetails;
      if (parsed && typeof parsed === "object") return parsed;
    } catch {
      return null;
    }
  }
  if (typeof raw === "object") {
    return raw as HostHygieneDetails;
  }
  return null;
}

function loadDismissed(): Set<string> {
  if (typeof window === "undefined" || !window.sessionStorage) {
    return new Set();
  }
  try {
    const raw = window.sessionStorage.getItem(DISMISS_STORAGE_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return new Set(parsed.map(String));
  } catch {
    // Malformed JSON — fall through to empty set.
  }
  return new Set();
}

function persistDismissed(set: Set<string>): void {
  if (typeof window === "undefined" || !window.sessionStorage) return;
  try {
    window.sessionStorage.setItem(
      DISMISS_STORAGE_KEY,
      JSON.stringify(Array.from(set)),
    );
  } catch {
    // sessionStorage write may fail under quota / private mode —
    // safe to swallow; the banner just re-renders next mount.
  }
}

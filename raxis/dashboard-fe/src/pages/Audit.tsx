import { useEffect, useMemo, useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { ChainStatusBanner } from "@/components/ChainStatusBanner";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import {
  FailurePill,
  FailureReasonPanel,
} from "@/components/FailureReasonPanel";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { auditBadgeClasses } from "@/lib/audit-tone";
import {
  failureFromAuditEvent,
  isFailureAuditEvent,
} from "@/lib/failure-extract";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import type { AuditEntryView } from "@/types/api";

const PAGE_SIZE = 50;

export function AuditPage() {
  const [params, setParams] = useSearchParams();
  const highlightInitiativeId =
    params.get("highlight_initiative_id") ??
    params.get("initiative_id") ??
    undefined;
  const dimUnrelated = (params.get("dim") ?? "1") !== "0";
  const [expanded, setExpanded] = useState<string | null>(null);
  // Controlled input mirroring the URL's initiative highlight.
  // The previous implementation used `defaultValue` which only
  // seeds the field on first mount — clicking the "clear" link
  // wiped the URL param but left whatever text the operator
  // had typed, so the visible input lied about the active
  // focus. Using a controlled state synced from the URL keeps
  // the input and the highlight in lockstep regardless of which
  // surface (input, "clear", browser back/forward) drove the
  // change.
  const [highlightDraft, setHighlightDraft] = useState(highlightInitiativeId ?? "");
  const [search, setSearch] = useState(params.get("search") ?? "");
  const [sessionFilter, setSessionFilter] = useState("");
  const [initiativeFilter, setInitiativeFilter] = useState("");
  const [workspaceName, setWorkspaceName] = useState("All");
  useEffect(() => {
    setHighlightDraft(highlightInitiativeId ?? "");
  }, [highlightInitiativeId]);

  const applyHighlight = (raw: string) => {
    const v = raw.trim();
    const sp = new URLSearchParams(params);
    sp.delete("initiative_id");
    if (v) sp.set("highlight_initiative_id", v);
    else {
      sp.delete("highlight_initiative_id");
      sp.delete("dim");
    }
    setParams(sp);
  };

  const clearHighlight = () => {
    const sp = new URLSearchParams(params);
    sp.delete("initiative_id");
    sp.delete("highlight_initiative_id");
    sp.delete("dim");
    setParams(sp);
  };

  const setDimUnrelated = (checked: boolean) => {
    const sp = new URLSearchParams(params);
    if (checked) sp.delete("dim");
    else sp.set("dim", "0");
    setParams(sp, { replace: true });
  };

  const q = useInfiniteQuery({
    queryKey: ["audit", { highlightInitiativeId }],
    queryFn: ({ pageParam, signal }) =>
      dashboardApi.audit.list(
        {
          limit: PAGE_SIZE,
          ...(pageParam !== undefined ? { cursor: pageParam } : {}),
          ...(highlightInitiativeId
            ? { highlight_initiative_id: highlightInitiativeId }
            : {}),
        },
        signal,
      ),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last: AuditEntryView[]) =>
      last.length === PAGE_SIZE ? last[last.length - 1].seq : undefined,
  });

  const initiatives = useQuery({
    queryKey: ["initiatives", "audit-filter", { limit: 500 }],
    queryFn: ({ signal }) =>
      dashboardApi.initiatives.list({ limit: 500 }, signal),
    staleTime: 30_000,
  });

  const all = useMemo(() => q.data?.pages.flat() ?? [], [q.data]);
  const workspaceOptions = useMemo(() => {
    const names = new Set<string>();
    for (const i of initiatives.data ?? []) {
      const name = i.display_name?.trim();
      if (name) names.add(name);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  }, [initiatives.data]);
  const workspaceInitiativeIds = useMemo(() => {
    if (workspaceName === "All") return null;
    const ids = new Set<string>();
    for (const i of initiatives.data ?? []) {
      if (i.display_name === workspaceName) ids.add(i.initiative_id);
    }
    return ids;
  }, [initiatives.data, workspaceName]);
  const filtered = useMemo(
    () =>
      all.filter((row) =>
        auditRowMatchesFilters(row, {
          query: search,
          sessionId: sessionFilter,
          initiativeId: initiativeFilter,
          workspaceInitiativeIds,
        }),
      ),
    [all, search, sessionFilter, initiativeFilter, workspaceInitiativeIds],
  );
  const highlightedCount = useMemo(
    () => all.filter((a) => rowHighlighted(a, highlightInitiativeId)).length,
    [all, highlightInitiativeId],
  );
  const filterActive =
    search.trim() !== "" ||
    sessionFilter.trim() !== "" ||
    initiativeFilter.trim() !== "" ||
    workspaceName !== "All";
  const clearFilters = () => {
    setSearch("");
    setSessionFilter("");
    setInitiativeFilter("");
    setWorkspaceName("All");
  };

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Audit Chain</h1>
          <p className="text-sm text-ink-muted">
            Tamper-evident, append-only record of every kernel state change.
          </p>
        </div>
        <form
          className="flex items-center gap-2 flex-wrap justify-end"
          onSubmit={(e) => {
            e.preventDefault();
            applyHighlight(highlightDraft);
          }}
        >
          <input
            className="input w-72"
            placeholder="Initiative id"
            value={highlightDraft}
            aria-label="Highlight initiative id"
            onChange={(e) => setHighlightDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                e.preventDefault();
                setHighlightDraft(highlightInitiativeId ?? "");
              }
            }}
          />
          <button type="submit" className="btn">
            Highlight
          </button>
        </form>
      </header>

      <ChainStatusBanner />

      <section
        className="card px-3 py-3 flex flex-wrap items-end gap-3 text-xs"
        aria-label="Audit filters"
      >
        <label className="flex flex-col gap-1 min-w-[18rem] flex-1">
          <span className="text-[11px] uppercase tracking-wider text-ink-subtle">
            Search
          </span>
          <input
            className="input"
            placeholder="Event name, payload text, task..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>
        <label className="flex flex-col gap-1 min-w-[13rem]">
          <span className="text-[11px] uppercase tracking-wider text-ink-subtle">
            Session ID
          </span>
          <input
            className="input font-mono text-xs"
            placeholder="session id"
            value={sessionFilter}
            onChange={(e) => setSessionFilter(e.target.value)}
          />
        </label>
        <label className="flex flex-col gap-1 min-w-[13rem]">
          <span className="text-[11px] uppercase tracking-wider text-ink-subtle">
            Initiative ID
          </span>
          <input
            className="input font-mono text-xs"
            placeholder="initiative id"
            value={initiativeFilter}
            onChange={(e) => setInitiativeFilter(e.target.value)}
          />
        </label>
        <label className="flex flex-col gap-1 min-w-[13rem]">
          <span className="text-[11px] uppercase tracking-wider text-ink-subtle">
            Workspace
          </span>
          <select
            className="input"
            value={workspaceName}
            onChange={(e) => setWorkspaceName(e.target.value)}
          >
            <option value="All">All workspaces</option>
            {workspaceOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <div className="ml-auto flex items-center gap-3 pb-1">
          <span className="text-ink-subtle">
            <span className="tabular text-ink">{filtered.length}</span> /{" "}
            <span className="tabular">{all.length}</span> loaded
          </span>
          {filterActive && (
            <button
              type="button"
              className="text-accent hover:underline"
              onClick={clearFilters}
            >
              clear filters
            </button>
          )}
        </div>
      </section>

      {highlightInitiativeId && (
        <div className="card px-3 py-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
          <span className="text-ink-muted">
            Kernel chain: <span className="tabular text-ink">{all.length}</span>{" "}
            loaded ·{" "}
            <span className="tabular text-accent">{highlightedCount}</span>{" "}
            highlighted for <Mono pill>{highlightInitiativeId}</Mono>
          </span>
          <label className="inline-flex items-center gap-2 text-ink-muted">
            <input
              type="checkbox"
              className="accent-accent"
              checked={dimUnrelated}
              onChange={(e) => setDimUnrelated(e.currentTarget.checked)}
            />
            Dim unrelated
          </label>
          <button
            type="button"
            onClick={clearHighlight}
            className="text-accent hover:underline"
          >
            clear
          </button>
        </div>
      )}

      {all.length === 0 ? (
        <Empty title="No audit events." />
      ) : filtered.length === 0 ? (
        <Empty
          title="No audit rows match these filters."
          hint="Search is partial and matches event names, ids, and payload text. Load more rows if the event is older than the current page."
        />
      ) : (
        <div className="card p-0 overflow-hidden">
          <ul className="divide-y divide-edge/50">
            {filtered.map((a) => {
              const rowId = String(a.seq);
              const rowKey = a.event_id || `seq-${a.seq}`;
              const isOpen = expanded === rowKey;
              const toggle = () => setExpanded(isOpen ? null : rowKey);
              const highlighted = rowHighlighted(a, highlightInitiativeId);
              const dimmed =
                !!highlightInitiativeId && dimUnrelated && !highlighted;
              const isFailure = isFailureAuditEvent(a.event_kind, a.payload);
              const reason = isFailure
                ? failureFromAuditEvent(a.event_kind, a.payload, {
                    seq: a.seq,
                    eventId: a.event_id,
                    observedAt: a.at,
                  })
                : null;
              // Outer row is a real interactive surface but
              // contains nested <a> links to the initiative /
              // task. Plain <button> would be invalid HTML
              // (interactive descendants), so we use
              // role="button" + keyboard handlers on a <div>.
              return (
                <li
                  key={rowKey}
                  className={clsx(
                    "border-l-2 transition-opacity",
                    highlighted
                      ? "border-accent bg-accent/5"
                      : "border-transparent",
                    dimmed && "opacity-45 hover:opacity-90",
                  )}
                  data-highlighted={highlighted || undefined}
                >
                  <div
                    role="button"
                    tabIndex={0}
                    aria-expanded={isOpen}
                    aria-controls={`audit-payload-${rowId}`}
                    onClick={toggle}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        toggle();
                      }
                    }}
                    className="w-full text-left px-4 py-2.5 flex items-center gap-3 cursor-pointer hover:bg-panel-high focus:outline-none focus-visible:ring-1 focus-visible:ring-accent focus-visible:bg-panel-high"
                  >
                    <span className="text-[11px] text-ink-subtle font-mono w-14 text-right">
                      #{a.seq}
                    </span>
                    <span className={auditBadgeClasses(a.event_kind)}>
                      {a.event_kind}
                    </span>
                    {highlighted && (
                      <span
                        className="badge bg-accent/10 border-accent/30 text-accent text-[10px]"
                        title={(a.highlight_reasons ?? []).join(", ")}
                      >
                        match
                      </span>
                    )}
                    {a.initiative_id && (
                      <Link
                        to={`/initiatives/${encodeURIComponent(a.initiative_id)}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-xs text-accent hover:underline font-mono"
                      >
                        {a.initiative_id}
                      </Link>
                    )}
                    {a.task_id && (
                      <Link
                        to={`/tasks/${encodeURIComponent(a.task_id)}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-[11px] text-ink-muted hover:text-accent font-mono"
                      >
                        · {a.task_id}
                      </Link>
                    )}
                    {isFailure && (
                      <FailurePill failed reason={reason} compact />
                    )}
                    <span className="ml-auto text-xs text-ink-subtle">
                      {fmtRelative(a.at)}
                    </span>
                    <span
                      aria-hidden="true"
                      className={`text-ink-subtle text-xs transition-transform ${
                        isOpen ? "rotate-90" : ""
                      }`}
                    >
                      ›
                    </span>
                  </div>
                  {isOpen && (
                    <div
                      id={`audit-payload-${rowId}`}
                      className="px-4 pb-3 pt-1 bg-panel space-y-2"
                    >
                      <div className="text-[11px] text-ink-subtle">
                        <Mono>{a.event_id}</Mono> · {fmtAbsolute(a.at)}
                      </div>
                      {isFailure && (
                        <FailureReasonPanel
                          reason={reason}
                          heading={`Failure event · #${a.seq}`}
                        />
                      )}
                      <JsonPayload payload={a.payload} />
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
          {q.hasNextPage && (
            <div className="p-3 border-t border-edge text-center">
              <button
                type="button"
                className="btn"
                disabled={q.isFetchingNextPage}
                onClick={() => q.fetchNextPage()}
              >
                {q.isFetchingNextPage ? "Loading…" : "Load more"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function rowHighlighted(
  row: AuditEntryView,
  highlightInitiativeId: string | undefined,
): boolean {
  if (!highlightInitiativeId) return false;
  return (
    row.is_highlighted === true ||
    row.initiative_id === highlightInitiativeId ||
    payloadInitiativeId(row.payload) === highlightInitiativeId
  );
}

function payloadInitiativeId(payload: unknown): string | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  const value = (payload as Record<string, unknown>).initiative_id;
  return typeof value === "string" ? value : null;
}

function auditRowMatchesFilters(
  row: AuditEntryView,
  filters: {
    query: string;
    sessionId: string;
    initiativeId: string;
    workspaceInitiativeIds: Set<string> | null;
  },
): boolean {
  const rowSession = row.session_id ?? payloadString(row.payload, "session_id") ?? "";
  const rowInitiative =
    row.initiative_id ?? payloadString(row.payload, "initiative_id") ?? "";
  if (
    filters.sessionId.trim() &&
    !rowSession.toLowerCase().includes(filters.sessionId.trim().toLowerCase())
  ) {
    return false;
  }
  if (
    filters.initiativeId.trim() &&
    !rowInitiative
      .toLowerCase()
      .includes(filters.initiativeId.trim().toLowerCase())
  ) {
    return false;
  }
  if (
    filters.workspaceInitiativeIds &&
    !filters.workspaceInitiativeIds.has(rowInitiative)
  ) {
    return false;
  }
  const query = filters.query.trim().toLowerCase();
  if (!query) return true;
  const haystack = [
    String(row.seq),
    row.event_id,
    row.event_kind,
    row.initiative_id ?? "",
    row.task_id ?? "",
    row.session_id ?? "",
    JSON.stringify(row.payload ?? {}),
  ]
    .join(" ")
    .toLowerCase();
  return query
    .split(/\s+/)
    .filter(Boolean)
    .every((token) => haystack.includes(token));
}

function payloadString(payload: unknown, key: string): string | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  const value = (payload as Record<string, unknown>)[key];
  return typeof value === "string" ? value : null;
}

function JsonPayload({ payload }: { payload: unknown }) {
  const body = useMemo(() => JSON.stringify(payload, null, 2), [payload]);
  return (
    <pre className="text-[11px] font-mono text-ink-muted overflow-x-auto scroll-thin max-h-96">
      {body}
    </pre>
  );
}

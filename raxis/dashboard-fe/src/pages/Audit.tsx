import { useEffect, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { auditBadgeClasses } from "@/lib/audit-tone";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import type { AuditEntryView } from "@/types/api";

const PAGE_SIZE = 50;

export function AuditPage() {
  const [params, setParams] = useSearchParams();
  const initiativeId = params.get("initiative_id") ?? undefined;
  const [expanded, setExpanded] = useState<string | null>(null);
  // Controlled input mirroring the URL's initiative_id filter.
  // The previous implementation used `defaultValue` which only
  // seeds the field on first mount — clicking the "clear" link
  // wiped the URL param but left whatever text the operator
  // had typed, so the visible input lied about the active
  // filter. Using a controlled state synced from the URL keeps
  // the input and the filter in lockstep regardless of which
  // surface (input, "clear", browser back/forward) drove the
  // change.
  const [filterDraft, setFilterDraft] = useState(initiativeId ?? "");
  useEffect(() => {
    setFilterDraft(initiativeId ?? "");
  }, [initiativeId]);

  const q = useInfiniteQuery({
    queryKey: ["audit", { initiativeId }],
    queryFn: ({ pageParam, signal }) =>
      dashboardApi.audit.list(
        {
          limit: PAGE_SIZE,
          ...(pageParam !== undefined ? { cursor: pageParam } : {}),
          ...(initiativeId ? { initiative_id: initiativeId } : {}),
        },
        signal,
      ),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last: AuditEntryView[]) =>
      last.length === PAGE_SIZE ? last[last.length - 1].seq : undefined,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;

  const all = q.data.pages.flat();

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Audit Chain</h1>
          <p className="text-sm text-ink-muted">
            Tamper-evident, append-only record of every kernel state change.
          </p>
        </div>
        <div className="flex gap-2">
          <input
            className="input w-72"
            placeholder="Filter by initiative id (press Enter)…"
            value={filterDraft}
            onChange={(e) => setFilterDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                const v = filterDraft.trim();
                if (v) setParams({ initiative_id: v });
                else setParams({});
              } else if (e.key === "Escape") {
                e.preventDefault();
                setFilterDraft(initiativeId ?? "");
              }
            }}
          />
        </div>
      </header>

      {initiativeId && (
        <div className="text-xs text-ink-muted">
          Filtered to initiative <Mono pill>{initiativeId}</Mono>{" "}
          <button
            type="button"
            onClick={() => setParams({})}
            className="text-accent hover:underline ml-2"
          >
            clear
          </button>
        </div>
      )}

      {all.length === 0 ? (
        <Empty title="No audit events." />
      ) : (
        <div className="card p-0 overflow-hidden">
          <ul className="divide-y divide-edge/50">
            {all.map((a) => {
              const isOpen = expanded === a.event_id;
              const toggle = () => setExpanded(isOpen ? null : a.event_id);
              // Outer row is a real interactive surface but
              // contains nested <a> links to the initiative /
              // task. Plain <button> would be invalid HTML
              // (interactive descendants), so we use
              // role="button" + keyboard handlers on a <div>.
              return (
                <li key={a.event_id}>
                  <div
                    role="button"
                    tabIndex={0}
                    aria-expanded={isOpen}
                    aria-controls={`audit-payload-${a.event_id}`}
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
                    {a.initiative_id && (
                      <Link
                        to={`/initiatives/${a.initiative_id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-xs text-accent hover:underline font-mono"
                      >
                        {a.initiative_id}
                      </Link>
                    )}
                    {a.task_id && (
                      <Link
                        to={`/tasks/${a.task_id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-[11px] text-ink-muted hover:text-accent font-mono"
                      >
                        · {a.task_id}
                      </Link>
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
                      id={`audit-payload-${a.event_id}`}
                      className="px-4 pb-3 pt-1 bg-panel"
                    >
                      <div className="text-[11px] text-ink-subtle">
                        <Mono>{a.event_id}</Mono> · {fmtAbsolute(a.at)}
                      </div>
                      <pre className="mt-2 text-[11px] font-mono text-ink-muted overflow-x-auto scroll-thin max-h-96">
                        {JSON.stringify(a.payload, null, 2)}
                      </pre>
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

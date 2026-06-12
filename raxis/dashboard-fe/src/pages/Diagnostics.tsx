import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { DiagnosticFindingsPanel } from "@/components/DiagnosticFindingsPanel";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import type { DiagnosticFinding } from "@/types/api";

const DIAGNOSTICS_POLL_MS = 10_000;

export function DiagnosticsPage() {
  const [params, setParams] = useSearchParams();
  const initiativeId = params.get("initiative_id") ?? undefined;
  const severity = params.get("severity") ?? "all";

  const q = useQuery({
    queryKey: ["diagnostics", initiativeId ?? "all"],
    queryFn: ({ signal }) =>
      dashboardApi.diagnostics.list(
        { initiative_id: initiativeId, limit: 100 },
        signal,
      ),
    refetchInterval: DIAGNOSTICS_POLL_MS,
    refetchIntervalInBackground: true,
  });

  const findings = useMemo(() => q.data?.findings ?? [], [q.data?.findings]);
  const counts = useMemo(() => countSeverities(findings), [findings]);
  const filtered = useMemo(() => {
    if (severity === "all") return findings;
    return findings.filter((f) => f.severity === severity);
  }, [findings, severity]);

  const setSeverity = (next: string) => {
    const sp = new URLSearchParams(params);
    if (next === "all") sp.delete("severity");
    else sp.set("severity", next);
    setParams(sp, { replace: true });
  };

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Diagnostics</h1>
          <p className="text-sm text-ink-muted max-w-3xl">
            Root-cause hints assembled from health, policy validation, audit,
            notifications, sessions, and kernel logs. Use this when something
            failed and you need the next useful place to look.
          </p>
          {initiativeId && (
            <div className="mt-2 text-xs text-ink-subtle">
              Focused on initiative <Mono>{initiativeId}</Mono>
            </div>
          )}
        </div>
        <div className="text-right text-xs text-ink-subtle">
          <div>Auto-refresh {Math.round(DIAGNOSTICS_POLL_MS / 1000)}s</div>
          <div title={fmtAbsolute(q.data?.generated_at ?? 0)}>
            Generated {fmtRelative(q.data?.generated_at ?? 0)}
          </div>
          {q.isFetching && <div className="text-accent">refreshing…</div>}
        </div>
      </header>

      <section className="card p-3">
        <div className="flex flex-wrap items-center gap-2">
          {["all", "critical", "high", "medium", "low"].map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSeverity(s)}
              className={clsx(
                "btn text-xs py-1 capitalize",
                severity === s && "border-accent text-accent bg-accent/10",
              )}
            >
              {s}{" "}
              <span className="text-ink-subtle">
                {s === "all" ? findings.length : counts[s] ?? 0}
              </span>
            </button>
          ))}
        </div>
      </section>

      <DiagnosticFindingsPanel findings={filtered} />
    </div>
  );
}

function countSeverities(findings: DiagnosticFinding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const finding of findings) {
    out[finding.severity] = (out[finding.severity] ?? 0) + 1;
  }
  return out;
}

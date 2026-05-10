import { useQuery } from "@tanstack/react-query";

import { dashboardApi } from "@/api/client";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtAbsolute, fmtRelative } from "@/lib/format";

export function HealthPage() {
  const q = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => dashboardApi.health(signal),
    refetchInterval: 5_000,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const h = q.data;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-ink">Kernel Health</h1>
        <p className="text-sm text-ink-muted">
          Doctor checklist for the running kernel. Auto-refreshes every 5s.
        </p>
      </header>

      <section className="card p-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Stat label="Status" value={h.status.toUpperCase()} tone={
            h.status === "ok" ? "ok" : h.status === "degraded" ? "warn" : "bad"
          } />
          <Stat label="Policy epoch" value={`#${h.policy_epoch}`} tone="info" />
          <Stat label="Active initiatives" value={String(h.active_initiatives)} />
          <Stat label="Active sessions" value={String(h.active_sessions)} />
        </div>
        <div className="mt-3 text-xs text-ink-subtle">
          Kernel booted {fmtRelative(h.kernel_booted_at)}
          {" · "}
          {fmtAbsolute(h.kernel_booted_at)}
        </div>
      </section>

      <section className="card p-0 overflow-hidden">
        <header className="px-4 py-3 border-b border-edge">
          <h2 className="text-sm font-semibold text-ink">Subsystem checks</h2>
        </header>
        {h.checks.length === 0 ? (
          <div className="py-8 text-center text-ink-subtle text-sm">
            No checks reported.
          </div>
        ) : (
          <ul className="divide-y divide-edge/40">
            {h.checks.map((c) => (
              <li
                key={c.id}
                className="px-4 py-2.5 flex items-center gap-3"
              >
                <span
                  className={
                    c.status === "ok"
                      ? "w-2.5 h-2.5 rounded-full bg-ok"
                      : c.status === "degraded"
                      ? "w-2.5 h-2.5 rounded-full bg-warn"
                      : "w-2.5 h-2.5 rounded-full bg-bad"
                  }
                  aria-hidden="true"
                />
                <Mono className="text-ink-muted w-56 shrink-0">{c.id}</Mono>
                <span className="text-sm text-ink flex-1">{c.message}</span>
                <span
                  className={`badge ${
                    c.status === "ok"
                      ? "bg-ok-muted/30 border-ok text-ok"
                      : c.status === "degraded"
                      ? "bg-warn-muted/30 border-warn text-warn"
                      : "bg-bad-muted/30 border-bad text-bad"
                  }`}
                >
                  {c.status}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function Stat({
  label,
  value,
  tone = "muted",
}: {
  label: string;
  value: string;
  tone?: "ok" | "warn" | "bad" | "info" | "muted";
}) {
  const c =
    tone === "ok"
      ? "text-ok"
      : tone === "warn"
      ? "text-warn"
      : tone === "bad"
      ? "text-bad"
      : tone === "info"
      ? "text-info"
      : "text-ink";
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-ink-subtle">{label}</div>
      <div className={`text-2xl font-semibold tabular ${c}`}>{value}</div>
    </div>
  );
}

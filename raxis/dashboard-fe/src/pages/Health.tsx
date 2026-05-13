import { useQuery } from "@tanstack/react-query";

import { dashboardApi } from "@/api/client";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import type { SubsystemHealthCard } from "@/types/api";

export function HealthPage() {
  const q = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => dashboardApi.health(signal),
    refetchInterval: 5_000,
  });
  // Subsystem cards are a separate endpoint so a slow per-card
  // query never blocks the coarse `/api/health` summary.
  const subQ = useQuery({
    queryKey: ["health", "subsystems"],
    queryFn: ({ signal }) => dashboardApi.subsystemHealth(signal),
    refetchInterval: 10_000,
    staleTime: 5_000,
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

      <section className="space-y-3">
        <header className="flex items-end justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-ink">Subsystems</h2>
            <p className="text-xs text-ink-muted">
              Per-subsystem verdicts from the kernel. Auto-refresh 10s.
            </p>
          </div>
          {subQ.data && (
            <span
              className={`badge ${aggregateBadge(subQ.data.aggregate_status)}`}
              data-aggregate-status={subQ.data.aggregate_status}
            >
              {subQ.data.aggregate_status.toUpperCase()}
            </span>
          )}
        </header>
        {subQ.isPending && (
          <div className="card p-4 text-sm text-ink-muted">
            Loading subsystem cards…
          </div>
        )}
        {subQ.error && !subQ.isPending && (
          <ErrorBox error={subQ.error} onRetry={() => subQ.refetch()} />
        )}
        {subQ.data && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {subQ.data.cards.map((card) => (
              <SubsystemCard key={card.id} card={card} />
            ))}
          </div>
        )}
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

function aggregateBadge(status: string): string {
  switch (status) {
    case "ok":
      return "bg-ok-muted/30 border-ok text-ok";
    case "degraded":
      return "bg-warn-muted/30 border-warn text-warn";
    case "failing":
      return "bg-bad-muted/30 border-bad text-bad";
    default:
      return "bg-panel-high border-edge text-ink-muted";
  }
}

function statusDotClass(status: string): string {
  switch (status) {
    case "ok":
      return "bg-ok";
    case "degraded":
      return "bg-warn";
    case "failing":
      return "bg-bad";
    default:
      return "bg-ink-subtle";
  }
}

function SubsystemCard({ card }: { card: SubsystemHealthCard }) {
  const isUnhealthy = card.status === "failing" || card.status === "degraded";
  // Operator-experience contract `INV-DASHBOARD-FAILURE-VISIBILITY-01`:
  // every `failing` / `degraded` card MUST surface its `last_error`.
  // When the kernel did NOT supply one we render an explicit
  // operator-actionable bug marker so the gap is visible rather
  // than silently swallowed by the green dot.
  const errorText =
    card.last_error?.trim() ||
    (isUnhealthy ? "No reason supplied — kernel bug" : "");
  return (
    <article
      className="card p-3 space-y-2"
      data-subsystem-id={card.id}
      data-subsystem-status={card.status}
    >
      <header className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span
            aria-hidden="true"
            className={`w-2.5 h-2.5 rounded-full ${statusDotClass(card.status)}`}
          />
          <h3 className="text-sm font-semibold text-ink truncate">
            {card.label}
          </h3>
        </div>
        <span className={`badge ${aggregateBadge(card.status)}`}>
          {card.status}
        </span>
      </header>
      <p className="text-xs text-ink-muted leading-snug">{card.summary}</p>
      {isUnhealthy && errorText && (
        <div
          role="alert"
          data-testid="subsystem-last-error"
          className="text-xs rounded border border-bad/40 bg-bad/10 text-bad px-2 py-1.5 whitespace-pre-wrap break-words leading-snug"
          title={errorText}
        >
          <span className="font-bold mr-1" aria-hidden="true">!</span>
          {errorText}
        </div>
      )}
      {card.details.length > 0 && (
        <dl className="text-[11px] text-ink-muted space-y-0.5">
          {card.details.map((row) => (
            <div key={row.label} className="flex gap-2">
              <dt className="shrink-0 text-ink-subtle">{row.label}:</dt>
              <dd className="truncate">{row.value}</dd>
            </div>
          ))}
        </dl>
      )}
      <footer className="flex items-center justify-between gap-2 text-[11px] text-ink-subtle">
        <Mono>{card.id}</Mono>
        <div className="flex items-center gap-2">
          {card.last_observed_at > 0 && (
            <span>{fmtRelative(card.last_observed_at)}</span>
          )}
          {card.grafana_url && (
            <a
              href={card.grafana_url}
              target="_blank"
              rel="noreferrer noopener"
              className="text-accent hover:underline"
            >
              Grafana ↗
            </a>
          )}
        </div>
      </footer>
    </article>
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

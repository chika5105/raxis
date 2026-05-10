import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import { fmtAbsolute, fmtRelative } from "@/lib/format";

export function TaskDetailPage() {
  const { id = "" } = useParams<{ id: string }>();

  const q = useQuery({
    queryKey: ["task", id],
    queryFn: ({ signal }) => dashboardApi.tasks.get(id, signal),
    refetchInterval: 4_000,
    enabled: id.length > 0,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const t = q.data;

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/initiatives" className="hover:text-accent">Initiatives</Link>
            <span>/</span>
            <Link
              to={`/initiatives/${t.initiative_id}`}
              className="hover:text-accent font-mono"
            >
              {t.initiative_id}
            </Link>
            <span>/</span>
            <Mono className="text-ink-muted">{t.task_id}</Mono>
            <CopyButton value={t.task_id} />
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink text-balance">
            {t.title}
          </h1>
          <div className="mt-2 flex items-center gap-2">
            <StateBadge state={t.state} pulse={t.state === "Running"} />
            <span className="text-xs text-ink-subtle">
              created {fmtRelative(t.created_at)}
              {" · "}updated {fmtRelative(t.updated_at)}
            </span>
          </div>
        </div>
        {t.session_id && (
          <Link to={`/sessions/${t.session_id}`} className="btn-primary">
            Open session →
          </Link>
        )}
      </header>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <section className="card p-4">
          <h2 className="text-sm font-semibold text-ink mb-3">Reviewer verdicts</h2>
          {t.reviewer_verdicts.length === 0 ? (
            <Empty
              title="No reviewer verdicts yet."
              hint="The reviewer driver will append verdicts here as they are emitted."
            />
          ) : (
            <ul className="space-y-3">
              {t.reviewer_verdicts.map((v, i) => (
                <li key={`${v.reviewer_session_id}-${i}`} className="border border-edge rounded p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={`badge ${
                        v.verdict.toLowerCase() === "approved"
                          ? "bg-ok-muted/30 border-ok text-ok"
                          : "bg-bad-muted/30 border-bad text-bad"
                      }`}
                    >
                      {v.verdict}
                    </span>
                    <span className="text-[11px] text-ink-subtle">
                      {fmtAbsolute(v.at)}
                    </span>
                  </div>
                  <Link
                    to={`/sessions/${v.reviewer_session_id}`}
                    className="text-xs text-accent hover:underline mt-1 inline-block"
                  >
                    <Mono>{v.reviewer_session_id}</Mono>
                  </Link>
                  {v.critique && (
                    <pre className="mt-2 text-[12px] whitespace-pre-wrap text-ink leading-relaxed font-sans">
                      {v.critique}
                    </pre>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-4">
          <h2 className="text-sm font-semibold text-ink mb-3">Structured outputs</h2>
          {t.structured_outputs.length === 0 ? (
            <Empty
              title="No structured outputs."
              hint={<>Outputs land here when the executor calls <code className="font-mono">structured_output</code>.</>}
            />
          ) : (
            <ul className="space-y-3">
              {t.structured_outputs.map((o, i) => (
                <li key={i} className="border border-edge rounded p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="badge bg-info-muted/30 border-info text-info">
                      {o.kind}
                    </span>
                    <span className="text-[11px] text-ink-subtle">
                      {fmtAbsolute(o.at)}
                    </span>
                  </div>
                  <pre className="mt-2 text-[11px] font-mono text-ink-muted overflow-x-auto scroll-thin max-h-64">
                    {JSON.stringify(o.payload, null, 2)}
                  </pre>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="card p-4">
        <h2 className="text-sm font-semibold text-ink mb-3">Path scope (allowlist)</h2>
        {t.path_allowlist.length === 0 ? (
          <p className="text-xs text-ink-subtle">No paths in the allowlist.</p>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {t.path_allowlist.map((p) => (
              <code
                key={p}
                className="font-mono text-[11px] px-2 py-1.5 rounded border border-edge bg-panel-high text-ink-muted truncate"
                title={p}
              >
                {p}
              </code>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

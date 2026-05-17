import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import type { WitnessView } from "@/types/api";

/// `<WitnessesPage>` — iter68 PR 5.
///
/// Cross-task newest-first witness timeline. Operators land here
/// when investigating a gate-rejection pattern that spans
/// multiple initiatives (e.g. "did the test-gate start failing
/// for everyone at the same time"). Per-task drill-down lives on
/// the TaskDetail page; this is the systemic view.
///
/// Backed by `GET /api/witnesses?limit=N` (capped at 500
/// server-side).

export function WitnessesPage() {
  const q = useQuery({
    queryKey: ["witnesses", "recent", 200],
    queryFn: ({ signal }) => dashboardApi.witnesses.list(200, signal),
    refetchInterval: 10_000,
  });

  if (q.isLoading) return <PageSpinner />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;

  const rows = q.data ?? [];
  const counts = summarise(rows);

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Witnesses</h1>
          <p className="text-sm text-ink-muted mt-0.5">
            Cross-task verdict timeline. Most-recent {rows.length} witness
            submissions across every initiative.
          </p>
        </div>
        <div className="flex items-center gap-1 text-[12px] flex-wrap">
          {counts.pass > 0 && (
            <VerdictPill kind="Pass" label={`${counts.pass} pass`} />
          )}
          {counts.fail > 0 && (
            <VerdictPill kind="Fail" label={`${counts.fail} fail`} />
          )}
          {counts.inconclusive > 0 && (
            <VerdictPill
              kind="Inconclusive"
              label={`${counts.inconclusive} inconclusive`}
            />
          )}
        </div>
      </header>

      {rows.length === 0 ? (
        <Empty
          title="No witnesses yet."
          hint={
            <>
              Witnesses land here as the kernel records each
              <code className="font-mono mx-1">SubmitWitness</code>
              the verifier accepts. Configure a gate in
              <code className="font-mono mx-1">policy.toml</code>
              to start producing rows.
            </>
          }
        />
      ) : (
        <section className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-panel-high text-[11px] uppercase tracking-wide text-ink-subtle">
              <tr>
                <th className="text-left px-3 py-2">Verdict</th>
                <th className="text-left px-3 py-2">Gate</th>
                <th className="text-left px-3 py-2">Task</th>
                <th className="text-left px-3 py-2">Eval sha</th>
                <th className="text-left px-3 py-2">Recorded</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((w) => (
                <tr
                  key={`${w.verifier_run_id}-${w.gate_type}-${w.recorded_at}`}
                  className="border-t border-edge hover:bg-panel-high transition-colors"
                >
                  <td className="px-3 py-2 align-middle">
                    <VerdictPill kind={w.result_class} />
                  </td>
                  <td className="px-3 py-2 align-middle font-mono text-[12px] text-ink">
                    {w.gate_type}
                  </td>
                  <td className="px-3 py-2 align-middle">
                    <div className="flex items-center gap-1 min-w-0">
                      <Link
                        to={`/tasks/${encodeURIComponent(w.task_id)}`}
                        className="hover:text-accent"
                      >
                        <Mono className="truncate text-[12px]">
                          {w.task_id}
                        </Mono>
                      </Link>
                      <CopyButton value={w.task_id} />
                    </div>
                  </td>
                  <td className="px-3 py-2 align-middle">
                    <div className="flex items-center gap-1 min-w-0">
                      <Mono className="truncate text-[12px] text-ink-muted">
                        {w.evaluation_sha.slice(0, 12)}
                      </Mono>
                      <CopyButton value={w.evaluation_sha} />
                    </div>
                  </td>
                  <td
                    className="px-3 py-2 align-middle text-[12px] text-ink-muted whitespace-nowrap"
                    title={fmtAbsolute(w.recorded_at)}
                  >
                    {fmtRelative(w.recorded_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}

function summarise(rows: WitnessView[]) {
  let pass = 0;
  let fail = 0;
  let inconclusive = 0;
  for (const r of rows) {
    switch (r.result_class) {
      case "Pass":
        pass += 1;
        break;
      case "Fail":
        fail += 1;
        break;
      case "Inconclusive":
        inconclusive += 1;
        break;
    }
  }
  return { pass, fail, inconclusive };
}

function VerdictPill({ kind, label }: { kind: string; label?: string }) {
  const klass = (() => {
    switch (kind) {
      case "Pass":
        return "bg-success-muted/40 border-success text-success";
      case "Fail":
        return "bg-danger-muted/40 border-danger text-danger";
      case "Inconclusive":
        return "bg-warning-muted/40 border-warning text-warning";
      default:
        return "bg-panel-high border-edge text-ink-muted";
    }
  })();
  return <span className={`badge ${klass}`}>{label ?? kind}</span>;
}

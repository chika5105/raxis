import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { DagGraph } from "@/components/DagGraph";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import {
  fmtAbsolute,
  fmtRelative,
  plural,
  shortFingerprint,
  shortSha,
} from "@/lib/format";

export function InitiativeDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [selectedTask, setSelectedTask] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["initiative", id],
    queryFn: ({ signal }) => dashboardApi.initiatives.get(id, signal),
    refetchInterval: 4_000,
    enabled: id.length > 0,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const init = q.data;
  const focusedTask =
    selectedTask && init.tasks.find((t) => t.task_id === selectedTask);

  return (
    <div className="space-y-5">
      <header className="flex items-start gap-4 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/initiatives" className="hover:text-accent">
              Initiatives
            </Link>
            <span>/</span>
            <Mono className="text-ink-muted">{init.initiative_id}</Mono>
            <CopyButton value={init.initiative_id} />
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink text-balance">
            {init.display_name}
          </h1>
          <div className="mt-2 flex flex-wrap gap-2 items-center">
            <StateBadge state={init.state} pulse={init.state === "Active"} />
            <span className="text-xs text-ink-muted">
              {plural(init.task_count, "task")} · {init.completed_tasks} done
              {init.failed_tasks > 0 && (
                <span className="text-bad"> · {init.failed_tasks} failed</span>
              )}
            </span>
            <span className="text-xs text-ink-subtle">
              · created {fmtRelative(init.created_at)}
            </span>
            <span className="text-xs text-ink-subtle">
              · updated {fmtRelative(init.updated_at)}
            </span>
          </div>
        </div>

        <div className="card p-3 text-xs space-y-1.5 min-w-[220px]">
          <Row label="Approved by" value={init.approved_by ?? "—"} mono />
          <Row label="Plan SHA" value={shortSha(init.plan_sha256)} mono />
          <Row label="Target ref" value={init.target_ref ?? "—"} mono />
          <Row label="Policy epoch" value={`#${init.policy_epoch}`} />
        </div>
      </header>

      {/* DAG */}
      <section className="card p-4">
        <header className="flex items-center justify-between mb-2 gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-ink">Task DAG</h2>
          <div className="flex items-center gap-3 text-[11px] text-ink-subtle">
            <span>Click to focus · double-click to open task</span>
            <Link
              to={`/initiatives/${init.initiative_id}/dag`}
              className="text-accent hover:underline"
            >
              Full DAG view →
            </Link>
          </div>
        </header>
        {init.tasks.length === 0 ? (
          <Empty title="This initiative has no tasks." />
        ) : (
          <DagGraph
            nodes={init.tasks.map((t) => ({
              task_id: t.task_id,
              title: t.title,
              state: t.state,
            }))}
            edges={init.edges}
            onSelect={setSelectedTask}
            onActivate={(taskId) => navigate(`/tasks/${taskId}`)}
            selected={selectedTask}
            height={Math.min(640, 80 + init.tasks.length * 40)}
          />
        )}
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Task list */}
        <section className="card p-0 overflow-hidden xl:col-span-2">
          <header className="px-4 py-3 border-b border-edge flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">Tasks</h2>
            <span className="text-xs text-ink-subtle">
              {plural(init.tasks.length, "task")}
            </span>
          </header>
          {init.tasks.length === 0 ? (
            <Empty title="No tasks." />
          ) : (
            <table className="w-full text-sm">
              <thead className="text-xs text-ink-subtle">
                <tr className="border-b border-edge">
                  <th className="text-left px-4 py-2 font-medium">Task</th>
                  <th className="text-left px-4 py-2 font-medium">State</th>
                  <th className="text-left px-4 py-2 font-medium">Session</th>
                  <th className="text-right px-4 py-2 font-medium">Updated</th>
                </tr>
              </thead>
              <tbody>
                {init.tasks.map((t) => (
                  <tr
                    key={t.task_id}
                    className={`border-b border-edge/40 last:border-b-0 hover:bg-panel-high cursor-pointer ${
                      selectedTask === t.task_id ? "bg-panel-high" : ""
                    }`}
                    onClick={() => setSelectedTask(t.task_id)}
                  >
                    <td className="px-4 py-2">
                      <Link
                        to={`/tasks/${t.task_id}`}
                        className="text-ink hover:text-accent"
                      >
                        {t.title}
                      </Link>
                      <div className="text-[11px] text-ink-subtle">
                        <Mono>{t.task_id}</Mono>
                      </div>
                    </td>
                    <td className="px-4 py-2">
                      <StateBadge
                        state={t.state}
                        pulse={t.state === "Running"}
                      />
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {t.session_id ? (
                        <Link
                          to={`/sessions/${t.session_id}`}
                          className="text-accent hover:underline font-mono"
                        >
                          {t.session_id.slice(0, 12)}…
                        </Link>
                      ) : (
                        <span className="text-ink-subtle">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-right text-xs text-ink-muted">
                      {fmtRelative(t.updated_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {/* Focused task panel */}
        <aside className="card p-4">
          <h2 className="text-sm font-semibold text-ink mb-2">
            {focusedTask ? "Focused task" : "Task detail"}
          </h2>
          {focusedTask ? (
            <>
              <Link
                to={`/tasks/${focusedTask.task_id}`}
                className="text-base font-medium text-ink hover:text-accent"
              >
                {focusedTask.title}
              </Link>
              <div className="text-xs text-ink-subtle mt-0.5 flex items-center gap-1">
                <Mono>{focusedTask.task_id}</Mono>
                <CopyButton value={focusedTask.task_id} />
              </div>
              <div className="mt-3 flex items-center gap-2">
                <StateBadge
                  state={focusedTask.state}
                  pulse={focusedTask.state === "Running"}
                />
              </div>
              <dl className="mt-3 space-y-2 text-xs">
                <Row
                  label="Session"
                  value={
                    focusedTask.session_id ? (
                      <Link
                        to={`/sessions/${focusedTask.session_id}`}
                        className="text-accent hover:underline"
                      >
                        <Mono>{focusedTask.session_id}</Mono>
                      </Link>
                    ) : (
                      "—"
                    )
                  }
                />
                <Row
                  label="Reviewer verdicts"
                  value={String(focusedTask.reviewer_verdicts.length)}
                />
                <Row
                  label="Outputs"
                  value={String(focusedTask.structured_outputs.length)}
                />
                <Row
                  label="Path scope"
                  value={
                    <div className="font-mono text-[11px] mt-1 max-h-32 overflow-y-auto scroll-thin">
                      {focusedTask.path_allowlist.length === 0 ? (
                        <span className="text-ink-subtle">—</span>
                      ) : (
                        focusedTask.path_allowlist.map((p) => (
                          <div key={p} className="text-ink-muted truncate">
                            {p}
                          </div>
                        ))
                      )}
                    </div>
                  }
                />
                <Row
                  label="Created"
                  value={fmtAbsolute(focusedTask.created_at)}
                />
                <Row
                  label="Updated"
                  value={fmtAbsolute(focusedTask.updated_at)}
                />
              </dl>
              <Link
                to={`/tasks/${focusedTask.task_id}`}
                className="btn w-full justify-center mt-4"
              >
                Open task page →
              </Link>
            </>
          ) : (
            <p className="text-xs text-ink-subtle">
              Select a task in the DAG or table to view its detail summary.
            </p>
          )}
        </aside>
      </div>
    </div>
  );
}

interface RowProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}

function Row({ label, value, mono }: RowProps) {
  return (
    <div className="flex items-start gap-3 text-xs">
      <span className="w-24 text-ink-subtle uppercase tracking-wider text-[10px] mt-0.5 shrink-0">
        {label}
      </span>
      <span
        className={`flex-1 min-w-0 ${mono ? "font-mono text-ink-muted" : "text-ink"}`}
      >
        {typeof value === "string" && mono && value.length > 18 ? (
          <span title={value}>{shortFingerprint(value)}</span>
        ) : (
          value
        )}
      </span>
    </div>
  );
}

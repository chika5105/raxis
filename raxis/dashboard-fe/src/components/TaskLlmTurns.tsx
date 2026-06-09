// `<TaskLlmTurns>` — the per-task LLM-turn panel.
//
// Consumes `GET /api/tasks/:task_id/llm-turns?limit=N` and
// renders one collapsible card per turn with:
//
//   * Turn number + timestamp + model + role
//   * Request preview (collapsed by default)
//   * Response preview
//   * Per-turn usage:
//       input_tokens, output_tokens,
//       cache_creation_input_tokens, cache_read_input_tokens,
//       cache_hit_ratio (FE-derived).
//     The ratio is colour coded: green > 0.8, yellow 0.3..0.8,
//     red < 0.3 / N/A so the operator's eye picks bad cache
//     behaviour out of a long-running task.
//   * Latency (when the kernel-side tap recorded one).
//
// `INV-DASHBOARD-LLM-TURN-CAPTURED-01` (paired with the
// kernel-side tap).

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Spinner } from "@/components/Spinner";
import { fmtAbsolute, fmtTokens } from "@/lib/format";
import type { TaskLlmTurnView } from "@/types/api";

interface Props {
  taskId: string;
  /// Tail size; clamped backend-side. Default 100.
  n?: number;
}

export function TaskLlmTurns({ taskId, n = 100 }: Props) {
  const q = useQuery({
    queryKey: ["task-llm-turns", taskId, n],
    queryFn: ({ signal }) => dashboardApi.tasks.llmTurns(taskId, n, signal),
    refetchInterval: 6_000,
    enabled: taskId.length > 0,
  });

  return (
    <section data-testid="task-llm-turns" className="card p-4 space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h2 className="text-sm font-semibold text-ink">LLM turns</h2>
        <span className="text-[11px] text-ink-subtle">
          last {n} turns · auto-refresh 6s
        </span>
      </div>
      {q.isPending ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : !q.data || q.data.length === 0 ? (
        <Empty
          title="No LLM turns recorded yet."
          hint="Turns appear here once the kernel-side gateway tap forwards them to the dashboard's TaskLlmCapture writer."
        />
      ) : (
        <ol data-testid="task-llm-turns-list" className="space-y-3">
          {q.data.map((turn, i) => (
            <li
              key={`${turn.turn_number}-${i}`}
              data-testid="task-llm-turns-row"
            >
              <TurnCard turn={turn} />
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

interface TurnCardProps {
  turn: TaskLlmTurnView;
}

function TurnCard({ turn }: TurnCardProps) {
  const [reqOpen, setReqOpen] = useState(false);
  const [respOpen, setRespOpen] = useState(false);
  const ratio = cacheHitRatio(turn);
  const ratioCls = ratioColourClass(ratio);
  return (
    <div className="border border-edge rounded p-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-info-muted/30 border-info text-info">
            Turn {turn.turn_number}
          </span>
          {turn.agent_role && (
            <span
              data-testid="task-llm-turns-agent-role"
              data-agent-role={turn.agent_role}
              className={`badge ${agentRoleClasses(turn.agent_role)}`}
              title="Which raxis session originated this call"
            >
              {turn.agent_role}
            </span>
          )}
          {turn.provider && (
            <span
              data-testid="task-llm-turns-provider"
              className="badge bg-accent/10 border-accent/30 text-accent font-mono text-[11px]"
              title="Observed LLM provider"
            >
              {turn.provider}
            </span>
          )}
          <span className="text-[11px] text-ink-subtle">
            {fmtAbsolute(turn.ts_unix)}
          </span>
          {turn.model && (
            <span className="text-[11px] font-mono text-ink-muted">
              {turn.model}
            </span>
          )}
          {turn.role && (
            <span
              className="text-[11px] text-ink-faint"
              title="Upstream LLM speaker (provider role)"
            >
              {turn.role}
            </span>
          )}
          {turn.error && (
            <span
              data-testid="task-llm-turns-error-badge"
              className="badge bg-bad-muted/30 border-bad text-bad"
              title="Upstream gateway error category"
            >
              upstream error: {turn.error}
            </span>
          )}
        </div>
        {turn.latency_ms !== null && turn.latency_ms !== undefined && (
          <span
            className="text-[11px] text-ink-subtle"
            title="Wall-clock latency"
          >
            {turn.latency_ms} ms
          </span>
        )}
      </div>

      <dl className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-x-3 gap-y-1 text-[11px]">
        <div>
          <dt className="text-ink-faint uppercase">in</dt>
          <dd className="font-mono text-ink-muted">
            {fmtTokens(turn.input_tokens ?? 0)}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint uppercase">out</dt>
          <dd className="font-mono text-ink-muted">
            {fmtTokens(turn.output_tokens ?? 0)}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint uppercase">cache rd</dt>
          <dd className="font-mono text-ink-muted">
            {fmtTokens(turn.cache_read_input_tokens ?? 0)}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint uppercase">cache crt</dt>
          <dd className="font-mono text-ink-muted">
            {fmtTokens(turn.cache_creation_input_tokens ?? 0)}
          </dd>
        </div>
      </dl>

      <div
        data-testid="task-llm-turns-cache-hit-ratio"
        className={`mt-2 inline-block badge ${ratioCls}`}
      >
        cache hit{" "}
        {ratio === null ? "N/A" : `${(ratio * 100).toFixed(0)}%`}
      </div>

      <div className="mt-3 space-y-2">
        <details
          open={reqOpen}
          onToggle={(e) => setReqOpen((e.target as HTMLDetailsElement).open)}
        >
          <summary className="text-[11px] text-accent cursor-pointer">
            Request payload
          </summary>
          <pre className="mt-1 max-h-64 overflow-auto overscroll-auto scroll-thin text-[10px] font-mono text-ink-muted whitespace-pre-wrap">
            {safeStringify(turn.request)}
          </pre>
        </details>
        <details
          open={respOpen}
          onToggle={(e) => setRespOpen((e.target as HTMLDetailsElement).open)}
        >
          <summary className="text-[11px] text-accent cursor-pointer">
            Response payload
            {turn.body_truncated && (
              <span
                data-testid="task-llm-turns-truncation-badge"
                className="ml-2 text-[10px] text-warn"
              >
                (truncated, original size {turn.original_body_bytes ?? 0} bytes)
              </span>
            )}
          </summary>
          <pre className="mt-1 max-h-64 overflow-auto overscroll-auto scroll-thin text-[10px] font-mono text-ink-muted whitespace-pre-wrap">
            {safeStringify(turn.response)}
          </pre>
        </details>
      </div>
    </div>
  );
}

function cacheHitRatio(turn: TaskLlmTurnView): number | null {
  const cacheRead = turn.cache_read_input_tokens ?? 0;
  const cacheCreate = turn.cache_creation_input_tokens ?? 0;
  const fresh = turn.input_tokens ?? 0;
  const denom = cacheRead + cacheCreate + fresh;
  if (denom <= 0) return null;
  return cacheRead / denom;
}

/// Map originating agent role → badge tone. Orchestrator =
/// accent (the planner conducting the initiative), Executor =
/// info (the do-er), Reviewer = warn (the gating critic). Any
/// unknown role falls through to the neutral edge tone so a
/// future role rolls forward without a UI break.
function agentRoleClasses(role: string): string {
  switch (role) {
    case "Orchestrator":
      return "bg-accent/15 border-accent text-accent";
    case "Executor":
      return "bg-info-muted/30 border-info text-info";
    case "Reviewer":
      return "bg-warn-muted/30 border-warn text-warn";
    default:
      return "bg-panel-raised border-edge text-ink-muted";
  }
}

function ratioColourClass(ratio: number | null): string {
  if (ratio === null) return "bg-bad-muted/20 border-bad text-bad";
  if (ratio >= 0.8) return "bg-ok-muted/30 border-ok text-ok";
  if (ratio >= 0.3) return "bg-warn-muted/30 border-warn text-warn";
  return "bg-bad-muted/30 border-bad text-bad";
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

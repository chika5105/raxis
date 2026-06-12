import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtRelative } from "@/lib/format";
import type { EscalationView } from "@/types/api";

export function EscalationsPage() {
  const navigate = useNavigate();
  const q = useQuery({
    queryKey: ["escalations"],
    queryFn: ({ signal }) => dashboardApi.escalations.list(signal),
    refetchInterval: 5_000,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const items = q.data;

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-ink">Escalations</h1>
        <p className="text-sm text-ink-muted">Pending operator-action items.</p>
      </header>

      {items.length === 0 ? (
        <Empty title="No pending escalations." hint="Operator inbox is clear." />
      ) : (
        <ul className="space-y-3">
          {items.map((e) => {
            const href = `/initiatives/${e.initiative_id}`;
            const commands = operatorCommands(e);
            const commandTitle =
              e.action_required === "LogicalDeadlock"
                ? "Recovery commands"
                : "Operator commands";
            return (
            <li
              key={e.escalation_id}
              tabIndex={0}
              onClick={() => navigate(href)}
              onKeyDown={(ev) => {
                if (ev.key === "Enter") {
                  ev.preventDefault();
                  navigate(href);
                }
              }}
              className="card p-4 cursor-pointer hover:border-accent/60 hover:bg-panel-high/40 transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-accent"
            >
              <div className="grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
                <div className="flex-1 min-w-0">
                  <div className="flex min-w-0 flex-wrap items-start gap-2">
                    <span
                      className={`badge ${
                        e.severity === "High"
                          ? "bg-bad-muted/30 border-bad text-bad"
                          : e.severity === "Normal"
                          ? "bg-warn-muted/30 border-warn text-warn"
                          : "bg-edge/40 border-edge-strong text-ink-muted"
                      }`}
                    >
                      {e.severity}
                    </span>
                    <Link
                      to={href}
                      onClick={(ev) => ev.stopPropagation()}
                      title={e.initiative_id}
                      className="min-w-0 max-w-full break-all font-mono text-sm text-accent [overflow-wrap:anywhere] hover:underline"
                    >
                      {e.initiative_id}
                    </Link>
                    {e.task_id && (
                      <Link
                        to={`/tasks/${e.task_id}`}
                        onClick={(ev) => ev.stopPropagation()}
                        title={e.task_id}
                        className="min-w-0 max-w-full break-all font-mono text-xs text-ink-muted [overflow-wrap:anywhere] hover:text-accent"
                      >
                        / {e.task_id}
                      </Link>
                    )}
                  </div>
                  <p className="mt-2 min-w-0 whitespace-pre-wrap break-words text-sm text-ink [overflow-wrap:anywhere]">
                    {e.reason}
                  </p>
                  <p className="mt-2 text-xs text-ink-muted">
                    <strong className="text-ink">Action required:</strong>{" "}
                    {e.action_required}
                  </p>
                  {commands.length > 0 && (
                    <div
                      className="mt-3 rounded border border-edge bg-panel-high p-3"
                      onClick={(ev) => ev.stopPropagation()}
                    >
                      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                        <p className="text-xs font-semibold text-ink">
                          {commandTitle}
                        </p>
                        <p className="text-[11px] text-ink-muted">
                          Requires <Mono>RAXIS_OPERATOR_KEY</Mono>
                        </p>
                      </div>
                      <div className="mt-2 space-y-2">
                        {commands.map((cmd) => (
                          <CommandHint key={cmd.label} {...cmd} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <div className="min-w-0 text-left text-xs text-ink-subtle sm:text-right">
                  <Mono title={e.escalation_id} className="break-all [overflow-wrap:anywhere]">
                    {e.escalation_id.slice(0, 12)}…
                  </Mono>
                  <div>{fmtRelative(e.created_at)}</div>
                </div>
              </div>
            </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

interface CommandHintProps {
  label: string;
  command: string;
}

function CommandHint({ label, command }: CommandHintProps) {
  return (
    <div className="grid min-w-0 gap-1 sm:grid-cols-[6.5rem_minmax(0,1fr)_auto] sm:items-start">
      <span className="text-[11px] font-medium text-ink-muted">{label}</span>
      <code className="min-w-0 whitespace-pre-wrap break-all rounded border border-edge bg-panel px-2 py-1.5 font-mono text-[11px] leading-relaxed text-ink [overflow-wrap:anywhere]">
        {command}
      </code>
      <CopyButton value={command} label={`Copy ${label.toLowerCase()} command`} />
    </div>
  );
}

function operatorCommands(e: EscalationView): CommandHintProps[] {
  if (e.action_required !== "LogicalDeadlock") {
    return [
      {
        label: "Approve",
        command:
          `raxis --operator-key "$RAXIS_OPERATOR_KEY" escalation approve ${shellQuote(e.escalation_id)} ` +
          "--scope <capability_class> --max-uses 1 --valid-for 600",
      },
      {
        label: "Deny",
        command:
          `raxis --operator-key "$RAXIS_OPERATOR_KEY" escalation deny ${shellQuote(e.escalation_id)} ` +
          '--reason "Denied by operator"',
      },
    ];
  }

  return [
    {
      label: "Resume",
      command:
        `raxis --operator-key "$RAXIS_OPERATOR_KEY" escalation approve ${shellQuote(e.escalation_id)} ` +
        "--scope LogicalDeadlock --max-uses 1 --valid-for 600",
    },
    {
      label: "Fail",
      command:
        `raxis --operator-key "$RAXIS_OPERATOR_KEY" escalation deny ${shellQuote(e.escalation_id)} ` +
        '--reason "Do not retry recovery; preserve failed state"',
    },
  ];
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9._:/@%+=,-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\"'\"'")}'`;
}

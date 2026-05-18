// `<GateLifecycleCard>` renders mechanical witness / gate-fixup
// lifecycle annotations. These are kernel-owned state transitions,
// not planner-authored explanations, so the card keeps the copy
// compact and puts ids / counters where operators can scan them.

import { Link } from "react-router-dom";

import { Mono } from "@/components/Mono";
import { fmtAbsolute, shortSha } from "@/lib/format";
import type { LifecycleAnnotation } from "@/types/api";

type GateAnnotation = Extract<
  LifecycleAnnotation,
  | { kind: "gate_rejection_accepted" }
  | { kind: "gate_fixup_spawned" }
  | { kind: "gate_rejection_terminal" }
  | { kind: "gate_fixup_completed" }
  | { kind: "witness_rejected" }
  | { kind: "verifier_process_failed" }
>;

interface Props {
  a: GateAnnotation;
}

function title(a: GateAnnotation): string {
  switch (a.kind) {
    case "gate_rejection_accepted":
      return "Gate rejected";
    case "gate_fixup_spawned":
      return "Fixup spawned";
    case "gate_rejection_terminal":
      return "Gate terminal";
    case "gate_fixup_completed":
      return "Fixup completed";
    case "witness_rejected":
      return "Witness rejected";
    case "verifier_process_failed":
      return "Verifier failed";
  }
}

function tone(a: GateAnnotation): string {
  switch (a.kind) {
    case "gate_rejection_terminal":
    case "witness_rejected":
    case "verifier_process_failed":
      return "border-bad/40 bg-bad/5";
    case "gate_rejection_accepted":
      return "border-warn/40 bg-warn/5";
    case "gate_fixup_spawned":
    case "gate_fixup_completed":
      return "border-info/40 bg-info/5";
  }
}

export function GateLifecycleCard({ a }: Props) {
  return (
    <div data-testid={`lifecycle-${a.kind}`} className={`card p-3 ${tone(a)}`}>
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-panel border-edge text-ink">{title(a)}</span>
          <span className="text-[11px] text-ink-subtle">
            {fmtAbsolute(a.ts_unix)}
          </span>
        </div>
        {"gate_type" in a && a.gate_type ? (
          <span className="text-[11px] font-mono text-ink-subtle">
            {a.gate_type}
          </span>
        ) : null}
      </div>

      {a.kind === "gate_rejection_accepted" && (
        <>
          <div className="mt-2 text-xs text-ink-muted">
            Fixup budget {a.attempt_index}/{a.max_attempts}; verifier{" "}
            <Mono>{a.verifier_run_id}</Mono>
          </div>
          <div className="mt-1 text-[11px] text-ink-subtle">
            evaluation <Mono>{shortSha(a.evaluation_sha)}</Mono>
          </div>
          {a.critique && (
            <pre className="mt-2 whitespace-pre-wrap text-[12px] leading-relaxed text-ink">
              {a.critique}
            </pre>
          )}
        </>
      )}

      {a.kind === "gate_fixup_spawned" && (
        <div className="mt-2 space-y-1 text-xs text-ink-muted">
          <div>
            Attempt {a.attempt_index} admitted as{" "}
            <Link
              to={`/tasks/${encodeURIComponent(a.fixup_task_id)}`}
              className="text-accent hover:underline"
            >
              <Mono>{a.fixup_task_id}</Mono>
            </Link>
          </div>
          <div className="text-[11px] text-ink-subtle">
            parent <Mono>{a.parent_task_id}</Mono> at{" "}
            <Mono>{shortSha(a.parent_evaluation_sha)}</Mono>
          </div>
        </div>
      )}

      {a.kind === "gate_rejection_terminal" && (
        <div className="mt-2 text-xs text-ink-muted">
          Reason <Mono>{a.terminal_reason}</Mono>; attempts used{" "}
          {a.attempts_used}
        </div>
      )}

      {a.kind === "gate_fixup_completed" && (
        <div className="mt-2 space-y-1 text-xs text-ink-muted">
          <div>
            <Link
              to={`/tasks/${encodeURIComponent(a.fixup_task_id)}`}
              className="text-accent hover:underline"
            >
              <Mono>{a.fixup_task_id}</Mono>
            </Link>{" "}
            finished with <Mono>{a.outcome}</Mono>
          </div>
          {a.new_evaluation_sha && (
            <div className="text-[11px] text-ink-subtle">
              new evaluation <Mono>{shortSha(a.new_evaluation_sha)}</Mono>
            </div>
          )}
        </div>
      )}

      {a.kind === "witness_rejected" && (
        <div className="mt-2 text-xs text-ink-muted">
          <Mono>{a.verifier_run_id}</Mono> rejected as <Mono>{a.reason}</Mono>
        </div>
      )}

      {a.kind === "verifier_process_failed" && (
        <div className="mt-2 text-xs text-ink-muted">
          Process exited before a valid witness
          {a.exit_code !== null && a.exit_code !== undefined ? (
            <>
              {" "}
              with code <Mono>{String(a.exit_code)}</Mono>
            </>
          ) : null}
        </div>
      )}
    </div>
  );
}

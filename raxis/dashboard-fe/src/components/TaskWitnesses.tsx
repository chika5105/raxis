import { useQuery } from "@tanstack/react-query";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { Spinner } from "@/components/Spinner";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import { toneClasses, type StateBadgeTone } from "@/lib/state-color";
import type { WitnessView } from "@/types/api";

/// `<TaskWitnesses>` — iter68 PR 3.
///
/// Renders every witness submission recorded against the task,
/// newest first. Each row carries the gate / verdict / blob-sha
/// metadata; the operator can copy the `blob_sha256` to drill
/// into the verifier body on disk (`<data_dir>/witness/<sha>`).
///
/// Backed by `GET /api/tasks/:task_id/witnesses`.

export function TaskWitnesses({ taskId }: { taskId: string }) {
  const q = useQuery({
    queryKey: ["task", taskId, "witnesses"],
    queryFn: ({ signal }) => dashboardApi.tasks.witnesses(taskId, signal),
    refetchInterval: 6_000,
    enabled: taskId.length > 0,
  });

  if (q.isPending) {
    return (
      <section className="card p-4">
        <h2 className="text-sm font-semibold text-ink mb-3">Witnesses</h2>
        <div className="flex items-center gap-2 text-xs text-ink-subtle">
          <Spinner /> Loading witnesses…
        </div>
      </section>
    );
  }
  if (q.error) {
    return (
      <section className="card p-4">
        <h2 className="text-sm font-semibold text-ink mb-3">Witnesses</h2>
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      </section>
    );
  }

  const rows = q.data ?? [];
  const counts = summarise(rows);

  return (
    <section className="card p-4">
      <header className="flex items-center justify-between mb-3 gap-2 flex-wrap">
        <h2 className="text-sm font-semibold text-ink">Witnesses</h2>
        <div className="flex items-center gap-1 text-[11px]">
          {counts.pending > 0 && (
            <VerdictPill label={`${counts.pending} pending`} kind="Pending" />
          )}
          {counts.pass > 0 && (
            <VerdictPill label={`${counts.pass} pass`} kind="Pass" />
          )}
          {counts.fail > 0 && (
            <VerdictPill label={`${counts.fail} fail`} kind="Fail" />
          )}
          {counts.inconclusive > 0 && (
            <VerdictPill
              label={`${counts.inconclusive} inconclusive`}
              kind="Inconclusive"
            />
          )}
          <span className="text-ink-subtle ml-1">
            {rows.length} total
          </span>
        </div>
      </header>

      {rows.length === 0 ? (
        <Empty
          title="No witnesses yet."
          hint={
            <>
              The kernel records verifier runs here as soon as they
              start. Pending runs become Pass, Fail, or Inconclusive
              when the verifier callback lands.
            </>
          }
        />
      ) : (
        <ul className="space-y-2">
          {rows.map((w) => (
            <WitnessRow key={witnessKey(w)} witness={w} />
          ))}
        </ul>
      )}
    </section>
  );
}

function summarise(rows: WitnessView[]) {
  let pass = 0;
  let fail = 0;
  let inconclusive = 0;
  let pending = 0;
  for (const r of rows) {
    switch (r.result_class) {
      case "Pending":
        pending += 1;
        break;
      case "Pass":
        pass += 1;
        break;
      case "Fail":
        fail += 1;
        break;
      case "SpawnFailed":
      case "ProcessFailed":
      case "Timeout":
      case "ConfigInvalid":
      case "BudgetExhausted":
      case "CapExceeded":
        fail += 1;
        break;
      case "Inconclusive":
        inconclusive += 1;
        break;
    }
  }
  return { pending, pass, fail, inconclusive };
}

function witnessKey(w: WitnessView): string {
  return `${w.verifier_run_id}:${w.gate_type}:${w.recorded_at}`;
}

function WitnessRow({ witness }: { witness: WitnessView }) {
  return (
    <li className="border border-edge rounded px-3 py-2">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <VerdictPill kind={witness.result_class} />
          <span className="font-mono text-[11px] text-ink">
            {witness.gate_type}
          </span>
          <span className="badge bg-surface-muted text-ink-muted border-edge">
            {gateSourceLabel(witness.gate_source)}
          </span>
          <span className="badge bg-surface-muted text-ink-muted border-edge">
            {hookLabel(witness.gate_hook)}
          </span>
          <Mono className="text-[11px] text-ink-muted truncate">
            {witness.evaluation_sha.slice(0, 12)}
          </Mono>
        </div>
        <span className="text-[11px] text-ink-subtle whitespace-nowrap">
          {fmtRelative(witness.recorded_at)}
        </span>
      </div>
      <dl className="mt-1.5 grid grid-cols-2 md:grid-cols-3 gap-1.5 text-[11px]">
        <Field label="Run id">
          <Mono className="truncate">{witness.verifier_run_id}</Mono>
          <CopyButton value={witness.verifier_run_id} />
        </Field>
        <Field label="Eval sha">
          <Mono className="truncate">{witness.evaluation_sha}</Mono>
          <CopyButton value={witness.evaluation_sha} />
        </Field>
        <Field label="Blob sha256">
          {witness.blob_sha256 ? (
            <>
              <span title={witness.blob_sha256} className="min-w-0 truncate">
                <Mono className="truncate">
                  {witness.blob_sha256.slice(0, 16)}…
                </Mono>
              </span>
              <CopyButton value={witness.blob_sha256} />
            </>
          ) : (
            <span className="text-ink-subtle">pending</span>
          )}
        </Field>
        <Field label="Verifier">
          <span className="truncate">
            {witness.verifier_image_alias ?? witness.verifier_command ?? "unknown"}
          </span>
        </Field>
        <Field label="Failure mode">
          <span className="truncate">{witness.verifier_on_failure ?? "record"}</span>
        </Field>
        <Field label="Recorded">{fmtAbsolute(witness.recorded_at)}</Field>
      </dl>
    </li>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-ink-subtle">{label}</dt>
      <dd className="text-ink flex items-center gap-1 min-w-0">{children}</dd>
    </div>
  );
}

function VerdictPill({ kind, label }: { kind: string; label?: string }) {
  const tone = WITNESS_TONE[kind] ?? "muted";
  return <span className={`badge ${toneClasses(tone)}`}>{label ?? kind}</span>;
}

const WITNESS_TONE: Record<string, StateBadgeTone> = {
  Pending: "info",
  Pass: "ok",
  Fail: "bad",
  Inconclusive: "warn",
  SpawnFailed: "bad",
  ProcessFailed: "bad",
  Timeout: "bad",
  ConfigInvalid: "bad",
  BudgetExhausted: "bad",
  CapExceeded: "bad",
};

function gateSourceLabel(source: string | undefined): string {
  switch (source) {
    case "task_verifier":
      return "Per-task";
    case "plan_integration_verifier":
      return "Plan integration";
    case "policy_integration_verifier":
      return "Policy integration";
    case "integration_verifier":
      return "Integration";
    case "policy_gate":
      return "Policy";
    default:
      return source ?? "Gate";
  }
}

function hookLabel(hook: string | undefined): string {
  switch (hook) {
    case "complete_task":
      return "CompleteTask";
    case "integration_merge":
      return "IntegrationMerge";
    case "intent":
      return "Intent";
    default:
      return hook ?? "Hook";
  }
}

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import {
  type StateBadgeTone,
  toneClasses,
} from "@/lib/state-color";
import type { GateStatRow, WitnessView } from "@/types/api";

/// Consolidated Gates page — iter69.
///
/// Operator-facing single surface for every "is this gate doing
/// what I think it's doing?" question. Two coupled sections:
///
///   1. **Per-gate rollup** (top) — one row per `gate_type` from
///      `GET /api/gates/stats`. Raw pass / fail / inconclusive
///      counts, a fixup-loop counter, last-seen timestamp, and a
///      warn-tone health flag when every failure spawned a
///      repair loop (`fixup_loop_count >= fail_count`,
///      `fail_count > 0`). Click a row to filter the timeline
///      below to just that gate; click again to clear.
///
///   2. **Witness timeline** (bottom) — newest-first cross-task
///      verdict events from `GET /api/witnesses?limit=200`.
///      Color-coded verdict pill, gate_type, task link with
///      copy-id, evaluation sha, recorded-at. The single place
///      to triage "did test-gate start failing for everyone at
///      the same time" patterns.
///
/// iter69 supersedes the standalone `/witnesses` page: the two
/// surfaces always answered overlapping questions ("is this
/// gate over-strict?" vs. "when did the gate last reject?") and
/// every operator session ended up flipping between them.
/// Merging removes the flip and gives the rollup ↔ timeline
/// click-to-filter coupling that neither page had on its own.
///
/// **Invariants preserved**
///
///   * INV-DASHBOARD-GATE-STATS-PER-GATE-ROLLUP-01 — FE renders
///     raw counts, never computes a pass-rate %. Backend remains
///     the single source of truth for any "verifier-author
///     should revisit" classification.
///   * The row-flag CSS hook (`raxis-gate-row-flagged`) is kept
///     verbatim because the existing Vitest suite pins it.
///   * Wire units: `last_seen_at` and `recorded_at` are
///     unix-SECONDS and are passed verbatim to `fmtRelative`
///     (cf. iter69 "in 56,355 years" regression — that ms-vs-s
///     confusion lives one floor up in the BE, not here).
export function GatesPage() {
  // Filter state — survives reload via `?gate=…`. Cleared by a
  // second click on the same row, by the "Clear filter" pill,
  // or by clearing the URL param.
  const [searchParams, setSearchParams] = useSearchParams();
  const gateParam = searchParams.get("gate") ?? "";
  const [hoverGate, setHoverGate] = useState<string | null>(null);

  const setGate = (next: string | null) => {
    const sp = new URLSearchParams(searchParams);
    if (next == null || next.length === 0) {
      sp.delete("gate");
    } else {
      sp.set("gate", next);
    }
    setSearchParams(sp, { replace: true });
  };

  const stats = useQuery({
    queryKey: ["gates", "stats"],
    queryFn: ({ signal }) => dashboardApi.gates.stats(signal),
    refetchInterval: 10_000,
  });

  const witnesses = useQuery({
    queryKey: ["witnesses", "recent", 200],
    queryFn: ({ signal }) => dashboardApi.witnesses.list(200, signal),
    refetchInterval: 10_000,
  });

  // Hooks MUST run on every render — keep these above the
  // early-return guards below, otherwise React's Rules of Hooks
  // bites on the first error/loading repaint.
  const filteredWitnesses = useMemo(() => {
    const witnessRows = witnesses.data ?? [];
    return gateParam.length > 0
      ? witnessRows.filter((w) => w.gate_type === gateParam)
      : witnessRows;
  }, [gateParam, witnesses.data]);
  const witnessCounts = useMemo(
    () => summariseWitnesses(filteredWitnesses),
    [filteredWitnesses],
  );

  if (stats.isLoading) return <PageSpinner />;
  if (stats.isError) return <ErrorBox error={stats.error} />;

  const data = stats.data;

  if (!data || data.gates.length === 0) {
    return (
      <div className="space-y-5">
        <header>
          <h1 className="text-xl font-semibold text-ink">Gates</h1>
          <p className="text-sm text-ink-muted mt-0.5">
            Per-gate rollup of witness outcomes and the cross-task verdict
            timeline.
          </p>
        </header>
        <section className="card p-6 text-sm text-ink-muted">
          No gates have run yet. Configure a <Mono>[[gates]]</Mono> entry in
          <Mono> policy.toml</Mono> to see witness rollups here.
        </section>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Gates</h1>
          <p className="text-sm text-ink-muted mt-0.5">
            Per-gate rollup of witness outcomes. Refreshed{" "}
            {fmtRelative(data.generated_at)}.
          </p>
        </div>
        <p className="text-[11px] text-ink-subtle max-w-md">
          A gate is flagged when every failure spawned a fixup loop
          (<code className="font-mono">fixup_loop_count ≥ fail_count</code>).
          That&apos;s the cue to revisit the verifier author or raise the budget.
        </p>
      </header>

      {/* Per-gate rollup */}
      <section className="card p-0 overflow-hidden">
        <header className="px-4 py-3 border-b border-edge flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-ink">Per-gate rollup</h2>
          <span className="text-[11px] text-ink-subtle">
            {data.gates.length} gate
            {data.gates.length === 1 ? "" : "s"} · click a row to filter the
            timeline below
          </span>
        </header>
        <table className="w-full text-sm">
          <thead className="bg-panel-high text-[11px] uppercase tracking-wide text-ink-subtle">
            <tr>
              <th scope="col" className="text-left px-3 py-2 w-[28%]">
                Gate
              </th>
              <th scope="col" className="text-right px-3 py-2 w-[8%]">
                Pass
              </th>
              <th scope="col" className="text-right px-3 py-2 w-[8%]">
                Fail
              </th>
              <th scope="col" className="text-right px-3 py-2 w-[12%]">
                Inconclusive
              </th>
              <th scope="col" className="text-right px-3 py-2 w-[12%]">
                Fixup loops
              </th>
              <th scope="col" className="text-left px-3 py-2 w-[18%]">
                Last seen
              </th>
              <th scope="col" className="text-left px-3 py-2 w-[14%]">
                Health flag
              </th>
            </tr>
          </thead>
          <tbody>
            {data.gates.map((row) => (
              <GateStatTableRow
                key={row.gate_type}
                row={row}
                selected={row.gate_type === gateParam}
                hover={row.gate_type === hoverGate}
                onClick={() =>
                  setGate(row.gate_type === gateParam ? null : row.gate_type)
                }
                onHover={(next) => setHoverGate(next ? row.gate_type : null)}
              />
            ))}
          </tbody>
        </table>
      </section>

      {/* Witness timeline */}
      <section className="card p-0 overflow-hidden">
        <header className="px-4 py-3 border-b border-edge flex items-center justify-between gap-2 flex-wrap">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-ink">Witness timeline</h2>
            <p className="text-[11px] text-ink-muted mt-0.5">
              {gateParam.length > 0 ? (
                <>
                  Showing witnesses for{" "}
                  <Mono className="text-[11px] text-ink">{gateParam}</Mono>{" "}
                  only.{" "}
                  <button
                    type="button"
                    onClick={() => setGate(null)}
                    className="text-accent hover:underline"
                  >
                    Clear filter
                  </button>
                </>
              ) : (
                <>
                  Most-recent {filteredWitnesses.length} witness
                  {filteredWitnesses.length === 1 ? "" : "s"} across every
                  initiative. Click a row in the rollup above to filter.
                </>
              )}
            </p>
          </div>
          <div className="flex items-center gap-1 text-[12px] flex-wrap">
            {witnessCounts.pass > 0 && (
              <VerdictPill kind="Pass" label={`${witnessCounts.pass} pass`} />
            )}
            {witnessCounts.fail > 0 && (
              <VerdictPill kind="Fail" label={`${witnessCounts.fail} fail`} />
            )}
            {witnessCounts.inconclusive > 0 && (
              <VerdictPill
                kind="Inconclusive"
                label={`${witnessCounts.inconclusive} inconclusive`}
              />
            )}
          </div>
        </header>
        {witnesses.isError ? (
          <div className="p-4">
            <ErrorBox
              error={witnesses.error}
              onRetry={() => witnesses.refetch()}
            />
          </div>
        ) : filteredWitnesses.length === 0 ? (
          <Empty
            title={
              gateParam.length > 0
                ? `No witnesses recorded against ${gateParam} yet.`
                : "No witnesses yet."
            }
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
          <table className="w-full text-sm">
            <thead className="bg-panel-high text-[11px] uppercase tracking-wide text-ink-subtle">
              <tr>
                <th scope="col" className="text-left px-3 py-2 w-[10%]">
                  Verdict
                </th>
                <th scope="col" className="text-left px-3 py-2 w-[22%]">
                  Gate
                </th>
                <th scope="col" className="text-left px-3 py-2 w-[28%]">
                  Task
                </th>
                <th scope="col" className="text-left px-3 py-2 w-[20%]">
                  Eval sha
                </th>
                <th scope="col" className="text-left px-3 py-2 w-[20%]">
                  Recorded
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredWitnesses.map((w) => (
                <WitnessTimelineRow key={witnessKey(w)} w={w} />
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

interface GateStatRowProps {
  row: GateStatRow;
  selected?: boolean;
  hover?: boolean;
  onClick?: () => void;
  onHover?: (entering: boolean) => void;
}

/// One row of the Gates table. Extracted as a stable component
/// so the Vitest suite can mount it in isolation against a
/// minimal fixture without paginating the full page query.
export function GateStatTableRow({
  row,
  selected = false,
  hover = false,
  onClick,
  onHover,
}: GateStatRowProps) {
  // Warn-tone flag: a gate that forced more fixup loops than it
  // has fails is "every failure spawned a repair loop — verify
  // hint quality / budget" territory. We do NOT compute a
  // pass-rate percent here; the operator reads raw counts and
  // the flag is the visual cue. The class `raxis-gate-row-
  // flagged` is preserved so existing tests in
  // `gates-page.test.tsx` keep working — the visual treatment
  // now also rides on a Tailwind tinted background.
  const flagged = row.fail_count > 0 && row.fixup_loop_count >= row.fail_count;
  const lastSeenLabel =
    row.last_seen_at != null ? fmtRelative(row.last_seen_at) : "never";
  const lastSeenTitle =
    row.last_seen_at != null ? fmtAbsolute(row.last_seen_at) : undefined;

  return (
    <tr
      data-testid={`gate-row-${row.gate_type}`}
      aria-selected={selected || undefined}
      tabIndex={onClick ? 0 : undefined}
      role={onClick ? "button" : undefined}
      onClick={onClick}
      onMouseEnter={() => onHover?.(true)}
      onMouseLeave={() => onHover?.(false)}
      onKeyDown={(e) => {
        if (!onClick) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick();
        }
      }}
      className={[
        "border-t border-edge transition-colors",
        onClick ? "cursor-pointer" : "",
        selected
          ? "bg-accent/10 ring-1 ring-inset ring-accent"
          : hover
            ? "bg-panel-high"
            : "hover:bg-panel-high",
        flagged ? "raxis-gate-row-flagged" : "",
        flagged && !selected ? "bg-warn-muted/30" : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <th scope="row" className="text-left px-3 py-2 align-middle font-normal">
        <Mono className="text-[12px] text-ink">{row.gate_type}</Mono>
      </th>
      <td
        className={`px-3 py-2 align-middle text-right font-mono tabular-nums ${
          row.pass_count > 0 ? "text-ok font-semibold" : "text-ink-subtle"
        }`}
      >
        {row.pass_count}
      </td>
      <td
        className={`px-3 py-2 align-middle text-right font-mono tabular-nums ${
          row.fail_count > 0 ? "text-bad font-semibold" : "text-ink-subtle"
        }`}
      >
        {row.fail_count}
      </td>
      <td
        className={`px-3 py-2 align-middle text-right font-mono tabular-nums ${
          row.inconclusive_count > 0
            ? "text-warn font-semibold"
            : "text-ink-subtle"
        }`}
      >
        {row.inconclusive_count}
      </td>
      <td
        className={`px-3 py-2 align-middle text-right font-mono tabular-nums ${
          row.fixup_loop_count > 0
            ? "text-warn font-semibold"
            : "text-ink-subtle"
        }`}
      >
        {row.fixup_loop_count}
      </td>
      <td
        className="px-3 py-2 align-middle text-[12px] text-ink-muted whitespace-nowrap"
        title={lastSeenTitle}
      >
        {lastSeenLabel}
      </td>
      <td className="px-3 py-2 align-middle">
        {flagged ? (
          <span
            className={`badge ${toneClasses("warn")}`}
            role="status"
            data-tone="warn"
          >
            Fixup-loop heavy
          </span>
        ) : (
          <span
            className={`badge ${toneClasses("ok")}`}
            role="status"
            data-tone="ok"
          >
            Healthy
          </span>
        )}
      </td>
    </tr>
  );
}

/// One witness row in the timeline. Pulled out so the page body
/// stays scannable and so a Vitest fixture can mount the row in
/// isolation without a router / query-client.
export function WitnessTimelineRow({ w }: { w: WitnessView }) {
  return (
    <tr className="border-t border-edge hover:bg-panel-high transition-colors">
      <td className="px-3 py-2 align-middle">
        <VerdictPill kind={w.result_class} />
      </td>
      <td className="px-3 py-2 align-middle">
        <Mono className="text-[12px] text-ink">{w.gate_type}</Mono>
      </td>
      <td className="px-3 py-2 align-middle">
        <div className="flex items-center gap-1 min-w-0">
          <Link
            to={`/tasks/${encodeURIComponent(w.task_id)}`}
            className="hover:text-accent"
          >
            <Mono className="truncate text-[12px]">{w.task_id}</Mono>
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
  );
}

/// Verdict → tone mapping for the witness panel. Mirrors the
/// `WitnessResultClass` wire enum.
///
/// iter69 — previous revisions used hard-coded
/// `bg-success-muted / border-success / text-success` classes,
/// none of which exist in `tailwind.config.js` (the project's
/// tone tokens are `ok / bad / warn / info / block` — see
/// `state-color.ts` + the CSS custom-property block in
/// `global.css`). Tailwind silently dropped the unknown classes
/// so every verdict rendered with no fill, no border, and no
/// text color — operators reported the witnesses table looked
/// "uncoloured". Route through `toneClasses` so the verdict
/// chips reuse the same WCAG-verified palette as
/// `<StateBadge>` and the DAG node tone family.
const VERDICT_TONE: Record<string, StateBadgeTone> = {
  Pass: "ok",
  Fail: "bad",
  Inconclusive: "warn",
};

export function VerdictPill({
  kind,
  label,
}: {
  kind: string;
  label?: string;
}) {
  const tone = VERDICT_TONE[kind] ?? "muted";
  return (
    <span
      className={`badge ${toneClasses(tone)}`}
      data-verdict={kind}
      data-tone={tone}
    >
      {label ?? kind}
    </span>
  );
}

function summariseWitnesses(rows: WitnessView[]) {
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

/// Stable React key for a witness row — the wire payload does
/// not carry a synthetic id, so we composite the verifier run +
/// gate + recorded_at (the underlying tuple uniqueness in
/// `witness_records`). Kept exported for the Vitest suite.
// eslint-disable-next-line react-refresh/only-export-components
export function witnessKey(w: WitnessView): string {
  return `${w.verifier_run_id}-${w.gate_type}-${w.recorded_at}`;
}

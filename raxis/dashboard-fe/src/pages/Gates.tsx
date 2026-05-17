import { useQuery } from "@tanstack/react-query";

import { dashboardApi } from "@/api/client";
import { ErrorBox } from "@/components/ErrorBox";
import { PageSpinner } from "@/components/Spinner";
import { Mono } from "@/components/Mono";
import { fmtRelative } from "@/lib/format";
import type { GateStatRow } from "@/types/api";

/// Operator-facing per-gate health page.
///
/// Renders the `/api/gates/stats` rollup as a minimal table:
/// one row per `gate_type`, with raw pass / fail / inconclusive
/// counts, a sparkline-style chip strip, and a warn-tone flag
/// when `fixup_loop_count >= max(1, fail_count)` — i.e. the
/// gate is forcing every failure into a repair loop, which is
/// the operator's cue to revisit the verifier author or raise
/// the budget.
///
/// **Why the FE never derives a "health score".** The
/// operator-visible classification ("over-strict gate", "weak
/// verifier", …) is a backend concern; the FE renders raw
/// counts and a flag, no policy. INV-DASHBOARD-GATE-STATS-PER-
/// GATE-ROLLUP-01 (server-side) is the single source of truth.
export function GatesPage() {
  const stats = useQuery({
    queryKey: ["gates", "stats"],
    queryFn: ({ signal }) => dashboardApi.gates.stats(signal),
    refetchInterval: 10_000,
  });

  if (stats.isLoading) return <PageSpinner label="Loading gate stats…" />;
  if (stats.isError)
    return (
      <ErrorBox
        message={`Failed to load gate stats: ${
          stats.error instanceof Error ? stats.error.message : "unknown"
        }`}
      />
    );

  const data = stats.data;
  if (!data || data.gates.length === 0) {
    return (
      <div className="raxis-page raxis-gates-page">
        <header className="raxis-page-header">
          <h1>Gates</h1>
        </header>
        <p className="raxis-empty-state">
          No gates have run yet. Configure a <Mono>[[gates]]</Mono> entry in
          <Mono> policy.toml</Mono> to see witness rollups here.
        </p>
      </div>
    );
  }

  return (
    <div className="raxis-page raxis-gates-page">
      <header className="raxis-page-header">
        <h1>Gates</h1>
        <span className="raxis-page-subtitle">
          Per-gate rollup of witness outcomes. Refreshed{" "}
          {fmtRelative(data.generated_at * 1000)}.
        </span>
      </header>
      <table className="raxis-table raxis-gates-table">
        <thead>
          <tr>
            <th scope="col">Gate</th>
            <th scope="col" className="raxis-cell-num">
              Pass
            </th>
            <th scope="col" className="raxis-cell-num">
              Fail
            </th>
            <th scope="col" className="raxis-cell-num">
              Inconclusive
            </th>
            <th scope="col" className="raxis-cell-num">
              Fixup loops
            </th>
            <th scope="col">Last seen</th>
            <th scope="col">Health flag</th>
          </tr>
        </thead>
        <tbody>
          {data.gates.map((row) => (
            <GateStatTableRow key={row.gate_type} row={row} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface GateStatRowProps {
  row: GateStatRow;
}

/// One row of the Gates table. Extracted as a stable component
/// so the Vitest suite can mount it in isolation against a
/// minimal fixture without paginating the full page query.
export function GateStatTableRow({ row }: GateStatRowProps) {
  // Warn-tone flag: a gate that forced more fixup loops than
  // it has fails is "every failure spawned a repair loop —
  // verify hint quality / budget" territory. We do NOT compute
  // a pass-rate percent here; the operator reads raw counts
  // and the flag is the visual cue.
  const flagged = row.fail_count > 0 && row.fixup_loop_count >= row.fail_count;
  const lastSeenLabel =
    row.last_seen_at != null
      ? fmtRelative(row.last_seen_at * 1000)
      : "never";

  return (
    <tr
      data-testid={`gate-row-${row.gate_type}`}
      className={flagged ? "raxis-gate-row raxis-gate-row-flagged" : "raxis-gate-row"}
    >
      <th scope="row">
        <Mono>{row.gate_type}</Mono>
      </th>
      <td className="raxis-cell-num">{row.pass_count}</td>
      <td className="raxis-cell-num">{row.fail_count}</td>
      <td className="raxis-cell-num">{row.inconclusive_count}</td>
      <td className="raxis-cell-num">{row.fixup_loop_count}</td>
      <td>{lastSeenLabel}</td>
      <td>
        {flagged ? (
          <span className="raxis-tag raxis-tag-warn" role="status">
            Fixup-loop heavy
          </span>
        ) : (
          <span className="raxis-tag raxis-tag-ok">Healthy</span>
        )}
      </td>
    </tr>
  );
}

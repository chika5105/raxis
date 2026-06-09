/* `mapTasksToDagNodes` — the seam between the
 * `GET /api/initiatives/:id` `TaskView` payload and the
 * embedded DAG renderer on the InitiativeDetail page.
 *
 * iter69 regression pin. The previous mapping projected only
 * `(task_id, title, state)` and silently dropped `is_active`.
 * Result: every Admitted-but-actively-executing task rendered
 * as a static `Admitted` chip in the DAG even though the
 * sibling tasks-list correctly showed it Running. Operators
 * reported "DAG only shows Admitted / Completed". The renderer
 * itself already lifts `Admitted + is_active` to `Running`
 * (`DagGraph.effectiveState`); the bug was the page never
 * forwarding the flag.
 *
 * INV-DASHBOARD-RUNNING-STATE-VISIBLE-01 — this file is the
 * gate against a regression that re-introduces the divergence.
 */

import { describe, expect, it } from "vitest";

import { mapTasksToDagNodes } from "@/pages/InitiativeDetail";
import type { TaskView } from "@/types/api";

// Minimal `TaskView`-shaped fixture. The renderer only reads
// task_id / title / state / is_active / review retry state, so we keep this terse
// and let TypeScript's `Partial<TaskView>` cast remind future
// editors that the bridge is INTENTIONALLY narrow.
function task(over: Partial<TaskView> & { task_id: string }): TaskView {
  return {
    task_id: over.task_id,
    initiative_id: over.initiative_id ?? "init-x",
    initiative_display_name: over.initiative_display_name ?? "Initiative X",
    agent_type: over.agent_type ?? "Executor",
    title: over.title ?? over.task_id,
    state: over.state ?? "Admitted",
    session_id: over.session_id ?? null,
    reviewer_verdicts: over.reviewer_verdicts ?? [],
    structured_outputs: over.structured_outputs ?? [],
    path_allowlist: over.path_allowlist ?? [],
    created_at: over.created_at ?? 0,
    updated_at: over.updated_at ?? 0,
    review_verdict: over.review_verdict,
    review_reject_count: over.review_reject_count,
    max_review_rejections: over.max_review_rejections,
    review_retry_exhausted: over.review_retry_exhausted,
    crash_retry_count: over.crash_retry_count,
    max_crash_retries: over.max_crash_retries,
    is_active: over.is_active,
  };
}

describe("mapTasksToDagNodes", () => {
  it("forwards is_active so the DAG can lift Admitted → Running", () => {
    const nodes = mapTasksToDagNodes([
      task({ task_id: "T1", title: "execute-a", state: "Admitted" }),
      task({
        task_id: "T2",
        title: "execute-b",
        state: "Admitted",
        is_active: true,
      }),
      task({ task_id: "T3", title: "execute-c", state: "Running" }),
    ]);

    expect(nodes).toHaveLength(3);
    expect(nodes[0]).toEqual({
      task_id: "T1",
      task_name: undefined,
      title: "execute-a",
      agent_type: "Executor",
      state: "Admitted",
      review_verdict: undefined,
      review_reject_count: undefined,
      max_review_rejections: undefined,
      review_retry_exhausted: undefined,
      is_active: undefined,
    });
    expect(nodes[1]).toEqual({
      task_id: "T2",
      task_name: undefined,
      title: "execute-b",
      agent_type: "Executor",
      state: "Admitted",
      review_verdict: undefined,
      review_reject_count: undefined,
      max_review_rejections: undefined,
      review_retry_exhausted: undefined,
      is_active: true,
    });
    expect(nodes[2]).toEqual({
      task_id: "T3",
      task_name: undefined,
      title: "execute-c",
      agent_type: "Executor",
      state: "Running",
      review_verdict: undefined,
      review_reject_count: undefined,
      max_review_rejections: undefined,
      review_retry_exhausted: undefined,
      is_active: undefined,
    });
  });

  it("returns a fresh array (no aliasing back into the React-query cache)", () => {
    const src = [task({ task_id: "T1" })];
    const out = mapTasksToDagNodes(src);
    expect(out).not.toBe(src);
    // And we copy by field, not by reference — mutating the
    // source TaskView post-call must not leak into the DAG nodes.
    (src[0] as { state: string }).state = "Mutated";
    expect(out[0].state).toBe("Admitted");
  });

  it("is the empty list for the empty list", () => {
    expect(mapTasksToDagNodes([])).toEqual([]);
  });
});

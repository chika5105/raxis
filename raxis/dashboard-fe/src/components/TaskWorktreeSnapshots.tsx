import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { TerminalDiffBlock } from "@/components/DiffView";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { Spinner } from "@/components/Spinner";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import { toneClasses, type StateBadgeTone } from "@/lib/state-color";
import type { WorktreeSnapshotView } from "@/types/api";

/// `<TaskWorktreeSnapshots>` — iter68.
///
/// Renders the task's content-addressed worktree snapshot timeline
/// (kernel-side `specs/v3/worktree-snapshots.md`). Each row is a
/// point-in-time projection of the worktree; the operator can
/// expand one row to view the four body blobs (diff / log /
/// tree / porcelain) inline.
///
/// Backed by `GET /api/tasks/:task_id/worktree-snapshots` and
/// `GET /api/worktree-snapshots/:snapshot_id/blob/:kind`.

export function TaskWorktreeSnapshots({ taskId }: { taskId: string }) {
  const q = useQuery({
    queryKey: ["task", taskId, "worktree-snapshots"],
    queryFn: ({ signal }) =>
      dashboardApi.tasks.worktreeSnapshots(taskId, signal),
    refetchInterval: 6_000,
    enabled: taskId.length > 0,
  });

  if (q.isPending) {
    return (
      <section className="card p-4">
        <h2 className="text-sm font-semibold text-ink mb-3">
          Worktree snapshots
        </h2>
        <div className="flex items-center gap-2 text-xs text-ink-subtle">
          <Spinner /> Loading snapshots…
        </div>
      </section>
    );
  }
  if (q.error) {
    return (
      <section className="card p-4">
        <h2 className="text-sm font-semibold text-ink mb-3">
          Worktree snapshots
        </h2>
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      </section>
    );
  }

  const rows = q.data ?? [];

  return (
    <section className="card p-4">
      <header className="flex items-center justify-between mb-3 gap-2 flex-wrap">
        <h2 className="text-sm font-semibold text-ink">Worktree snapshots</h2>
        <span className="text-[11px] text-ink-subtle">
          {rows.length} {rows.length === 1 ? "snapshot" : "snapshots"}
        </span>
      </header>

      {rows.length === 0 ? (
        <Empty
          title="No worktree snapshots yet."
          hint={
            <>
              Snapshots land here after the executor commits, after
              every witness verdict, and unconditionally before the
              session worktree is garbage-collected.
            </>
          }
        />
      ) : (
        <ul className="space-y-2">
          {rows.map((s) => (
            <SnapshotRow
              key={s.snapshot_id}
              snapshot={s}
              currentTaskId={taskId}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

function SnapshotRow({
  snapshot,
  currentTaskId,
}: {
  snapshot: WorktreeSnapshotView;
  currentTaskId: string;
}) {
  const [open, setOpen] = useState(false);
  const isRelatedSnapshot =
    snapshot.task_id.length > 0 && snapshot.task_id !== currentTaskId;
  return (
    <li className="border border-edge rounded">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-3 py-2 flex items-center justify-between gap-3 hover:bg-panel-high transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0">
          <TriggerBadge trigger={snapshot.trigger} />
          <Mono className="text-[11px] text-ink-muted truncate">
            {snapshot.head_sha.slice(0, 12)}
          </Mono>
          {snapshot.commit_count > 0 && (
            <span className="badge bg-info-muted/30 border-info text-info">
              {snapshot.commit_count}{" "}
              {snapshot.commit_count === 1 ? "commit" : "commits"}
            </span>
          )}
          {snapshot.diff_truncated && (
            <span
              className={`badge ${toneClasses("warn")}`}
              title={`Diff was truncated at 1 MiB cap. Original size: ${snapshot.diff_bytes_total} bytes.`}
            >
              diff truncated
            </span>
          )}
          {isRelatedSnapshot && (
            <span
              className="badge bg-info-muted/30 border-info text-info"
              title="Captured on the related initiative/session row for this task."
            >
              related
            </span>
          )}
        </div>
        <span className="text-[11px] text-ink-subtle whitespace-nowrap">
          {fmtRelative(snapshot.taken_at)}
        </span>
      </button>

      {open && (
        <SnapshotDetail snapshot={snapshot} currentTaskId={currentTaskId} />
      )}
    </li>
  );
}

function TriggerBadge({ trigger }: { trigger: string }) {
  // INV-WORKTREE-SNAPSHOT-PRE-GC-01 — PreGc is the only
  // trigger the operator MUST trust as terminal-state-of-tree.
  // Pass / Fail / Inconclusive flow the witness-verdict colour
  // language so the timeline reads at a glance.
  const tone = SNAPSHOT_TRIGGER_TONE[trigger] ?? "muted";
  return <span className={`badge ${toneClasses(tone)}`}>{trigger}</span>;
}

const SNAPSHOT_TRIGGER_TONE: Record<string, StateBadgeTone> = {
  WitnessPass: "ok",
  WitnessFail: "bad",
  WitnessInconclusive: "warn",
  IntegrationMerge: "info",
  PreGc: "info",
};

function SnapshotDetail({
  snapshot,
  currentTaskId,
}: {
  snapshot: WorktreeSnapshotView;
  currentTaskId: string;
}) {
  type Kind = "diff" | "log" | "tree" | "porcelain";
  const available = useMemo(() => {
    const out: Kind[] = [];
    if (snapshot.diff_blob_sha256) out.push("diff");
    if (snapshot.log_blob_sha256) out.push("log");
    if (snapshot.tree_blob_sha256) out.push("tree");
    if (snapshot.porcelain_blob_sha256) out.push("porcelain");
    return out;
  }, [snapshot]);
  const [active, setActive] = useState<Kind | null>(
    available[0] ?? null,
  );

  return (
    <div className="border-t border-edge p-3 space-y-3 bg-panel-high">
      <dl className="grid grid-cols-2 md:grid-cols-3 gap-2 text-[11px]">
        <Field label="Snapshot id">
          <Mono className="truncate">{snapshot.snapshot_id}</Mono>
          <CopyButton value={snapshot.snapshot_id} />
        </Field>
        <Field label="Taken at">{fmtAbsolute(snapshot.taken_at)}</Field>
        <Field label="Trigger">{snapshot.trigger}</Field>
        <Field label="Base sha">
          <Mono className="truncate">{snapshot.base_sha}</Mono>
          <CopyButton value={snapshot.base_sha} />
        </Field>
        <Field label="Head sha">
          <Mono className="truncate">{snapshot.head_sha}</Mono>
          <CopyButton value={snapshot.head_sha} />
        </Field>
        <Field label="Commits">{snapshot.commit_count}</Field>
        {snapshot.task_id && (
          <Field label={snapshot.task_id === currentTaskId ? "Task" : "Related task"}>
            <Mono className="truncate">{snapshot.task_id}</Mono>
            <CopyButton value={snapshot.task_id} />
          </Field>
        )}
        {snapshot.session_id && (
          <Field label="Session">
            <Mono className="truncate">{snapshot.session_id}</Mono>
            <CopyButton value={snapshot.session_id} />
          </Field>
        )}
        {snapshot.initiative_id && (
          <Field label="Initiative">
            <Mono className="truncate">{snapshot.initiative_id}</Mono>
            <CopyButton value={snapshot.initiative_id} />
          </Field>
        )}
      </dl>

      {available.length === 0 ? (
        <p className="text-[11px] text-ink-subtle">
          This snapshot captured no body blobs — the worktree had
          no diff, log, tree-listing, or uncommitted changes at
          this point in time.
        </p>
      ) : (
        <>
          <div className="flex items-center gap-1 flex-wrap text-[11px]">
            {available.map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => setActive(k)}
                className={`px-2 py-1 rounded border ${
                  active === k
                    ? "bg-accent-muted/40 border-accent text-accent"
                    : "bg-panel border-edge text-ink-muted hover:text-ink"
                }`}
              >
                {k}
              </button>
            ))}
          </div>
          {active && (
            <BlobViewer snapshotId={snapshot.snapshot_id} kind={active} />
          )}
        </>
      )}
    </div>
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

function BlobViewer({
  snapshotId,
  kind,
}: {
  snapshotId: string;
  kind: "diff" | "log" | "tree" | "porcelain";
}) {
  const q = useQuery({
    queryKey: ["worktree-snapshot", snapshotId, "blob", kind],
    queryFn: ({ signal }) =>
      dashboardApi.worktreeSnapshots.fetchBlob(snapshotId, kind, signal),
    // INV-WORKTREE-SNAPSHOT-CONTENT-ADDR-01: bodies are
    // content-addressed and immutable for a given (id, kind).
    // Aggressive cache is safe.
    staleTime: Infinity,
    gcTime: 5 * 60_000,
  });
  if (q.isPending) {
    return (
      <div className="flex items-center gap-2 text-[11px] text-ink-subtle">
        <Spinner /> Loading {kind}…
      </div>
    );
  }
  if (q.error) {
    return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  }
  if (kind === "diff") {
    return (
      <div className="text-[11px] font-mono overflow-x-auto scroll-thin max-h-96 bg-panel border border-edge rounded">
        <TerminalDiffBlock diffText={q.data} />
      </div>
    );
  }
  return (
    <pre className="text-[11px] font-mono text-ink-muted overflow-x-auto scroll-thin max-h-96 bg-panel border border-edge rounded p-2">
      {q.data}
    </pre>
  );
}

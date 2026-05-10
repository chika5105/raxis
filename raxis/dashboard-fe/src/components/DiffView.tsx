import type { WorktreeDiff } from "@/types/api";

import { Empty } from "@/components/Empty";
import { Mono } from "@/components/Mono";
import { plural, shortSha } from "@/lib/format";

interface DiffViewProps {
  diff: WorktreeDiff;
}

/// Side-by-side-light unified diff renderer. Each file shows
/// the header, status, line counts, and the hunk text colored
/// per line:
///   * `+` insertion (green)
///   * `-` deletion (red)
///   * `@@` hunk header (info)
///   * everything else (subtle context)
export function DiffView({ diff }: DiffViewProps) {
  const totalIns = diff.files.reduce((s, f) => s + f.insertions, 0);
  const totalDel = diff.files.reduce((s, f) => s + f.deletions, 0);

  return (
    <div className="space-y-4">
      <header className="card p-3 flex items-center gap-3 text-xs">
        <Mono className="text-ink-muted">{shortSha(diff.from_sha)}</Mono>
        <span className="text-ink-subtle">→</span>
        <Mono className="text-ink-muted">{shortSha(diff.to_sha)}</Mono>
        <span className="ml-auto text-ink-subtle">
          {plural(diff.files.length, "file")}
          <span className="text-ok ml-2">+{totalIns}</span>
          <span className="text-bad ml-2">−{totalDel}</span>
        </span>
      </header>

      {diff.files.length === 0 ? (
        <Empty title="No file-level changes." />
      ) : (
        diff.files.map((f) => (
          <div key={f.path} className="card p-0 overflow-hidden">
            <header className="px-3 py-2 border-b border-edge bg-panel-high flex items-center gap-3 text-xs">
              <span
                className={`badge ${
                  f.status === "A"
                    ? "bg-ok-muted/30 border-ok text-ok"
                    : f.status === "D"
                    ? "bg-bad-muted/30 border-bad text-bad"
                    : f.status === "M"
                    ? "bg-info-muted/30 border-info text-info"
                    : "bg-edge/40 border-edge-strong text-ink-muted"
                }`}
              >
                {f.status}
              </span>
              <Mono className="text-ink truncate flex-1" >{f.path}</Mono>
              <span className="text-ok">+{f.insertions}</span>
              <span className="text-bad">−{f.deletions}</span>
            </header>
            <pre className="font-mono text-[11.5px] leading-relaxed overflow-x-auto scroll-thin px-0">
              {f.hunk.length === 0 ? (
                <span className="block px-3 py-2 text-ink-subtle italic">
                  (binary or empty diff)
                </span>
              ) : (
                f.hunk.split("\n").map((line, i) => {
                  const tone =
                    line.startsWith("+++") || line.startsWith("---")
                      ? "text-ink-subtle bg-panel"
                      : line.startsWith("+")
                      ? "text-ok bg-ok-muted/15"
                      : line.startsWith("-")
                      ? "text-bad bg-bad-muted/15"
                      : line.startsWith("@@")
                      ? "text-info bg-info-muted/15 font-semibold"
                      : "text-ink-muted";
                  return (
                    <span key={i} className={`block px-3 ${tone}`}>
                      {line || " "}
                    </span>
                  );
                })
              )}
            </pre>
          </div>
        ))
      )}
    </div>
  );
}

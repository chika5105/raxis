import { INVARIANTS, invariantsByGroup, type InvariantGroup } from "@/lib/paradigm";
import { Card } from "./Card";

const GROUP_ORDER: InvariantGroup[] = [
  "Structural separation",
  "Authority model",
  "Accountability",
  "Coordination & recovery",
];

const GROUP_BLURB: Record<InvariantGroup, string> = {
  "Structural separation":
    "Without a real boundary between intelligence and authority, no other invariant can be enforced — a co-located agent simply edits the policy or the audit log.",
  "Authority model":
    "How authority makes decisions. Without these, authority degrades into either \"the agent can do anything\" or \"the agent can do nothing.\"",
  "Accountability":
    "The audit chain is what makes authority verifiable after the fact. These invariants make that record cryptographic, reproducible, and attributable.",
  "Coordination & recovery":
    "How agents talk to each other and how they extend their authority safely. Done wrong, both create audit blind spots.",
};

export function InvariantsGrid({ compact = false }: { compact?: boolean }) {
  const groups = invariantsByGroup();
  return (
    <div className="space-y-12">
      {GROUP_ORDER.map((g) => (
        <div key={g}>
          <div className="flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-2">
            <h3 className="text-lg font-semibold tracking-tight">
              <span className="font-mono text-accent text-sm mr-2">
                {String(GROUP_ORDER.indexOf(g) + 1).padStart(2, "0")}
              </span>
              {g}
            </h3>
            {!compact && (
              <p className="max-w-2xl text-sm text-[var(--muted)]">
                {GROUP_BLURB[g]}
              </p>
            )}
          </div>
          <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {groups[g].map((inv) => (
              <Card key={inv.id} hoverable className="h-full">
                <div className="flex items-baseline gap-3">
                  <span className="font-mono text-xs font-semibold text-accent">
                    {inv.id}
                  </span>
                  <h4 className="font-semibold tracking-tight">{inv.name}</h4>
                </div>
                <p className="mt-3 text-sm leading-relaxed">{inv.oneLiner}</p>
                {!compact && (
                  <>
                    <p className="mt-3 text-xs leading-relaxed text-[var(--muted)]">
                      <span className="font-medium text-[var(--fg)]">Why:</span>{" "}
                      {inv.rationale}
                    </p>
                    <p className="mt-2 text-xs leading-relaxed text-[var(--muted)]">
                      <span className="font-medium text-[var(--fg)]">In the reference impl:</span>{" "}
                      {inv.example}
                    </p>
                  </>
                )}
              </Card>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

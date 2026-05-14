import { invariantsByGroup, type InvariantGroup } from "@/lib/paradigm";

const GROUP_ORDER: InvariantGroup[] = [
  "Structural separation",
  "Authority model",
  "Accountability",
  "Coordination & recovery",
];

export const GROUP_SLUGS: Record<InvariantGroup, string> = {
  "Structural separation": "structural-separation",
  "Authority model": "authority-model",
  "Accountability": "accountability",
  "Coordination & recovery": "coordination-recovery",
};

export function InvariantsGrid({ compact = false }: { compact?: boolean }) {
  const groups = invariantsByGroup();
  return (
    <div className="space-y-16">
      {GROUP_ORDER.map((g, gi) => (
      <div key={g} id={GROUP_SLUGS[g]}>
          <div className="flex items-baseline gap-3 border-b border-[var(--rule)] pb-4">
            <span className="text-sm tabular-nums text-[var(--soft)]">
              {String(gi + 1).padStart(2, "0")}
            </span>
            <h3 className="h-sub">{g}</h3>
          </div>
          <ul className="mt-8 space-y-10">
            {groups[g].map((inv) => (
              <li
                key={inv.id}
                id={inv.id.toLowerCase()}
                className="grid gap-3 sm:grid-cols-[6rem_minmax(0,1fr)] sm:gap-10"
              >
                <div>
                  <div className="font-mono text-sm text-accent">{inv.id}</div>
                  <div className="text-sm text-[var(--soft)] mt-0.5">
                    {inv.name}
                  </div>
                </div>
                <div>
                  <p className="text-[var(--fg)] leading-relaxed">
                    {inv.oneLiner}
                  </p>
                  {!compact && (
                    <>
                      <p className="mt-3 text-[var(--muted)] leading-relaxed text-[0.95rem]">
                        {inv.rationale}
                      </p>
                      <p className="mt-2 text-[var(--muted)] leading-relaxed text-[0.95rem]">
                        <span className="text-[var(--fg)] font-semibold">
                          In the reference implementation.{" "}
                        </span>
                        {inv.example}
                      </p>
                    </>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

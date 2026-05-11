const TIERS = [
  {
    tier: "1",
    name: "RAXIS-Aligned",
    evidence:
      "Public conformance statement mapping each of the 12 invariants to its enforcement mechanism, plus an architectural diagram of the intelligence/authority boundary.",
    verification: "Self-attested",
    use: "Early-stage implementations, research prototypes, RAXIS adapted to a new domain.",
    status: "current" as const,
  },
  {
    tier: "2",
    name: "RAXIS-Tested",
    evidence:
      "Tier 1 + the canonical RAXIS conformance test suite passes (positive and adversarial cases for every invariant).",
    verification: "Self-tested with an open-source, reproducible test suite",
    use: "Production-bound implementations seeking engineered, demonstrable conformance.",
    status: "partial" as const,
  },
  {
    tier: "3",
    name: "RAXIS-Verified",
    evidence:
      "Tier 2 + independent third-party audit by a qualified verifier; covers source-code audit of the authority layer, isolation soundness review, audit-format conformance, credential-isolation pen-test, policy artifact format conformance; annual re-audit.",
    verification: "Third-party audit",
    use: "Regulated deployments, customer-facing claims, contractual conformance commitments.",
    status: "future" as const,
  },
];

export function ConformanceTable() {
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {TIERS.map((t) => (
        <div
          key={t.tier}
          className="rounded-xl border border-[var(--card-rule)] bg-[var(--card)] p-6 flex flex-col"
        >
          <div className="flex items-baseline justify-between">
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-xs uppercase tracking-wider text-[var(--muted)]">
                Tier {t.tier}
              </span>
              <h3 className="text-lg font-semibold tracking-tight">{t.name}</h3>
            </div>
            <StatusBadge status={t.status} />
          </div>
          <p className="mt-4 text-sm leading-relaxed text-[var(--fg)]">
            <span className="font-medium">Evidence: </span>
            <span className="text-[var(--muted)]">{t.evidence}</span>
          </p>
          <p className="mt-3 text-sm leading-relaxed text-[var(--fg)]">
            <span className="font-medium">Verification: </span>
            <span className="text-[var(--muted)]">{t.verification}</span>
          </p>
          <p className="mt-3 text-sm leading-relaxed text-[var(--fg)]">
            <span className="font-medium">Use case: </span>
            <span className="text-[var(--muted)]">{t.use}</span>
          </p>
        </div>
      ))}
    </div>
  );
}

function StatusBadge({ status }: { status: "current" | "partial" | "future" }) {
  const map: Record<typeof status, { label: string; cls: string }> = {
    current: {
      label: "Current",
      cls: "bg-accent-soft text-accent border-accent/30",
    },
    partial: {
      label: "Partial",
      cls: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30",
    },
    future: {
      label: "v3 GA",
      cls: "bg-[var(--code-bg)] text-[var(--muted)] border-[var(--rule)]",
    },
  };
  const { label, cls } = map[status];
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${cls}`}
    >
      {label}
    </span>
  );
}

import type { ReactNode } from "react";

interface PageHeaderProps {
  eyebrow?: string;
  title: ReactNode;
  lead?: ReactNode;
}

export function PageHeader({ eyebrow, title, lead }: PageHeaderProps) {
  return (
    <section className="border-b border-[var(--rule)]">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 pt-20 sm:pt-28 pb-16 sm:pb-20">
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1 className="h-hero mt-4 max-w-4xl">{title}</h1>
        {lead && <p className="lead mt-6 max-w-3xl">{lead}</p>}
      </div>
    </section>
  );
}

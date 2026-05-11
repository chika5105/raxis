import { ReactNode } from "react";
import clsx from "clsx";

interface SectionProps {
  id?: string;
  eyebrow?: string;
  title: string | ReactNode;
  lead?: string | ReactNode;
  children?: ReactNode;
  align?: "left" | "center";
  className?: string;
  bleed?: boolean;
}

export function Section({
  id,
  eyebrow,
  title,
  lead,
  children,
  align = "left",
  className,
  bleed,
}: SectionProps) {
  return (
    <section
      id={id}
      className={clsx(
        "border-t border-[var(--rule)] py-16 sm:py-20",
        bleed && "bg-[var(--card)]",
        className,
      )}
    >
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className={clsx(align === "center" && "text-center mx-auto")}>
          {eyebrow && (
            <p className="text-xs font-mono uppercase tracking-[0.18em] text-accent">
              {eyebrow}
            </p>
          )}
          <h2 className={clsx(
            "mt-2 text-3xl sm:text-4xl font-semibold tracking-tight",
            align === "center" && "max-w-3xl mx-auto",
          )}>
            {title}
          </h2>
          {lead && (
            <p className={clsx(
              "mt-4 text-lg text-[var(--muted)] leading-relaxed",
              align === "center" ? "max-w-2xl mx-auto" : "max-w-3xl",
            )}>
              {lead}
            </p>
          )}
        </div>
        {children && <div className="mt-12">{children}</div>}
      </div>
    </section>
  );
}

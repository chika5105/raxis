import { ReactNode } from "react";
import clsx from "clsx";

interface SectionProps {
  id?: string;
  title?: string | ReactNode;
  lead?: string | ReactNode;
  children?: ReactNode;
  className?: string;
  bleed?: boolean;
  divider?: boolean;
  align?: "left" | "center";
}

export function Section({
  id,
  title,
  lead,
  children,
  className,
  bleed,
  divider = true,
  align = "left",
}: SectionProps) {
  return (
    <section
      id={id}
      className={clsx(
        "py-20 sm:py-24",
        divider && "border-t border-[var(--rule)]",
        bleed && "bg-[var(--surface)]",
        className,
      )}
    >
      <div className="mx-auto max-w-5xl px-4 sm:px-6">
        {title && (
          <h2 className={clsx("h-section", align === "center" && "text-center mx-auto")}>
            {title}
          </h2>
        )}
        {lead && (
          <p
            className={clsx(
              "subtitle mt-6",
              align === "center" && "text-center mx-auto",
            )}
          >
            {lead}
          </p>
        )}
        {children && <div className={clsx(lead ? "mt-12" : title ? "mt-8" : "")}>{children}</div>}
      </div>
    </section>
  );
}

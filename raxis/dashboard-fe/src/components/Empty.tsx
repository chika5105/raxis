import type { ReactNode } from "react";

interface EmptyProps {
  /// Short headline (e.g. "No initiatives yet").
  title: string;
  /// Longer explanation, often suggesting a next step.
  hint?: ReactNode;
  /// Optional icon glyph (an `<svg>` element).
  icon?: ReactNode;
}

/// Empty-state placeholder used by tables and lists when the
/// backend returns zero rows. NOT used for errors — those go
/// through `<ErrorBox>`.
export function Empty({ title, hint, icon }: EmptyProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      {icon && <div className="mb-3 text-ink-muted">{icon}</div>}
      <p className="text-base font-medium text-ink">{title}</p>
      {hint && <p className="mt-2 text-sm text-ink-muted max-w-md">{hint}</p>}
    </div>
  );
}

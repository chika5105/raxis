import clsx from "clsx";
import type { ReactNode } from "react";

interface MonoProps {
  children: ReactNode;
  className?: string;
  title?: string;
  /// Add a subtle background pill (used for inline ids).
  pill?: boolean;
}

/// Monospace span for ids, hashes, fingerprints, etc.
export function Mono({ children, className, pill, title }: MonoProps) {
  return (
    <code
      title={title}
      className={clsx(
        "font-mono text-[0.78rem]",
        pill && "px-1 py-0.5 rounded bg-panel-high border border-edge text-ink",
        className,
      )}
    >
      {children}
    </code>
  );
}

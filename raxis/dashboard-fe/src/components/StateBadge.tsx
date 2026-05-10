import { stateTone, toneClasses } from "@/lib/state-color";
import clsx from "clsx";

interface StateBadgeProps {
  state: string | null | undefined;
  /// Optional pulsing dot for live/running states.
  pulse?: boolean;
  className?: string;
}

/// Renders a kernel FSM state as a colored, bordered badge.
/// Used everywhere a `state` field is surfaced (initiatives,
/// tasks, sessions, escalations, audit-event ribbons).
export function StateBadge({ state, pulse, className }: StateBadgeProps) {
  const label = state ?? "unknown";
  const tone = stateTone(label);
  return (
    <span className={clsx("badge", toneClasses(tone), className)}>
      {pulse && tone === "info" && (
        <span className="pulse-dot mr-1.5" aria-hidden="true" />
      )}
      {label}
    </span>
  );
}

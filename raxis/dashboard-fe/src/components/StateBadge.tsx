import {
  stateDescription,
  stateGlyph,
  stateShouldPulse,
  stateTone,
  toneClasses,
} from "@/lib/state-color";
import clsx from "clsx";

import { Tooltip } from "@/components/Tooltip";

interface StateBadgeProps {
  state: string | null | undefined;
  /// Optional pulsing dot for live/running states. When omitted,
  /// the per-state visual treatment in `state-color.ts::VISUAL`
  /// decides — e.g. `Running` / `Executing` pulse by default while
  /// `Admitted` / `Completed` do not. Pass `pulse={false}`
  /// explicitly to suppress the pulse for a state that would
  /// otherwise have it.
  pulse?: boolean;
  className?: string;
}

/// Renders a kernel FSM state as a colored, bordered badge with
/// a leading per-state glyph. Used everywhere a `state` field is
/// surfaced (initiatives, tasks, sessions, escalations,
/// audit-event ribbons).
///
/// `INV-DASHBOARD-FSM-STATE-VISIBILITY-01` — the badge
/// composition is `(tone-coloured pill) + (glyph) + (label)`. The
/// glyph is the third axis of disambiguation alongside colour and
/// label so that two states sharing a tone (e.g. `Aborted` and
/// `Cancelled` both `block`) remain visually distinct on colour-blindness
/// filters and on tinted monitors.
export function StateBadge({ state, pulse, className }: StateBadgeProps) {
  const label = state ?? "unknown";
  const tone = stateTone(label);
  const glyph = stateGlyph(label);
  const description = stateDescription(label);
  const shouldPulse = pulse ?? stateShouldPulse(label);
  const badge = (
    <span
      className={clsx("badge", toneClasses(tone), className)}
    >
      {shouldPulse && (
        <span className="pulse-dot mr-1.5" aria-hidden="true" />
      )}
      <span aria-hidden="true" className="mr-1 font-mono text-[0.95em] leading-none">
        {glyph}
      </span>
      {label}
    </span>
  );
  if (!description) return badge;
  return <Tooltip content={description}>{badge}</Tooltip>;
}

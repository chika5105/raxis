import clsx from "clsx";

interface SpinnerProps {
  /// Tailwind size class (defaults to `w-5 h-5`).
  className?: string;
  /// Visually-hidden status text for screen readers.
  label?: string;
}

export function Spinner({ className, label = "Loading" }: SpinnerProps) {
  return (
    <span
      role="status"
      aria-live="polite"
      className={clsx(
        "inline-block rounded-full border-2 border-edge-strong border-t-accent animate-spin",
        className ?? "w-5 h-5",
      )}
    >
      <span className="sr-only">{label}</span>
    </span>
  );
}

export function PageSpinner() {
  return (
    <div className="flex items-center justify-center py-24">
      <Spinner className="w-7 h-7" />
    </div>
  );
}

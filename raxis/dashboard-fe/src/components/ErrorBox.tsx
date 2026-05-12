import { ApiError } from "@/api/client";

interface ErrorBoxProps {
  error: unknown;
  /// Optional action label (e.g. "Retry").
  onRetry?: () => void;
}

/// Standard error renderer for React Query failure paths.
/// Shows the `code` discriminator + the safe `detail` string.
export function ErrorBox({ error, onRetry }: ErrorBoxProps) {
  const message = error instanceof Error ? error.message : String(error);
  const code = error instanceof ApiError ? error.code : "ERROR";
  const detail = error instanceof ApiError ? error.detail : message;

  return (
    <div className="card border-bad/40 p-4">
      <div className="flex items-start gap-3">
        <div className="text-bad text-lg leading-none mt-0.5">!</div>
        <div className="flex-1">
          <p className="text-sm font-medium text-bad">{code}</p>
          <p className="mt-1 text-sm text-ink">{detail}</p>
          {onRetry && (
            <button type="button" className="btn mt-3" onClick={onRetry}>
              Retry
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

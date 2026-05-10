// Shared formatters used across pages.
//
// All time values from the kernel are unix-seconds (signed
// integer for audit timestamps where the policy table allows
// negatives, unsigned for lifecycle timestamps). The helpers
// below tolerate both.

const RTF = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

const FMT_DT = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const UNITS: ReadonlyArray<[Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 365 * 24 * 60 * 60],
  ["month", 30 * 24 * 60 * 60],
  ["day", 24 * 60 * 60],
  ["hour", 60 * 60],
  ["minute", 60],
  ["second", 1],
];

export function fmtAbsolute(unixSeconds: number): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return "—";
  return FMT_DT.format(new Date(unixSeconds * 1000));
}

export function fmtRelative(unixSeconds: number): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return "—";
  const nowSec = Math.floor(Date.now() / 1000);
  const diff = unixSeconds - nowSec;
  for (const [unit, sec] of UNITS) {
    const v = diff / sec;
    if (Math.abs(v) >= 1 || unit === "second") {
      return RTF.format(Math.round(v), unit);
    }
  }
  return "just now";
}

export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

export function fmtCount(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

export function fmtTokens(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  return new Intl.NumberFormat("en-US").format(n);
}

export function shortSha(sha: string | null | undefined): string {
  if (!sha) return "—";
  return sha.length >= 8 ? sha.slice(0, 8) : sha;
}

export function shortFingerprint(fp: string | null | undefined): string {
  if (!fp) return "—";
  return fp.length >= 12 ? `${fp.slice(0, 8)}…${fp.slice(-4)}` : fp;
}

/// Pluralize an English noun. Operator-tooling-grade: not for
/// localization, just for the dashboard's English UI.
export function plural(n: number, singular: string, plural?: string): string {
  if (n === 1) return `${n} ${singular}`;
  return `${n} ${plural ?? `${singular}s`}`;
}

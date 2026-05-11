interface Props {
  size?: "sm" | "md" | "lg";
}

export function Wordmark({ size = "md" }: Props) {
  const dim = size === "lg" ? 28 : size === "sm" ? 18 : 22;
  const text = size === "lg" ? 22 : size === "sm" ? 15 : 18;
  return (
    <span
      className="inline-flex items-center gap-2 font-wordmark font-semibold tracking-tight text-[var(--fg)]"
      style={{ fontSize: text, letterSpacing: "-0.01em" }}
    >
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="/raxis-logo.svg"
        alt=""
        width={dim}
        height={dim}
        aria-hidden="true"
        className="rounded-[5px]"
        style={{ width: dim, height: dim }}
      />
      Raxis
    </span>
  );
}

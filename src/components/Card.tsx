import clsx from "clsx";
import { ReactNode } from "react";

export function Card({
  children,
  className,
  as: Tag = "div",
  hoverable = false,
}: {
  children: ReactNode;
  className?: string;
  as?: keyof React.JSX.IntrinsicElements;
  hoverable?: boolean;
}) {
  const Component = Tag as any;
  return (
    <Component
      className={clsx(
        "rounded-xl border border-[var(--card-rule)] bg-[var(--card)] p-6",
        hoverable && "card-hover",
        className,
      )}
    >
      {children}
    </Component>
  );
}

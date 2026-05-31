import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type MouseEventHandler,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";

type TooltipSide = "top" | "bottom" | "left" | "right";
type TooltipAlign = "start" | "center" | "end";

interface TooltipProps {
  content: ReactNode;
  children: ReactNode;
  side?: TooltipSide;
  align?: TooltipAlign;
  className?: string;
  style?: CSSProperties;
  tooltipClassName?: string;
  onMouseEnter?: MouseEventHandler<HTMLSpanElement>;
  onMouseLeave?: MouseEventHandler<HTMLSpanElement>;
}

const VIEWPORT_MARGIN = 8;
const GAP = 8;

export function Tooltip({
  content,
  children,
  side = "top",
  align = "center",
  className = "",
  style,
  tooltipClassName = "",
  onMouseEnter,
  onMouseLeave,
}: TooltipProps) {
  const id = useId();
  const triggerRef = useRef<HTMLSpanElement | null>(null);
  const tooltipRef = useRef<HTMLSpanElement | null>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState<{ left: number; top: number } | null>(
    null,
  );

  const updatePosition = useCallback(() => {
    const trigger = triggerRef.current;
    const tooltip = tooltipRef.current;
    if (!trigger || !tooltip) return;

    const triggerRect = trigger.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    let left = triggerRect.left;
    let top = triggerRect.bottom + GAP;

    if (side === "top" || side === "bottom") {
      if (align === "center") {
        left = triggerRect.left + triggerRect.width / 2 - tooltipRect.width / 2;
      } else if (align === "end") {
        left = triggerRect.right - tooltipRect.width;
      }
      top =
        side === "top"
          ? triggerRect.top - tooltipRect.height - GAP
          : triggerRect.bottom + GAP;
    } else {
      top = triggerRect.top + triggerRect.height / 2 - tooltipRect.height / 2;
      left =
        side === "left"
          ? triggerRect.left - tooltipRect.width - GAP
          : triggerRect.right + GAP;
    }

    left = Math.max(
      VIEWPORT_MARGIN,
      Math.min(left, window.innerWidth - tooltipRect.width - VIEWPORT_MARGIN),
    );
    top = Math.max(
      VIEWPORT_MARGIN,
      Math.min(top, window.innerHeight - tooltipRect.height - VIEWPORT_MARGIN),
    );

    setPosition({ left, top });
  }, [align, side]);

  useLayoutEffect(() => {
    if (!open) {
      setPosition(null);
      return;
    }
    updatePosition();
  }, [content, open, updatePosition]);

  useEffect(() => {
    if (!open) return;
    const onMove = () => updatePosition();
    window.addEventListener("resize", onMove);
    window.addEventListener("scroll", onMove, true);
    return () => {
      window.removeEventListener("resize", onMove);
      window.removeEventListener("scroll", onMove, true);
    };
  }, [open, updatePosition]);

  if (!content) return <>{children}</>;

  return (
    <span
      ref={triggerRef}
      className={`inline-flex ${className}`}
      style={style}
      aria-describedby={open ? id : undefined}
      onMouseEnter={(event) => {
        setOpen(true);
        onMouseEnter?.(event);
      }}
      onMouseLeave={(event) => {
        setOpen(false);
        onMouseLeave?.(event);
      }}
      onFocusCapture={() => setOpen(true)}
      onBlurCapture={() => setOpen(false)}
    >
      {children}
      {open &&
        createPortal(
          <span
            id={id}
            ref={tooltipRef}
            role="tooltip"
            className={`pointer-events-none z-[100] max-w-[min(22rem,calc(100vw-1rem))] rounded-md border border-edge bg-panel-raised px-2.5 py-1.5 text-left text-[11px] font-normal leading-relaxed text-ink shadow-soft ${tooltipClassName}`}
            style={{
              position: "fixed",
              left: position?.left ?? 0,
              top: position?.top ?? 0,
              visibility: position ? "visible" : "hidden",
            }}
          >
            {content}
          </span>,
          document.body,
        )}
    </span>
  );
}

export function InfoTooltip({
  content,
  className = "",
}: {
  content: ReactNode;
  className?: string;
}) {
  return (
    <Tooltip content={content} side="bottom" align="start">
      <span
        tabIndex={0}
        aria-label={typeof content === "string" ? content : "More information"}
        className={`inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-info/30 bg-info-muted text-[10px] font-semibold text-info focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${className}`}
      >
        i
      </span>
    </Tooltip>
  );
}

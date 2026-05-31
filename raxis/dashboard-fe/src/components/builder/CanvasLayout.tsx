/**
 * CanvasLayout — reusable 3-pane canvas shell for the Raxis builders.
 *
 * Layout:
 *   ┌──────────────────────────────────────────────────────┐
 *   │  headerBar (optional) — actions, title, status       │
 *   ├────────────┬─────────────────────────┬───────────────┤
 *   │ left pane  │   center canvas         │  right pane   │
 *   │ (palette)  │   (children)            │  (inspector)  │
 *   │ collapsible│                         │  collapsible  │
 *   └────────────┴─────────────────────────┴───────────────┘
 *
 * Both side panes are collapsible. State is persisted per-key to
 * localStorage so reopening the builder restores the operator's
 * preferred layout.
 *
 * Keyboard: [ toggles left pane, ] toggles right pane (Figma/VS Code
 * convention) — only fires when no input/textarea is focused.
 */
/* eslint-disable react-refresh/only-export-components */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { Tooltip } from "@/components/Tooltip";

export interface CanvasLayoutProps {
  /** Toolbar shown at the very top of the canvas area (full width). */
  headerBar?: ReactNode;

  // --- Left pane (tool palette / composables) ---
  leftPane?: ReactNode;
  /** Label shown in the collapsed-state toggle button. */
  leftPaneTitle?: string;
  /** Width in px when open. Default 260. */
  leftPaneWidth?: number;
  /** localStorage key for persisting open state. */
  leftPaneStorageKey?: string;
  /** Whether the left pane starts open. Default true. */
  leftPaneDefaultOpen?: boolean;
  /**
   * When true, the left pane content is responsible for its own scroll
   * container. Use this for inspectors/palettes with sticky internal
   * controls so the layout does not create nested vertical scroll regions.
   */
  leftPaneOwnsScroll?: boolean;

  // --- Center canvas ---
  /** Main content — DAG graph, Monaco editor, form area, etc. */
  children: ReactNode;
  /** Extra classes applied to the canvas wrapper. */
  canvasClassName?: string;

  // --- Right pane (inspector / output) ---
  rightPane?: ReactNode;
  rightPaneTitle?: string;
  rightPaneWidth?: number;
  rightPaneStorageKey?: string;
  rightPaneDefaultOpen?: boolean;
  /**
   * When true, the right pane content is responsible for its own scroll
   * container. This avoids the "scroll jail" feeling caused by nested pane
   * and inspector scrollbars.
   */
  rightPaneOwnsScroll?: boolean;
}

function usePaneOpen(key: string | undefined, defaultOpen: boolean) {
  const [open, setOpen] = useState<boolean>(() => {
    if (!key) return defaultOpen;
    try {
      const stored = window.localStorage.getItem(key);
      if (stored === "0") return false;
      if (stored === "1") return true;
    } catch {
      // localStorage unavailable (private mode, etc.)
    }
    return defaultOpen;
  });

  const toggle = useCallback(() => {
    setOpen((prev) => {
      const next = !prev;
      if (key) {
        try {
          window.localStorage.setItem(key, next ? "1" : "0");
        } catch {
          // ignore
        }
      }
      return next;
    });
  }, [key]);

  return [open, toggle] as const;
}

export function CanvasLayout({
  headerBar,
  leftPane,
  leftPaneTitle = "Palette",
  leftPaneWidth = 260,
  leftPaneStorageKey,
  leftPaneDefaultOpen = true,
  leftPaneOwnsScroll = false,
  children,
  canvasClassName = "",
  rightPane,
  rightPaneTitle = "Inspector",
  rightPaneWidth = 340,
  rightPaneStorageKey,
  rightPaneDefaultOpen = true,
  rightPaneOwnsScroll = false,
}: CanvasLayoutProps) {
  const [leftOpen, toggleLeft] = usePaneOpen(leftPaneStorageKey, leftPaneDefaultOpen);
  const [rightOpen, toggleRight] = usePaneOpen(rightPaneStorageKey, rightPaneDefaultOpen);

  // Keyboard shortcuts: [ / ] toggle panes, skip when an editable is focused.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement)?.tagName;
      const editable =
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        (e.target as HTMLElement)?.isContentEditable;
      if (editable) return;
      if (e.key === "[") { e.preventDefault(); toggleLeft(); }
      if (e.key === "]") { e.preventDefault(); toggleRight(); }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleLeft, toggleRight]);

  return (
    <div className="flex flex-col h-full min-h-0 bg-panel">
      {/* Header bar */}
      {headerBar && (
        <div className="shrink-0 border-b border-edge bg-panel-raised">
          {headerBar}
        </div>
      )}

      {/* Three-pane body */}
      <div className="flex flex-1 min-h-0 min-w-0 overflow-hidden">
        {/* ── Left pane ─────────────────────────────────── */}
        {leftPane && (
          <PaneSide
            side="left"
            open={leftOpen}
            onToggle={toggleLeft}
            title={leftPaneTitle}
            width={leftPaneWidth}
            contentOwnsScroll={leftPaneOwnsScroll}
          >
            {leftPane}
          </PaneSide>
        )}

        {/* ── Center canvas ─────────────────────────────── */}
        <main
          className={`flex-1 min-w-0 min-h-0 overflow-hidden flex flex-col ${canvasClassName}`}
        >
          {children}
        </main>

        {/* ── Right pane ────────────────────────────────── */}
        {rightPane && (
          <PaneSide
            side="right"
            open={rightOpen}
            onToggle={toggleRight}
            title={rightPaneTitle}
            width={rightPaneWidth}
            contentOwnsScroll={rightPaneOwnsScroll}
          >
            {rightPane}
          </PaneSide>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// PaneSide — one collapsible side panel.
// ---------------------------------------------------------------------------

interface PaneSideProps {
  side: "left" | "right";
  open: boolean;
  onToggle: () => void;
  title: string;
  width: number;
  contentOwnsScroll?: boolean;
  children: ReactNode;
}

function PaneSide({
  side,
  open,
  onToggle,
  title,
  width,
  contentOwnsScroll = false,
  children,
}: PaneSideProps) {
  const borderClass = side === "left" ? "border-r" : "border-l";
  const isLeft = side === "left";

  return (
    <div
      className={`relative shrink-0 flex min-h-0 flex-col ${borderClass} border-edge bg-panel-raised transition-all duration-200`}
      style={{ width: open ? width : 0, minWidth: open ? width : 0 }}
    >
      {/* Content — clipped when collapsing */}
      <div
        className="flex flex-col h-full min-h-0 overflow-hidden"
        style={{ width, opacity: open ? 1 : 0, transition: "opacity 150ms" }}
      >
        {/* Pane title bar */}
        <div className="flex items-center justify-between px-3 py-2 shrink-0 border-b border-edge">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
            {title}
          </span>
          <Tooltip
            content={`Collapse (${isLeft ? "[" : "]"})`}
            side={isLeft ? "right" : "left"}
          >
            <button
              type="button"
              onClick={onToggle}
              aria-label={`Collapse ${title}`}
              className="p-0.5 rounded text-ink-subtle hover:text-ink hover:bg-panel-high transition-colors"
            >
              <ChevronIcon side={side} collapsed={false} />
            </button>
          </Tooltip>
        </div>

        {/* Pane body. Some builder panes own their internal scroll so sticky
            controls and long forms do not fight a parent scrollbar. */}
        <div
          className={
            contentOwnsScroll
              ? "flex-1 min-h-0 overflow-hidden"
              : "flex-1 min-h-0 overflow-y-auto overscroll-contain scroll-thin pb-4"
          }
        >
          {children}
        </div>
      </div>

      {/* Collapsed toggle tab — sits outside the panel at its edge */}
      {!open && (
        <Tooltip
          content={`Expand (${isLeft ? "[" : "]"})`}
          side={isLeft ? "right" : "left"}
          className={`absolute top-1/2 -translate-y-1/2 z-10 ${
            isLeft ? "-right-7 rounded-l-none" : "-left-7 rounded-r-none"
          }`}
        >
          <button
            type="button"
            onClick={onToggle}
            aria-label={`Expand ${title}`}
            className={`flex items-center gap-1 px-1.5 py-3 text-[10px] font-semibold uppercase tracking-wider rounded border border-edge bg-panel-raised shadow-soft text-ink-muted hover:text-ink hover:border-accent transition-colors ${
              isLeft ? "rounded-l-none" : "rounded-r-none"
            }`}
            style={{ writingMode: "vertical-rl", textOrientation: "mixed" }}
          >
            <ChevronIcon side={side} collapsed={true} />
            <span>{title}</span>
          </button>
        </Tooltip>
      )}
    </div>
  );
}

function ChevronIcon({ side, collapsed }: { side: "left" | "right"; collapsed: boolean }) {
  // When left pane is open → point left (collapse). Collapsed → point right (expand).
  // When right pane is open → point right (collapse). Collapsed → point left (expand).
  const pointRight = (side === "left" && collapsed) || (side === "right" && !collapsed);
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 12 12"
      fill="none"
      className="shrink-0"
      aria-hidden
    >
      {pointRight ? (
        <path d="M4 2L8 6L4 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      ) : (
        <path d="M8 2L4 6L8 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      )}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Utility sub-components reused across all builders
// ---------------------------------------------------------------------------

/** Horizontal divider with optional label. */
export function PaneDivider({ label }: { label?: string }) {
  if (!label) return <div className="border-t border-edge mx-3 my-2" />;
  return (
    <div className="flex items-center gap-2 px-3 py-1.5">
      <div className="flex-1 border-t border-edge" />
      <span className="text-[10px] uppercase tracking-wider text-ink-subtle font-semibold shrink-0">
        {label}
      </span>
      <div className="flex-1 border-t border-edge" />
    </div>
  );
}

/** Section heading inside a pane. */
export function PaneSection({
  title,
  action,
  children,
  className = "",
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`px-3 py-2 ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between gap-2 mb-2">
          {title && (
            <span className="text-[10px] uppercase tracking-wider text-ink-subtle font-semibold">
              {title}
            </span>
          )}
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

/** Tab bar used in right-pane inspector panels. */
export interface InspectorTab {
  id: string;
  label: string;
  badge?: number;
}

export function InspectorTabBar({
  tabs,
  active,
  onChange,
}: {
  tabs: InspectorTab[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="flex items-center border-b border-edge bg-panel-raised shrink-0 px-1 pt-1 gap-0.5">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={`relative px-3 py-1.5 text-xs font-medium rounded-t transition-colors ${
            active === tab.id
              ? "bg-panel text-ink border-t border-l border-r border-edge -mb-px"
              : "text-ink-muted hover:text-ink hover:bg-panel-high"
          }`}
        >
          {tab.label}
          {tab.badge !== undefined && tab.badge > 0 && (
            <span className="ml-1.5 inline-flex items-center justify-center w-4 h-4 text-[9px] font-bold rounded-full bg-bad/20 text-bad">
              {tab.badge > 9 ? "9+" : tab.badge}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

/** Canvas header toolbar row. */
export function CanvasHeaderBar({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 px-4 h-11 flex-wrap">
      {children}
    </div>
  );
}

/** A composable "chip" button in the left palette. */
export function ComposableChip({
  label,
  description,
  onClick,
  variant = "default",
}: {
  label: string;
  description?: string;
  onClick: () => void;
  variant?: "default" | "executor" | "reviewer" | "pair" | "fanout";
}) {
  const variantClass: Record<string, string> = {
    default: "border-edge hover:border-accent",
    executor: "border-info/40 bg-info/5 hover:border-info",
    reviewer: "border-ok/40 bg-ok/5 hover:border-ok",
    pair: "border-accent/40 bg-accent/5 hover:border-accent",
    fanout: "border-warn/40 bg-warn/5 hover:border-warn",
  };
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full text-left rounded border px-2.5 py-2 transition-colors ${variantClass[variant] ?? variantClass.default} bg-panel hover:bg-panel-high`}
    >
      <div className="text-xs font-semibold text-ink leading-tight">{label}</div>
      {description && (
        <div className="text-[10px] text-ink-muted mt-0.5 leading-relaxed">{description}</div>
      )}
    </button>
  );
}

/** Empty-state placeholder for canvas areas. */
export function CanvasEmptyState({ icon, title, body }: { icon?: string; title: string; body?: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-3 text-center p-8">
      {icon && <span className="text-4xl opacity-30">{icon}</span>}
      <p className="text-sm font-medium text-ink-muted">{title}</p>
      {body && <p className="text-xs text-ink-subtle max-w-xs leading-relaxed">{body}</p>}
    </div>
  );
}

// Export a hook for downstream resizable usage (future).
export function usePaneToggle(storageKey: string, defaultOpen = true) {
  return usePaneOpen(storageKey, defaultOpen);
}

// Re-export a simple collapsible details section for inline pane sections.
export function CollapsibleSection({
  title,
  defaultOpen = false,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const bodyRef = useRef<HTMLDivElement>(null);
  return (
    <div className="border-b border-edge last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-3 py-2 text-xs font-semibold text-ink hover:bg-panel-high transition-colors"
      >
        <span>{title}</span>
        <svg
          width="12"
          height="12"
          viewBox="0 0 12 12"
          fill="none"
          className={`shrink-0 transition-transform duration-150 ${open ? "rotate-180" : ""}`}
          aria-hidden
        >
          <path d="M2 4L6 8L10 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && (
        <div ref={bodyRef} className="px-3 pb-3">
          {children}
        </div>
      )}
    </div>
  );
}

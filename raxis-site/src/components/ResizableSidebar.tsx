"use client";

import { useState, useCallback, useEffect, useRef } from "react";

const MIN_WIDTH = 180;
const MAX_WIDTH = 520;
const DEFAULT_WIDTH = 220;
const STORAGE_KEY = "raxis-sidebar-width-v2";

const RIGHT_MIN_WIDTH = 150;
const RIGHT_MAX_WIDTH = 480;
const RIGHT_DEFAULT_WIDTH = 200;
const RIGHT_STORAGE_KEY = "raxis-sidebar-right-width-v1";

function getInitialWidth(storageKey: string, defaultWidth: number, min: number, max: number): number {
  if (typeof window === "undefined") return defaultWidth;
  const stored = localStorage.getItem(storageKey);
  if (stored) {
    const n = parseInt(stored, 10);
    if (!isNaN(n) && n >= min && n <= max) return n;
  }
  return defaultWidth;
}

interface Props {
  children: React.ReactNode;
  /** Which edge the drag handle sits on. Default: "left" (handle on right edge). */
  side?: "left" | "right";
}

export function ResizableSidebar({ children, side = "left" }: Props) {
  const isRight = side === "right";
  const minWidth = isRight ? RIGHT_MIN_WIDTH : MIN_WIDTH;
  const maxWidth = isRight ? RIGHT_MAX_WIDTH : MAX_WIDTH;
  const defaultWidth = isRight ? RIGHT_DEFAULT_WIDTH : DEFAULT_WIDTH;
  const storageKey = isRight ? RIGHT_STORAGE_KEY : STORAGE_KEY;

  const [width, setWidth] = useState(defaultWidth);
  const dragging = useRef(false);
  const startX = useRef(0);
  const startWidth = useRef(defaultWidth);

  // Hydrate from localStorage after mount
  useEffect(() => {
    setWidth(getInitialWidth(storageKey, defaultWidth, minWidth, maxWidth));
  }, [storageKey, defaultWidth, minWidth, maxWidth]);

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    dragging.current = true;
    startX.current = e.clientX;
    startWidth.current = width;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }, [width]);

  useEffect(() => {
    function onMouseMove(e: MouseEvent) {
      if (!dragging.current) return;
      // Left sidebar: drag right = wider. Right sidebar: drag left = wider.
      const delta = isRight
        ? startX.current - e.clientX
        : e.clientX - startX.current;
      const next = Math.min(maxWidth, Math.max(minWidth, startWidth.current + delta));
      setWidth(next);
    }
    function onMouseUp() {
      if (!dragging.current) return;
      dragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      setWidth((w) => {
        localStorage.setItem(storageKey, String(w));
        return w;
      });
    }
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, [isRight, minWidth, maxWidth, storageKey]);

  const handleStyle: React.CSSProperties = isRight
    ? { position: "absolute", top: 0, left: -4, bottom: 0, width: 8, cursor: "col-resize", zIndex: 10 }
    : { position: "absolute", top: 0, right: -4, bottom: 0, width: 8, cursor: "col-resize", zIndex: 10 };

  return (
    <div style={{ width, minWidth, maxWidth, position: "relative" }}>
      {children}

      {/* Drag handle */}
      <div
        onMouseDown={onMouseDown}
        title="Drag to resize"
        aria-hidden="true"
        style={handleStyle}
        className="group"
      >
        {/* Visible indicator line */}
        <div
          className="absolute inset-y-0 left-1/2 -translate-x-1/2 w-px bg-transparent group-hover:bg-[var(--rule-strong)] transition-colors duration-150"
        />
      </div>
    </div>
  );
}

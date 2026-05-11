"use client";

import { useState, useCallback, useEffect, useRef } from "react";

const MIN_WIDTH = 180;
const MAX_WIDTH = 520;
const DEFAULT_WIDTH = 220;
const STORAGE_KEY = "raxis-sidebar-width-v2";

function getInitialWidth(): number {
  if (typeof window === "undefined") return DEFAULT_WIDTH;
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    const n = parseInt(stored, 10);
    if (!isNaN(n) && n >= MIN_WIDTH && n <= MAX_WIDTH) return n;
  }
  return DEFAULT_WIDTH;
}

interface Props {
  children: React.ReactNode;
}

export function ResizableSidebar({ children }: Props) {
  const [width, setWidth] = useState(DEFAULT_WIDTH);
  const dragging = useRef(false);
  const startX = useRef(0);
  const startWidth = useRef(DEFAULT_WIDTH);

  // Hydrate from localStorage after mount
  useEffect(() => {
    setWidth(getInitialWidth());
  }, []);

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
      const delta = e.clientX - startX.current;
      const next = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, startWidth.current + delta));
      setWidth(next);
    }
    function onMouseUp() {
      if (!dragging.current) return;
      dragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      // Persist
      setWidth((w) => {
        localStorage.setItem(STORAGE_KEY, String(w));
        return w;
      });
    }
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, []);

  return (
    <div style={{ width, minWidth: MIN_WIDTH, maxWidth: MAX_WIDTH, position: "relative" }}>
      {children}

      {/* Drag handle */}
      <div
        onMouseDown={onMouseDown}
        title="Drag to resize"
        aria-hidden="true"
        style={{
          position: "absolute",
          top: 0,
          right: -4,
          bottom: 0,
          width: 8,
          cursor: "col-resize",
          zIndex: 10,
        }}
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

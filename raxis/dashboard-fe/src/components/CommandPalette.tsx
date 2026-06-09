import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

/// A command-palette entry. `to` is a SPA path for navigation
/// or a function for arbitrary actions; only one of the two is
/// used at activation time.
interface PaletteCommandBase {
  /// Human-readable label shown in the list.
  label: string;
  /// Optional keyword string to widen matchable text without
  /// cluttering the visible label (e.g. add "doctor" so
  /// searching "doctor" finds "Health").
  keywords?: string;
  /// Right-aligned hint (route path, "action", etc.).
  hint?: string;
  /// Single-letter glyph (mirrors the sidebar nav glyphs).
  glyph?: string;
}

export type PaletteCommand = PaletteCommandBase &
  (
    | { to: string; run?: never }
    | { to?: never; run: () => void }
  );

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  /// Static / pre-curated commands. Operators can extend this
  /// per-page via `extraCommands` (currently unused — the
  /// shell-level palette only carries top-level navigation).
  commands: PaletteCommand[];
}

/// Keyboard-first quick-nav overlay. The Shell binds Cmd/Ctrl-K
/// to toggle this open. Inside:
///
///   * Type to fuzzy-filter the command list.
///   * Up / Down move selection (wrap-around).
///   * Enter activates; Escape closes.
///   * Click on a row also activates.
///
/// Implementation notes:
///   * Render-gated on `open` to avoid keeping a global keydown
///     listener when the palette is unmounted (one less moving
///     part for the page).
///   * Filtering is a simple case-insensitive substring on
///     `label + keywords + hint` — we explicitly chose this over
///     a fuzzy library because the command set is < 30 items
///     and operators benefit more from predictable matches than
///     from clever ranking.
///   * Selection is clamped to the filtered list length on every
///     re-filter so the highlight never points off the end.
export function CommandPalette({ open, onClose, commands }: CommandPaletteProps) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return commands;
    return commands.filter((c) => {
      const hay = `${c.label} ${c.keywords ?? ""} ${c.hint ?? ""}`.toLowerCase();
      return hay.includes(needle);
    });
  }, [commands, query]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setSelected(0);
    const t = window.setTimeout(() => inputRef.current?.focus(), 0);
    return () => window.clearTimeout(t);
  }, [open]);

  useEffect(() => {
    if (selected >= filtered.length) setSelected(Math.max(0, filtered.length - 1));
  }, [filtered.length, selected]);

  // Scroll the selected row into view as the operator arrows
  // through a long list (we cap visible rows, so out-of-view
  // selections need to be tugged into the scroll container).
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLLIElement>(
      `[data-palette-index="${selected}"]`,
    );
    if (el) el.scrollIntoView({ block: "nearest" });
  }, [selected]);

  if (!open) return null;

  const activate = (cmd: PaletteCommand | undefined) => {
    if (!cmd) return;
    if (cmd.to !== undefined) navigate(cmd.to);
    else cmd.run();
    onClose();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelected((s) => (filtered.length === 0 ? 0 : (s + 1) % filtered.length));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelected((s) =>
        filtered.length === 0 ? 0 : (s - 1 + filtered.length) % filtered.length,
      );
    } else if (e.key === "Enter") {
      e.preventDefault();
      activate(filtered[selected]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Quick navigation"
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="card w-full max-w-xl mx-4 overflow-hidden flex flex-col"
      >
        <div className="border-b border-edge px-3 py-2 flex items-center gap-2">
          <span className="text-ink-subtle text-sm" aria-hidden="true">⌘K</span>
          <input
            ref={inputRef}
            type="text"
            spellCheck={false}
            autoComplete="off"
            placeholder="Jump to page or action…"
            className="flex-1 bg-transparent border-0 outline-none text-sm text-ink placeholder:text-ink-subtle"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            aria-controls="command-palette-list"
            aria-activedescendant={
              filtered[selected]
                ? `command-palette-row-${selected}`
                : undefined
            }
          />
          <span className="kbd">esc</span>
        </div>
        <ul
          id="command-palette-list"
          ref={listRef}
          role="listbox"
          className="max-h-80 overflow-y-auto overscroll-y-auto scroll-thin"
        >
          {filtered.length === 0 ? (
            <li className="px-4 py-6 text-center text-sm text-ink-subtle">
              No matches.
            </li>
          ) : (
            filtered.map((c, i) => {
              const isSel = i === selected;
              return (
                <li
                  key={`${c.label}-${i}`}
                  id={`command-palette-row-${i}`}
                  data-palette-index={i}
                  role="option"
                  aria-selected={isSel}
                  onMouseEnter={() => setSelected(i)}
                  onClick={() => activate(c)}
                  className={`px-3 py-2 flex items-center gap-3 cursor-pointer text-sm ${
                    isSel ? "bg-panel-high text-ink" : "text-ink-muted"
                  }`}
                >
                  {c.glyph && (
                    <span
                      aria-hidden="true"
                      className="font-mono text-[11px] text-ink-subtle w-3 text-center"
                    >
                      {c.glyph}
                    </span>
                  )}
                  <span className="flex-1">{c.label}</span>
                  {c.hint && (
                    <span className="text-[11px] text-ink-subtle font-mono">
                      {c.hint}
                    </span>
                  )}
                </li>
              );
            })
          )}
        </ul>
        <div className="border-t border-edge px-3 py-1.5 text-[11px] text-ink-subtle flex items-center gap-3">
          <span>
            <span className="kbd">↑</span> <span className="kbd">↓</span> navigate
          </span>
          <span>
            <span className="kbd">↵</span> select
          </span>
          <span className="ml-auto">
            <span className="kbd">esc</span> close
          </span>
        </div>
      </div>
    </div>
  );
}

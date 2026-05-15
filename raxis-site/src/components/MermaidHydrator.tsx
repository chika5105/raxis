"use client";

/**
 * MermaidHydrator
 *
 * Finds every `pre[data-language="mermaid"]` block the server rendered
 * (produced by rehype-pretty-code) and replaces it with an actual SVG diagram.
 *
 * This must be a client component because mermaid.js requires a DOM.
 */

import { useEffect } from "react";

function isDark() {
  return (
    typeof document !== "undefined" &&
    document.documentElement.classList.contains("dark")
  );
}

export function MermaidHydrator() {
  useEffect(() => {
    let cancelled = false;

    async function hydrate() {
      const mermaid = (await import("mermaid")).default;

      mermaid.initialize({
        startOnLoad: false,
        theme: isDark() ? "dark" : "default",
        fontFamily:
          "var(--font-sans, ui-sans-serif, system-ui, -apple-system, sans-serif)",
        fontSize: 14,
        securityLevel: "strict",
        flowchart: { htmlLabels: true, curve: "basis" },
        sequence: { actorMargin: 50 },
      });

      // rehype-pretty-code wraps pre in <figure data-rehype-pretty-code-figure>
      const figures = document.querySelectorAll<HTMLElement>(
        '.doc-prose figure[data-rehype-pretty-code-figure]'
      );

      let idx = 0;
      for (const figure of figures) {
        if (cancelled) return;

        const pre = figure.querySelector<HTMLElement>('pre[data-language="mermaid"]');
        if (!pre) continue;

        const code = pre.querySelector("code");
        // Extract raw diagram source — strip Shiki span wrappers
        const source = (code as HTMLElement)?.innerText ?? code?.textContent ?? "";
        if (!source.trim()) continue;

        const id = `mermaid-raxis-${idx++}`;
        try {
          const { svg } = await mermaid.render(id, source.trim());
          const wrapper = document.createElement("div");
          wrapper.className = "mermaid-diagram";
          wrapper.innerHTML = svg;
          figure.replaceWith(wrapper);
      } catch (err) {
          console.warn("[MermaidHydrator] render failed:", err);
        }
      }
    }

    hydrate();
    return () => { cancelled = true; };
  }, []);

  return null;
}

import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ThemeProvider } from "@/lib/theme";
import { useTheme } from "@/lib/theme-context";

function ThemeProbe() {
  const { theme, hasExplicitPreference } = useTheme();
  return (
    <output data-explicit={String(hasExplicitPreference)}>{theme}</output>
  );
}

function renderThemeProbe() {
  return render(
    <ThemeProvider>
      <ThemeProbe />
    </ThemeProvider>,
  );
}

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.className = "";
});

describe("<ThemeProvider>", () => {
  it("starts in light mode when the operator has no stored preference", () => {
    window.localStorage.clear();

    renderThemeProbe();

    const output = screen.getByText("light");
    expect(output).toHaveAttribute("data-explicit", "false");
    expect(document.documentElement).toHaveClass("light");
    expect(document.documentElement).not.toHaveClass("dark");
  });

  it("honours an explicit stored dark preference", () => {
    window.localStorage.setItem("theme", "dark");

    renderThemeProbe();

    const output = screen.getByText("dark");
    expect(output).toHaveAttribute("data-explicit", "true");
    expect(document.documentElement).toHaveClass("dark");
    expect(document.documentElement).not.toHaveClass("light");
  });
});

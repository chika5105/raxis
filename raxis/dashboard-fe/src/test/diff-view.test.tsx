import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { DiffView } from "@/components/DiffView";
import type { WorktreeDiff } from "@/types/api";

const diff: WorktreeDiff = {
  name: "session-demo",
  from_sha: "a".repeat(40),
  to_sha: "b".repeat(40),
  files: [
    {
      path: "src/app.rs",
      status: "M",
      insertions: 1,
      deletions: 1,
      hunk: [
        "diff --git a/src/app.rs b/src/app.rs",
        "index 1111111..2222222 100644",
        "--- a/src/app.rs",
        "+++ b/src/app.rs",
        "@@ -1,2 +1,2 @@",
        " fn main() {",
        "-    old();",
        "+    new();",
        " }",
      ].join("\n"),
    },
  ],
};

describe("<DiffView>", () => {
  it("offers inline, side-by-side, and raw diff views", () => {
    render(<DiffView diff={diff} />);

    expect(screen.getByText("Inline")).toBeInTheDocument();
    expect(screen.getByText("Side by side")).toBeInTheDocument();
    expect(screen.getByText("Raw")).toBeInTheDocument();
    expect(screen.getByText("-")).toBeInTheDocument();
    expect(screen.getByText("+")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Side by side"));
    expect(screen.getByText("old();")).toBeInTheDocument();
    expect(screen.getByText("new();")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Raw"));
    expect(
      screen.getByText((_, node) => node?.textContent === "-    old();"),
    ).toBeInTheDocument();
    expect(
      screen.getByText((_, node) => node?.textContent === "+    new();"),
    ).toBeInTheDocument();
  });
});

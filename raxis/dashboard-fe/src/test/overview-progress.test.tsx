import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { Progress } from "@/pages/Overview";

describe("<Overview.Progress>", () => {
  it("reports completion percent from completed tasks only", () => {
    render(<Progress completed={11} failed={5} total={16} />);

    expect(screen.getByText("69%")).toBeInTheDocument();
    expect(screen.queryByText("100%")).toBeNull();
    expect(screen.getByText(/11\/16 done/)).toBeInTheDocument();
    expect(screen.getByText(/5 failed/)).toBeInTheDocument();
  });
});

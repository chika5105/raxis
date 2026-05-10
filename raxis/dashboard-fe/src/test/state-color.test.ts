import { describe, expect, it } from "vitest";

import { stateTone, toneClasses } from "@/lib/state-color";

describe("stateTone", () => {
  it("maps known kernel states to expected tones", () => {
    expect(stateTone("Pending")).toBe("muted");
    expect(stateTone("Active")).toBe("info");
    expect(stateTone("Running")).toBe("info");
    expect(stateTone("Completed")).toBe("ok");
    expect(stateTone("Failed")).toBe("bad");
    expect(stateTone("Blocked")).toBe("block");
    expect(stateTone("Reviewing")).toBe("warn");
  });

  it("normalizes case for unknown variants", () => {
    expect(stateTone("ACTIVE")).toBe("info");
    expect(stateTone("running")).toBe("info");
  });

  it("falls through to muted for unrecognized states", () => {
    expect(stateTone("ZZZ_UNKNOWN")).toBe("muted");
    expect(stateTone(null)).toBe("muted");
  });

  it("toneClasses returns Tailwind class strings", () => {
    expect(toneClasses("ok")).toContain("bg-ok-muted");
    expect(toneClasses("bad")).toContain("border-bad");
  });
});

import { describe, expect, it } from "vitest";

import {
  fmtAbsolute,
  fmtBytes,
  fmtCount,
  fmtTokens,
  plural,
  shortFingerprint,
  shortSha,
} from "@/lib/format";

describe("format helpers", () => {
  it("returns em-dash for non-finite times", () => {
    expect(fmtAbsolute(0)).toBe("—");
    expect(fmtAbsolute(NaN)).toBe("—");
  });

  it("renders bytes with binary units", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(1024)).toBe("1.0 KiB");
    expect(fmtBytes(1024 * 1024 * 5)).toBe("5.0 MiB");
  });

  it("counts use SI suffixes above 1k", () => {
    expect(fmtCount(999)).toBe("999");
    expect(fmtCount(1500)).toBe("1.5k");
    expect(fmtCount(2_500_000)).toBe("2.5M");
  });

  it("token counts use comma grouping", () => {
    expect(fmtTokens(1234567)).toBe("1,234,567");
    expect(fmtTokens(-1)).toBe("—");
  });

  it("short helpers are bounded", () => {
    expect(shortSha(null)).toBe("—");
    expect(shortSha("abcdef0123")).toBe("abcdef01");
    expect(shortFingerprint("abcdefghijklmnop")).toBe("abcdefgh…mnop");
  });

  it("pluralizes English nouns", () => {
    expect(plural(1, "task")).toBe("1 task");
    expect(plural(2, "task")).toBe("2 tasks");
    expect(plural(2, "child", "children")).toBe("2 children");
  });
});

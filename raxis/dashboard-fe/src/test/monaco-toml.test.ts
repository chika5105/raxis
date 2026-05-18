import { describe, expect, it, vi } from "vitest";

import { ensureTomlLanguage } from "@/lib/monaco-toml";

describe("ensureTomlLanguage", () => {
  it("registers a TOML language and Monarch tokenizer", () => {
    const register = vi.fn();
    const setLanguageConfiguration = vi.fn();
    const setMonarchTokensProvider = vi.fn();
    const monaco = {
      languages: {
        getLanguages: () => [{ id: "json" }],
        register,
        setLanguageConfiguration,
        setMonarchTokensProvider,
      },
    };

    ensureTomlLanguage(monaco);

    expect(register).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "toml",
        extensions: [".toml"],
      }),
    );
    expect(setLanguageConfiguration).toHaveBeenCalledWith(
      "toml",
      expect.objectContaining({ comments: { lineComment: "#" } }),
    );
    expect(setMonarchTokensProvider).toHaveBeenCalledWith(
      "toml",
      expect.objectContaining({
        tokenizer: expect.objectContaining({ root: expect.any(Array) }),
      }),
    );
  });
});

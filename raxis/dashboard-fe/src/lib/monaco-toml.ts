type MonacoLanguageApi = {
  editor?: {
    defineTheme?: (
      name: string,
      theme: {
        base: "vs" | "vs-dark";
        inherit: boolean;
        rules: Array<{
          token: string;
          foreground?: string;
          fontStyle?: string;
        }>;
        colors: Record<string, string>;
      },
    ) => void;
  };
  languages: {
    getLanguages: () => Array<{ id: string }>;
    register: (lang: {
      id: string;
      aliases?: string[];
      extensions?: string[];
      mimetypes?: string[];
    }) => void;
    setLanguageConfiguration: (id: string, config: unknown) => void;
    setMonarchTokensProvider: (id: string, provider: unknown) => void;
  };
};

let tomlTokensRegistered = false;
let raxisThemesRegistered = false;

export type RaxisMonacoTheme = "raxis-light" | "raxis-dark";

export function raxisMonacoTheme(theme: "light" | "dark"): RaxisMonacoTheme {
  return theme === "dark" ? "raxis-dark" : "raxis-light";
}

/// Register a compact TOML Monarch tokenizer with Monaco.
///
/// Monaco does not ship TOML out of the box. The dashboard maps
/// `policy.toml`, `Cargo.toml`, plan artifacts, and TOML-formatted
/// credentials to the `"toml"` language id, so without this hook
/// those editors silently render as plain text. Keeping the tokenizer
/// local avoids pulling a larger highlighter into the hot dashboard
/// bundle and lets every Monaco surface share one fast registration.
export function ensureTomlLanguage(monaco: MonacoLanguageApi): void {
  if (!monaco.languages.getLanguages().some((l) => l.id === "toml")) {
    monaco.languages.register({
      id: "toml",
      aliases: ["TOML", "toml"],
      extensions: [".toml"],
      mimetypes: ["application/toml"],
    });
  }

  registerRaxisThemes(monaco);

  if (tomlTokensRegistered) return;
  tomlTokensRegistered = true;

  monaco.languages.setLanguageConfiguration("toml", {
    comments: { lineComment: "#" },
    brackets: [
      ["[", "]"],
      ["{", "}"],
      ["(", ")"],
    ],
    autoClosingPairs: [
      { open: "[", close: "]" },
      { open: "{", close: "}" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
      { open: "'", close: "'" },
    ],
    surroundingPairs: [
      { open: "[", close: "]" },
      { open: "{", close: "}" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
      { open: "'", close: "'" },
    ],
  });

  monaco.languages.setMonarchTokensProvider("toml", {
    defaultToken: "",
    tokenPostfix: ".toml",
    escapes: /\\(?:[btnfr"\\]|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,
    tokenizer: {
      root: [
        [/^\s*\[\[[^\]]+\]\]/, "metatag"],
        [/^\s*\[[^\]]+\]/, "namespace"],
        [/#.*$/, "comment"],
        [/^\s*[A-Za-z0-9_.-]+(?=\s*=)/, "type.identifier"],
        [/=/, "operator"],
        [/\b(?:true|false)\b/, "keyword"],
        [
          /\b\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?\b/,
          "number",
        ],
        [/[+-]?(?:0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+)\b/, "number"],
        [/[+-]?(?:\d[\d_]*)(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?\b/, "number"],
        [/"""/, "string", "@tripleBasicString"],
        [/'''/, "string", "@tripleLiteralString"],
        [/"/, "string", "@basicString"],
        [/'[^']*'/, "string"],
        [/[\]{}()[,.]/, "delimiter"],
        [/[A-Za-z0-9_.-]+/, "identifier"],
      ],
      basicString: [
        [/[^\\"]+/, "string"],
        [/@escapes/, "string.escape"],
        [/\\./, "invalid"],
        [/"/, "string", "@pop"],
      ],
      tripleBasicString: [
        [/"""/, "string", "@pop"],
        [/@escapes/, "string.escape"],
        [/\\./, "invalid"],
        [/[^\\"]+|"/, "string"],
      ],
      tripleLiteralString: [
        [/'''/, "string", "@pop"],
        [/[^']+|'/, "string"],
      ],
    },
  });
}

function registerRaxisThemes(monaco: MonacoLanguageApi): void {
  if (raxisThemesRegistered) return;
  const defineTheme = monaco.editor?.defineTheme;
  if (!defineTheme) return;
  raxisThemesRegistered = true;

  defineTheme("raxis-light", {
    base: "vs",
    inherit: true,
    rules: [
      { token: "metatag.toml", foreground: "8b5e00", fontStyle: "bold" },
      { token: "namespace.toml", foreground: "8b5e00", fontStyle: "bold" },
      { token: "type.identifier.toml", foreground: "0b7285" },
      { token: "keyword.toml", foreground: "9f1239", fontStyle: "bold" },
      { token: "string.toml", foreground: "2f7d32" },
      { token: "string.escape.toml", foreground: "6d28d9", fontStyle: "bold" },
      { token: "number.toml", foreground: "6d28d9" },
      { token: "comment.toml", foreground: "6b7280", fontStyle: "italic" },
      { token: "operator.toml", foreground: "374151" },
      { token: "delimiter.toml", foreground: "4b5563" },
      { token: "invalid.toml", foreground: "b91c1c", fontStyle: "bold underline" },
    ],
    colors: {
      "editor.background": "#ffffff",
      "editor.foreground": "#172021",
      "editorLineNumber.foreground": "#8a9697",
      "editorLineNumber.activeForeground": "#286f7d",
      "editorCursor.foreground": "#286f7d",
      "editor.selectionBackground": "#cfe9ee",
      "editor.inactiveSelectionBackground": "#edf5f6",
      "editor.lineHighlightBackground": "#f6f9f9",
      "editorIndentGuide.background1": "#dce2e2",
      "editorIndentGuide.activeBackground1": "#9fb4b7",
    },
  });

  defineTheme("raxis-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "metatag.toml", foreground: "f0d38a", fontStyle: "bold" },
      { token: "namespace.toml", foreground: "f0d38a", fontStyle: "bold" },
      { token: "type.identifier.toml", foreground: "9ac9d4" },
      { token: "keyword.toml", foreground: "f0a6b4", fontStyle: "bold" },
      { token: "string.toml", foreground: "b8dfae" },
      { token: "string.escape.toml", foreground: "d7b1ff", fontStyle: "bold" },
      { token: "number.toml", foreground: "d7b1ff" },
      { token: "comment.toml", foreground: "73888c", fontStyle: "italic" },
      { token: "operator.toml", foreground: "e2edf0" },
      { token: "delimiter.toml", foreground: "aabdc1" },
      { token: "invalid.toml", foreground: "ff8b96", fontStyle: "bold underline" },
    ],
    colors: {
      "editor.background": "#0f1718",
      "editor.foreground": "#d8e8e8",
      "editorLineNumber.foreground": "#51666b",
      "editorLineNumber.activeForeground": "#9ac9d4",
      "editorCursor.foreground": "#e7f1f1",
      "editor.selectionBackground": "#28515a",
      "editor.inactiveSelectionBackground": "#1a2a2d",
      "editor.lineHighlightBackground": "#152124",
      "editorIndentGuide.background1": "#24373a",
      "editorIndentGuide.activeBackground1": "#56777d",
    },
  });
}

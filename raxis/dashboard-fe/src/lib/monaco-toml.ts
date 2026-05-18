type MonacoLanguageApi = {
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

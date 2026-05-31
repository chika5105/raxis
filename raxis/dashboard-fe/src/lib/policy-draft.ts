export const POLICY_DRAFT_STORAGE_KEY = "raxis.dashboard.policyDraft.v1";

export function readPolicyDraft(): string | null {
  if (typeof window === "undefined" || !window.localStorage) return null;
  try {
    return window.localStorage.getItem(POLICY_DRAFT_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function writePolicyDraft(toml: string | null) {
  if (typeof window === "undefined" || !window.localStorage) return;
  try {
    if (toml === null) window.localStorage.removeItem(POLICY_DRAFT_STORAGE_KEY);
    else window.localStorage.setItem(POLICY_DRAFT_STORAGE_KEY, toml);
  } catch {
    // Local draft persistence is a UI convenience only. The signed
    // policy epoch in the kernel remains the source of truth.
  }
}

export interface PolicySnippetMerge {
  toml: string;
  anchor: string;
  mode: "append" | "replace";
}

const ARRAY_TABLE_KEYS: Record<string, string> = {
  lanes: "lane_id",
  providers: "provider_id",
  gates: "gate_type",
  permitted_credentials: "name",
  vm_images: "name",
  integration_merge_verifiers: "name",
};

export function mergePolicySnippet(current: string, snippet: string): PolicySnippetMerge {
  const cleanSnippet = snippet.trim();
  const header = firstTomlHeader(cleanSnippet);
  if (!header) {
    return appendPolicySnippet(current, cleanSnippet, cleanSnippet.split(/\r?\n/, 1)[0] ?? "");
  }

  if (header.array) {
    const key = ARRAY_TABLE_KEYS[header.name];
    const value = key ? readTomlStringField(cleanSnippet, key) : null;
    if (key && value) {
      const removed = removeArrayTableBlock(current, header.name, key, value);
      const appended = appendPolicySnippet(removed.toml, cleanSnippet, `${key} = "${value}"`);
      return { ...appended, mode: removed.removed ? "replace" : "append" };
    }
    return appendPolicySnippet(current, cleanSnippet, `[[${header.name}]]`);
  }

  const removed = removeSectionBlock(current, header.name);
  const appended = appendPolicySnippet(removed.toml, cleanSnippet, `[${header.name}]`);
  return { ...appended, mode: removed.removed ? "replace" : "append" };
}

function appendPolicySnippet(current: string, snippet: string, anchor: string): PolicySnippetMerge {
  const base = current.trimEnd();
  return {
    toml: `${base}${base ? "\n\n" : ""}${snippet}\n`,
    anchor,
    mode: "append",
  };
}

interface TomlHeader {
  array: boolean;
  name: string;
}

function firstTomlHeader(text: string): TomlHeader | null {
  for (const line of text.split(/\r?\n/)) {
    const header = parseTomlHeader(line);
    if (header) return header;
  }
  return null;
}

function parseTomlHeader(line: string): TomlHeader | null {
  const trimmed = line.trim();
  const arrayMatch = trimmed.match(/^\[\[([A-Za-z0-9_.-]+)\]\]$/);
  if (arrayMatch) return { array: true, name: arrayMatch[1] };
  const sectionMatch = trimmed.match(/^\[([A-Za-z0-9_.-]+)\]$/);
  if (sectionMatch) return { array: false, name: sectionMatch[1] };
  return null;
}

function readTomlStringField(text: string, key: string): string | null {
  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = text.match(new RegExp(`^\\s*${escapedKey}\\s*=\\s*"([^"]+)"\\s*$`, "m"));
  return match?.[1] ?? null;
}

function removeArrayTableBlock(
  text: string,
  tableName: string,
  key: string,
  value: string,
): { toml: string; removed: boolean } {
  const lines = text.split(/\r?\n/);
  const ranges: Array<[number, number]> = [];
  for (let i = 0; i < lines.length; i += 1) {
    const header = parseTomlHeader(lines[i]);
    if (!header || !header.array || header.name !== tableName) continue;
    const end = findTomlBlockEnd(lines, i, tableName);
    const block = lines.slice(i, end).join("\n");
    if (readTomlStringField(block, key) === value) ranges.push([i, end]);
    i = end - 1;
  }
  return removeRanges(lines, ranges);
}

function removeSectionBlock(text: string, sectionName: string): { toml: string; removed: boolean } {
  const lines = text.split(/\r?\n/);
  const ranges: Array<[number, number]> = [];
  for (let i = 0; i < lines.length; i += 1) {
    const header = parseTomlHeader(lines[i]);
    if (!header || header.array || header.name !== sectionName) continue;
    const end = findTomlBlockEnd(lines, i, sectionName);
    ranges.push([i, end]);
    i = end - 1;
  }
  return removeRanges(lines, ranges);
}

function findTomlBlockEnd(lines: string[], start: number, ownerName: string): number {
  for (let i = start + 1; i < lines.length; i += 1) {
    const header = parseTomlHeader(lines[i]);
    if (!header) continue;
    if (header.name === ownerName || header.name.startsWith(`${ownerName}.`)) continue;
    return trimTrailingBlankLines(lines, i);
  }
  return trimTrailingBlankLines(lines, lines.length);
}

function trimTrailingBlankLines(lines: string[], end: number): number {
  let cursor = end;
  while (cursor > 0 && lines[cursor - 1]?.trim() === "") cursor -= 1;
  return cursor;
}

function removeRanges(lines: string[], ranges: Array<[number, number]>): { toml: string; removed: boolean } {
  if (ranges.length === 0) return { toml: lines.join("\n"), removed: false };
  const keep = lines.filter((_, index) => !ranges.some(([start, end]) => index >= start && index < end));
  return { toml: keep.join("\n").trimEnd(), removed: true };
}

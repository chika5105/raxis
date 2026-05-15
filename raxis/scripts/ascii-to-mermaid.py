#!/usr/bin/env python3
"""ascii-to-mermaid.py — convert ASCII-art diagrams in fenced code blocks
to mermaid blocks where it can be done unambiguously, and skip everything
else with an explicit reason.

The pass walks tracked markdown files looking for untyped (no language tag)
or ``text``-tagged fenced code blocks that look like ASCII diagrams. For
each candidate it:

  1. Checks an optional **rescue manifest** (defaults to
     `/tmp/iter62-wip-mermaid-rescue.json`) for a hand-authored mermaid
     block that matches the ASCII content. If found, the ASCII block is
     replaced with the rescued mermaid, with the original ASCII kept as an
     HTML comment immediately above for auditability.
  2. Otherwise, runs a conservative auto-converter for a small set of
     well-defined shapes (linear arrow flows). The auto-converter must
     produce a syntactically valid mermaid block; on any ambiguity it
     falls through to skip.
  3. Any other block is SKIPped with a classified reason
     (``file-tree``, ``decorative``, ``too-small``, ``tabular-format``,
     ``alignment-critical``, ``ambiguous-labels``).

The pass is **idempotent**: blocks that are already wrapped in the
audit-comment marker are recognised and left alone on subsequent runs.
The mermaid blocks themselves are tagged ``mermaid`` (not ``text``) so
they aren't reclassified as ASCII candidates on a re-run.

Usage:
    python3 scripts/ascii-to-mermaid.py [--check | --apply]
        [--manifest /tmp/iter62-wip-mermaid-rescue.json]
        [paths ...]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


SKIP_DIR_FRAGMENTS = ("node_modules/", "target/", ".git/", "dist/", "build/")
AUDIT_MARKER = "Original ASCII diagram (auto-converted to mermaid in iter62-linkify-repair):"


def repo_root() -> Path:
    out = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True
    ).strip()
    return Path(out)


def list_tracked_md_files(root: Path) -> list[Path]:
    out = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "*.md"], text=True
    )
    files: list[Path] = []
    for rel in out.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        if any(frag in rel for frag in SKIP_DIR_FRAGMENTS):
            continue
        p = root / rel
        if p.is_file():
            files.append(p)
    return files


# ---------------------------------------------------------------------------
# Fenced-block scanner (preserves indentation of opening fence)
# ---------------------------------------------------------------------------


_FENCE_OPEN_RE = re.compile(r"^(?P<indent>\s{0,3})```(?P<lang>[^\s`]*)\s*$")


@dataclass
class FencedBlock:
    open_idx: int  # index of opening fence line
    close_idx: int  # index of closing fence line
    indent: str
    lang: str
    body: list[str]  # lines between fences (no fence lines)


def scan_fenced_blocks(lines: list[str]) -> list[FencedBlock]:
    blocks: list[FencedBlock] = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n").rstrip("\r")
        m = _FENCE_OPEN_RE.match(line)
        if not m:
            i += 1
            continue
        open_idx = i
        indent = m.group("indent")
        lang = m.group("lang")
        close_idx = None
        body: list[str] = []
        j = i + 1
        while j < len(lines):
            jline = lines[j].rstrip("\n").rstrip("\r")
            if re.match(rf"^{re.escape(indent)}```\s*$", jline):
                close_idx = j
                break
            body.append(lines[j].rstrip("\n").rstrip("\r"))
            j += 1
        if close_idx is None:
            i = j
            continue
        blocks.append(FencedBlock(open_idx, close_idx, indent, lang, body))
        i = close_idx + 1
    return blocks


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


_FILE_TREE_RE = re.compile(r"[\u2514\u251c]\u2500\u2500|^\s*[\u2502]\s{2,}", re.MULTILINE)
_BOX_DRAWING_RE = re.compile(r"[\u2500-\u257f]")
_ASCII_BOX_RE = re.compile(r"^\s*\+[-=]{3,}\+\s*$", re.MULTILINE)
_ARROW_RE = re.compile(r"-->|<--|==>|<==|\u2192|\u2190|\u2194")
_SEQ_DIAGRAM_RE = re.compile(r"\|.*<--|\|.*-->|\|.*<==|\|.*==>|\|.*\u2192|\|.*\u2190")
_VERTICAL_BARS_RE = re.compile(r"^\s*\|.*\|.*\|", re.MULTILINE)
_DECORATIVE_BANNER_RE = re.compile(r"^\s*([=*#~_+\-]{20,}|[\u2550]{8,})\s*$", re.MULTILINE)


def looks_like_ascii_diagram(body: str) -> bool:
    if _BOX_DRAWING_RE.search(body):
        return True
    if _ASCII_BOX_RE.search(body):
        return True
    if _ARROW_RE.search(body):
        return True
    return False


def classify_skip_reason(body: str, lang: str) -> str | None:
    """Return a skip reason if the block should be skipped, else None.

    None means "candidate for conversion attempt".
    """
    if _FILE_TREE_RE.search(body):
        return "file-tree"
    if _DECORATIVE_BANNER_RE.search(body) and not _SEQ_DIAGRAM_RE.search(body):
        return "decorative"
    non_blank = [ln for ln in body.splitlines() if ln.strip()]
    if len(non_blank) < 3:
        return "too-small"
    arrow_count = len(_ARROW_RE.findall(body))
    if arrow_count == 0:
        if _VERTICAL_BARS_RE.search(body) and not _SEQ_DIAGRAM_RE.search(body):
            return "tabular-format"
        if _BOX_DRAWING_RE.search(body):
            return "alignment-critical"
        return "no-arrows"
    if _SEQ_DIAGRAM_RE.search(body):
        return None
    if _ARROW_RE.search(body) and arrow_count >= 2:
        if _is_linear_arrow_flow(body):
            return None
    return "ambiguous-labels"


_LINEAR_ARROW_RE = re.compile(
    r"^([^\n]*?)\s*(?:-->|->|\u2192|=>)\s*([^\n]+)$"
)
_NUMBERED_PREFIX_RE = re.compile(r"^\s*(?:\d+[.)]|[\(\[]?[a-z][.)\]]\s)")
_ARROW_SPLIT_RE = re.compile(r"\s*(?:-->|->|\u2192|=>)\s*")


def _is_linear_arrow_flow(body: str) -> bool:
    """True if body is a connected pipeline of N >= 3 nodes, each line of
    the form ``A -> B`` (or ``A -> B -> C`` chain), with line ``k``'s first
    node equal to line ``k-1``'s last node.

    Numbered or lettered list-style enumerations are rejected — those are
    *fallthrough* sequences, not flows.

    Box-drawing characters and vertical-bar tables disqualify outright.
    """
    if _BOX_DRAWING_RE.search(body):
        return False
    if _ASCII_BOX_RE.search(body):
        return False
    if _VERTICAL_BARS_RE.search(body):
        return False
    non_blank = [ln.rstrip() for ln in body.splitlines() if ln.strip()]
    if len(non_blank) < 3:
        return False
    chained_tail: str | None = None
    for ln in non_blank:
        if _NUMBERED_PREFIX_RE.match(ln):
            return False
        m = _LINEAR_ARROW_RE.match(ln.strip())
        if not m:
            return False
        parts = [p.strip() for p in _ARROW_SPLIT_RE.split(ln.strip()) if p.strip()]
        if len(parts) < 2:
            return False
        if chained_tail is not None and parts[0] != chained_tail:
            return False
        chained_tail = parts[-1]
    return True


# ---------------------------------------------------------------------------
# Auto-conversion: linear arrow flow only.
# ---------------------------------------------------------------------------


_NODE_ID_BAD_CHARS = re.compile(r"[^A-Za-z0-9_]+")


def _node_id(label: str, used: dict[str, str]) -> str:
    if label in used:
        return used[label]
    base = _NODE_ID_BAD_CHARS.sub("_", label.strip()).strip("_")
    if not base:
        base = f"N{len(used)}"
    if not base[0].isalpha():
        base = "N" + base
    nid = base
    i = 1
    existing_ids = set(used.values())
    while nid in existing_ids:
        i += 1
        nid = f"{base}_{i}"
    used[label] = nid
    return nid


def convert_linear_arrow_flow(body: str) -> str | None:
    """Convert a linear arrow flow block to a mermaid flowchart LR. Returns
    None if conversion is not safe.
    """
    if not _is_linear_arrow_flow(body):
        return None
    used: dict[str, str] = {}
    edges: list[tuple[str, str]] = []
    for ln in (l.strip() for l in body.splitlines() if l.strip()):
        parts = re.split(r"\s*(?:-->|->|\u2192|=>)\s*", ln)
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) < 2:
            return None
        for a, b in zip(parts, parts[1:]):
            edges.append((a, b))
    out_lines = ["flowchart LR"]
    for a, b in edges:
        aid = _node_id(a, used)
        bid = _node_id(b, used)
        out_lines.append(f"    {aid}[\"{a}\"] --> {bid}[\"{b}\"]")
    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# Rescue-manifest matching
# ---------------------------------------------------------------------------


@dataclass
class RescueEntry:
    file: str
    matched_ascii_content: str | None
    mermaid_content: str
    preceding_header: str


def load_rescue_manifest(path: Path | None) -> list[RescueEntry]:
    if path is None or not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    out = []
    for e in data:
        out.append(
            RescueEntry(
                file=e.get("file", ""),
                matched_ascii_content=e.get("matched_ascii_content"),
                mermaid_content=e.get("mermaid_content", ""),
                preceding_header=e.get("preceding_header", ""),
            )
        )
    return out


def _normalise(s: str) -> str:
    return "\n".join(line.rstrip() for line in s.splitlines()).strip()


def find_rescue_for_block(
    body: str, file_rel: str, rescue: list[RescueEntry]
) -> RescueEntry | None:
    bn = _normalise(body)
    for e in rescue:
        if e.file != file_rel:
            continue
        if e.matched_ascii_content is None:
            continue
        if _normalise(e.matched_ascii_content) == bn:
            return e
    return None


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------


@dataclass
class FileChangeStats:
    rescued: int = 0
    auto_converted: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    skip_logs: list[str] = field(default_factory=list)


def process_file(
    path: Path,
    root: Path,
    rescue: list[RescueEntry],
) -> tuple[str | None, FileChangeStats]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    bare_lines = [ln.rstrip("\n").rstrip("\r") for ln in lines]
    blocks = scan_fenced_blocks(lines)

    stats = FileChangeStats()
    file_rel = str(path.relative_to(root))

    replacements: list[tuple[int, int, list[str]]] = []

    for blk in blocks:
        if blk.lang not in ("", "text"):
            continue
        body = "\n".join(blk.body)
        if not looks_like_ascii_diagram(body):
            continue
        prev_idx = blk.open_idx - 1
        if prev_idx >= 0 and AUDIT_MARKER in bare_lines[prev_idx]:
            continue
        if (
            blk.open_idx > 0
            and bare_lines[blk.open_idx - 1].strip().endswith("-->")
            and any(AUDIT_MARKER in bl for bl in bare_lines[max(0, blk.open_idx - 20) : blk.open_idx])
        ):
            continue

        line_no = blk.open_idx + 1
        rescue_hit = find_rescue_for_block(body, file_rel, rescue)
        if rescue_hit is not None:
            new_block_lines = _build_mermaid_replacement(
                blk.indent, body, rescue_hit.mermaid_content
            )
            replacements.append((blk.open_idx, blk.close_idx, new_block_lines))
            stats.rescued += 1
            continue

        skip = classify_skip_reason(body, blk.lang)
        if skip is None:
            mermaid = convert_linear_arrow_flow(body)
            if mermaid is None:
                skip = "auto-convert-failed"
            else:
                new_block_lines = _build_mermaid_replacement(blk.indent, body, mermaid)
                replacements.append((blk.open_idx, blk.close_idx, new_block_lines))
                stats.auto_converted += 1
                continue

        stats.skipped[skip] = stats.skipped.get(skip, 0) + 1
        stats.skip_logs.append(
            f"SKIP: ASCII block in {file_rel}:{line_no} not converted — reason: {skip}"
        )

    if not replacements:
        return None, stats

    replacements.sort(key=lambda r: r[0], reverse=True)
    out_lines = list(lines)
    for open_idx, close_idx, new_block in replacements:
        replacement_lines = [s + "\n" for s in new_block]
        if out_lines and not out_lines[-1].endswith("\n") and close_idx == len(out_lines) - 1:
            replacement_lines[-1] = replacement_lines[-1].rstrip("\n")
        out_lines[open_idx : close_idx + 1] = replacement_lines

    return "".join(out_lines), stats


def _build_mermaid_replacement(
    indent: str, original_ascii: str, mermaid_content: str
) -> list[str]:
    out: list[str] = []
    out.append(f"{indent}<!-- {AUDIT_MARKER}")
    for ln in original_ascii.splitlines():
        out.append(f"{indent}     {ln}" if ln else f"{indent}")
    out.append(f"{indent}-->")
    out.append(f"{indent}```mermaid")
    for ln in mermaid_content.splitlines():
        out.append(f"{indent}{ln}" if ln else "")
    out.append(f"{indent}```")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--root", default=None)
    parser.add_argument(
        "--manifest",
        default="/tmp/iter62-wip-mermaid-rescue.json",
        help="WIP rescue manifest path (JSON)",
    )
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else repo_root()
    rescue = load_rescue_manifest(Path(args.manifest))

    if args.paths:
        files = [Path(p).resolve() for p in args.paths]
    else:
        files = list_tracked_md_files(root)

    total_rescued = 0
    total_converted = 0
    total_skipped: dict[str, int] = {}
    total_changed_files = 0
    all_skip_logs: list[str] = []

    for f in files:
        try:
            new_text, stats = process_file(f, root, rescue)
        except Exception as e:
            print(f"ERROR: {f}: {e}", file=sys.stderr)
            continue
        total_rescued += stats.rescued
        total_converted += stats.auto_converted
        for k, v in stats.skipped.items():
            total_skipped[k] = total_skipped.get(k, 0) + v
        all_skip_logs.extend(stats.skip_logs)
        if new_text is None:
            continue
        total_changed_files += 1
        action = "WROTE" if args.apply else "WOULD CHANGE"
        print(
            f"{action} {f.relative_to(root)} "
            f"(rescued={stats.rescued}, auto={stats.auto_converted}, "
            f"skipped={sum(stats.skipped.values())})"
        )
        if args.apply:
            f.write_text(new_text, encoding="utf-8")

    for ln in all_skip_logs:
        print(ln, file=sys.stderr)

    print(
        f"\nSummary: {total_changed_files} file(s) "
        f"{'rewritten' if args.apply else 'would change'}, "
        f"{total_rescued} rescued, {total_converted} auto-converted, "
        f"{sum(total_skipped.values())} skipped."
    )
    if total_skipped:
        print("Skip reasons:")
        for k, v in sorted(total_skipped.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")

    if not args.apply and total_changed_files > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

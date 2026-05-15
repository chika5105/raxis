#!/usr/bin/env python3
"""linkify-md.py — code-block-aware Markdown cross-reference linkifier.

Walks tracked markdown files in the repo and rewrites bare backticked
references to .md files into proper markdown links:

    `path/to/file.md`         -> [`path/to/file.md`](path/to/file.md)
    `path/to/file.md §X.Y`    -> [`path/to/file.md §X.Y`](path/to/file.md)

Skips fenced code blocks, indented code blocks, inline code spans that
are not themselves a backtick-ref, HTML comments, YAML front-matter,
and existing markdown links. Idempotent: a second run is a no-op.
References to files that do not resolve (relative-first, repo-root
fallback) are left untouched with a WARN logged to stderr.

Also repairs a known prior-script corruption pattern (orphan trailing
backticks on section-anchor refs):

    [`X.md`](X.md) §1b`   -> [`X.md §1b`](X.md)

Usage:
    python3 scripts/linkify-md.py [--check | --apply]

    --check (default): dry run. Prints would-be changes. Exits 1 if
                       any file would change. Suitable for CI.
    --apply:           rewrite files in place.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


SKIP_DIR_FRAGMENTS = ("node_modules/", "target/", ".git/", "dist/", "build/")

SKIP_DIRECTIVE = "<!-- linkify: skip -->"


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
# Per-line classification (block-level state machine)
# ---------------------------------------------------------------------------


PROSE = "prose"
SKIP_FRONTMATTER = "skip-frontmatter"
SKIP_FENCE = "skip-fence"
SKIP_INDENTED = "skip-indented"
SKIP_HTML_COMMENT = "skip-html-comment"
SKIP_HTML_BLOCK = "skip-html-block"


_FENCE_OPEN_RE = re.compile(r"^(?P<indent>\s{0,3})(?P<marker>`{3,}|~{3,})(?P<rest>.*)$")
_HTML_BLOCK_OPEN_RE = re.compile(r"<(?P<tag>pre|code|script|style)\b", re.IGNORECASE)


def classify_lines(lines: list[str]) -> list[str]:
    """Classify each line as PROSE or one of the SKIP_* states.

    The classifier is conservative: when uncertain, prefer SKIP so we
    don't accidentally rewrite shell commands or other non-prose.
    """
    out: list[str] = []

    in_frontmatter = False
    fence_marker: str | None = None
    in_html_comment = False
    in_html_block_tag: str | None = None
    prev_blank = True

    # YAML front-matter: only if very first line is exactly "---".
    if lines and lines[0].rstrip("\n").rstrip("\r") == "---":
        in_frontmatter = True

    for i, raw in enumerate(lines):
        line = raw.rstrip("\n").rstrip("\r")
        stripped = line.strip()

        if in_frontmatter:
            out.append(SKIP_FRONTMATTER)
            if i > 0 and (line == "---" or line == "..."):
                in_frontmatter = False
            elif i == 0:
                pass
            prev_blank = stripped == ""
            continue

        if in_html_comment:
            out.append(SKIP_HTML_COMMENT)
            if "-->" in line:
                in_html_comment = False
            prev_blank = stripped == ""
            continue

        if in_html_block_tag is not None:
            out.append(SKIP_HTML_BLOCK)
            if re.search(rf"</{in_html_block_tag}\s*>", line, re.IGNORECASE):
                in_html_block_tag = None
            prev_blank = stripped == ""
            continue

        if fence_marker is not None:
            out.append(SKIP_FENCE)
            m = re.match(rf"^\s{{0,3}}{re.escape(fence_marker[0])}{{{len(fence_marker)},}}\s*$", line)
            if m:
                fence_marker = None
            prev_blank = stripped == ""
            continue

        fm = _FENCE_OPEN_RE.match(line)
        if fm:
            fence_marker = fm.group("marker")
            out.append(SKIP_FENCE)
            prev_blank = False
            continue

        comment_open = "<!--" in line
        comment_close = "-->" in line
        if comment_open and not comment_close:
            in_html_comment = True
        # A single-line HTML comment is fine: line is still PROSE around the
        # comment, but the linkifier will skip the comment span on the line.

        hb = _HTML_BLOCK_OPEN_RE.search(line)
        if hb and not re.search(rf"</{hb.group('tag')}\s*>", line, re.IGNORECASE):
            in_html_block_tag = hb.group("tag").lower()
            out.append(SKIP_HTML_BLOCK)
            prev_blank = False
            continue

        if prev_blank and (raw.startswith("    ") or raw.startswith("\t")):
            out.append(SKIP_INDENTED)
            prev_blank = stripped == ""
            continue

        out.append(PROSE)
        prev_blank = stripped == ""

    return out


# ---------------------------------------------------------------------------
# Reference parsing and resolution
# ---------------------------------------------------------------------------


_REF_CONTENT_RE = re.compile(
    r"""^
    (?P<file>[^\s`<>(){}\[\]]+\.md)
    (?P<anchor>(?:\s+§[^`]+)?)
    $
    """,
    re.VERBOSE,
)


@dataclass
class Ref:
    file: str
    anchor: str  # empty or starts with whitespace + "§..."


def parse_ref(content: str) -> Ref | None:
    """If `content` (the text inside backticks) looks like an .md cross-ref,
    return a Ref; otherwise None."""
    m = _REF_CONTENT_RE.match(content)
    if not m:
        return None
    return Ref(file=m.group("file"), anchor=m.group("anchor") or "")


def resolve_md_path(ref: str, file_dir: Path, root: Path) -> Path | None:
    """Resolve a markdown ref, trying file_dir first then repo root."""
    base = ref.split("#", 1)[0]
    base = base.split("?", 1)[0]
    if base.startswith("/"):
        # Treat as repo-relative
        cand = (root / base.lstrip("/"))
        if cand.is_file():
            return cand
        return None
    cand = (file_dir / base)
    if cand.is_file():
        return cand
    cand = (root / base)
    if cand.is_file():
        return cand
    return None


# ---------------------------------------------------------------------------
# Pattern A repair (orphan trailing backtick on section-anchor refs)
# ---------------------------------------------------------------------------


_PATTERN_A_RE = re.compile(
    r"""
    \[`(?P<file>[^`\]\s]+\.md)`\]
    \((?P<target>[^)\s]+)\)
    (?P<anchor>\s+§[^`\n]+?)
    `
    (?!`)
    """,
    re.VERBOSE,
)


def repair_pattern_a(line: str) -> tuple[str, int]:
    """Repair orphan trailing backticks left by the previous broken script.

    Only repairs lines with an odd backtick count (the orphan signature);
    otherwise the line's backticks are all paired and any apparent match
    is a false positive.
    """
    if line.count("`") % 2 == 0:
        return line, 0
    new_line, n = _PATTERN_A_RE.subn(
        lambda m: f"[`{m.group('file')}{m.group('anchor')}`]({m.group('target')})",
        line,
    )
    return new_line, n


# ---------------------------------------------------------------------------
# Linkify pass — operates on a single prose line
# ---------------------------------------------------------------------------


def _strip_html_comments(line: str) -> list[tuple[int, int]]:
    """Return (start, end_exclusive) spans of HTML comments on the line."""
    spans: list[tuple[int, int]] = []
    i = 0
    while True:
        j = line.find("<!--", i)
        if j == -1:
            break
        k = line.find("-->", j + 4)
        if k == -1:
            spans.append((j, len(line)))
            break
        spans.append((j, k + 3))
        i = k + 3
    return spans


def linkify_line(
    line: str,
    file_dir: Path,
    root: Path,
    file_rel: str,
    line_no: int,
) -> tuple[str, int, list[str]]:
    """Linkify backtick refs on a single prose line.

    Returns (new_line, edits, warnings).
    """
    edits = 0
    warnings: list[str] = []

    comment_spans = _strip_html_comments(line)

    def in_comment(pos: int) -> bool:
        return any(s <= pos < e for s, e in comment_spans)

    # Scan for inline code spans (paired runs of backticks of equal length).
    out: list[str] = []
    i = 0
    n = len(line)

    while i < n:
        if line[i] != "`":
            out.append(line[i])
            i += 1
            continue

        # Found a backtick; measure run length.
        run_start = i
        while i < n and line[i] == "`":
            i += 1
        run_len = i - run_start
        content_start = i

        # Search for matching closing run (same length, not embedded in
        # longer run).
        close_start = None
        j = content_start
        while j < n:
            if line[j] == "`":
                k = j
                while k < n and line[k] == "`":
                    k += 1
                if k - j == run_len:
                    close_start = j
                    break
                j = k
            else:
                j += 1

        if close_start is None:
            # Unmatched run; emit as literal and continue.
            out.append(line[run_start:content_start])
            continue

        content = line[content_start:close_start]
        close_end = close_start + run_len

        # If inside an HTML comment span, don't touch.
        if in_comment(run_start):
            out.append(line[run_start:close_end])
            i = close_end
            continue

        # Check if this code span is the link-text of an existing markdown link:
        #   [`...`](url)
        prev_char = line[run_start - 1] if run_start > 0 else ""
        after = line[close_end : close_end + 2]
        is_existing_link_text = prev_char == "[" and after.startswith("](")

        # Only linkify single-backtick spans that look like md refs.
        ref: Ref | None = None
        if run_len == 1 and not is_existing_link_text:
            ref = parse_ref(content)

        if ref is None:
            out.append(line[run_start:close_end])
            i = close_end
            continue

        resolved = resolve_md_path(ref.file, file_dir, root)
        if resolved is None:
            warnings.append(
                f"WARN: unresolved {ref.file!r} in {file_rel}:{line_no}"
            )
            out.append(line[run_start:close_end])
            i = close_end
            continue

        # Choose link target: keep ref-as-written when it resolves relative to
        # file_dir; otherwise compute a relative path from file_dir.
        rel_cand = (file_dir / ref.file)
        if rel_cand.is_file():
            target = ref.file
        else:
            try:
                target = os.path.relpath(resolved, file_dir)
            except ValueError:
                target = ref.file

        link_text = f"`{ref.file}{ref.anchor}`"
        out.append(f"[{link_text}]({target})")
        edits += 1
        i = close_end

    return "".join(out), edits, warnings


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------


@dataclass
class FileResult:
    path: Path
    changed: bool
    new_text: str | None
    pattern_a_edits: int
    linkify_edits: int
    warnings: list[str] = field(default_factory=list)


def process_file(path: Path, root: Path) -> FileResult:
    text = path.read_text(encoding="utf-8")
    rel = str(path.relative_to(root))

    if text.lstrip().startswith(SKIP_DIRECTIVE):
        return FileResult(path, False, None, 0, 0)

    lines = text.splitlines(keepends=True)
    classified = classify_lines(lines)

    pattern_a = 0
    linkify = 0
    warnings: list[str] = []

    new_lines: list[str] = []
    for i, line in enumerate(lines):
        if classified[i] != PROSE:
            new_lines.append(line)
            continue
        had_newline = line.endswith("\n")
        body = line[:-1] if had_newline else line

        body, n_a = repair_pattern_a(body)
        pattern_a += n_a

        body, n_l, w = linkify_line(body, path.parent, root, rel, i + 1)
        linkify += n_l
        warnings.extend(w)

        new_lines.append(body + ("\n" if had_newline else ""))

    new_text = "".join(new_lines)
    changed = new_text != text
    return FileResult(
        path=path,
        changed=changed,
        new_text=new_text if changed else None,
        pattern_a_edits=pattern_a,
        linkify_edits=linkify,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="dry run (default)")
    mode.add_argument("--apply", action="store_true", help="rewrite files in place")
    parser.add_argument(
        "--root",
        default=None,
        help="repository root (defaults to `git rev-parse --show-toplevel`)",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="limit processing to these files (defaults to all tracked .md)",
    )
    args = parser.parse_args(argv)

    apply = args.apply
    # `--check` is the default behaviour.

    root = Path(args.root).resolve() if args.root else repo_root()

    if args.paths:
        files = [Path(p).resolve() for p in args.paths]
    else:
        files = list_tracked_md_files(root)

    total_changed = 0
    total_pattern_a = 0
    total_linkify = 0
    all_warnings: list[str] = []
    changed_files: list[Path] = []

    for f in files:
        try:
            res = process_file(f, root)
        except Exception as e:
            print(f"ERROR: {f}: {e}", file=sys.stderr)
            continue
        all_warnings.extend(res.warnings)
        if not res.changed:
            continue
        total_changed += 1
        total_pattern_a += res.pattern_a_edits
        total_linkify += res.linkify_edits
        changed_files.append(f)
        if apply:
            f.write_text(res.new_text, encoding="utf-8")
            print(
                f"WROTE {f.relative_to(root)} "
                f"(pattern_a={res.pattern_a_edits}, linkify={res.linkify_edits})"
            )
        else:
            print(
                f"WOULD CHANGE {f.relative_to(root)} "
                f"(pattern_a={res.pattern_a_edits}, linkify={res.linkify_edits})"
            )

    for w in all_warnings:
        print(w, file=sys.stderr)

    summary = (
        f"\nSummary: {total_changed} file(s) "
        f"{'rewritten' if apply else 'would change'}, "
        f"{total_pattern_a} Pattern-A repair(s), "
        f"{total_linkify} linkification(s), "
        f"{len(all_warnings)} unresolved warning(s)."
    )
    print(summary)

    if not apply and total_changed > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Tests for scripts/linkify-md.py and scripts/ascii-to-mermaid.py.

Run: python3 scripts/test_linkify_md.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent


def _load_module(filename: str, modname: str):
    """Load a hyphenated-filename script as a Python module."""
    spec = importlib.util.spec_from_file_location(modname, str(_HERE / filename))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


lm = _load_module("linkify-md.py", "linkify_md")
am = _load_module("ascii-to-mermaid.py", "ascii_to_mermaid")


class FakeRepo:
    """A scratch repo on disk that holds a few .md files for resolution."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def write(self, rel: str, content: str = "") -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def close(self) -> None:
        self.tmp.cleanup()


class LinkifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = FakeRepo()
        self.repo.write("specs/v2/credential-proxy.md", "# cred proxy\n")
        self.repo.write("specs/v2/airgap-architecture.md", "# airgap\n")
        self.repo.write("specs/v2/vm-network-isolation.md", "# vm net\n")
        self.repo.write("guides/recipes/ops/03-backup.md", "# backup\n")
        self.repo.write("README.md", "# readme\n")

    def tearDown(self) -> None:
        self.repo.close()

    # ---- helpers --------------------------------------------------------

    def _run_on(self, rel: str, content: str) -> lm.FileResult:
        p = self.repo.write(rel, content)
        return lm.process_file(p, self.repo.root)

    # ---- pattern A repair ----------------------------------------------

    def test_pattern_a_repair_orphan_trailing_backtick(self) -> None:
        body = (
            "# Doc\n"
            "\n"
            "See [`credential-proxy.md`](credential-proxy.md) \u00a71b` for "
            "TCP details.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNotNone(res.new_text)
        self.assertIn(
            "[`credential-proxy.md \u00a71b`](credential-proxy.md)",
            res.new_text,
        )
        self.assertNotIn("\u00a71b`", res.new_text.replace(
            "[`credential-proxy.md \u00a71b`](credential-proxy.md)", ""
        ))
        self.assertGreaterEqual(res.pattern_a_edits, 1)

    def test_pattern_a_does_not_fire_on_benign_trailing_inline_code(self) -> None:
        body = (
            "# Doc\n"
            "\n"
            "See [`credential-proxy.md`](credential-proxy.md) \u00a72.5 and "
            "the `[config]` table.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNone(res.new_text)
        self.assertEqual(res.pattern_a_edits, 0)

    # ---- pattern B (don't touch inside fences) -------------------------

    def test_no_linkify_inside_fenced_code_block(self) -> None:
        # File at repo root so `README.md` resolves relative to file_dir
        # and link target stays as `README.md`.
        body = (
            "# Recipe\n"
            "\n"
            "Run the backup:\n"
            "\n"
            "```bash\n"
            "cat README.md\n"
            "ls specs/v2/credential-proxy.md\n"
            "```\n"
            "\n"
            "See `README.md` for details.\n"
        )
        res = self._run_on("recipe.md", body)
        self.assertIsNotNone(res.new_text)
        self.assertIn("cat README.md\n", res.new_text)
        self.assertIn("ls specs/v2/credential-proxy.md\n", res.new_text)
        self.assertIn("See [`README.md`](README.md)", res.new_text)

    def test_no_linkify_inside_tilde_fence(self) -> None:
        body = (
            "Run:\n"
            "\n"
            "~~~bash\n"
            "cat README.md\n"
            "~~~\n"
        )
        res = self._run_on("README.md", body)
        # Nothing in prose to linkify; tilde fence preserved.
        self.assertIsNone(res.new_text)

    def test_no_linkify_inside_indented_code_block(self) -> None:
        body = (
            "Some prose.\n"
            "\n"
            "    cat README.md\n"
            "    ls specs/v2/credential-proxy.md\n"
            "\n"
            "More prose with `README.md`.\n"
        )
        res = self._run_on("foo.md", body)
        self.assertIsNotNone(res.new_text)
        self.assertIn("    cat README.md\n", res.new_text)
        self.assertIn("    ls specs/v2/credential-proxy.md\n", res.new_text)
        self.assertIn("[`README.md`](README.md)", res.new_text)

    # ---- inline code spans that are not refs ---------------------------

    def test_inline_code_span_not_a_ref_is_left_alone(self) -> None:
        body = "Use `git status` to check; see `README.md` for details.\n"
        res = self._run_on("foo.md", body)
        self.assertIsNotNone(res.new_text)
        self.assertIn("`git status`", res.new_text)
        self.assertIn("[`README.md`](README.md)", res.new_text)

    # ---- section anchor inside link text -------------------------------

    def test_section_anchor_inside_link_text(self) -> None:
        # Sibling-file ref: resolves relative to file_dir, target preserved.
        body = (
            "Cross-ref: `credential-proxy.md \u00a71b` covers TCP.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNotNone(res.new_text)
        self.assertIn(
            "[`credential-proxy.md \u00a71b`](credential-proxy.md)",
            res.new_text,
        )

    # ---- idempotence ---------------------------------------------------

    def test_idempotent_second_run(self) -> None:
        body = (
            "# Doc\n"
            "\n"
            "See `credential-proxy.md` and `credential-proxy.md \u00a71b`.\n"
            "\n"
            "```bash\n"
            "cat credential-proxy.md\n"
            "```\n"
        )
        p = self.repo.write("specs/v2/vm-network-isolation.md", body)
        first = lm.process_file(p, self.repo.root)
        self.assertIsNotNone(first.new_text)
        p.write_text(first.new_text, encoding="utf-8")
        second = lm.process_file(p, self.repo.root)
        self.assertIsNone(second.new_text)
        self.assertEqual(second.pattern_a_edits, 0)
        self.assertEqual(second.linkify_edits, 0)

    # ---- unresolved ref ------------------------------------------------

    def test_unresolved_ref_skipped_with_warning(self) -> None:
        body = "See `does-not-exist.md` for more.\n"
        res = self._run_on("foo.md", body)
        self.assertIsNone(res.new_text)
        self.assertTrue(any("does-not-exist.md" in w for w in res.warnings))

    # ---- existing well-formed link is untouched ------------------------

    def test_existing_link_left_untouched(self) -> None:
        body = (
            "Already linked: [`credential-proxy.md`](credential-proxy.md) "
            "covers Tier 2.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNone(res.new_text)

    def test_existing_link_with_prose_anchor_left_untouched(self) -> None:
        # Existing convention on main: link the filename, leave §anchor in prose.
        body = (
            "See [`credential-proxy.md`](credential-proxy.md) \u00a72.5 for "
            "details.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNone(res.new_text)

    # ---- HTML comments and YAML front-matter ---------------------------

    def test_html_comment_inline_is_skipped(self) -> None:
        body = (
            "<!-- See `credential-proxy.md` for the spec. -->\n"
            "\n"
            "Public: `credential-proxy.md` is the spec.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNotNone(res.new_text)
        self.assertIn(
            "<!-- See `credential-proxy.md` for the spec. -->\n",
            res.new_text,
        )
        self.assertIn(
            "Public: [`credential-proxy.md`](credential-proxy.md) is the spec.",
            res.new_text,
        )

    def test_multiline_html_comment_is_skipped(self) -> None:
        body = (
            "<!--\n"
            "See `credential-proxy.md` for the spec.\n"
            "Also `airgap-architecture.md`.\n"
            "-->\n"
            "\n"
            "Public: `credential-proxy.md`.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNotNone(res.new_text)
        self.assertIn("See `credential-proxy.md` for the spec.", res.new_text)
        self.assertIn("Also `airgap-architecture.md`.", res.new_text)
        self.assertIn(
            "Public: [`credential-proxy.md`](credential-proxy.md).",
            res.new_text,
        )

    def test_yaml_frontmatter_is_skipped(self) -> None:
        body = (
            "---\n"
            "title: My Doc\n"
            "see_also: `credential-proxy.md`\n"
            "---\n"
            "\n"
            "Body: `credential-proxy.md`.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNotNone(res.new_text)
        self.assertIn("see_also: `credential-proxy.md`\n", res.new_text)
        self.assertIn(
            "Body: [`credential-proxy.md`](credential-proxy.md).",
            res.new_text,
        )

    # ---- skip directive -----------------------------------------------

    def test_first_line_skip_directive(self) -> None:
        body = (
            "<!-- linkify: skip -->\n"
            "\n"
            "See `credential-proxy.md`.\n"
        )
        res = self._run_on("specs/v2/vm-network-isolation.md", body)
        self.assertIsNone(res.new_text)

    # ---- backtick run length -------------------------------------------

    def test_double_backtick_span_not_linkified(self) -> None:
        # Double-backtick spans aren't md refs; leave alone.
        body = "Embedded: ``foo.md`` is special.\n"
        res = self._run_on("foo.md", body)
        self.assertIsNone(res.new_text)

    # ---- non-md inline code is not linkified ---------------------------

    def test_non_md_filename_not_linkified(self) -> None:
        body = "See `Cargo.toml` and `main.rs` and `policy.json`.\n"
        res = self._run_on("foo.md", body)
        self.assertIsNone(res.new_text)


class AsciiToMermaidTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, rel: str, content: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def _process(self, rel: str, rescue=None):
        p = self._write(rel, "") if not (self.root / rel).is_file() else self.root / rel
        rescue = rescue or []
        return am.process_file(p, self.root, rescue)

    def test_file_tree_skipped(self) -> None:
        body = (
            "Layout:\n"
            "\n"
            "```text\n"
            "raxis/\n"
            "\u251c\u2500\u2500 cli\n"
            "\u251c\u2500\u2500 crates\n"
            "\u2514\u2500\u2500 specs\n"
            "```\n"
        )
        p = self._write("doc.md", body)
        new_text, stats = am.process_file(p, self.root, [])
        self.assertIsNone(new_text)
        self.assertIn("file-tree", stats.skipped)

    def test_too_small_skipped(self) -> None:
        body = (
            "Flow:\n"
            "\n"
            "```text\n"
            "Agent --> Kernel\n"
            "```\n"
        )
        p = self._write("doc.md", body)
        new_text, stats = am.process_file(p, self.root, [])
        self.assertIsNone(new_text)
        self.assertIn("too-small", stats.skipped)

    def test_decorative_banner_skipped(self) -> None:
        body = (
            "Splash:\n"
            "\n"
            "```text\n"
            "==============================\n"
            "  RAXIS  -->  banner\n"
            "==============================\n"
            "```\n"
        )
        p = self._write("doc.md", body)
        new_text, stats = am.process_file(p, self.root, [])
        self.assertIsNone(new_text)
        self.assertIn("decorative", stats.skipped)

    def test_linear_arrow_flow_auto_converted(self) -> None:
        body = (
            "Flow:\n"
            "\n"
            "```text\n"
            "Agent --> Kernel --> Tproxy\n"
            "Tproxy --> Upstream\n"
            "Upstream --> Agent\n"
            "```\n"
        )
        p = self._write("doc.md", body)
        new_text, stats = am.process_file(p, self.root, [])
        self.assertIsNotNone(new_text)
        self.assertEqual(stats.auto_converted, 1)
        self.assertIn("```mermaid", new_text)
        self.assertIn("flowchart LR", new_text)
        self.assertIn(am.AUDIT_MARKER, new_text)
        self.assertIn("Agent --> Kernel --> Tproxy", new_text)

    def test_rescue_replaces_ascii_with_manifest_mermaid(self) -> None:
        ascii_block = (
            "Agent process       Tproxy       Kernel\n"
            "    |                 |            |\n"
            "    |--TCP connect--->|            |\n"
            "    |                 |--admit--->|\n"
            "    |                 |<--ok------|\n"
        )
        body = (
            "Flow:\n"
            "\n"
            "```text\n"
            f"{ascii_block}```\n"
        )
        p = self._write("doc.md", body)
        rescue = [
            am.RescueEntry(
                file="doc.md",
                matched_ascii_content=ascii_block.rstrip("\n"),
                mermaid_content=(
                    "sequenceDiagram\n"
                    "    participant Agent\n"
                    "    participant Tproxy\n"
                    "    participant Kernel\n"
                    "    Agent->>Tproxy: TCP connect\n"
                    "    Tproxy->>Kernel: admit\n"
                    "    Kernel-->>Tproxy: ok"
                ),
                preceding_header="",
            )
        ]
        new_text, stats = am.process_file(p, self.root, rescue)
        self.assertIsNotNone(new_text)
        self.assertEqual(stats.rescued, 1)
        self.assertIn("```mermaid", new_text)
        self.assertIn("sequenceDiagram", new_text)
        self.assertIn(am.AUDIT_MARKER, new_text)
        self.assertIn("Agent process", new_text)

    def test_idempotent_second_run(self) -> None:
        body = (
            "Flow:\n"
            "\n"
            "```text\n"
            "Agent --> Kernel --> Tproxy\n"
            "Tproxy --> Upstream\n"
            "Upstream --> Agent\n"
            "```\n"
        )
        p = self._write("doc.md", body)
        new_text, stats = am.process_file(p, self.root, [])
        self.assertIsNotNone(new_text)
        p.write_text(new_text, encoding="utf-8")
        new_text2, stats2 = am.process_file(p, self.root, [])
        self.assertIsNone(new_text2)
        self.assertEqual(stats2.auto_converted, 0)
        self.assertEqual(stats2.rescued, 0)

    def test_already_mermaid_block_left_alone(self) -> None:
        body = (
            "Flow:\n"
            "\n"
            "```mermaid\n"
            "flowchart LR\n"
            "    A --> B\n"
            "```\n"
        )
        p = self._write("doc.md", body)
        new_text, stats = am.process_file(p, self.root, [])
        self.assertIsNone(new_text)
        self.assertEqual(stats.auto_converted, 0)
        self.assertEqual(stats.rescued, 0)


if __name__ == "__main__":
    unittest.main()

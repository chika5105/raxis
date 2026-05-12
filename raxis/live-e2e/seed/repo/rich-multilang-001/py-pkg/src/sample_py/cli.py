"""Entry-point used by `python -m sample_py.cli` and the project script."""

from __future__ import annotations

import sys

from .greet import render_greeting


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    name = args[0] if args else "World"
    sys.stdout.write(render_greeting(name) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Greeting rendering — mirror of `rust-crate::greeting::render_greeting`.

Renaming this function (or its signature) is part of the
cross-file-refactor e2e scenario and must propagate to the Rust and
TypeScript trees in the same commit.
"""

from __future__ import annotations


def render_greeting(name: str) -> str:
    """Render a greeting for the supplied name.

    An empty name is rendered as the literal "friend" so callers do
    not have to special-case unauthenticated paths.
    """
    trimmed = name.strip()
    who = trimmed if trimmed else "friend"
    return f"Hello, {who}!"

#!/usr/bin/env python3
"""Pull the service-evidence rows from Postgres and write them to a text file.

Standard environment variables consumed:

  DATABASE_URL    libpq-compatible connection string. Required.
                  Example: postgresql://user:pass@db.example.com:5432/
  PG_DATABASE     Database name (default: raxis_e2e_pg).
  PG_TABLE        Table name (default: service_evidence_pg).

Output: one row per line, pipe-delimited, sorted ascending by `id`:

    pg_seed_row_1|service-evidence-name-1|7919
    pg_seed_row_2|service-evidence-name-2|15838
    ...

The script knows nothing about transport layers — it uses psycopg2
against whatever the URL points at. Connection or query errors raise
and exit non-zero so the calling shell can see them.
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg2


def fetch_rows(url: str, dbname: str, table: str) -> list[tuple[str, str, int]]:
    """Open one connection, SELECT every row in `table`, sorted by id."""
    conn = psycopg2.connect(url, dbname=dbname, connect_timeout=10)
    try:
        with conn.cursor() as cur:
            # Table identifier is a developer-supplied constant; we
            # validate the shape rather than parameterising to keep
            # the query portable across psycopg versions.
            if not table.replace("_", "").isalnum():
                raise ValueError(f"refusing to query suspicious table name: {table!r}")
            cur.execute(f"SELECT id, name, value FROM {table} ORDER BY id ASC")
            return [(str(r[0]), str(r[1]), int(r[2])) for r in cur.fetchall()]
    finally:
        conn.close()


def render(rows: list[tuple[str, str, int]]) -> bytes:
    """Render rows to the canonical pipe-delimited bytes form."""
    out = []
    for row_id, name, value in rows:
        out.append(f"{row_id}|{name}|{value}\n")
    return "".join(out).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dump service-evidence Postgres rows")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument(
        "--table",
        default=os.environ.get("PG_TABLE", "service_evidence_pg"),
        help="Postgres table to query",
    )
    parser.add_argument(
        "--database",
        default=os.environ.get("PG_DATABASE", "raxis_e2e_pg"),
        help="Postgres database name",
    )
    args = parser.parse_args(argv)

    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.stderr.write("DATABASE_URL not set; cannot continue\n")
        return 2

    rows = fetch_rows(url, args.database, args.table)
    payload = render(rows)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(payload)

    sys.stdout.write(
        f"postgres: {len(rows)} row(s) -> {args.output} "
        f"({len(payload)} bytes)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

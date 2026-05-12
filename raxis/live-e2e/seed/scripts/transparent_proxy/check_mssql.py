#!/usr/bin/env python3
"""Pull the service-evidence rows from SQL Server and write them to a text file.

Standard environment variables consumed:

  MSSQL_URL       pymssql-compatible connection string. Required.
                  Example: mssql://user:pass@db.example.com:1433/
  MSSQL_DATABASE  Database name (default: master).
  MSSQL_TABLE     Table name (default: service_evidence_mssql).

Output: one row per line, pipe-delimited, sorted ascending by `id`:

    mssql_seed_row_1|service-evidence-mssql-1|15485863
    mssql_seed_row_2|service-evidence-mssql-2|30971726
    ...

Uses `pymssql` — the standard pure-FreeTDS Python driver.
"""

from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import urlparse

import pymssql


def parse_url(url: str) -> dict:
    """Convert an mssql:// URL to a pymssql.connect() kwargs dict."""
    u = urlparse(url)
    if u.scheme not in ("mssql", "tds"):
        raise ValueError(f"unexpected scheme: {u.scheme!r} (want mssql / tds)")
    return {
        "server": u.hostname or "127.0.0.1",
        "port": int(u.port or 1433),
        "user": u.username or "sa",
        "password": u.password or "",
        "login_timeout": 10,
    }


def fetch_rows(url: str, database: str, table: str) -> list[tuple[str, str, int]]:
    """Open one connection, SELECT every row in `table`, sorted by id."""
    if not table.replace("_", "").replace(".", "").isalnum():
        raise ValueError(f"refusing to query suspicious table name: {table!r}")
    kwargs = parse_url(url)
    kwargs["database"] = database
    conn = pymssql.connect(**kwargs)
    try:
        with conn.cursor() as cur:
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
    parser = argparse.ArgumentParser(description="Dump service-evidence MSSQL rows")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument(
        "--table",
        default=os.environ.get("MSSQL_TABLE", "dbo.service_evidence_mssql"),
        help="MSSQL table to query",
    )
    parser.add_argument(
        "--database",
        default=os.environ.get("MSSQL_DATABASE", "master"),
        help="MSSQL database name",
    )
    args = parser.parse_args(argv)

    url = os.environ.get("MSSQL_URL")
    if not url:
        sys.stderr.write("MSSQL_URL not set; skipping (this service is opt-in)\n")
        return 0  # Not a hard failure when the service is opt-in.

    rows = fetch_rows(url, args.database, args.table)
    payload = render(rows)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(payload)

    sys.stdout.write(
        f"mssql: {len(rows)} row(s) -> {args.output} "
        f"({len(payload)} bytes)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

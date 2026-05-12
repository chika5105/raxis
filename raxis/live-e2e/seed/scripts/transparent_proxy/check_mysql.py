#!/usr/bin/env python3
"""Pull the service-evidence rows from MySQL and write them to a text file.

Standard environment variables consumed:

  MYSQL_URL      pymysql-compatible connection string. Required.
                 Example: mysql://user:pass@db.example.com:3306/
  MYSQL_DATABASE Database name (default: raxis_e2e).
  MYSQL_TABLE    Table name (default: service_evidence_mysql).

Output: one row per line, pipe-delimited, sorted ascending by `id`:

    mysql_seed_row_1|service-evidence-mysql-1|1299709
    mysql_seed_row_2|service-evidence-mysql-2|2599418
    ...

Uses PyMySQL — a pure-Python MySQL driver with no compiled
dependencies, the most common pick for Python-on-Linux deployments.
"""

from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import urlparse

import pymysql


def parse_url(url: str) -> dict:
    """Convert a mysql:// URL to a pymysql.connect() kwargs dict."""
    u = urlparse(url)
    if u.scheme not in ("mysql", "mariadb"):
        raise ValueError(f"unexpected scheme: {u.scheme!r} (want mysql / mariadb)")
    return {
        "host": u.hostname or "127.0.0.1",
        "port": int(u.port or 3306),
        "user": u.username or "root",
        "password": u.password or "",
        "connect_timeout": 10,
    }


def fetch_rows(url: str, database: str, table: str) -> list[tuple[str, str, int]]:
    """Open one connection, SELECT every row in `table`, sorted by id."""
    if not table.replace("_", "").isalnum():
        raise ValueError(f"refusing to query suspicious table name: {table!r}")
    kwargs = parse_url(url)
    kwargs["database"] = database
    conn = pymysql.connect(**kwargs)
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
    parser = argparse.ArgumentParser(description="Dump service-evidence MySQL rows")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument(
        "--table",
        default=os.environ.get("MYSQL_TABLE", "service_evidence_mysql"),
        help="MySQL table to query",
    )
    parser.add_argument(
        "--database",
        default=os.environ.get("MYSQL_DATABASE", "raxis_e2e"),
        help="MySQL database name",
    )
    args = parser.parse_args(argv)

    url = os.environ.get("MYSQL_URL")
    if not url:
        sys.stderr.write("MYSQL_URL not set; skipping (this service is opt-in)\n")
        return 0  # Not a hard failure when the service is opt-in.

    rows = fetch_rows(url, args.database, args.table)
    payload = render(rows)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(payload)

    sys.stdout.write(
        f"mysql: {len(rows)} row(s) -> {args.output} "
        f"({len(payload)} bytes)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

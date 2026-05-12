#!/usr/bin/env python3
"""Pull the service-evidence documents from MongoDB and write them to a JSON-lines file.

Standard environment variables consumed:

  MONGO_URL          MongoDB connection string. Required.
                     Example: mongodb://user:pass@db.example.com:27017/
  MONGO_URI          Alias for MONGO_URL (some platforms use this name).
  MONGO_DATABASE     Database name (default: raxis_e2e_mongo).
  MONGO_COLLECTION   Collection name (default: service_evidence_mongo).

Output: one JSON object per line, sorted ascending by `doc_id`, with a
stable key order `{doc_id, label, magic}`:

    {"doc_id":"mongo_seed_doc_1","label":"service-evidence-label-1","magic":1000003}
    {"doc_id":"mongo_seed_doc_2","label":"service-evidence-label-2","magic":2000006}
    ...

Uses `pymongo` and the standard `json` module; the stable key order
is enforced by emitting an explicit `OrderedDict` so a future pymongo
version cannot reshuffle field order on us.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import OrderedDict

from pymongo import MongoClient


def fetch_docs(url: str, database: str, collection: str) -> list[OrderedDict]:
    """Open one client, find every document in `collection`, sorted by doc_id."""
    client = MongoClient(url, serverSelectionTimeoutMS=10_000)
    try:
        coll = client[database][collection]
        # Project only the canonical fields so a future driver-side
        # extra (`_id`, etc.) cannot smear the output shape.
        cursor = coll.find(
            {},
            {"_id": 0, "doc_id": 1, "label": 1, "magic": 1},
        ).sort("doc_id", 1)
        out: list[OrderedDict] = []
        for doc in cursor:
            ordered = OrderedDict()
            ordered["doc_id"] = str(doc["doc_id"])
            ordered["label"] = str(doc["label"])
            ordered["magic"] = int(doc["magic"])
            out.append(ordered)
        return out
    finally:
        client.close()


def render(docs: list[OrderedDict]) -> bytes:
    """Render docs to JSON-lines bytes (no spaces, no trailing blank line)."""
    out = []
    for d in docs:
        # `separators=(",", ":")` strips inter-field spaces. `sort_keys`
        # is intentionally false — we encoded the order explicitly above.
        out.append(json.dumps(d, separators=(",", ":")))
        out.append("\n")
    return "".join(out).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dump service-evidence Mongo docs")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument(
        "--database",
        default=os.environ.get("MONGO_DATABASE", "raxis_e2e_mongo"),
        help="Mongo database name",
    )
    parser.add_argument(
        "--collection",
        default=os.environ.get("MONGO_COLLECTION", "service_evidence_mongo"),
        help="Mongo collection name",
    )
    args = parser.parse_args(argv)

    url = os.environ.get("MONGO_URL") or os.environ.get("MONGO_URI")
    if not url:
        sys.stderr.write("MONGO_URL / MONGO_URI not set; cannot continue\n")
        return 2

    docs = fetch_docs(url, args.database, args.collection)
    payload = render(docs)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(payload)

    sys.stdout.write(
        f"mongodb: {len(docs)} doc(s) -> {args.output} "
        f"({len(payload)} bytes)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

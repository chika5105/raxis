#!/usr/bin/env python3
"""Pull the service-evidence keys from Redis and write them to a text file.

Standard environment variables consumed:

  REDIS_URL          redis-py connection string. Required.
                     Example: redis://user:pass@cache.example.com:6379/0
  REDIS_KEY_PREFIX   Key prefix to SCAN (default: service-evidence:).

Output: one `key=value` line per SCANned entry, sorted ascending by
key (so the on-disk shape is stable across hash-bucket orderings):

    service-evidence:redis_seed_key_1=redis_seed_value_1
    service-evidence:redis_seed_key_2=redis_seed_value_2
    ...

Uses the `SCAN` + `GET` command pair; the redis_proxy_redis_evidence
allowlist already contains both. We deliberately avoid `KEYS *` and
`MGET` — many production Redis deployments forbid `KEYS` for
latency reasons.
"""

from __future__ import annotations

import argparse
import os
import sys

import redis


def fetch_entries(url: str, prefix: str) -> list[tuple[str, str]]:
    """SCAN every key under `prefix`, GET each value, decode as UTF-8."""
    client = redis.from_url(url, socket_connect_timeout=10, socket_timeout=10)
    try:
        pairs: list[tuple[str, str]] = []
        for raw_key in client.scan_iter(match=f"{prefix}*", count=100):
            key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
            raw_val = client.get(raw_key)
            if raw_val is None:
                # A racing TTL or a deletion mid-SCAN — skip rather than
                # writing `None`. The witness compares byte-exact output
                # so a None here would surface as a mismatch.
                continue
            value = raw_val.decode("utf-8") if isinstance(raw_val, bytes) else str(raw_val)
            pairs.append((key, value))
        return pairs
    finally:
        try:
            client.close()
        except AttributeError:
            # redis-py < 5.0 used `.connection_pool.disconnect()`.
            client.connection_pool.disconnect()


def render(pairs: list[tuple[str, str]]) -> bytes:
    """Render kv pairs to the canonical `key=value\\n` bytes form, sorted by key."""
    pairs_sorted = sorted(pairs, key=lambda kv: kv[0])
    out = []
    for k, v in pairs_sorted:
        out.append(f"{k}={v}\n")
    return "".join(out).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dump service-evidence Redis keys")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument(
        "--prefix",
        default=os.environ.get("REDIS_KEY_PREFIX", "service-evidence:"),
        help="Key prefix to SCAN",
    )
    args = parser.parse_args(argv)

    url = os.environ.get("REDIS_URL")
    if not url:
        sys.stderr.write("REDIS_URL not set; cannot continue\n")
        return 2

    pairs = fetch_entries(url, args.prefix)
    payload = render(pairs)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(payload)

    sys.stdout.write(
        f"redis: {len(pairs)} key(s) -> {args.output} "
        f"({len(payload)} bytes)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

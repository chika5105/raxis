#!/usr/bin/env python3
"""Submit a canonical service-evidence message via SMTP and record the envelope locally.

Standard environment variables consumed:

  SMTP_URL       host:port pair the SMTP relay listens on. Required.
                 Example: smtp.example.com:587
  SMTP_HOST      Alternative: explicit host (if SMTP_URL is not set).
  SMTP_PORT      Alternative: explicit port (default 25).
  SMTP_FROM      Envelope sender (default sender@live-e2e.test).
  SMTP_TO        Envelope recipient (default raxis-tenant@live-e2e.test).
  SMTP_SUBJECT   Message subject (default smtp_seed_subject_1).
  SMTP_BODY      Message body (default smtp_seed_body_1: ...).

Behaviour: open one SMTP submission, send the message, and on
success write a canonical four-line envelope record to --output:

    from: sender@live-e2e.test
    to: raxis-tenant@live-e2e.test
    subject: smtp_seed_subject_1
    body: smtp_seed_body_1: service-evidence smtp round-trip

The submission uses `smtplib.SMTP` from the standard library — no
third-party SMTP dependency. We do NOT call `.login()` because the
upstream relay's auth (if any) is the operator's responsibility,
configured outside this script.
"""

from __future__ import annotations

import argparse
import os
import smtplib
import sys
from email.message import EmailMessage


def parse_host_port(raw: str, default_port: int = 25) -> tuple[str, int]:
    """Split a `host:port` string. Falls back to `default_port` when absent."""
    # `smtp://` prefix is allowed for compatibility with URL-style env vars.
    s = raw
    for scheme in ("smtp://", "smtps://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
            break
    s = s.rstrip("/")
    if ":" in s:
        host, _, port_text = s.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            host, port = s, default_port
    else:
        host, port = s, default_port
    return host, port


def send_one(host: str, port: int, *, sender: str, recipient: str, subject: str, body: str) -> None:
    """Open an SMTP submission and send a single canonical message."""
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=15) as client:
        # Some relays expect EHLO before MAIL FROM; smtplib handles
        # this implicitly via send_message, but we call it once
        # explicitly so a transcript reader sees the negotiated
        # extensions.
        client.ehlo("transparent-proxy-realscripts")
        client.send_message(msg)


def render_envelope(sender: str, recipient: str, subject: str, body: str) -> bytes:
    """Write the canonical four-line envelope record."""
    out = (
        f"from: {sender}\n"
        f"to: {recipient}\n"
        f"subject: {subject}\n"
        f"body: {body}\n"
    )
    return out.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SMTP envelope round-trip")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument(
        "--from",
        dest="sender",
        default=os.environ.get("SMTP_FROM", "sender@live-e2e.test"),
        help="Envelope sender",
    )
    parser.add_argument(
        "--to",
        dest="recipient",
        default=os.environ.get("SMTP_TO", "raxis-tenant@live-e2e.test"),
        help="Envelope recipient",
    )
    parser.add_argument(
        "--subject",
        default=os.environ.get("SMTP_SUBJECT", "smtp_seed_subject_1"),
        help="Message subject",
    )
    parser.add_argument(
        "--body",
        default=os.environ.get(
            "SMTP_BODY",
            "smtp_seed_body_1: service-evidence smtp round-trip",
        ),
        help="Message body",
    )
    args = parser.parse_args(argv)

    raw = os.environ.get("SMTP_URL")
    if raw:
        host, port = parse_host_port(raw)
    else:
        host = os.environ.get("SMTP_HOST")
        if not host:
            sys.stderr.write("SMTP_URL / SMTP_HOST not set; cannot continue\n")
            return 2
        try:
            port = int(os.environ.get("SMTP_PORT", "25"))
        except ValueError:
            sys.stderr.write("SMTP_PORT is not an integer\n")
            return 2

    send_one(
        host,
        port,
        sender=args.sender,
        recipient=args.recipient,
        subject=args.subject,
        body=args.body,
    )

    payload = render_envelope(args.sender, args.recipient, args.subject, args.body)
    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(payload)

    sys.stdout.write(
        f"smtp: relayed envelope -> {args.output} "
        f"({len(payload)} bytes; upstream={host}:{port})\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

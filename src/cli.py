# Mourad.Soltani — stdhook-cli
"""CLI entrypoint for Standard Webhooks sign / verify / headers."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

from .webhooks import (
    SignatureVerificationError,
    WebhookError,
    make_headers,
    sign,
    verify,
)


def _read_body(args: argparse.Namespace) -> bytes:
    if args.body is not None:
        return args.body.encode("utf-8")
    if args.file is not None:
        return Path(args.file).read_bytes()
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    raise SystemExit("No body provided: use --body, --file, or pipe stdin")


def cmd_sign(args: argparse.Namespace) -> int:
    body = _read_body(args)
    msg_id = args.id or f"msg_{uuid.uuid4().hex}"
    ts = args.timestamp if args.timestamp is not None else int(time.time())
    try:
        sig = sign(args.secret, msg_id, ts, body)
    except WebhookError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"webhook-id": msg_id, "webhook-timestamp": str(ts), "webhook-signature": sig}))
    else:
        print(sig)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    body = _read_body(args)
    try:
        verify(
            args.secret,
            args.id,
            args.timestamp,
            body,
            args.signature,
            tolerance=args.tolerance,
        )
    except SignatureVerificationError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    except WebhookError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print("VALID")
    return 0


def cmd_headers(args: argparse.Namespace) -> int:
    body = _read_body(args)
    try:
        headers = make_headers(
            args.secret,
            body,
            msg_id=args.id,
            timestamp=args.timestamp,
        )
    except WebhookError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(headers))
    else:
        for k, v in headers.items():
            print(f"{k}: {v}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="stdhook",
        description="Sign and verify Standard Webhooks (webhook-id / webhook-timestamp / webhook-signature).",
    )
    parser.add_argument("--version", action="version", version="stdhook-cli 0.1.0 (Mourad.Soltani)")
    sub = parser.add_subparsers(dest="command", required=True)

    # shared body options
    def add_body(p: argparse.ArgumentParser) -> None:
        g = p.add_mutually_exclusive_group()
        g.add_argument("--body", help="Raw body string")
        g.add_argument("--file", "-f", help="Read body from file")

    p_sign = sub.add_parser("sign", help="Produce a webhook-signature value")
    p_sign.add_argument("--secret", "-s", required=True, help="Secret (whsec_... or raw base64)")
    p_sign.add_argument("--id", help="webhook-id (default: msg_<uuid>)")
    p_sign.add_argument("--timestamp", "-t", type=int, help="Unix timestamp (default: now)")
    p_sign.add_argument("--json", action="store_true", help="Emit id/timestamp/signature as JSON")
    add_body(p_sign)
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify a signature against body + headers")
    p_verify.add_argument("--secret", "-s", required=True)
    p_verify.add_argument("--id", required=True, help="webhook-id header value")
    p_verify.add_argument("--timestamp", "-t", required=True, help="webhook-timestamp header value")
    p_verify.add_argument("--signature", required=True, help="webhook-signature header value")
    p_verify.add_argument("--tolerance", type=int, default=300, help="Allowed clock skew in seconds (default 300)")
    add_body(p_verify)
    p_verify.set_defaults(func=cmd_verify)

    p_headers = sub.add_parser("headers", help="Generate all three Standard Webhooks headers")
    p_headers.add_argument("--secret", "-s", required=True)
    p_headers.add_argument("--id", help="webhook-id (default: msg_<uuid>)")
    p_headers.add_argument("--timestamp", "-t", type=int, help="Unix timestamp (default: now)")
    p_headers.add_argument("--json", action="store_true")
    add_body(p_headers)
    p_headers.set_defaults(func=cmd_headers)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""
CLI entry point for stdhook-cli.
Signature: Mourad.Soltani
"""

import argparse
import json
import sys
from .webhooks import generate_signature, verify_signature


def main():
    parser = argparse.ArgumentParser(
        description="Standard Webhooks signature CLI — Mourad.Soltani"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="Generate webhook headers")
    gen.add_argument("--secret", required=True, help="whsec_... or base64 secret")
    gen.add_argument("--body", required=True, help="Raw JSON body string")
    gen.add_argument("--id", help="Optional webhook-id (msg_...)")
    gen.add_argument("--timestamp", type=int, help="Optional Unix timestamp")

    ver = sub.add_parser("verify", help="Verify webhook signature")
    ver.add_argument("--secret", required=True)
    ver.add_argument("--body", required=True)
    ver.add_argument("--id", required=True)
    ver.add_argument("--timestamp", required=True)
    ver.add_argument("--signature", required=True, help="webhook-signature header value")
    ver.add_argument("--tolerance", type=int, default=300)

    args = parser.parse_args()

    if args.cmd == "generate":
        headers = generate_signature(
            args.secret, args.body, args.id, args.timestamp
        )
        print(json.dumps(headers, indent=2))
    elif args.cmd == "verify":
        ok = verify_signature(
            args.secret,
            args.body,
            args.id,
            args.timestamp,
            args.signature,
            args.tolerance,
        )
        if ok:
            print("VALID")
            sys.exit(0)
        else:
            print("INVALID")
            sys.exit(1)


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
from .receipts import verify_chain, summarize_badge, review_packet


def print_json(obj: object) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="olp-swarm-gate", description="Verify and review OpenLine Swarm Improvement Gate receipts.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_verify = sub.add_parser("verify", help="Verify receipt hash chain.")
    p_verify.add_argument("path")
    p_badge = sub.add_parser("badge", help="Summarize mutation decisions.")
    p_badge.add_argument("path")
    p_review = sub.add_parser("review", help="Produce review packet for quarantined/no-badge mutations.")
    p_review.add_argument("path")
    args = parser.parse_args(argv)
    if args.cmd == "verify":
        result = verify_chain(args.path)
        print_json(result)
        return 0 if result["valid"] else 2
    if args.cmd == "badge":
        result = summarize_badge(args.path)
        print_json(result)
        return 0 if result["badge"] == "PASS" else 1
    if args.cmd == "review":
        print_json(review_packet(args.path))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

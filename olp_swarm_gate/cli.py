from __future__ import annotations

import argparse
import json
from pathlib import Path

from .receipts import verify_chain, summarize_badge, review_packet
from .successor_benchmark import default_benchmark_root, run_frozen_benchmark


def print_json(obj: object) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="olp-swarm-gate", description="Verify swarm improvement receipts and run the frozen successor-promotion benchmark.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_verify = sub.add_parser("verify", help="Verify receipt hash chain.")
    p_verify.add_argument("path")
    p_badge = sub.add_parser("badge", help="Summarize mutation decisions.")
    p_badge.add_argument("path")
    p_review = sub.add_parser("review", help="Produce review packet for quarantined/no-badge mutations.")
    p_review.add_argument("path")
    p_successor = sub.add_parser("successor-benchmark", help="Run the frozen successor-promotion benchmark.")
    p_successor.add_argument("--root", default=None, help="Optional benchmark directory; packaged frozen data is used by default.")
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
    if args.cmd == "successor-benchmark":
        root = Path(args.root) if args.root else default_benchmark_root()
        result = run_frozen_benchmark(root)
        print_json(result)
        return 0 if result["passed"] else 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

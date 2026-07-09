import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
from demo_good_commit import main as good_main
from demo_missing_grader import main as bad_main
from demo_memory_policy_quarantine import main as danger_main
from demo_protected_valid_quorum import main as guarded_main
from olp_swarm_gate.receipts import summarize_badge, review_packet, load_receipts


def main():
    Path("receipts").mkdir(exist_ok=True)
    Path("results").mkdir(exist_ok=True)
    good_main(); bad_main(); danger_main()
    guarded_main()
    paths = {"good": "receipts/good_commit.jsonl", "missing_grader": "receipts/missing_grader.jsonl", "memory_policy": "receipts/memory_policy_quarantine.jsonl", "protected_valid_quorum": "receipts/protected_valid_quorum.jsonl"}
    summary = {}; decisions = {}
    for name, path in paths.items():
        rows = load_receipts(path)
        decisions[name] = rows[-1]["decision"] if rows else "NO_RECEIPTS"
        summary[name] = {"badge": summarize_badge(path), "review": review_packet(path)}
    result = {"decisions": decisions, "summary": summary}
    Path("results/demo_summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"decisions": decisions, "badges": {k: v["badge"]["badge"] for k, v in summary.items()}}, indent=2))

if __name__ == "__main__":
    main()

from __future__ import annotations

import hashlib
import json
import time
import uuid
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class InvalidReceiptChainError(RuntimeError):
    """Raised when an append would extend an already-invalid receipt chain."""



def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def hash_any(value: Any) -> str:
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    if isinstance(value, str):
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
    return sha256_json(value)


def _parse_jsonl(path: str | Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], bool, bool]:
    p = Path(path)
    if not p.exists():
        return [], [{"reason": "missing_receipt_file", "line_number": None}], True, False
    text = p.read_text(encoding="utf-8")
    if not text.strip():
        return [], [{"reason": "empty_receipt_chain", "line_number": None}], False, True
    rows: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except JSONDecodeError as exc:
            errors.append({"reason": "json_parse_error", "line_number": line_number, "message": exc.msg, "position": exc.pos})
            continue
        if not isinstance(item, dict):
            errors.append({"reason": "json_receipt_not_object", "line_number": line_number})
            continue
        rows.append(item)
    return rows, errors, False, False


def load_receipts(path: str | Path) -> List[Dict[str, Any]]:
    rows, _errors, _missing, _empty = _parse_jsonl(path)
    return rows


def last_hash(path: str | Path) -> Optional[str]:
    chain = verify_chain(path)
    if not chain["valid"]:
        return None
    rows = load_receipts(path)
    return rows[-1].get("receipt_hash") if rows else None


def append_receipt(path: str | Path, body: Dict[str, Any]) -> Dict[str, Any]:
    p = Path(path)
    chain = verify_chain(p)
    startable = chain["missing"] or chain["empty"]
    if not chain["valid"] and not startable:
        raise InvalidReceiptChainError("refusing to append to invalid receipt chain")

    receipt = dict(body)
    receipt.setdefault("schema", "openline.swarm_improvement_gate.v0.1")
    receipt.setdefault("receipt_id", str(uuid.uuid4()))
    receipt.setdefault("timestamp", time.time())
    receipt["parent_hash"] = chain["last_hash"] if chain["valid"] else None
    receipt["receipt_hash"] = sha256_json({k: v for k, v in receipt.items() if k != "receipt_hash"})
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(receipt, sort_keys=True, ensure_ascii=False) + "\n")
    return receipt


def verify_chain(path: str | Path) -> Dict[str, Any]:
    rows, parse_errors, missing, empty = _parse_jsonl(path)
    errors = list(parse_errors)
    prev = None
    if not parse_errors:
        for i, row in enumerate(rows):
            if row.get("parent_hash") != prev:
                errors.append({"index": i, "receipt_id": row.get("receipt_id"), "reason": "parent_hash_mismatch"})
            expected = sha256_json({k: v for k, v in row.items() if k != "receipt_hash"})
            if row.get("receipt_hash") != expected:
                errors.append({"index": i, "receipt_id": row.get("receipt_id"), "reason": "receipt_hash_mismatch"})
            prev = row.get("receipt_hash")
    return {"path": str(path), "valid": not errors, "count": len(rows), "missing": missing, "empty": empty, "errors": errors, "last_hash": prev if not errors else None}


def summarize_badge(path: str | Path) -> Dict[str, Any]:
    chain = verify_chain(path)
    if chain["missing"] or chain["empty"]:
        return {"path": str(path), "badge": "NO_BADGE", "review_required": True, "reason": "empty_or_missing_receipt_chain", "counts": {"COMMIT": 0, "QUARANTINE": 0, "NO_BADGE": 0}, "chain": chain}
    if not chain["valid"]:
        return {"path": str(path), "badge": "INVALID_CHAIN", "review_required": True, "reason": "receipt chain failed verification", "counts": {"COMMIT": 0, "QUARANTINE": 0, "NO_BADGE": 0}, "chain": chain}
    counts = {"COMMIT": 0, "QUARANTINE": 0, "NO_BADGE": 0}
    for row in load_receipts(path):
        decision = row.get("decision")
        if decision in counts:
            counts[decision] += 1
    if counts["NO_BADGE"] > 0:
        badge, review_required, reason = "NO_BADGE", True, "one or more proposed improvements lacked enough proof"
    elif counts["QUARANTINE"] > 0:
        badge, review_required, reason = "REVIEW", True, "one or more proposed improvements were quarantined"
    elif counts["COMMIT"] > 0:
        badge, review_required, reason = "PASS", False, "all proposed improvements committed with required proof"
    else:
        badge, review_required, reason = "NO_BADGE", True, "empty_or_missing_receipt_chain"
    return {"path": str(path), "badge": badge, "review_required": review_required, "reason": reason, "counts": counts, "chain": chain}


def review_packet(path: str | Path) -> Dict[str, Any]:
    badge = summarize_badge(path)
    rows = load_receipts(path) if badge["chain"]["valid"] else []
    review_items = []
    for row in rows:
        if row.get("decision") in {"QUARANTINE", "NO_BADGE"}:
            review_items.append({
                "receipt_id": row.get("receipt_id"),
                "mutation_id": row.get("mutation_id"),
                "proposer": row.get("proposer"),
                "decision": row.get("decision"),
                "policy_flags": row.get("policy_flags", []),
                "exit_path": row.get("exit_path"),
                "receipt_hash": row.get("receipt_hash"),
                "next_use_note": row.get("next_use_note"),
            })
    if badge["badge"] in {"INVALID_CHAIN", "NO_BADGE"} and not review_items:
        review_items.append({"receipt_id": None, "mutation_id": None, "proposer": None, "decision": badge["badge"], "policy_flags": [badge["reason"]], "exit_path": {"mode": "rebuild_receipt_chain", "allowed_resolutions": ["rerun_with_valid_receipts", "human_review"]}, "receipt_hash": None, "next_use_note": "No trusted improvement receipt chain exists. Do not certify this swarm mutation."})
    return {"badge": badge, "review_items": review_items}

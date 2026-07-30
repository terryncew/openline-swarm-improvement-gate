from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .schemas import EvalAirlockAppraisal

APPRAISAL_RECEIPT_SCHEMA = "openline.eval_airlock.appraisal_receipt.v0.3"
APPRAISAL_RECEIPT_TYPE = "eval_airlock_appraisal"
APPRAISAL_SIGNATURE_ALGORITHM = "Ed25519"
_MAX_RECEIPT_BYTES = 262_144


class DuplicateJSONKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _reject_nonfinite(value: str):
    raise ValueError(f"non-finite JSON number: {value}")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def public_key_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def evaluator_key_fingerprint(public_key: str | bytes | Ed25519PrivateKey | Ed25519PublicKey) -> str:
    if isinstance(public_key, (Ed25519PrivateKey, Ed25519PublicKey)):
        raw = bytes.fromhex(public_key_hex(public_key))
    elif isinstance(public_key, str):
        raw = bytes.fromhex(public_key)
    elif isinstance(public_key, bytes):
        raw = public_key
    else:
        raise TypeError("unsupported public key type")
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return _sha256_bytes(raw)


def appraisal_claim(appraisal: EvalAirlockAppraisal) -> Dict[str, Any]:
    """Exact appraisal fields bound by the external receipt artifact.

    The locator hash is deliberately excluded to avoid self-reference.
    """
    data = appraisal.to_public_dict()
    data.pop("appraisal_receipt_hash", None)
    return data


def unsigned_appraisal_receipt_body(appraisal: EvalAirlockAppraisal) -> Dict[str, Any]:
    return {
        "schema": APPRAISAL_RECEIPT_SCHEMA,
        "receipt_type": APPRAISAL_RECEIPT_TYPE,
        "witness": {
            "evaluator_id": appraisal.evaluator_id,
            "evaluator_hash": appraisal.evaluator_hash,
        },
        "appraisal": appraisal_claim(appraisal),
    }


def build_appraisal_receipt_document(
    appraisal: EvalAirlockAppraisal,
    signing_key: Ed25519PrivateKey,
) -> Dict[str, Any]:
    """Build one signed appraisal receipt.

    The signature covers the full witness + appraisal body. The content-addressed
    receipt hash is computed over the resulting signed document by the caller.
    """
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise TypeError("signing_key must be an Ed25519PrivateKey")
    body = unsigned_appraisal_receipt_body(appraisal)
    canonical = _canonical_bytes(body)
    return {
        **body,
        "payload_hash": _sha256_bytes(canonical),
        "signature": {
            "algorithm": APPRAISAL_SIGNATURE_ALGORITHM,
            "public_key": public_key_hex(signing_key),
            "value": signing_key.sign(canonical).hex(),
        },
    }


def appraisal_receipt_digest(document: Dict[str, Any]) -> str:
    return _sha256_bytes(_canonical_bytes(document))


def materialize_appraisal_receipt(
    appraisal: EvalAirlockAppraisal,
    directory: str | Path,
    *,
    signing_key: Ed25519PrivateKey,
) -> EvalAirlockAppraisal:
    """Write one signed, immutable-by-address appraisal artifact.

    Existing content at the same digest must parse to the same canonical document.
    The receiver still owns the store; the evaluator private key must not be
    available to the proposing successor.
    """
    document = build_appraisal_receipt_document(appraisal, signing_key)
    digest = appraisal_receipt_digest(document)
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{digest}.json"
    if path.exists():
        existing = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        if existing != document:
            raise ValueError("content-addressed appraisal receipt collision")
    else:
        path.write_text(json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    return replace(appraisal, appraisal_receipt_hash=digest)


def verify_materialized_appraisal_receipt(
    appraisal: EvalAirlockAppraisal,
    directory: str | Path,
    *,
    expected_public_key: str,
    require_signature: bool = True,
) -> list[str]:
    """Verify exact content binding and receiver-pinned evaluator provenance.

    A matching evaluator id/hash is not enough. When ``require_signature`` is
    true, the full appraisal body must carry a valid Ed25519 signature from the
    receiver-pinned evaluator public key.
    """
    digest = str(appraisal.appraisal_receipt_hash).strip().lower()
    root = Path(directory)
    path = root / f"{digest}.json"

    if not path.exists():
        return ["appraisal_receipt_not_found"]
    if path.is_symlink():
        return ["appraisal_receipt_symlink_forbidden"]
    try:
        if path.stat().st_size > _MAX_RECEIPT_BYTES:
            return ["appraisal_receipt_too_large"]
        text = path.read_text(encoding="utf-8")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateJSONKeyError, ValueError):
        return ["appraisal_receipt_unreadable"]

    if not isinstance(document, dict):
        return ["appraisal_receipt_shape_mismatch"]
    try:
        if appraisal_receipt_digest(document) != digest:
            return ["appraisal_receipt_hash_mismatch"]
    except (TypeError, ValueError, OverflowError):
        return ["appraisal_receipt_unreadable"]

    base_keys = {"schema", "receipt_type", "witness", "appraisal", "payload_hash"}
    if not base_keys.issubset(document) or (set(document) - (base_keys | {"signature"})):
        return ["appraisal_receipt_shape_mismatch"]
    if document.get("schema") != APPRAISAL_RECEIPT_SCHEMA:
        return ["appraisal_receipt_schema_mismatch"]
    if document.get("receipt_type") != APPRAISAL_RECEIPT_TYPE:
        return ["appraisal_receipt_type_mismatch"]

    expected_witness = {
        "evaluator_id": appraisal.evaluator_id,
        "evaluator_hash": appraisal.evaluator_hash,
    }
    if document.get("witness") != expected_witness:
        return ["appraisal_receipt_witness_mismatch"]
    if document.get("appraisal") != appraisal_claim(appraisal):
        return ["appraisal_receipt_payload_mismatch"]

    if not require_signature:
        return []

    signature = document.get("signature")
    if not isinstance(signature, dict):
        return ["appraisal_signature_missing"]
    if set(signature) != {"algorithm", "public_key", "value"}:
        return ["appraisal_signature_shape_mismatch"]
    if signature.get("algorithm") != APPRAISAL_SIGNATURE_ALGORITHM:
        return ["appraisal_signature_algorithm_mismatch"]

    supplied_key = signature.get("public_key")
    if not isinstance(supplied_key, str) or supplied_key.lower() != str(expected_public_key).strip().lower():
        return ["appraisal_signer_not_pinned"]

    body = {
        "schema": document["schema"],
        "receipt_type": document["receipt_type"],
        "witness": document["witness"],
        "appraisal": document["appraisal"],
    }
    try:
        canonical = _canonical_bytes(body)
    except (TypeError, ValueError, OverflowError):
        return ["appraisal_receipt_unreadable"]
    if document.get("payload_hash") != _sha256_bytes(canonical):
        return ["appraisal_payload_hash_mismatch"]

    try:
        public_raw = bytes.fromhex(supplied_key)
        signature_raw = bytes.fromhex(str(signature.get("value", "")))
        if len(public_raw) != 32 or len(signature_raw) != 64:
            return ["appraisal_signature_invalid"]
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature_raw, canonical)
    except (ValueError, TypeError, InvalidSignature):
        return ["appraisal_signature_invalid"]
    return []

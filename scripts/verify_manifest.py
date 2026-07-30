from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def included_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel == "MANIFEST.json":
            continue
        if any(part in {"__pycache__", ".pytest_cache", "build", "dist"} or part.endswith(".egg-info") for part in path.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        yield path, rel


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    expected = {item["path"]: item for item in manifest["files"]}
    actual = {rel: path for path, rel in included_files()}
    errors = []
    if set(expected) != set(actual):
        errors.append({"reason": "file_set_mismatch", "missing": sorted(set(expected)-set(actual)), "unexpected": sorted(set(actual)-set(expected))})
    for rel in sorted(set(expected) & set(actual)):
        item = expected[rel]
        path = actual[rel]
        if path.stat().st_size != item["bytes"]:
            errors.append({"reason": "size_mismatch", "path": rel})
        if sha256(path) != item["sha256"]:
            errors.append({"reason": "sha256_mismatch", "path": rel})
    result = {"schema":"openline.swarm_improvement_gate.manifest_verification.v0.3","valid":not errors,"file_count":len(actual),"errors":errors}
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if not errors else 2

if __name__ == "__main__":
    raise SystemExit(main())

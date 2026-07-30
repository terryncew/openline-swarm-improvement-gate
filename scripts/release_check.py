from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.2.0rc3"
EXPECTED_CASE_COUNT = 26
EXPECTED_COUNTS = {"PROMOTE": 1, "QUARANTINE": 22, "REJECT": 3}


def run(cmd, *, cwd=ROOT, env=None):
    proc = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)
    return {
        "cmd": [str(x) for x in cmd],
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "passed": proc.returncode == 0,
    }


def main() -> int:
    checks = []

    sys.path.insert(0, str(ROOT))
    import olp_swarm_gate
    checks.append({"name": "version", "passed": olp_swarm_gate.__version__ == EXPECTED_VERSION, "observed": olp_swarm_gate.__version__})

    benchmark_root = ROOT / "benchmarks" / "successor-promotion"
    packaged_root = ROOT / "olp_swarm_gate" / "data" / "successor-promotion"
    profile = json.loads((benchmark_root / "FROZEN_PROFILE.json").read_text(encoding="utf-8"))
    cases = json.loads((benchmark_root / "FROZEN_CASES.json").read_text(encoding="utf-8"))
    report = json.loads((benchmark_root / "BENCHMARK_REPORT.json").read_text(encoding="utf-8"))
    checks.append({"name": "profile_frozen_before_outcomes", "passed": profile.get("frozen_before_outcomes") is True})
    checks.append({"name": "materialized_appraisal_required", "passed": profile.get("require_materialized_appraisal_receipt") is True})
    checks.append({"name": "signed_appraisal_required", "passed": profile.get("require_signed_appraisal_receipt") is True})
    public_key = profile.get("expected_evaluator_public_key")
    try:
        import hashlib
        public_raw = bytes.fromhex(public_key) if isinstance(public_key, str) else b""
        key_pin_valid = len(public_raw) == 32 and hashlib.sha256(public_raw).hexdigest() == profile.get("expected_evaluator_hash")
    except ValueError:
        key_pin_valid = False
    checks.append({"name": "evaluator_public_key_pin_matches_fingerprint", "passed": key_pin_valid})
    checks.append({"name": "frozen_case_count", "passed": len(cases.get("cases", [])) == EXPECTED_CASE_COUNT, "observed": len(cases.get("cases", []))})
    checks.append({"name": "frozen_decision_counts", "passed": report.get("decision_counts") == EXPECTED_COUNTS, "observed": report.get("decision_counts")})
    checks.append({"name": "benchmark_report_passed", "passed": report.get("passed") is True})

    parity = all((benchmark_root / name).read_bytes() == (packaged_root / name).read_bytes() for name in ("FROZEN_PROFILE.json", "FROZEN_CASES.json", "BENCHMARK_REPORT.json"))
    checks.append({"name": "packaged_benchmark_data_matches_source", "passed": parity})

    from olp_swarm_gate.successor_benchmark import run_frozen_benchmark
    recomputed = run_frozen_benchmark(benchmark_root)
    stable_fields = ("profile_id", "frozen_before_outcomes", "case_count", "decision_counts", "all_cases_match_expected", "passed", "cases", "claim_boundary")
    matches = all(recomputed.get(k) == report.get(k) for k in stable_fields)
    checks.append({"name": "benchmark_recomputes_exactly", "passed": matches})

    unittest_result = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    unittest_result["name"] = "stdlib_unittest_suite"
    checks.append(unittest_result)
    pytest_refs = []
    for test_path in sorted((ROOT / "tests").glob("test*.py")):
        text = test_path.read_text(encoding="utf-8")
        if "import pytest" in text or "pytest." in text:
            pytest_refs.append(str(test_path.relative_to(ROOT)))
    checks.append({"name": "no_pytest_runtime_dependency", "passed": not pytest_refs, "files": pytest_refs})

    independent = run([sys.executable, str(benchmark_root / "verify_independent.py")])
    independent["name"] = "independent_verifier"
    checks.append(independent)

    hostile = run([sys.executable, str(ROOT / "scripts" / "hostile_successor_probe.py")])
    hostile["name"] = "hostile_successor_probe"
    checks.append(hostile)

    signature_probe = run([sys.executable, str(ROOT / "scripts" / "adversarial_signature_probe.py")])
    signature_probe["name"] = "adversarial_signature_probe"
    checks.append(signature_probe)

    compile_result = run([sys.executable, "-m", "compileall", "-q", "olp_swarm_gate", "tests", "benchmarks/successor-promotion", "examples", "scripts"])
    compile_result["name"] = "compileall"
    checks.append(compile_result)

    with tempfile.TemporaryDirectory(prefix="swarm-gate-wheel-") as td:
        td_path = Path(td)
        source_copy = td_path / "src"
        shutil.copytree(
            ROOT,
            source_copy,
            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", "*.pyo", "build", "dist", "*.egg-info"),
        )
        wheel_dir = td_path / "wheels"
        wheel_dir.mkdir()
        build = run([sys.executable, "-m", "pip", "wheel", str(source_copy), "--no-deps", "--no-build-isolation", "-q", "-w", str(wheel_dir)], cwd=td_path)
        build["name"] = "wheel_build"
        checks.append(build)

        wheels = sorted(wheel_dir.glob("*.whl"))
        wheel = wheels[0] if len(wheels) == 1 else None
        required_members = {
            "olp_swarm_gate/data/successor-promotion/FROZEN_PROFILE.json",
            "olp_swarm_gate/data/successor-promotion/FROZEN_CASES.json",
            "olp_swarm_gate/data/successor-promotion/BENCHMARK_REPORT.json",
        }
        if wheel:
            with zipfile.ZipFile(wheel) as zf:
                members = set(zf.namelist())
            package_data_ok = required_members <= members
        else:
            package_data_ok = False
        checks.append({"name": "wheel_contains_frozen_benchmark", "passed": package_data_ok, "wheel_count": len(wheels)})
        dependency_declared = False
        if wheel:
            with zipfile.ZipFile(wheel) as zf:
                metadata_names = [name for name in zf.namelist() if name.endswith(".dist-info/METADATA")]
                metadata_text = zf.read(metadata_names[0]).decode("utf-8") if len(metadata_names) == 1 else ""
            dependency_declared = "Requires-Dist: cryptography>=42" in metadata_text or "Requires-Dist: cryptography >=42" in metadata_text
        checks.append({"name": "wheel_declares_ed25519_runtime_dependency", "passed": dependency_declared})

        venv = td_path / "venv"
        # CI is intentionally offline. Inherit the already-verified runtime crypto
        # module, then install the candidate wheel itself without dependency fetches.
        create_venv = run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)], cwd=td_path)
        create_venv["name"] = "create_clean_venv"
        checks.append(create_venv)
        py = venv / "bin" / "python"
        cli = venv / "bin" / "olp-swarm-gate"
        if wheel and create_venv["passed"]:
            install = run([str(py), "-m", "pip", "install", str(wheel), "--no-deps", "-q"], cwd=td_path)
        else:
            install = {"cmd": [], "returncode": 2, "stdout": "", "stderr": "wheel or venv unavailable", "passed": False}
        install["name"] = "clean_wheel_install"
        checks.append(install)

        unrelated = td_path / "unrelated"
        unrelated.mkdir()
        smoke = run([str(py), "-c", f"import cryptography, olp_swarm_gate; assert olp_swarm_gate.__version__ == '{EXPECTED_VERSION}'; print('ok', cryptography.__version__)"], cwd=unrelated) if install["passed"] else {"cmd": [], "returncode": 2, "stdout": "", "stderr": "install failed", "passed": False}
        smoke["name"] = "installed_import_smoke"
        checks.append(smoke)

        cli_check = run([str(cli), "successor-benchmark"], cwd=unrelated) if install["passed"] else {"cmd": [], "returncode": 2, "stdout": "", "stderr": "install failed", "passed": False}
        if cli_check["passed"]:
            try:
                installed_report = json.loads(cli_check["stdout"])
                cli_check["passed"] = installed_report.get("passed") is True and installed_report.get("case_count") == EXPECTED_CASE_COUNT and installed_report.get("decision_counts") == EXPECTED_COUNTS
            except json.JSONDecodeError:
                cli_check["passed"] = False
        cli_check["name"] = "installed_cli_successor_benchmark"
        checks.append(cli_check)

    forbidden = []
    for path in ROOT.rglob("*"):
        if any(part in {"__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        if path.name.endswith(".pyc") or path.name.endswith(".pyo"):
            forbidden.append(str(path.relative_to(ROOT)))
    checks.append({"name": "no_bytecode_in_release_tree", "passed": not forbidden, "forbidden": forbidden})

    passed = all(c.get("passed") is True for c in checks)
    result = {
        "schema": "openline.swarm_improvement_gate.release_verification.v0.3",
        "version": EXPECTED_VERSION,
        "feature": "successor_promotion",
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c.get("passed") is True),
        "passed": passed,
        "checks": checks,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())

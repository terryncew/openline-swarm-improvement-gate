from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_check", ROOT / "scripts" / "release_check.py")
assert SPEC is not None and SPEC.loader is not None
release_check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_check)


class ReleaseCheckRunnerTests(unittest.TestCase):
    def test_missing_executable_is_recorded_as_failed_check(self):
        missing = ROOT / ".definitely-missing-release-check-command"
        result = release_check.run([str(missing)])

        self.assertFalse(result["passed"])
        self.assertEqual(result["returncode"], 127)
        self.assertEqual(result["error_type"], "FileNotFoundError")
        self.assertIn("FileNotFoundError", result["stderr"])


if __name__ == "__main__":
    unittest.main()

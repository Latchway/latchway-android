#!/usr/bin/env python3
"""Regression checks for the offline release and workflow-schema gates."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts/run-offline-release-tests.py"
SPEC = importlib.util.spec_from_file_location("run_offline_release_tests", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class OfflineReleaseInventoryTests(unittest.TestCase):
    def test_manifest_covers_every_repository_python_test(self) -> None:
        self.assertEqual(tuple(sorted(RUNNER.TEST_PATHS)), RUNNER.repository_test_paths())

    def test_ci_and_release_preflight_run_the_offline_release_umbrella(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        preflight = (ROOT / "scripts/release-preflight.sh").read_text(encoding="utf-8")
        command = "python3 scripts/run-offline-release-tests.py"
        self.assertIn(command, ci)
        self.assertIn('python3 "$repository_root/scripts/run-offline-release-tests.py"', preflight)

    def test_ci_pins_and_runs_actionlint_for_every_workflow(self) -> None:
        tools = tomllib.loads((ROOT / ".mise.toml").read_text(encoding="utf-8"))
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertEqual(tools["tools"]["actionlint"], "1.7.12")
        self.assertIn(
            "actionlint -shellcheck= -pyflakes= -oneline .github/workflows/*.yml",
            ci,
        )
        self.assertIn(
            "actionlint_version=$(actionlint -version | sed -n '1p')",
            ci,
        )
        self.assertIn('test "$actionlint_version" = "1.7.12"', ci)


if __name__ == "__main__":
    unittest.main()

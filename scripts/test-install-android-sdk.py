#!/usr/bin/env python3
"""Tests for the pinned Android SDK installation contract."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts/install-android-sdk.sh"
WORKFLOWS = (
    ROOT / ".github/workflows/ci.yml",
    ROOT / ".github/workflows/release.yml",
)
SETUP_ANDROID_SHA = "40fd30fb8d7440372e1316f5d1809ec01dcd3699"
VERSION_CATALOG = ROOT / "gradle/libs.versions.toml"


class AndroidSDKInstallationTests(unittest.TestCase):
    def run_installer(
        self,
        *,
        create_packages: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory(prefix="latchway-android-sdk-") as directory:
            temporary = Path(directory)
            sdk_root = temporary / "sdk"
            executable_directory = temporary / "bin"
            executable_directory.mkdir()
            arguments_path = temporary / "arguments.txt"
            sdkmanager = executable_directory / "sdkmanager"
            sdkmanager.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "printf '%s\\n' \"$@\" > \"$SDKMANAGER_ARGUMENTS\"\n"
                "sdk_root=\n"
                "platform=0\n"
                "build_tools=0\n"
                "for argument in \"$@\"; do\n"
                "  case \"$argument\" in\n"
                "    --sdk_root=*) sdk_root=${argument#--sdk_root=} ;;\n"
                "    --channel=0) ;;\n"
                "    \"platforms;android-37.0\") platform=1 ;;\n"
                "    \"build-tools;36.0.0\") build_tools=1 ;;\n"
                "    *) exit 64 ;;\n"
                "  esac\n"
                "done\n"
                "test -n \"$sdk_root\"\n"
                "test \"$platform\" = 1\n"
                "test \"$build_tools\" = 1\n"
                "if test \"${FAKE_SKIP_INSTALL:-0}\" = 1; then exit 0; fi\n"
                "mkdir -p \"$sdk_root/platforms/android-37.0\" "
                "\"$sdk_root/build-tools/36.0.0\"\n"
                ": > \"$sdk_root/platforms/android-37.0/android.jar\"\n"
                "printf '%s\\n' '<localPackage path=\"platforms;android-37.0\" />' "
                "> \"$sdk_root/platforms/android-37.0/package.xml\"\n"
                ": > \"$sdk_root/build-tools/36.0.0/aapt2\"\n"
                "chmod +x \"$sdk_root/build-tools/36.0.0/aapt2\"\n"
                "printf '%s\\n' '<localPackage path=\"build-tools;36.0.0\" />' "
                "> \"$sdk_root/build-tools/36.0.0/package.xml\"\n",
                encoding="utf-8",
            )
            sdkmanager.chmod(0o700)
            environment = os.environ.copy()
            environment["PATH"] = f"{executable_directory}:{environment['PATH']}"
            environment["ANDROID_SDK_ROOT"] = str(sdk_root)
            environment["ANDROID_HOME"] = str(sdk_root)
            environment["SDKMANAGER_ARGUMENTS"] = str(arguments_path)
            if not create_packages:
                environment["FAKE_SKIP_INSTALL"] = "1"
            result = subprocess.run(
                ["bash", str(INSTALLER)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            arguments = (
                arguments_path.read_text(encoding="utf-8").splitlines()
                if arguments_path.exists()
                else []
            )
            return result, arguments

    def test_installs_and_verifies_exact_stable_packages(self) -> None:
        result, arguments = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(arguments[1:], [
            "--channel=0",
            "platforms;android-37.0",
            "build-tools;36.0.0",
        ])
        self.assertRegex(arguments[0], r"^--sdk_root=.+/sdk$")

    def test_fails_closed_when_sdkmanager_does_not_install_packages(self) -> None:
        result, _ = self.run_installer(create_packages=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "package verification failed for platforms;android-37.0",
            result.stderr,
        )

    def test_workflows_use_the_same_pinned_toolchain(self) -> None:
        for path in WORKFLOWS:
            with self.subTest(path=path.name):
                workflow = path.read_text(encoding="utf-8")
                self.assertIn(f"setup-android@{SETUP_ANDROID_SHA}", workflow)
                self.assertIn('cmdline-tools-version: "14742923"', workflow)
                self.assertIn('packages: ""', workflow)
                self.assertIn("run: scripts/install-android-sdk.sh", workflow)
                self.assertNotIn("platforms;android-37\"", workflow)

    def test_gradle_sdk_levels_match_the_base_37_0_platform(self) -> None:
        self.assertIn(
            'agp = "9.3.2"',
            VERSION_CATALOG.read_text(encoding="utf-8"),
        )
        compile_levels: dict[str, list[int]] = {}
        target_levels: dict[str, list[int]] = {}
        for path in ROOT.glob("*/build.gradle.kts"):
            text = path.read_text(encoding="utf-8")
            compile_values = [
                int(value) for value in re.findall(r"compileSdk\s*=\s*(\d+)", text)
            ]
            target_values = [
                int(value) for value in re.findall(r"targetSdk\s*=\s*(\d+)", text)
            ]
            if compile_values:
                compile_levels[path.parent.name] = compile_values
            if target_values:
                target_levels[path.parent.name] = target_values

        self.assertIn("latchway-core", compile_levels)
        self.assertTrue(target_levels)
        self.assertEqual({37}, {level for levels in compile_levels.values() for level in levels})
        self.assertEqual({37}, {level for levels in target_levels.values() for level in levels})


if __name__ == "__main__":
    unittest.main()

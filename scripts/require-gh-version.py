#!/usr/bin/env python3
"""Fail closed unless the GitHub CLI has the required security baseline."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys


MINIMUM_VERSION = (2, 97, 0)
VERSION_LINE = re.compile(
    r"^gh version (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?: \([^\r\n()]+\))?$"
)
MAXIMUM_OUTPUT_BYTES = 16 * 1024


class Rejected(RuntimeError):
    """The installed GitHub CLI cannot safely run release verification."""


def parse_version(output: str) -> tuple[int, int, int]:
    if not output or len(output.encode("utf-8")) > MAXIMUM_OUTPUT_BYTES:
        raise Rejected("GitHub CLI returned empty or oversized version output.")
    lines = output.splitlines()
    match = VERSION_LINE.fullmatch(lines[0]) if lines else None
    if match is None:
        raise Rejected("GitHub CLI returned an unrecognized version string.")
    return tuple(int(component) for component in match.groups())


def require_version(executable: str = "gh") -> tuple[int, int, int]:
    if not executable or any(character in executable for character in "\x00\r\n"):
        raise Rejected("GitHub CLI executable is invalid.")
    environment = dict(os.environ)
    environment["GH_PROMPT_DISABLED"] = "1"
    try:
        result = subprocess.run(
            [executable, "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise Rejected("GitHub CLI version probe failed.") from error
    if result.returncode != 0:
        raise Rejected("GitHub CLI version probe failed.")
    version = parse_version(result.stdout)
    if version < MINIMUM_VERSION:
        observed = ".".join(str(component) for component in version)
        required = ".".join(str(component) for component in MINIMUM_VERSION)
        raise Rejected(f"GitHub CLI {observed} is below required minimum {required}.")
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gh", default="gh", help="GitHub CLI executable to probe")
    arguments = parser.parse_args()
    try:
        version = require_version(arguments.gh)
    except Rejected as error:
        print(f"GitHub CLI rejected: {error}", file=sys.stderr)
        return 1
    print(f"GitHub CLI {'.'.join(str(component) for component in version)} satisfies the release security baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed validation for GnuPG detached-signature status output."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
STATUS_TAG = re.compile(r"^[A-Z][A-Z0-9_]*$")
MAXIMUM_STATUS_BYTES = 64 * 1024
ALLOWED_TAGS = {
    "NEWSIG",
    "KEY_CONSIDERED",
    "SIG_ID",
    "GOODSIG",
    "VALIDSIG",
    "TRUST_UNDEFINED",
    "TRUST_NEVER",
    "TRUST_MARGINAL",
    "TRUST_FULLY",
    "TRUST_ULTIMATE",
    "VERIFICATION_COMPLIANCE_MODE",
}
INVALID_TAGS = {
    "BADSIG",
    "ERRSIG",
    "EXPSIG",
    "EXPKEYSIG",
    "REVKEYSIG",
    "NO_PUBKEY",
    "NODATA",
    "BADARMOR",
    "FAILURE",
    "ERROR",
    "INV_SGNR",
    "DECRYPTION_FAILED",
    "KEYEXPIRED",
    "SIGEXPIRED",
    "KEYREVOKED",
}


class Rejected(RuntimeError):
    """The status stream does not prove one valid signature by the pinned key."""


def _bounded_text(path: Path) -> str:
    metadata = path.stat()
    if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_STATUS_BYTES:
        raise Rejected("GnuPG status output has an invalid size")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise Rejected("GnuPG status output is not UTF-8") from error
    if "\x00" in text or "\r" in text:
        raise Rejected("GnuPG status output contains unsafe control bytes")
    return text


def validate(path: Path, expected_primary_fingerprint: str) -> dict[str, object]:
    if FINGERPRINT.fullmatch(expected_primary_fingerprint) is None:
        raise Rejected("expected primary fingerprint is invalid")

    lines = _bounded_text(path).splitlines()
    parsed: list[tuple[str, list[str], str]] = []
    for line in lines:
        prefix = "[GNUPG:] "
        if not line.startswith(prefix):
            raise Rejected("GnuPG emitted a non-status line")
        payload = line[len(prefix):]
        if not payload or any(ord(character) < 32 for character in payload):
            raise Rejected("GnuPG status line is malformed")
        fields = payload.split(" ")
        if any(field == "" for field in fields):
            raise Rejected("GnuPG status fields are malformed")
        tag, arguments = fields[0], fields[1:]
        if STATUS_TAG.fullmatch(tag) is None:
            raise Rejected("GnuPG status tag is malformed")
        if tag in INVALID_TAGS:
            raise Rejected(f"GnuPG rejected the signature with {tag}")
        if tag not in ALLOWED_TAGS:
            raise Rejected(f"GnuPG emitted unreviewed status {tag}")
        parsed.append((tag, arguments, line))

    by_tag: dict[str, list[list[str]]] = {}
    for tag, arguments, _ in parsed:
        by_tag.setdefault(tag, []).append(arguments)

    if len(by_tag.get("NEWSIG", [])) != 1:
        raise Rejected("GnuPG did not describe exactly one new signature")
    if len(by_tag.get("GOODSIG", [])) != 1:
        raise Rejected("GnuPG did not report exactly one good signature")
    if len(by_tag.get("VALIDSIG", [])) != 1:
        raise Rejected("GnuPG did not report exactly one valid signature")
    if len(by_tag.get("SIG_ID", [])) != 1:
        raise Rejected("GnuPG did not report exactly one signature identifier")
    if not by_tag.get("KEY_CONSIDERED"):
        raise Rejected("GnuPG did not bind the signature to the reviewed key")

    valid = by_tag["VALIDSIG"][0]
    # GnuPG DETAILS documents nine mandatory VALIDSIG fields after the tag and
    # an optional tenth field containing the primary-key fingerprint when a
    # signing subkey made the signature.
    if len(valid) not in (9, 10):
        raise Rejected("GnuPG VALIDSIG field count is invalid")
    signing_fingerprint = valid[0]
    if FINGERPRINT.fullmatch(signing_fingerprint) is None:
        raise Rejected("GnuPG signing fingerprint is invalid")
    primary_fingerprint = valid[9] if len(valid) == 10 else signing_fingerprint
    if FINGERPRINT.fullmatch(primary_fingerprint) is None:
        raise Rejected("GnuPG primary fingerprint is invalid")
    if primary_fingerprint != expected_primary_fingerprint:
        raise Rejected("GnuPG signature does not descend from the pinned primary key")

    goodsig = by_tag["GOODSIG"][0]
    if len(goodsig) < 2 or not re.fullmatch(r"(?:[0-9A-F]{16}|[0-9A-F]{40})", goodsig[0]):
        raise Rejected("GnuPG GOODSIG fields are invalid")
    if not (
        goodsig[0] == signing_fingerprint
        or (len(goodsig[0]) == 16 and signing_fingerprint.endswith(goodsig[0]))
    ):
        raise Rejected("GnuPG GOODSIG key ID does not match VALIDSIG")

    for considered in by_tag["KEY_CONSIDERED"]:
        if len(considered) != 2 or considered[0] != expected_primary_fingerprint:
            raise Rejected("GnuPG considered a key other than the pinned primary key")
        if considered[1] not in {"0", "1"}:
            raise Rejected("GnuPG KEY_CONSIDERED flags are invalid")

    signature_id = by_tag["SIG_ID"][0]
    if len(signature_id) != 3 or any(not field for field in signature_id):
        raise Rejected("GnuPG SIG_ID fields are invalid")

    trust_tags = [tag for tag in by_tag if tag.startswith("TRUST_")]
    if len(trust_tags) > 1 or any(len(by_tag[tag]) != 1 for tag in trust_tags):
        raise Rejected("GnuPG trust status is ambiguous")
    compliance = by_tag.get("VERIFICATION_COMPLIANCE_MODE", [])
    if len(compliance) > 1 or any(len(item) != 1 or not item[0].isdigit() for item in compliance):
        raise Rejected("GnuPG verification compliance status is invalid")

    return {
        "schema_version": 1,
        "primary_fingerprint": primary_fingerprint,
        "signing_fingerprint": signing_fingerprint,
        "status_lines": [line for _, _, line in parsed],
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--expected-primary-fingerprint", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        result = validate(arguments.status, arguments.expected_primary_fingerprint)
    except (OSError, Rejected) as error:
        print(f"GnuPG status rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

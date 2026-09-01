from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("build_docs_bundle", ROOT / "scripts/build_docs_bundle.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DocumentationBundleTests(unittest.TestCase):
    def test_full_source_references_and_supported_coordinate_closure(self) -> None:
        config = json.loads((ROOT / "docs-bundle.config.json").read_text(encoding="utf-8"))
        release_notes = next(item for item in config["documents"] if item["kind"] == "release_notes")["source"]
        for source in (release_notes, *(item["source"] for item in config["examples"])):
            line_count = len((ROOT / source["file"]).read_text(encoding="utf-8").splitlines())
            self.assertEqual(source["start_line"], 1)
            self.assertEqual(source["end_line"], line_count)

        supported = {item["name"] for item in config["supported_versions"]}
        self.assertTrue({
            "dev.latchway:latchway-core", "dev.latchway:latchway-okhttp",
            "dev.latchway:latchway-play-integrity", "dev.latchway:latchway-firebase-auth",
            "dev.latchway:latchway-bom", "Android API", "Android compile SDK",
            "Android Gradle Plugin", "Gradle", "Kotlin", "Java bytecode",
            "Play Integrity", "Firebase BOM", "Ktor OkHttp", "LangChain4j OkHttp SPI",
            "React Native bridge",
        } <= supported)
        publishing = "\n".join(
            (ROOT / "docs/publishing.md").read_text(encoding="utf-8").splitlines()[2:36]
        )
        for coordinate in (
            "dev.latchway:latchway-core", "dev.latchway:latchway-okhttp",
            "dev.latchway:latchway-play-integrity", "dev.latchway:latchway-firebase-auth",
            "dev.latchway:latchway-bom",
        ):
            self.assertIn(coordinate, publishing)
        self.assertIn("1.0.0", publishing)

    def test_bundle_is_reproducible_self_describing_and_checksum_bound(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            archives = []
            for output in (first, second):
                subprocess.run([
                    sys.executable, str(ROOT / "scripts/build_docs_bundle.py"),
                    "--output-dir", output, "--source-date-epoch", "0",
                ], cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
                archives.append(Path(output, "docs-bundle-1.0.0.tar.gz"))
            self.assertEqual(archives[0].read_bytes(), archives[1].read_bytes())
            with tarfile.open(archives[0], "r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual([item.name for item in members], sorted(item.name for item in members))
                self.assertTrue(all(item.isfile() and item.uid == item.gid == 0 and item.mode == 0o644 and item.mtime == 0 for item in members))
                payloads = {
                    item.name.split("/", 1)[1]: archive.extractfile(item).read()  # type: ignore[union-attr]
                    for item in members
                }
            manifest = json.loads(payloads["bundle-manifest.json"])
            self.assertEqual(manifest["schema_version"], MODULE.SCHEMA)
            self.assertEqual(manifest["release"]["version"], "1.0.0")
            retrofit = payloads["frameworks/retrofit.kt"].decode("utf-8")
            self.assertTrue(retrofit.startswith(
                "    @Test\n"
                "    fun retrofitUsesTheProductionHooksAndReplacesItsPlaceholderAuthorization() {\n"
            ))
            self.assertIn(
                "fun retrofitStreamingIsIncrementalAndCallCancellationReachesOkHttp()",
                retrofit,
            )
            self.assertIn("canceled.await(2, TimeUnit.SECONDS)", retrofit)
            self.assertTrue(retrofit.endswith(
                "        } finally {\n"
                "            close(http, harness, server)\n"
                "        }\n"
                "    }\n"
            ))
            koog = payloads["frameworks/koog.kt"].decode("utf-8")
            self.assertTrue(koog.startswith(
                "    @Test\n"
                "    fun koogPreservesChatToolsAndStructuredOutputThroughLatchwayOkHttp() = runBlocking {\n"
            ))
            self.assertIn("structured-output", koog)
            self.assertTrue(koog.endswith(
                "        } finally {\n"
                "            close(fixture, harness, server)\n"
                "        }\n"
                "    }\n"
            ))
            self.assertEqual({item["kind"] for item in manifest["files"]} >= {
                "quickstart", "framework", "release_notes", "supported_versions",
                "public_symbols", "errors", "examples",
            }, True)
            for item in manifest["files"]:
                self.assertEqual(hashlib.sha256(payloads[item["path"]]).hexdigest(), item["sha256"])
                self.assertTrue(item["provenance"])
                for source in item["provenance"]:
                    self.assertEqual(source["repository"], manifest["repository"])
                    self.assertEqual(source["release"], manifest["release"]["tag"])
                    self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
                    self.assertLessEqual(source["region"]["start_line"], source["region"]["end_line"])
                    source_bytes = Path(ROOT, source["file"]).read_bytes()
                    source_lines = source_bytes.decode("utf-8").splitlines(keepends=True)
                    region = "".join(source_lines[
                        source["region"]["start_line"] - 1:source["region"]["end_line"]
                    ]).encode("utf-8")
                    self.assertEqual(hashlib.sha256(source_bytes).hexdigest(), source["source_sha256"])
                    self.assertEqual(hashlib.sha256(region).hexdigest(), source["region_sha256"])
            checksums = {}
            for line in payloads["SHA256SUMS"].decode("ascii").splitlines():
                digest, name = line.split("  ", 1)
                checksums[name] = digest
            self.assertEqual(set(checksums), set(payloads) - {"SHA256SUMS"})
            for name, digest in checksums.items():
                self.assertEqual(hashlib.sha256(payloads[name]).hexdigest(), digest)
            catalogs = {}
            for name, key in (("supported-versions.json", "versions"), ("public-symbols.json", "symbols"), ("errors.json", "errors"), ("examples.json", "examples")):
                catalogs[name] = json.loads(payloads[name])[key]
                self.assertTrue(catalogs[name])
            for name in ("public-symbols.json", "errors.json"):
                for row in catalogs[name]:
                    source = row["source"]
                    line = (ROOT / source["file"]).read_text(encoding="utf-8").splitlines()[
                        source["region"]["start_line"] - 1
                    ]
                    self.assertIn(row["name"], line)

            symbols = catalogs["public-symbols.json"]
            symbol_locations = {
                (row["name"], row["source"]["file"], row["source"]["region"]["start_line"])
                for row in symbols
            }
            for path in sorted(ROOT.glob("latchway-*/src/main/**/*.kt")):
                lines = path.read_text(encoding="utf-8").splitlines()
                in_public_data_class = False
                parenthesis_depth = 0
                for line_number, line in enumerate(lines, 1):
                    if re.match(r"^[ \t]*public data class [A-Za-z]", line):
                        inline = re.search(r"public (?:val|var) (?P<name>[A-Za-z][A-Za-z0-9_]*)", line)
                        if inline is not None:
                            self.assertIn(
                                (inline.group("name"), path.relative_to(ROOT).as_posix(), line_number),
                                symbol_locations,
                            )
                        in_public_data_class = True
                        parenthesis_depth = line.count("(") - line.count(")")
                        if parenthesis_depth <= 0:
                            in_public_data_class = False
                        continue
                    if in_public_data_class:
                        property_match = re.match(
                            r"^[ \t]*(?!(?:private|internal|protected) )"
                            r"(?:public |override )?(?:val|var) (?P<name>[A-Za-z][A-Za-z0-9_]*)",
                            line,
                        )
                        if property_match is not None:
                            self.assertIn(
                                (property_match.group("name"), path.relative_to(ROOT).as_posix(), line_number),
                                symbol_locations,
                            )
                        parenthesis_depth += line.count("(") - line.count(")")
                        if parenthesis_depth <= 0:
                            in_public_data_class = False
            symbol_names = {row["name"] for row in symbols}
            self.assertNotIn("interface", symbol_names)
            self.assertTrue({"identityToken", "execute", "close", "maximumAttempts"} <= symbol_names)
            self.assertIn("response_invalid", {row["name"] for row in catalogs["errors.json"]})

    def test_path_validation_and_archive_verifier_reject_traversal(self) -> None:
        for value in ("/absolute", "../escape", "a/../escape", "a\\b"):
            with self.assertRaises(MODULE.BundleError):
                MODULE.safe_relative(value)
        with tempfile.TemporaryDirectory() as temporary:
            malicious = Path(temporary, "malicious.tar.gz")
            with malicious.open("wb") as output:
                with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w") as archive:
                        payload = b"unsafe"
                        info = tarfile.TarInfo("../escape")
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
            with self.assertRaises(MODULE.BundleError):
                MODULE.verify_archive(malicious, "docs-bundle-1.0.0")

    def test_provenance_commit_must_equal_the_checked_out_source(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            with self.assertRaisesRegex(MODULE.BundleError, "checked-out source commit"):
                MODULE.build(MODULE.DEFAULT_CONFIG, Path(output), None, "0" * 40, 0, False)


if __name__ == "__main__":
    unittest.main()

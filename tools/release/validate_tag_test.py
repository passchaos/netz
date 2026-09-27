#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).with_name("validate_tag.py")
SPEC = importlib.util.spec_from_file_location("validate_tag", MODULE)
assert SPEC is not None and SPEC.loader is not None
VALIDATE_TAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATE_TAG)


class ValidateTagTest(unittest.TestCase):
    def manifest(self, version: str) -> Path:
        path = Path(self.temporary.name) / "build.zig.zon"
        path.write_text(
            f'.{{\n    .name = .netz,\n    .version = "{version}",\n}}\n',
            encoding="utf-8",
        )
        return path

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_accepts_matching_stable_and_prerelease_tags(self) -> None:
        self.assertEqual(
            "1.2.3",
            VALIDATE_TAG.validate("v1.2.3", self.manifest("1.2.3")),
        )
        self.assertEqual(
            "1.2.3-rc.1+build.7",
            VALIDATE_TAG.validate(
                "v1.2.3-rc.1+build.7",
                self.manifest("1.2.3-rc.1+build.7"),
            ),
        )
        self.assertEqual(
            "1.2.3-0alpha",
            VALIDATE_TAG.validate(
                "v1.2.3-0alpha",
                self.manifest("1.2.3-0alpha"),
            ),
        )

    def test_rejects_mismatch_and_missing_v_prefix(self) -> None:
        manifest = self.manifest("1.2.3")
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            VALIDATE_TAG.validate("v1.2.4", manifest)
        with self.assertRaisesRegex(RuntimeError, "not v<SemVer>"):
            VALIDATE_TAG.validate("1.2.3", manifest)

    def test_rejects_noncanonical_semver_and_ambiguous_manifest(self) -> None:
        for tag in ("v01.2.3", "v1.2", "v1.2.3-01", "release-1.2.3"):
            with self.assertRaisesRegex(RuntimeError, "not v<SemVer>"):
                VALIDATE_TAG.validate(tag, self.manifest("1.2.3"))
        manifest = Path(self.temporary.name) / "build.zig.zon"
        manifest.write_text(
            '.{ .version = "1.2.3", .other = .{ .version = "1.2.3" } }\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            VALIDATE_TAG.package_version(manifest)

    def test_release_workflow_keeps_validation_before_publication(self) -> None:
        workflow = (
            Path(__file__).parents[2] / ".github/workflows/release.yml"
        ).read_text(encoding="utf-8")
        required = (
            'tags:\n      - "v*"',
            "contents: write",
            "persist-credentials: false",
            "python3 tools/release/validate_tag.py",
            "zig build test -j1 --summary all",
            "zig build verify-release-source --summary all",
            "sha256sum -c netz-${GITHUB_REF_NAME#v}-source.tar.gz.sha256",
            'gh release view "$GITHUB_REF_NAME"',
            'gh release upload "$GITHUB_REF_NAME"',
            'gh release create "$GITHUB_REF_NAME"',
            "--verify-tag",
        )
        positions = []
        for fragment in required:
            with self.subTest(fragment=fragment):
                position = workflow.find(fragment)
                self.assertNotEqual(-1, position)
                positions.append(position)
        self.assertLess(
            workflow.index("python3 tools/release/validate_tag.py"),
            workflow.index("zig build test -j1 --summary all"),
        )
        self.assertLess(
            workflow.index("zig build verify-release-source --summary all"),
            workflow.index('gh release view "$GITHUB_REF_NAME"'),
        )


if __name__ == "__main__":
    unittest.main()

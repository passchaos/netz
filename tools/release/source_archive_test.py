#!/usr/bin/env python3

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

MODULE = Path(__file__).with_name("source_archive.py")
SPEC = importlib.util.spec_from_file_location("source_archive", MODULE)
assert SPEC is not None and SPEC.loader is not None
SOURCE_ARCHIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE_ARCHIVE)
VERIFY_MODULE = Path(__file__).with_name("verify_source_archive.py")
VERIFY_SPEC = importlib.util.spec_from_file_location(
    "verify_source_archive", VERIFY_MODULE
)
assert VERIFY_SPEC is not None and VERIFY_SPEC.loader is not None
VERIFY_ARCHIVE = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY_ARCHIVE)
CHECKSUM_MODULE = Path(__file__).with_name("archive_checksum.py")
CHECKSUM_SPEC = importlib.util.spec_from_file_location(
    "archive_checksum", CHECKSUM_MODULE
)
assert CHECKSUM_SPEC is not None and CHECKSUM_SPEC.loader is not None
CHECKSUM = importlib.util.module_from_spec(CHECKSUM_SPEC)
CHECKSUM_SPEC.loader.exec_module(CHECKSUM)


def initialize_repository(root: Path, files: dict[str, bytes]) -> str:
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Netz Test",
            "-c",
            "user.email=netz@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=root,
        check=True,
    )
    return SOURCE_ARCHIVE.revision(root)


class SourceArchiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.root = base / "netz"
        self.vail = base / "vail"
        self.vort = base / "vort"
        self.pbz = base / "pbz"
        self.zio = base / "zio"
        for path in (self.root, self.vail, self.vort, self.pbz, self.zio):
            path.mkdir()
        manifest = b""".{
    .dependencies = .{
        .vail = .{ .path = \"../vail\" },
        .vort = .{ .path = \"../vort\" },
        .zio = .{
            .url = \"git+https://github.com/passchaos/zio#4daa0c0a9522a37c4d28e3dcec2515cc955abe71\",
            .hash = \"zio-0.19.1-xHbVVJXzKwAKLRAABWeDvQG9Dg1kf9FM3haWG0YqtScn\",
        },
        .pbz = .{ .path = \"../pbz\" },
    },
    .paths = .{
        \"build.zig\",
        \"build.zig.zon\",
        \"src\",
    },
}
"""
        self.netz_revision = initialize_repository(
            self.root,
            {
                "build.zig": b"pub fn build() void {}\n",
                "build.zig.zon": manifest,
                ".github/workflows/ci.yml": b"not published\n",
                "src/root.zig": b"pub const value = 1;\n",
            },
        )
        self.vail_revision = initialize_repository(
            self.vail,
            {
                "build.zig": b"pub fn build() void {}\n",
                "build.zig.zon": b".{}\n",
                "src/root.zig": b"pub const value = 2;\n",
            },
        )
        self.vort_revision = initialize_repository(
            self.vort,
            {
                "build.zig": b"pub fn build() void {}\n",
                "build.zig.zon": b".{}\n",
                "src/root.zig": b"pub const value = 5;\n",
            },
        )
        self.pbz_revision = initialize_repository(
            self.pbz,
            {
                "build.zig": b"pub fn build() void {}\n",
                "build.zig.zon": b".{}\n",
                "src/root.zig": b"pub const value = 3;\n",
            },
        )
        (self.zio / "src").mkdir()
        (self.zio / "build.zig").write_text(
            "pub fn build() void {}\n", encoding="utf-8"
        )
        (self.zio / "build.zig.zon").write_text(
            """.{
    .name = .zio,
    .version = "0.19.1",
    .fingerprint = 0xcf1598b354d576c4,
    .minimum_zig_version = "0.16.0",
    .paths = .{ "build.zig", "build.zig.zon", "src" },
}
""",
            encoding="utf-8",
        )
        (self.zio / "src/root.zig").write_text(
            "pub const value = 4;\n", encoding="utf-8"
        )
        self.zio_hash = SOURCE_ARCHIVE.package_hash(self.zio, "zig")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self, output: Path) -> None:
        SOURCE_ARCHIVE.create_archive(
            self.root,
            self.vail,
            self.vort,
            self.pbz,
            self.zio,
            output,
            expected_vail_revision=self.vail_revision,
            expected_vort_revision=self.vort_revision,
            expected_pbz_revision=self.pbz_revision,
            expected_zio_package_hash=self.zio_hash,
        )

    def test_archive_is_deterministic_and_rewrites_dependencies(self) -> None:
        first = Path(self.temporary.name) / "first.tar.gz"
        second = Path(self.temporary.name) / "second.tar.gz"
        self.create(first)
        self.create(second)
        self.assertEqual(first.read_bytes(), second.read_bytes())

        with tarfile.open(first, mode="r:gz") as archive:
            names = archive.getnames()
            self.assertNotIn("netz-0.1.0/.github/workflows/ci.yml", names)
            self.assertIn("netz-0.1.0/deps/vail/src/root.zig", names)
            self.assertIn("netz-0.1.0/deps/vort/src/root.zig", names)
            self.assertIn("netz-0.1.0/deps/pbz/src/root.zig", names)
            self.assertIn("netz-0.1.0/deps/zio/src/root.zig", names)
            package = archive.extractfile(
                "netz-0.1.0/build.zig.zon"
            ).read().decode("utf-8")
            metadata = json.load(
                io.TextIOWrapper(
                    archive.extractfile(
                        "netz-0.1.0/RELEASE-MANIFEST.json"
                    ),
                    encoding="utf-8",
                )
            )

        self.assertIn('.path = "deps/vail"', package)
        self.assertIn('.path = "deps/vort"', package)
        self.assertIn('.path = "deps/pbz"', package)
        self.assertIn('.path = "deps/zio"', package)
        self.assertIn('"deps"', package)
        self.assertNotIn("../vail", package)
        self.assertNotIn("../vort", package)
        self.assertNotIn("../pbz", package)
        self.assertNotIn("git+https://github.com/passchaos/zio", package)
        self.assertEqual(self.netz_revision, metadata["source_revision"])
        self.assertEqual(
            self.vail_revision,
            metadata["vendored_dependencies"]["vail"]["revision"],
        )
        self.assertEqual(
            self.vort_revision,
            metadata["vendored_dependencies"]["vort"]["revision"],
        )
        self.assertEqual(
            self.pbz_revision,
            metadata["vendored_dependencies"]["pbz"]["revision"],
        )
        with tempfile.TemporaryDirectory() as extracted_name:
            extracted = Path(extracted_name)
            with tarfile.open(first, mode="r:gz") as archive:
                archive.extractall(extracted, filter="data")
            VERIFY_ARCHIVE.verify_layout(extracted / "netz-0.1.0")

    def test_rejects_dirty_source_repository(self) -> None:
        (self.root / "src/root.zig").write_text(
            "pub const value = 4;\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "not clean"):
            self.create(Path(self.temporary.name) / "dirty.tar.gz")

    def test_rejects_dependency_revision_mismatch(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "vail revision mismatch"):
            SOURCE_ARCHIVE.create_archive(
                self.root,
                self.vail,
                self.vort,
                self.pbz,
                self.zio,
                Path(self.temporary.name) / "mismatch.tar.gz",
                expected_vail_revision="0" * 40,
                expected_vort_revision=self.vort_revision,
                expected_pbz_revision=self.pbz_revision,
                expected_zio_package_hash=self.zio_hash,
            )

    def test_verifier_rejects_unsafe_and_duplicate_paths(self) -> None:
        safe = tarfile.TarInfo("netz-0.1.0/build.zig")
        unsafe = tarfile.TarInfo("netz-0.1.0/../outside")
        with self.assertRaisesRegex(RuntimeError, "unsafe archive path"):
            VERIFY_ARCHIVE.validate_members([safe, unsafe])
        with self.assertRaisesRegex(RuntimeError, "duplicate archive path"):
            VERIFY_ARCHIVE.validate_members([safe, safe])

    def test_verifier_rejects_tampered_content(self) -> None:
        archive_path = Path(self.temporary.name) / "verified.tar.gz"
        self.create(archive_path)
        extracted = Path(self.temporary.name) / "extracted"
        with tarfile.open(archive_path, mode="r:gz") as archive:
            archive.extractall(extracted, filter="data")
        root = extracted / "netz-0.1.0"
        (root / "src/root.zig").write_text(
            "pub const value = 99;\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "file manifest"):
            VERIFY_ARCHIVE.verify_layout(root)

    def test_consumer_manifest_targets_release_archive(self) -> None:
        base = Path(self.temporary.name)
        archive = base / "netz-0.1.0-source.tar.gz"
        archive.write_bytes(b"archive")
        consumer = base / "consumer"
        VERIFY_ARCHIVE.write_consumer(consumer, archive, "netz-0.1.0-testhash")
        manifest = (consumer / "build.zig.zon").read_text(
            encoding="utf-8"
        )
        self.assertIn(f'.url = "{archive.resolve().as_uri()}"', manifest)
        self.assertIn('.hash = "netz-0.1.0-testhash"', manifest)
        self.assertIn('@import("netz")', (consumer / "src/main.zig").read_text())

    def test_checksum_sidecar_detects_tampering_and_wrong_name(self) -> None:
        archive = Path(self.temporary.name) / "netz.tar.gz"
        checksum = Path(self.temporary.name) / "netz.tar.gz.sha256"
        archive.write_bytes(b"release")
        CHECKSUM.write(archive, checksum)
        CHECKSUM.verify(archive, checksum)

        archive.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
            CHECKSUM.verify(archive, checksum)
        checksum.write_text("0" * 64 + "  other.tar.gz\n", encoding="ascii")
        with self.assertRaisesRegex(RuntimeError, "checksum names"):
            CHECKSUM.verify(archive, checksum)


if __name__ == "__main__":
    unittest.main()

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

REPOSITORY_ROOT = Path(__file__).parents[2]


def extract_all(archive: tarfile.TarFile, path: Path) -> None:
    try:
        archive.extractall(path, filter="data")
    except TypeError:
        # Python < 3.12 lacks the extraction filter argument.
        archive.extractall(path)


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
        self.kron = base / "kron"
        self.webpkiz = base / "webpkiz"
        self.regexz = base / "regexz"
        self.zio = base / "zio"
        self.harnessz = base / "harnessz"
        for path in (
            self.root,
            self.vail,
            self.vort,
            self.pbz,
            self.kron,
            self.webpkiz,
            self.regexz,
            self.zio,
            self.harnessz,
        ):
            path.mkdir()
        manifest = b""".{
    .dependencies = .{
        .harnessz = .{ .path = \"../harnessz\" },
        .vail = .{ .path = \"../vail\" },
        .vort = .{ .path = \"../vort\" },
        .zio = .{
            .url = \"git+https://github.com/passchaos/zio#8f4ce3a97cc69eddb03409b01d1137c2f99ef42b\",
            .hash = \"zio-0.19.1-xHbVVE1kLABhvcTZ2InisM3hdkwDdj0fzzAUxvw2AmGk\",
        },
        .pbz = .{ .path = \"../pbz\" },
        .kron = .{ .path = \"../kron\" },
        .webpkiz = .{ .path = \"../webpkiz\" },
        .regexz = .{ .path = \"../regexz\" },
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
        self.kron_revision = initialize_repository(
            self.kron,
            {
                "build.zig": b"pub fn build() void {}\n",
                "build.zig.zon": b".{}\n",
                "src/root.zig": b"pub const value = 9;\n",
            },
        )
        self.webpkiz_revision = initialize_repository(
            self.webpkiz,
            {
                "build.zig": b"pub fn build() void {}\n",
                "build.zig.zon": b".{}\n",
                "src/root.zig": b"pub const value = 7;\n",
            },
        )
        self.regexz_revision = initialize_repository(
            self.regexz,
            {
                "build.zig": b"pub fn build() void {}\n",
                "build.zig.zon": b".{}\n",
                "src/root.zig": b"pub const value = 8;\n",
            },
        )
        self.harnessz_revision = initialize_repository(
            self.harnessz,
            {
                "build.zig": b"pub fn build() void {}\n",
                "build.zig.zon": b".{}\n",
                "src/root.zig": b"pub const value = 6;\n",
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
            self.kron,
            self.webpkiz,
            self.regexz,
            self.zio,
            self.harnessz,
            output,
            expected_vail_revision=self.vail_revision,
            expected_vort_revision=self.vort_revision,
            expected_pbz_revision=self.pbz_revision,
            expected_kron_revision=self.kron_revision,
            expected_webpkiz_revision=self.webpkiz_revision,
            expected_regexz_revision=self.regexz_revision,
            expected_harnessz_revision=self.harnessz_revision,
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
            self.assertIn("netz-0.1.0/deps/kron/src/root.zig", names)
            self.assertIn("netz-0.1.0/deps/webpkiz/src/root.zig", names)
            self.assertIn("netz-0.1.0/deps/regexz/src/root.zig", names)
            self.assertIn("netz-0.1.0/deps/harnessz/src/root.zig", names)
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

        self.assertIn('.path = "deps/harnessz"', package)
        self.assertIn('.path = "deps/vail"', package)
        self.assertIn('.path = "deps/vort"', package)
        self.assertIn('.path = "deps/pbz"', package)
        self.assertIn('.path = "deps/kron"', package)
        self.assertIn('.path = "deps/webpkiz"', package)
        self.assertIn('.path = "deps/regexz"', package)
        self.assertIn('.path = "deps/zio"', package)
        self.assertIn('"deps"', package)
        self.assertNotIn("../harnessz", package)
        self.assertNotIn("../vail", package)
        self.assertNotIn("../vort", package)
        self.assertNotIn("../pbz", package)
        self.assertNotIn("../kron", package)
        self.assertNotIn("../webpkiz", package)
        self.assertNotIn("../regexz", package)
        self.assertNotIn("git+https://github.com/passchaos/zio", package)
        self.assertEqual(self.netz_revision, metadata["source_revision"])
        self.assertEqual(
            self.harnessz_revision,
            metadata["vendored_dependencies"]["harnessz"]["revision"],
        )
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
        self.assertEqual(
            self.kron_revision,
            metadata["vendored_dependencies"]["kron"]["revision"],
        )
        self.assertEqual(
            self.webpkiz_revision,
            metadata["vendored_dependencies"]["webpkiz"]["revision"],
        )
        self.assertEqual(
            self.regexz_revision,
            metadata["vendored_dependencies"]["regexz"]["revision"],
        )
        with tempfile.TemporaryDirectory() as extracted_name:
            extracted = Path(extracted_name)
            with tarfile.open(first, mode="r:gz") as archive:
                extract_all(archive, extracted)
            VERIFY_ARCHIVE.verify_layout(extracted / "netz-0.1.0")

    def test_rejects_dirty_source_repository(self) -> None:
        (self.root / "src/root.zig").write_text(
            "pub const value = 4;\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "not clean"):
            self.create(Path(self.temporary.name) / "dirty.tar.gz")

    def test_ignores_untracked_files(self) -> None:
        (self.root / "untracked.txt").write_text(
            "local only\n", encoding="utf-8"
        )
        self.create(Path(self.temporary.name) / "untracked.tar.gz")

    def test_rejects_dependency_revision_mismatch(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "vail revision mismatch"):
            SOURCE_ARCHIVE.create_archive(
                self.root,
                self.vail,
                self.vort,
                self.pbz,
                self.kron,
                self.webpkiz,
                self.regexz,
                self.zio,
                self.harnessz,
                Path(self.temporary.name) / "mismatch.tar.gz",
                expected_vail_revision="0" * 40,
                expected_vort_revision=self.vort_revision,
                expected_pbz_revision=self.pbz_revision,
                expected_kron_revision=self.kron_revision,
                expected_webpkiz_revision=self.webpkiz_revision,
                expected_regexz_revision=self.regexz_revision,
                expected_harnessz_revision=self.harnessz_revision,
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
            extract_all(archive, extracted)
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


class RepositoryDependencyPinTest(unittest.TestCase):
    def test_workflows_and_release_generator_use_the_same_dependencies(self) -> None:
        manifest = (REPOSITORY_ROOT / "build.zig.zon").read_text(encoding="utf-8")
        self.assertIn(f'.url = "{SOURCE_ARCHIVE.ZIO_SOURCE}"', manifest)
        self.assertIn(
            f'.hash = "{SOURCE_ARCHIVE.ZIO_PACKAGE_HASH}"',
            manifest,
        )

        ci = (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        release = (REPOSITORY_ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        sibling_pins = {
            "harnessz": SOURCE_ARCHIVE.HARNESSZ_REVISION,
            "vail": SOURCE_ARCHIVE.VAIL_REVISION,
            "vort": SOURCE_ARCHIVE.VORT_REVISION,
            "pbz": SOURCE_ARCHIVE.PBZ_REVISION,
            "kron": SOURCE_ARCHIVE.KRON_REVISION,
            "webpkiz": SOURCE_ARCHIVE.WEBPKIZ_REVISION,
            "regexz": SOURCE_ARCHIVE.REGEXZ_REVISION,
        }
        for name, revision in sibling_pins.items():
            checkout_lines = [
                f"repository: passchaos/{name}",
                f"          ref: {revision}",
            ]
            if name in (
                "harnessz",
                "vail",
                "vort",
                "kron",
                "webpkiz",
                "regexz",
            ):
                checkout_lines.append(
                    "          token: ${{ secrets.NETZ_DEPENDENCIES_TOKEN }}"
                )
            checkout_lines.append(f"          path: {name}")
            checkout = "\n".join(checkout_lines)
            self.assertEqual(4, ci.count(checkout), name)
            self.assertEqual(1, release.count(checkout), name)

        self.assertIn("'vort/build.zig.zon'", ci)
        for target in (
            "aarch64-linux-gnu",
            "x86_64-linux-gnu",
            "x86_64-windows-gnu",
            "aarch64-macos-none",
            "x86_64-macos-none",
        ):
            self.assertEqual(1, ci.count(target), target)
        self.assertIn(
            "zig build test-compile -j1 -Dtarget=${{ matrix.target }} --summary all",
            ci,
        )


if __name__ == "__main__":
    unittest.main()

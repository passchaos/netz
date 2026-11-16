#!/usr/bin/env python3
"""Create a deterministic Netz source archive with local path dependencies."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile


FORMAT_VERSION = 1
PACKAGE_NAME = "netz"
DEFAULT_PACKAGE_VERSION = "0.1.0"
VAIL_REVISION = "3b772b0cccb64d84fbc760df6428bc51e0fe0761"
VORT_REVISION = "b661c887e21fb1965db358bc6d12ea379d20178d"
PBZ_REVISION = "6513ef1f8b130b308bd86ba0bd02f6acc2be64e8"
WEBPKIZ_REVISION = "35c9f4bfecb51a7794670d474c01b3c6fe541e9e"
REGEXZ_REVISION = "f150767088ef11fb4435f3b42c99165333b6e51c"
HARNESSZ_REVISION = "e626f26b0a7ead0377254ed3a04b43b25fb2d270"
ZIO_SOURCE = (
    "git+https://github.com/passchaos/zio"
    "#8f4ce3a97cc69eddb03409b01d1137c2f99ef42b"
)
ZIO_PACKAGE_HASH = "zio-0.19.1-xHbVVE1kLABhvcTZ2InisM3hdkwDdj0fzzAUxvw2AmGk"
ROOT_FILES = {
    ".gitignore",
    "LICENSE",
    "README.md",
    "build.zig",
    "build.zig.zon",
}
ROOT_DIRECTORIES = {"benchmarks", "docs", "examples", "src", "test", "tools"}
IGNORED_PACKAGE_PARTS = {
    ".git",
    ".zig-cache",
    "zig-cache",
    "zig-out",
    "target",
    "__pycache__",
}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def revision(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD").decode("ascii").strip()


def package_hash(repo: Path, zig: str) -> str:
    with tempfile.TemporaryDirectory(prefix="netz-package-hash-") as cache:
        return subprocess.run(
            [zig, "fetch", "--global-cache-dir", cache, str(repo)],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()


def require_clean(repo: Path) -> None:
    # Only tracked content is archived, so untracked editor/OS files cannot
    # change the archive. Reject tracked modifications and staged changes.
    status = git(repo, "status", "--porcelain", "--untracked-files=no")
    if status:
        raise RuntimeError(f"source repository is not clean: {repo}")


def tracked_files(repo: Path) -> list[tuple[str, int]]:
    entries: list[tuple[str, int]] = []
    for record in git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode = int(metadata.split(b" ", 1)[0], 8)
        path = raw_path.decode("utf-8")
        normalized = PurePosixPath(path)
        if normalized.is_absolute() or ".." in normalized.parts:
            raise RuntimeError(f"unsafe tracked path in {repo}: {path}")
        if mode not in (0o100644, 0o100755):
            raise RuntimeError(f"unsupported tracked file mode {mode:o}: {path}")
        entries.append((path, mode))
    entries.sort()
    return entries


def package_files(root: Path) -> list[tuple[str, int]]:
    entries: list[tuple[str, int]] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        relative = path.relative_to(root)
        if any(part in IGNORED_PACKAGE_PARTS for part in relative.parts):
            continue
        if not path.is_file():
            raise RuntimeError(f"unsupported package entry: {path}")
        entries.append((relative.as_posix(), path.stat().st_mode))
    entries.sort()
    return entries


def is_published_root_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return path in ROOT_FILES or pure.parts[0] in ROOT_DIRECTORIES


def release_manifest(
    package_version: str,
    netz_revision: str,
    vail_revision: str,
    vort_revision: str,
    pbz_revision: str,
    webpkiz_revision: str,
    regexz_revision: str,
    harnessz_revision: str,
    file_hashes: dict[str, str],
) -> bytes:
    return (
        json.dumps(
            {
                "format_version": FORMAT_VERSION,
                "package": PACKAGE_NAME,
                "version": package_version,
                "source_revision": netz_revision,
                "files": file_hashes,
                "vendored_dependencies": {
                    "harnessz": {
                        "path": "deps/harnessz",
                        "revision": harnessz_revision,
                    },
                    "pbz": {
                        "path": "deps/pbz",
                        "revision": pbz_revision,
                    },
                    "vail": {
                        "path": "deps/vail",
                        "revision": vail_revision,
                    },
                    "vort": {
                        "path": "deps/vort",
                        "revision": vort_revision,
                    },
                    "webpkiz": {
                        "path": "deps/webpkiz",
                        "revision": webpkiz_revision,
                    },
                    "regexz": {
                        "path": "deps/regexz",
                        "revision": regexz_revision,
                    },
                    "zio": {
                        "path": "deps/zio",
                        "package_hash": ZIO_PACKAGE_HASH,
                        "source": ZIO_SOURCE,
                    },
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def rewrite_package_manifest(data: bytes) -> bytes:
    text = data.decode("utf-8")
    replacements = {
        '.harnessz = .{ .path = "../harnessz" },':
            '.harnessz = .{ .path = "deps/harnessz" },',
        '.vail = .{ .path = "../vail" },':
            '.vail = .{ .path = "deps/vail" },',
        '.vort = .{ .path = "../vort" },':
            '.vort = .{ .path = "deps/vort" },',
        '.pbz = .{ .path = "../pbz" },':
            '.pbz = .{ .path = "deps/pbz" },',
        '.webpkiz = .{ .path = "../webpkiz" },':
            '.webpkiz = .{ .path = "deps/webpkiz" },',
        '.regexz = .{ .path = "../regexz" },':
            '.regexz = .{ .path = "deps/regexz" },',
        '        .zio = .{\n'
        '            .url = "' + ZIO_SOURCE + '",\n'
        '            .hash = "' + ZIO_PACKAGE_HASH + '",\n'
        '        },': '.zio = .{ .path = "deps/zio" },',
        '        "build.zig.zon",\n        "src",':
            '        "build.zig.zon",\n'
            '        "RELEASE-MANIFEST.json",\n'
            '        "deps",\n'
            '        "src",',
    }
    for old, new in replacements.items():
        if text.count(old) != 1:
            raise RuntimeError(
                f"expected one package-manifest fragment: {old!r}"
            )
        text = text.replace(old, new)
    return text.encode("utf-8")


def add_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info)


def add_bytes(
    archive: tarfile.TarFile,
    name: str,
    data: bytes,
    mode: int,
) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755 if mode & stat.S_IXUSR else 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, io.BytesIO(data))


def create_archive(
    root: Path,
    vail: Path,
    vort: Path,
    pbz: Path,
    webpkiz: Path,
    regexz: Path,
    zio: Path,
    harnessz: Path,
    output: Path,
    package_version: str = DEFAULT_PACKAGE_VERSION,
    expected_vail_revision: str = VAIL_REVISION,
    expected_vort_revision: str = VORT_REVISION,
    expected_pbz_revision: str = PBZ_REVISION,
    expected_webpkiz_revision: str = WEBPKIZ_REVISION,
    expected_regexz_revision: str = REGEXZ_REVISION,
    expected_harnessz_revision: str = HARNESSZ_REVISION,
    expected_zio_package_hash: str = ZIO_PACKAGE_HASH,
    zig: str = "zig",
) -> None:
    repositories = {
        "": root.resolve(),
        "deps/vail": vail.resolve(),
        "deps/vort": vort.resolve(),
        "deps/pbz": pbz.resolve(),
        "deps/webpkiz": webpkiz.resolve(),
        "deps/regexz": regexz.resolve(),
        "deps/harnessz": harnessz.resolve(),
    }
    for repo in repositories.values():
        require_clean(repo)

    revisions = {prefix: revision(repo) for prefix, repo in repositories.items()}
    if revisions["deps/vail"] != expected_vail_revision:
        raise RuntimeError(
            "vail revision mismatch: expected "
            f"{expected_vail_revision}, found {revisions['deps/vail']}"
        )
    if revisions["deps/vort"] != expected_vort_revision:
        raise RuntimeError(
            "vort revision mismatch: expected "
            f"{expected_vort_revision}, found {revisions['deps/vort']}"
        )
    if revisions["deps/pbz"] != expected_pbz_revision:
        raise RuntimeError(
            "pbz revision mismatch: expected "
            f"{expected_pbz_revision}, found {revisions['deps/pbz']}"
        )
    if revisions["deps/webpkiz"] != expected_webpkiz_revision:
        raise RuntimeError(
            "webpkiz revision mismatch: expected "
            f"{expected_webpkiz_revision}, "
            f"found {revisions['deps/webpkiz']}"
        )
    if revisions["deps/regexz"] != expected_regexz_revision:
        raise RuntimeError(
            "regexz revision mismatch: expected "
            f"{expected_regexz_revision}, "
            f"found {revisions['deps/regexz']}"
        )
    if revisions["deps/harnessz"] != expected_harnessz_revision:
        raise RuntimeError(
            "harnessz revision mismatch: expected "
            f"{expected_harnessz_revision}, "
            f"found {revisions['deps/harnessz']}"
        )
    actual_zio_hash = package_hash(zio, zig)
    if actual_zio_hash != expected_zio_package_hash:
        raise RuntimeError(
            "zio package hash mismatch: expected "
            f"{expected_zio_package_hash}, found {actual_zio_hash}"
        )

    files: dict[str, tuple[bytes, int]] = {}
    for prefix, repo in repositories.items():
        for relative, mode in tracked_files(repo):
            if prefix == "" and not is_published_root_path(relative):
                continue
            archive_relative = str(PurePosixPath(prefix, relative))
            data = (repo / relative).read_bytes()
            if prefix == "" and relative == "build.zig.zon":
                data = rewrite_package_manifest(data)
            if archive_relative in files:
                raise RuntimeError(f"duplicate archive path: {archive_relative}")
            files[archive_relative] = (data, mode)
    for relative, mode in package_files(zio.resolve()):
        archive_relative = str(PurePosixPath("deps/zio", relative))
        if archive_relative in files:
            raise RuntimeError(f"duplicate archive path: {archive_relative}")
        files[archive_relative] = ((zio / relative).read_bytes(), mode)
    file_hashes = {
        path: hashlib.sha256(data).hexdigest()
        for path, (data, _) in sorted(files.items())
    }
    files["RELEASE-MANIFEST.json"] = (
        release_manifest(
            package_version,
            revisions[""],
            revisions["deps/vail"],
            revisions["deps/vort"],
            revisions["deps/pbz"],
            revisions["deps/webpkiz"],
            revisions["deps/regexz"],
            revisions["deps/harnessz"],
            file_hashes,
        ),
        0o100644,
    )

    prefix = f"{PACKAGE_NAME}-{package_version}"
    directories = {prefix}
    for relative in files:
        parent = PurePosixPath(prefix, relative).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_output,
            mtime=0,
        ) as compressed:
            with tarfile.open(
                mode="w",
                fileobj=compressed,
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for directory in sorted(directories):
                    add_directory(archive, directory)
                for relative, (data, mode) in sorted(files.items()):
                    add_bytes(archive, f"{prefix}/{relative}", data, mode)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--vail", type=Path, required=True)
    parser.add_argument("--vort", type=Path, required=True)
    parser.add_argument("--pbz", type=Path, required=True)
    parser.add_argument("--webpkiz", type=Path, required=True)
    parser.add_argument("--regexz", type=Path, required=True)
    parser.add_argument("--zio", type=Path, required=True)
    parser.add_argument("--harnessz", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", default=DEFAULT_PACKAGE_VERSION)
    parser.add_argument("--zig", default="zig")
    args = parser.parse_args()
    create_archive(
        args.root,
        args.vail,
        args.vort,
        args.pbz,
        args.webpkiz,
        args.regexz,
        args.zio,
        args.harnessz,
        args.output,
        package_version=args.version,
        zig=args.zig,
    )


if __name__ == "__main__":
    main()

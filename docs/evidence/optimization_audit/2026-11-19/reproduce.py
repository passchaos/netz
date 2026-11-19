#!/usr/bin/env python3
"""Run review probes in a source copy, leaving production files untouched."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[4])
    parser.add_argument("--zig", default="zig")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    fixture = Path(__file__).resolve().parent
    cohort = Path(tempfile.mkdtemp(prefix="netz-optimization-review-"))
    isolated = cohort / "netz"
    isolated.mkdir()

    for directory in ("src", "build"):
        shutil.copytree(repo / directory, isolated / directory)
    for name in ("build.zig", "build.zig.zon"):
        shutil.copy2(repo / name, isolated / name)
    for name in ("tools", "examples", "test", "docs", "benchmarks", "zig-pkg"):
        if (repo / name).exists():
            (isolated / name).symlink_to(repo / name, target_is_directory=True)
    for name in ("harnessz", "kron", "vail", "vort", "webpkiz", "pbz", "regexz"):
        (cohort / name).symlink_to(repo.parent / name, target_is_directory=True)

    # Expose only the test entry point; do not alter its body or its sender.
    owner = isolated / "src/proxy/hysteria/shared/server.zig"
    source = owner.read_text()
    private_entry = "    fn flushRelayOutbound("
    if source.count(private_entry) != 1:
        raise RuntimeError("expected one private Hysteria relay drain entry")
    owner.write_text(source.replace(private_entry, "    pub fn flushRelayOutbound(", 1))
    shutil.copy2(fixture / "reproduction_tests.zig", isolated / "src/audit_review.zig")
    build = isolated / "build.zig"
    source = build.read_text()
    root_entry = 'b.path("src/root.zig")'
    if source.count(root_entry) != 1:
        raise RuntimeError("expected one library root registration")
    build.write_text(source.replace(root_entry, 'b.path("src/audit_review.zig")', 1))

    print(f"Isolated source: {isolated}", flush=True)
    print("Only visibility and the test root change in this copy.", flush=True)
    if args.prepare_only:
        return 0

    failed = False
    for probe, name in (
        ("audit review", "ownership-and-fractional-refill.log"),
        ("audit overflow", "overflow.log"),
        ("audit boundary", "packetization.log"),
    ):
        command = [
            args.zig, "build", "test-lib", f"-Dtest-filter={probe}",
            "--summary", "all", "--cache-dir", str(repo / ".zig-cache"),
        ]
        log = cohort / name
        with log.open("w") as output:
            result = subprocess.run(
                command, cwd=isolated, stdout=output, stderr=subprocess.STDOUT,
                timeout=180,
            )
        print(f"{probe}: exit={result.returncode}; log={log}", flush=True)
        failed |= result.returncode != 0
    print("At the audited baseline, the first two probes fail and the boundary probe passes.")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

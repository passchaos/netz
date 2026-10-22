"""Owned production broker processes for the Mosquitto wire gates."""

from __future__ import annotations

from pathlib import Path
import signal
import socket
import subprocess


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class NetzBroker:
    def __init__(
        self,
        executable: Path,
        connections: int = 1,
        ignore_errors: bool = False,
        restore: bool = False,
        extra_args: tuple[str, ...] = (),
    ):
        self.executable = executable
        self.connections = connections
        self.ignore_errors = ignore_errors
        self.restore = restore
        self.extra_args = extra_args
        self.port = free_port()
        self.process: subprocess.Popen[str] | None = None
        self.crashed = False

    def __enter__(self) -> "NetzBroker":
        command = [
            str(self.executable),
            f"--bind=127.0.0.1:{self.port}",
            f"--connections={self.connections}",
            "--max-queued-deliveries=1024",
            "--max-outgoing-inflight=64",
            "--connect-timeout-ms=5000",
            *self.extra_args,
        ]
        if not self.restore:
            command.append("--no-restore")
        if self.ignore_errors:
            command.append("--ignore-connection-errors")
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if "listening" not in line:
            raise RuntimeError(f"netz broker failed to start: {line.strip()}")
        return self

    def connect(self) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        sock.settimeout(5)
        return sock

    def crash(self) -> None:
        """Kill only this fixture's live broker and verify its crash boundary."""
        assert self.process is not None
        if self.process.poll() is not None:
            raise RuntimeError("cannot crash an already exited broker")
        self.process.kill()
        self.process.wait(timeout=5)
        if self.process.returncode != -signal.SIGKILL:
            raise RuntimeError(f"unexpected broker crash status: {self.process.returncode}")
        self.crashed = True

    def __exit__(self, exc_type, exc, traceback) -> None:
        assert self.process is not None
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=5)
            if exc_type is None:
                raise RuntimeError("netz broker did not exit after DISCONNECT")
        expected_returncode = -signal.SIGKILL if self.crashed else 0
        if exc_type is None and self.process.returncode != expected_returncode:
            assert self.process.stdout is not None
            raise RuntimeError(
                f"netz broker exited {self.process.returncode}: "
                + self.process.stdout.read()
            )

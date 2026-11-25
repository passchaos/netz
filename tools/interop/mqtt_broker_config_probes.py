"""Bounded observation for failed TLS/MQTT interoperability preconditions."""
import os
import socket
import time


def tls_peer_state(sock, phase, started):
    state = {"phase": phase, "age_ms": round((time.monotonic() - started) * 1000, 3)}
    try:
        state["tls_pending"] = sock.pending()
        if os.name != "posix" or not hasattr(socket, "MSG_DONTWAIT"):
            state["tcp"] = "unavailable"
            return state
        descriptor = os.dup(sock.fileno())
        try:
            raw = socket.socket(fileno=descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        try:
            try:
                peek = raw.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                state["tcp"] = "pending" if peek else "eof"
            except BlockingIOError:
                state["tcp"] = "idle"
        finally:
            raw.close()
    except (OSError, ValueError) as error:
        state["probe_error"] = str(error)
    return state


def buffered_process_output(process, limit=1024):
    descriptor = process.stdout.fileno()
    was_blocking = os.get_blocking(descriptor)
    os.set_blocking(descriptor, False)
    try:
        try:
            return process.stdout.read(limit) or ""
        except (BlockingIOError, OSError, TypeError):
            return ""
    finally:
        os.set_blocking(descriptor, was_blocking)

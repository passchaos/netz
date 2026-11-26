#!/usr/bin/env python3
"""Stream command logs and expose the last visible test in bounded annotations."""
import argparse
import codecs
import html
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import threading
import time


class Interrupted(BaseException):
    def __init__(self, signum):
        self.signum = signum


def interrupt(signum, _):
    raise Interrupted(signum)


def escape(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def run(command, log, title, interval):
    # Create the log before starting a child so a path error cannot orphan it.
    with Path(log).open("wb") as output:
        return stream(command, output, title, interval)


def stream(command, output, title, interval):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    chunks = queue.Queue(maxsize=16)

    def read():
        try:
            while True:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                chunks.put(chunk)
        finally:
            chunks.put(None)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.monotonic() + interval
    recent = ""
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    last_test = "No test name emitted yet; build or startup is still active."

    def summary():
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if path:
            last_output = recent.splitlines()[-1][-2000:] if recent else "No command output yet."
            Path(path).write_text("### " + html.escape(title) + "\n\n<pre>" + html.escape(last_test) + "\n\nLast command output:\n" + html.escape(last_output) + "</pre>\n", encoding="utf-8")

    def notice(update_summary=True):
        if update_summary:
            summary()
        property_title = escape(title).replace(",", "%2C").replace(":", "%3A")
        # Test names are printed before their result without a newline. Actions
        # commands must begin a new line to become annotations.
        # Public Actions annotations display the step name in place of the
        # custom title. Keep invocation ownership in the visible message too.
        line = "\n::notice title=" + property_title + "::" + escape(title + ": " + last_test) + "\n"
        sys.stdout.buffer.write(line.encode("utf-8"))
        sys.stdout.buffer.flush()

    try:
        # Even a command admitted near the step's timeout must identify itself
        # before its first periodic notice. Do not write the optional summary
        # until the child has had a chance to produce output.
        notice(update_summary=False)
        while True:
            try:
                chunk = chunks.get(timeout=max(0.001, deadline - time.monotonic()))
            except queue.Empty:
                notice()
                deadline = time.monotonic() + interval
                continue
            if chunk is None:
                break
            output.write(chunk)
            output.flush()
            decoded = decoder.decode(chunk)
            # Do not insert an annotation inside a split UTF-8 code point.
            # The log keeps the exact bytes; console output uses complete text.
            sys.stdout.buffer.write(decoded.encode("utf-8"))
            sys.stdout.buffer.flush()
            recent = (recent + decoded)[-8192:]
            matches = list(re.finditer(r"(?:^|\n)(\d+/\d+ [^\r\n]{1,2000})", recent))
            if matches:
                last_test = matches[-1].group(1)
            if time.monotonic() >= deadline:
                notice()
                deadline = time.monotonic() + interval
    except BaseException as err:
        # A second CLI interrupt must not unwind child cleanup. Preserve the
        # first failure/signal while this command wrapper finishes teardown.
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        # Drain the bounded queue so a blocked reader can finish its final put.
        while reader.is_alive():
            try:
                if chunks.get(timeout=1) is None:
                    break
            except queue.Empty:
                pass
        reader.join()
        process.stdout.close()
        # Child cleanup must finish even if the optional summary/console fails.
        summary()
        if isinstance(err, Interrupted):
            property_title = escape(title).replace(",", "%2C").replace(":", "%3A")
            last_output = recent.splitlines()[-1][-2000:] if recent else "No command output yet."
            line = "\n::error title=" + property_title + "::" + escape("Interrupted command [" + title + "]; last visible test: " + last_test + "; last output: " + last_output) + "\n"
            sys.stdout.buffer.write(line.encode("utf-8"))
            sys.stdout.buffer.flush()
        raise
    reader.join()
    process.stdout.close()
    sys.stdout.buffer.write(decoder.decode(b"", final=True).encode("utf-8"))
    sys.stdout.buffer.flush()
    status = process.wait()
    summary()
    if status:
        notice()
    return status if status >= 0 else 128 - status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True)
    parser.add_argument("--title", default="Test progress")
    parser.add_argument("--interval", type=float, default=60)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.interval <= 0:
        parser.error("a command and positive annotation interval are required")
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        return run(command, args.log, args.title, args.interval)
    except Interrupted as err:
        return 128 + err.signum


if __name__ == "__main__":
    sys.exit(main())

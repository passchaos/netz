#!/usr/bin/env python3
"""Stream command logs and expose the last visible test in bounded annotations."""
import argparse
import codecs
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time


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

    def notice():
        property_title = escape(title).replace(",", "%2C").replace(":", "%3A")
        # Test names are printed before their result without a newline. Actions
        # commands must begin a new line to become annotations.
        line = "\n::notice title=" + property_title + "::" + escape(last_test) + "\n"
        sys.stdout.buffer.write(line.encode("utf-8"))
        sys.stdout.buffer.flush()

    try:
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
    except BaseException:
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
        raise
    reader.join()
    process.stdout.close()
    sys.stdout.buffer.write(decoder.decode(b"", final=True).encode("utf-8"))
    sys.stdout.buffer.flush()
    status = process.wait()
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
    return run(command, args.log, args.title, args.interval)


if __name__ == "__main__":
    sys.exit(main())

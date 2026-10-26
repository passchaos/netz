#!/usr/bin/env python3
"""Independent HTTP/2 peer and pinned official grpc-js response-policy probe."""
from pathlib import Path
import subprocess
import sys


def main():
    client = Path(__file__).with_name("grpc_response")
    if not (client / "node_modules/@grpc/grpc-js").exists():
        subprocess.run(["npm", "ci", "--prefix", str(client), "--ignore-scripts", "--no-audit", "--no-fund"], check=True)
    subprocess.run(["node", str(client / "client.js"), sys.argv[1]], check=True, timeout=60)


if __name__ == "__main__":
    main()

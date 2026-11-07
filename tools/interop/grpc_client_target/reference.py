#!/usr/bin/env python3
"""One fresh gRPC C-Core channel; all target parsing stays inside C-Core."""
import argparse
import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sys

import grpc
import grpc._cython.cygrpc as cygrpc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--default-authority")
    parser.add_argument("--metadata-only", action="store_true")
    args = parser.parse_args()
    if grpc.__version__ != "1.76.0":
        raise RuntimeError(f"Expected grpcio 1.76.0; got {grpc.__version__}")
    extensions = importlib.metadata.version("typing_extensions")
    if extensions != "4.15.0":
        raise RuntimeError(f"Expected typing_extensions 4.15.0; got {extensions}")
    if sys.prefix == sys.base_prefix:
        raise RuntimeError("The reference must run in a dedicated virtual environment")
    core = Path(cygrpc.__file__).resolve()
    dependency_hashes = {}
    for distribution_name in ("grpcio", "typing_extensions"):
        distribution = importlib.metadata.distribution(distribution_name)
        for file in distribution.files or ():
            if str(file).endswith((".py", ".so", ".pyd", "/METADATA", "/WHEEL", "/RECORD")):
                actual = Path(distribution.locate_file(file))
                dependency_hashes[str(file)] = hashlib.sha256(actual.read_bytes()).hexdigest()
    result = {
        "grpcio": grpc.__version__, "typing_extensions": extensions,
        "python": platform.python_version(), "core_extension": str(core),
        "core_sha256": hashlib.sha256(core.read_bytes()).hexdigest(),
        "dependency_sha256": dependency_hashes,
    }
    if args.metadata_only:
        print(json.dumps(result))
        return
    options = []
    if args.default_authority is not None:
        options.append(("grpc.default_authority", args.default_authority))
    with grpc.insecure_channel(args.target, options=options) as channel:
        unary = channel.unary_unary("/fixture.Target/Unary")
        try:
            response = unary(b"target-probe", timeout=args.timeout, wait_for_ready=False)
            result.update(status="ok", response_base64=base64.b64encode(response).decode("ascii"))
        except grpc.RpcError as error:
            result.update(status="error", code=error.code().name, details=error.details())
    print(json.dumps(result))


if __name__ == "__main__":
    main()

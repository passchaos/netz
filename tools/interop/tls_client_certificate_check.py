#!/usr/bin/env python3
"""Verify the actual incoming client Certificate in an OpenSSL -msg trace."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import re

HEADER = re.compile(r"^<<< TLS (1\.[23]), Handshake \[length ([0-9a-fA-F]+)\], (Certificate|CertificateVerify|Finished)$")
HEX = re.compile(r"^\s+(?:[0-9a-fA-F]{2}(?:\s+|$))+$")

def messages(text: str) -> list[tuple[str, str, bytes]]:
    lines = text.splitlines()
    result = []
    index = 0
    while index < len(lines):
        header = HEADER.fullmatch(lines[index].strip())
        index += 1
        if header is None:
            continue
        data = []
        while index < len(lines) and HEX.fullmatch(lines[index]):
            data.extend(lines[index].split())
            index += 1
        payload = bytes.fromhex("".join(data))
        expected_kind = {"Certificate": 11, "CertificateVerify": 15, "Finished": 20}[header[3]]
        if len(payload) != int(header[2], 16) or len(payload) < 4 or payload[0] != expected_kind or int.from_bytes(payload[1:4], "big") != len(payload) - 4:
            raise ValueError("malformed incoming " + header[3])
        result.append((header[1], header[3], payload[4:]))
    return result

def check(text: str, protocol: str, present: bool, certificate: bytes) -> dict:
    version = {"tls12": "1.2", "tls13": "1.3"}[protocol]
    entries = messages(text)
    if any(value[0] != version for value in entries):
        raise ValueError("unexpected handshake protocol")
    certs = [value[2] for value in entries if value[1] == "Certificate"]
    verifies = [value[2] for value in entries if value[1] == "CertificateVerify"]
    finished = [value[2] for value in entries if value[1] == "Finished"]
    if len(certs) != 1 or len(verifies) != int(present) or len(finished) != 1:
        raise ValueError("unexpected client handshake message counts")
    if len(finished[0]) != (12 if protocol == "tls12" else 32):
        raise ValueError("invalid Finished length for the configured suite")
    body = certs[0]
    if protocol == "tls13":
        if not body or body[0] != 0:
            raise ValueError("nonempty initial Certificate context")
        body = body[1:]
    if len(body) < 3 or int.from_bytes(body[:3], "big") != len(body) - 3:
        raise ValueError("invalid certificate list length")
    body = body[3:]
    chain = []
    while body:
        if len(body) < 3:
            raise ValueError("truncated certificate entry")
        length = int.from_bytes(body[:3], "big")
        if length == 0 or len(body) < 3 + length:
            raise ValueError("invalid certificate entry")
        chain.append(body[3:3 + length])
        body = body[3 + length:]
        if protocol == "tls13":
            if len(body) < 2:
                raise ValueError("truncated certificate extensions")
            length = int.from_bytes(body[:2], "big")
            if len(body) < 2 + length:
                raise ValueError("invalid certificate extensions")
            body = body[2 + length:]
    if len(chain) != int(present) or (present and chain[0] != certificate):
        raise ValueError("unexpected client certificate identity")
    if present:
        signature = verifies[0]
        if len(signature) < 4 or int.from_bytes(signature[:2], "big") != 0x0403 or int.from_bytes(signature[2:4], "big") != len(signature) - 4 or len(signature) == 4:
            raise ValueError("invalid ECDSA CertificateVerify")
    return {"protocol": protocol, "client_certificate": "present" if present else "absent", "certificate_count": len(chain), "certificate_verify": present, "finished": True}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("protocol", choices=("tls12", "tls13"))
    parser.add_argument("expectation", choices=("present", "absent"))
    parser.add_argument("certificate", type=Path)
    args = parser.parse_args()
    encoded = args.certificate.read_text().split("-----BEGIN CERTIFICATE-----", 1)[1].split("-----END CERTIFICATE-----", 1)[0]
    certificate = base64.b64decode("".join(encoded.split()), validate=True)
    print(json.dumps(check(args.log.read_text(), args.protocol, args.expectation == "present", certificate), sort_keys=True))

if __name__ == "__main__":
    main()

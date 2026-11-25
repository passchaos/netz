#!/usr/bin/env python3
import unittest
from tls_client_certificate_check import check

def message(protocol, kind, body):
    payload = bytes([{"Certificate": 11, "CertificateVerify": 15, "Finished": 20}[kind]]) + len(body).to_bytes(3, "big") + body
    return "<<< TLS " + ("1.2" if protocol == "tls12" else "1.3") + ", Handshake [length " + format(len(payload), "04x") + "], " + kind + "\n    " + payload.hex(" ") + "\n"

def trace(protocol, certificate=b"cert", verify=True):
    entry = len(certificate).to_bytes(3, "big") + certificate if certificate else b""
    if certificate and protocol == "tls13": entry += b"\x00\x00"
    body = len(entry).to_bytes(3, "big") + entry
    if protocol == "tls13": body = b"\x00" + body
    value = message(protocol, "Certificate", body)
    if verify: value += message(protocol, "CertificateVerify", b"\x04\x03\x00\x01x")
    return value + message(protocol, "Finished", b"x" * (12 if protocol == "tls12" else 32))

class CheckTest(unittest.TestCase):
    def test_matching_and_empty_chains_in_both_protocols(self):
        for protocol in ("tls12", "tls13"):
            self.assertEqual(1, check(trace(protocol), protocol, True, b"cert")["certificate_count"])
            self.assertEqual(0, check(trace(protocol, b"", False), protocol, False, b"cert")["certificate_count"])

    def test_changed_identity_is_rejected(self):
        with self.assertRaises(ValueError): check(trace("tls13", b"other"), "tls13", True, b"cert")

    def test_missing_verify_is_rejected(self):
        with self.assertRaises(ValueError): check(trace("tls12", verify=False), "tls12", True, b"cert")

    def test_unmatched_identity_cannot_have_verify(self):
        with self.assertRaises(ValueError): check(trace("tls13", b"", True), "tls13", False, b"cert")

    def test_duplicate_certificate_is_rejected(self):
        value = trace("tls12")
        with self.assertRaises(ValueError): check(value + value, "tls12", True, b"cert")

    def test_protocol_and_wire_length_are_checked(self):
        with self.assertRaises(ValueError): check(trace("tls12"), "tls13", True, b"cert")
        with self.assertRaises(ValueError): check(trace("tls13").replace("length 0011", "length 0012", 1), "tls13", True, b"cert")

if __name__ == "__main__": unittest.main()

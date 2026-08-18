//! Deterministic localhost TLS identity for transport tests and benchmarks.
//!
//! Production callers provide their own certificate chain and signer. Keeping
//! this identity in the TLS namespace lets HTTP/WebSocket/MQTT tests share real
//! encrypted handshakes without introducing protocol-layer dependencies.

const std = @import("std");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// The matching private key is the deterministic scalar in `serverKeyPair`.
// The certificate is valid from 2026-01-01 through 2036-01-01 and contains a
// localhost DNS SAN. Keeping it DER/base64 avoids filesystem fixtures.
pub const certificate_base64 =
    "MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=";
pub const certificate_der_len: usize = 308;

pub fn serverKeyPair() !EcdsaP256Sha256.KeyPair {
    const secret = try EcdsaP256Sha256.SecretKey.fromBytes(.{
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1,
        0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34,
    });
    return EcdsaP256Sha256.KeyPair.fromSecretKey(secret);
}

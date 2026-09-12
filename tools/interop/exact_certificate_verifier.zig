//! Exact-certificate verifier for external interop fixtures that expose one
//! self-signed endpoint certificate instead of a CA-signed leaf. This helper
//! is intentionally tool-local; production APIs use Vail's bundle verifier.

const std = @import("std");
const netz = @import("netz");

pub const Verifier = struct {
    certificate_der: []const u8,
    now_seconds: i64,

    pub fn init(
        bundle: *const std.crypto.Certificate.Bundle,
        now_seconds: i64,
    ) !Verifier {
        if (bundle.map.count() != 1 or bundle.bytes.items.len == 0) {
            return error.InvalidCertificate;
        }
        const element = try std.crypto.Certificate.der.Element.parse(
            bundle.bytes.items,
            0,
        );
        if (element.slice.end != bundle.bytes.items.len) {
            return error.InvalidCertificate;
        }
        return .{
            .certificate_der = bundle.bytes.items,
            .now_seconds = now_seconds,
        };
    }

    pub fn clientVerifier(self: *const Verifier) netz.quic.tls.auth.ClientVerifier {
        return .{
            .verify_trust = verifyTrust,
            .context = @ptrCast(@constCast(self)),
        };
    }

    fn verifyTrust(
        context: ?*anyopaque,
        trust: netz.quic.tls.auth.TrustContext,
    ) anyerror!void {
        const self: *const Verifier = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        if (trust.chain.len != 1 or
            !std.mem.eql(u8, trust.chain[0], self.certificate_der))
        {
            return error.CertificateUntrusted;
        }
        const certificate = try std.crypto.Certificate.parse(.{
            .buffer = trust.chain[0],
            .index = 0,
        });
        try certificate.verifyHostName(
            trust.server_name orelse return error.MissingServerName,
        );
        if (self.now_seconds < certificate.validity.not_before) {
            return error.CertificateNotYetValid;
        }
        if (self.now_seconds > certificate.validity.not_after) {
            return error.CertificateExpired;
        }
    }
};

test "interop exact certificate verifier checks DER hostname and validity" {
    const allocator = std.testing.allocator;
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &certificate_der);
    try bundle.parseCert(allocator, 0, 1_900_000_000);
    var verifier = try Verifier.init(&bundle, 1_900_000_000);
    try verifier.clientVerifier().verifyTrust(
        "localhost",
        &.{&certificate_der},
    );
    var corrupted = certificate_der;
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.clientVerifier().verifyTrust(
            "localhost",
            &.{&corrupted},
        ),
    );
    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.clientVerifier().verifyTrust(
            "localhost",
            &.{ &certificate_der, &certificate_der },
        ),
    );
    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.clientVerifier().verifyTrust(
            "other.example",
            &.{&certificate_der},
        ),
    );
    verifier.now_seconds = 1;
    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.clientVerifier().verifyTrust(
            "localhost",
            &.{&certificate_der},
        ),
    );
}

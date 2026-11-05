const std = @import("std");
const sds = @import("../sds.zig");
const fixture = @import("testing.zig");
const gpa = std.testing.allocator;

test "gRPC SDS decodes an inline TLS certificate secret" {
    const bytes = try fixture.tlsSecret(gpa, "cert-1", "CERTIFICATE", "PRIVATE KEY");
    defer gpa.free(bytes);
    var owned = try sds.decode(gpa, bytes, .{});
    defer owned.deinit();
    try std.testing.expectEqualStrings("cert-1", owned.value.name);
    const certificate = owned.value.kind.tls_certificate;
    try std.testing.expectEqualStrings("CERTIFICATE", certificate.certificate_chain);
    try std.testing.expectEqualStrings("PRIVATE KEY", certificate.private_key);
    const config = owned.value.tlsConfig();
    try std.testing.expectEqualStrings("CERTIFICATE", config.certificate_chain);
    try std.testing.expectEqualStrings("PRIVATE KEY", config.private_key);
    try std.testing.expectEqualStrings("", config.trusted_ca);
}

test "gRPC SDS decodes a validation context with SAN matchers" {
    const bytes = try fixture.validationSecret(gpa, "roots", "CA BUNDLE", &.{
        .{ .kind = .exact, .value = "backend.test" },
        .{ .kind = .prefix, .value = "spiffe://", .ignore_case = true },
        .{ .kind = .suffix, .value = ".internal" },
        .{ .kind = .contains, .value = "trusted" },
    });
    defer gpa.free(bytes);
    var owned = try sds.decode(gpa, bytes, .{});
    defer owned.deinit();
    try std.testing.expectEqualStrings("roots", owned.value.name);
    const validation = owned.value.kind.validation_context;
    try std.testing.expectEqualStrings("CA BUNDLE", validation.trusted_ca);
    try std.testing.expectEqual(@as(usize, 4), validation.san_matchers.len);
    try std.testing.expectEqual(.exact, validation.san_matchers[0].kind);
    try std.testing.expectEqualStrings("backend.test", validation.san_matchers[0].value);
    try std.testing.expectEqual(.prefix, validation.san_matchers[1].kind);
    try std.testing.expect(validation.san_matchers[1].ignore_case);
    try std.testing.expectEqual(.suffix, validation.san_matchers[2].kind);
    try std.testing.expectEqual(.contains, validation.san_matchers[3].kind);
    const config = owned.value.tlsConfig();
    try std.testing.expectEqualStrings("CA BUNDLE", config.trusted_ca);
    try std.testing.expectEqual(@as(usize, 4), config.san_matchers.?.len);
}

test "gRPC SDS accepts inline_string data sources" {
    var certificate = fixture.Builder{ .allocator = gpa };
    defer certificate.deinit();
    var chain = fixture.Builder{ .allocator = gpa };
    defer chain.deinit();
    try chain.bytes(2, "CERTIFICATE");
    var key = fixture.Builder{ .allocator = gpa };
    defer key.deinit();
    try key.bytes(2, "PRIVATE KEY");
    try certificate.bytes(1, chain.data.items);
    try certificate.bytes(2, key.data.items);
    var secret = fixture.Builder{ .allocator = gpa };
    defer secret.deinit();
    try secret.bytes(1, "cert-1");
    try secret.bytes(2, certificate.data.items);
    var owned = try sds.decode(gpa, secret.data.items, .{});
    defer owned.deinit();
    const value = owned.value.kind.tls_certificate;
    try std.testing.expectEqualStrings("CERTIFICATE", value.certificate_chain);
    try std.testing.expectEqualStrings("PRIVATE KEY", value.private_key);
}

test "gRPC SDS rejects malformed and unsupported secrets" {
    // Missing name.
    var no_name = fixture.Builder{ .allocator = gpa };
    defer no_name.deinit();
    var certificate = fixture.Builder{ .allocator = gpa };
    defer certificate.deinit();
    var chain = fixture.Builder{ .allocator = gpa };
    defer chain.deinit();
    try chain.bytes(1, "CERTIFICATE");
    var key = fixture.Builder{ .allocator = gpa };
    defer key.deinit();
    try key.bytes(1, "PRIVATE KEY");
    try certificate.bytes(1, chain.data.items);
    try certificate.bytes(2, key.data.items);
    try no_name.bytes(2, certificate.data.items);
    try std.testing.expectError(error.InvalidSdsResource, sds.decode(gpa, no_name.data.items, .{}));

    // No kind.
    var no_kind = fixture.Builder{ .allocator = gpa };
    defer no_kind.deinit();
    try no_kind.bytes(1, "secret");
    try std.testing.expectError(error.InvalidSdsResource, sds.decode(gpa, no_kind.data.items, .{}));

    // Both kinds.
    var both = fixture.Builder{ .allocator = gpa };
    defer both.deinit();
    try both.bytes(1, "secret");
    try both.bytes(2, certificate.data.items);
    try both.bytes(3, "");
    try std.testing.expectError(error.InvalidSdsResource, sds.decode(gpa, both.data.items, .{}));

    // Generic secret is not a TLS secret.
    var generic = fixture.Builder{ .allocator = gpa };
    defer generic.deinit();
    try generic.bytes(1, "secret");
    try generic.bytes(4, "opaque");
    try std.testing.expectError(error.UnsupportedSdsFeature, sds.decode(gpa, generic.data.items, .{}));

    // Missing private key.
    var missing_key = fixture.Builder{ .allocator = gpa };
    defer missing_key.deinit();
    try missing_key.bytes(1, "secret");
    var only_chain = fixture.Builder{ .allocator = gpa };
    defer only_chain.deinit();
    try only_chain.bytes(1, chain.data.items);
    try missing_key.bytes(2, only_chain.data.items);
    try std.testing.expectError(error.InvalidSdsResource, sds.decode(gpa, missing_key.data.items, .{}));

    // File-backed data sources belong to bootstrap providers.
    var file_source = fixture.Builder{ .allocator = gpa };
    defer file_source.deinit();
    var chain_with_file = fixture.Builder{ .allocator = gpa };
    defer chain_with_file.deinit();
    var file = fixture.Builder{ .allocator = gpa };
    defer file.deinit();
    try file.bytes(3, "/etc/cert.pem");
    try chain_with_file.bytes(1, file.data.items);
    try chain_with_file.bytes(2, key.data.items);
    try file_source.bytes(1, "secret");
    try file_source.bytes(2, chain_with_file.data.items);
    try std.testing.expectError(error.UnsupportedSdsFeature, sds.decode(gpa, file_source.data.items, .{}));

    // Encrypted keys and OCSP staples are not represented by tls_material.
    var password = fixture.Builder{ .allocator = gpa };
    defer password.deinit();
    var cert_with_password = fixture.Builder{ .allocator = gpa };
    defer cert_with_password.deinit();
    try cert_with_password.bytes(1, chain.data.items);
    try cert_with_password.bytes(2, key.data.items);
    try cert_with_password.bytes(3, chain.data.items);
    try password.bytes(1, "secret");
    try password.bytes(2, cert_with_password.data.items);
    try std.testing.expectError(error.UnsupportedSdsFeature, sds.decode(gpa, password.data.items, .{}));

    // Missing trust bundle.
    var no_ca = fixture.Builder{ .allocator = gpa };
    defer no_ca.deinit();
    try no_ca.bytes(1, "secret");
    try no_ca.bytes(3, "");
    try std.testing.expectError(error.InvalidSdsResource, sds.decode(gpa, no_ca.data.items, .{}));

    // Expired-certificate acceptance changes verification semantics.
    var allow_expired = fixture.Builder{ .allocator = gpa };
    defer allow_expired.deinit();
    var expired_validation = fixture.Builder{ .allocator = gpa };
    defer expired_validation.deinit();
    var trusted = fixture.Builder{ .allocator = gpa };
    defer trusted.deinit();
    try trusted.bytes(1, "CA");
    try expired_validation.bytes(1, trusted.data.items);
    try expired_validation.number(6, 1);
    try allow_expired.bytes(1, "secret");
    try allow_expired.bytes(3, expired_validation.data.items);
    try std.testing.expectError(error.UnsupportedSdsFeature, sds.decode(gpa, allow_expired.data.items, .{}));

    // A truncated resource never decodes partially.
    try std.testing.expectError(error.TruncatedMessage, sds.decode(gpa, &.{ 0x0a, 0x7f }, .{}));
}

test "gRPC SDS enforces byte, text and SAN limits" {
    const bytes = try fixture.tlsSecret(gpa, "cert-1", "CERTIFICATE", "PRIVATE KEY");
    defer gpa.free(bytes);
    try std.testing.expectError(error.SdsLimitExceeded, sds.decode(gpa, bytes, .{ .max_bytes = bytes.len - 1 }));
    try std.testing.expectError(error.SdsLimitExceeded, sds.decode(gpa, bytes, .{ .max_text_bytes = 3 }));

    var sans: [3]fixture.SanSpec = undefined;
    for (&sans) |*value| value.* = .{ .kind = .exact, .value = "host" };
    const validation = try fixture.validationSecret(gpa, "roots", "CA", &sans);
    defer gpa.free(validation);
    try std.testing.expectError(error.SdsLimitExceeded, sds.decode(gpa, validation, .{ .max_san_matchers = 2 }));
    var owned = try sds.decode(gpa, validation, .{ .max_san_matchers = 3 });
    defer owned.deinit();
    try std.testing.expectEqual(@as(usize, 3), owned.value.kind.validation_context.san_matchers.len);
}

test "gRPC SDS decodes certificate hash pins" {
    const hash = [_]u8{0xab} ** 32;
    const bytes = try fixture.validationSecretHashes(gpa, "roots", "CA BUNDLE", &.{}, &.{hash});
    defer gpa.free(bytes);
    var owned = try sds.decode(gpa, bytes, .{});
    defer owned.deinit();
    const validation = owned.value.kind.validation_context;
    try std.testing.expectEqual(@as(usize, 1), validation.verify_certificate_hashes.len);
    try std.testing.expectEqualSlices(u8, &hash, &validation.verify_certificate_hashes[0]);
    const config = owned.value.tlsConfig();
    try std.testing.expectEqual(@as(usize, 1), config.verify_certificate_hashes.?.len);

    var invalid = fixture.Builder{ .allocator = gpa };
    defer invalid.deinit();
    try invalid.bytes(1, "roots");
    var validation_message = fixture.Builder{ .allocator = gpa };
    defer validation_message.deinit();
    var trusted = fixture.Builder{ .allocator = gpa };
    defer trusted.deinit();
    try trusted.bytes(1, "CA");
    try validation_message.bytes(1, trusted.data.items);
    try validation_message.bytes(4, "zz");
    try invalid.bytes(3, validation_message.data.items);
    try std.testing.expectError(error.InvalidSdsResource, sds.decode(gpa, invalid.data.items, .{}));
}

test "gRPC SDS decodes SPKI pins" {
    const spki = [_]u8{0xcd} ** 32;
    const bytes = try fixture.validationSecretPins(gpa, "roots", "CA BUNDLE", &.{}, &.{}, &.{spki});
    defer gpa.free(bytes);
    var owned = try sds.decode(gpa, bytes, .{});
    defer owned.deinit();
    const validation = owned.value.kind.validation_context;
    try std.testing.expectEqual(@as(usize, 1), validation.verify_certificate_spkis.len);
    try std.testing.expectEqualSlices(u8, &spki, &validation.verify_certificate_spkis[0]);

    var invalid = fixture.Builder{ .allocator = gpa };
    defer invalid.deinit();
    try invalid.bytes(1, "roots");
    var validation_message = fixture.Builder{ .allocator = gpa };
    defer validation_message.deinit();
    var trusted = fixture.Builder{ .allocator = gpa };
    defer trusted.deinit();
    try trusted.bytes(1, "CA");
    try validation_message.bytes(1, trusted.data.items);
    try validation_message.bytes(5, "!!");
    try invalid.bytes(3, validation_message.data.items);
    try std.testing.expectError(error.InvalidSdsResource, sds.decode(gpa, invalid.data.items, .{}));
}

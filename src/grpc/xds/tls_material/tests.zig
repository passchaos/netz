const std = @import("std");
const tls_material_root = @import("../tls_material.zig");

const builtin = @import("builtin");
const vail = @import("vail");

const Material = tls_material_root.Material;
const certificateSpki = tls_material_root.certificateSpki;
const formatIp = tls_material_root.formatIp;
const sanSequence = tls_material_root.sanSequence;

test "xDS TLS SAN matchers accept and reject leaf names" {
    const tls_testing = @import("../../../tls/testing.zig");
    const allocator = std.testing.allocator;
    const pem = try std.fmt.allocPrint(allocator, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer allocator.free(pem);
    var der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&der, tls_testing.certificate_base64);
    const leaf = try std.crypto.Certificate.parse(.{ .buffer = &der, .index = 0 });
    var matching = try Material.create(allocator, std.testing.io, .{ .trusted_ca = pem, .san_matchers = &.{.{ .kind = .exact, .value = "localhost" }} });
    defer matching.deinit();
    try matching.checkSans(leaf.subjectAltName());
    var rejecting = try Material.create(allocator, std.testing.io, .{ .trusted_ca = pem, .san_matchers = &.{.{ .kind = .exact, .value = "other" }} });
    defer rejecting.deinit();
    try std.testing.expectError(error.CertificateHostMismatch, rejecting.checkSans(leaf.subjectAltName()));
}

test "xDS TLS certificate hash pins accept and reject the peer chain" {
    const tls_testing = @import("../../../tls/testing.zig");
    const allocator = std.testing.allocator;
    const pem = try std.fmt.allocPrint(allocator, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer allocator.free(pem);
    var der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&der, tls_testing.certificate_base64);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&der, &digest, .{});
    const trust: vail.tls.auth.TrustContext = .{ .server_name = "localhost", .chain = &.{&der} };
    var matching = try Material.create(allocator, std.testing.io, .{ .trusted_ca = pem, .verify_certificate_hashes = &.{digest} });
    defer matching.deinit();
    try Material.verifySanTrust(matching, trust);
    var wrong = digest;
    wrong[0] ^= 0xff;
    var rejecting = try Material.create(allocator, std.testing.io, .{ .trusted_ca = pem, .verify_certificate_hashes = &.{wrong} });
    defer rejecting.deinit();
    try std.testing.expectError(error.CertificateUntrusted, Material.verifySanTrust(rejecting, trust));
}

test "xDS TLS SPKI pins accept and reject the peer chain" {
    const tls_testing = @import("../../../tls/testing.zig");
    const allocator = std.testing.allocator;
    const pem = try std.fmt.allocPrint(allocator, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer allocator.free(pem);
    var der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&der, tls_testing.certificate_base64);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(certificateSpki(&der).?, &digest, .{});
    const trust: vail.tls.auth.TrustContext = .{ .server_name = "localhost", .chain = &.{&der} };
    var matching = try Material.create(allocator, std.testing.io, .{ .trusted_ca = pem, .verify_certificate_spkis = &.{digest} });
    defer matching.deinit();
    try Material.verifySanTrust(matching, trust);
    var wrong = digest;
    wrong[0] ^= 0xff;
    var rejecting = try Material.create(allocator, std.testing.io, .{ .trusted_ca = pem, .verify_certificate_spkis = &.{wrong} });
    defer rejecting.deinit();
    try std.testing.expectError(error.CertificateUntrusted, Material.verifySanTrust(rejecting, trust));
}

test "xDS TLS platform root certs install a verifier" {
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
    var material = try Material.create(std.testing.allocator, std.testing.io, .{
        .server_name = "example.com",
        .platform_root_certs = true,
    });
    defer material.deinit();
    const options = material.options();
    try std.testing.expect(options.server_verifier != null);
}

test "xDS TLS hash-only verification uses the platform trust store" {
    const allocator = std.testing.allocator;
    var material = try Material.create(allocator, std.testing.io, .{
        .verify_certificate_hashes = &.{.{0x11} ** 32},
    });
    defer material.deinit();
    try std.testing.expect(material.bundle_loaded);
    try std.testing.expect(material.bundle.map.count() != 0);
}

test "xDS TLS system root certs load the platform trust store" {
    const allocator = std.testing.allocator;
    var material = try Material.create(allocator, std.testing.io, .{
        .system_root_certs = true,
    });
    defer material.deinit();
    try std.testing.expect(material.bundle_loaded);
    try std.testing.expect(material.bundle.map.count() != 0);
}

test "xDS typed SAN matchers restrict by type and format IP addresses" {
    const tls_testing = @import("../../../tls/testing.zig");
    const allocator = std.testing.allocator;
    const pem = try std.fmt.allocPrint(allocator, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer allocator.free(pem);

    const ipv4 = [_]u8{ 192, 168, 1, 10 };
    const ipv6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var buffer: [128]u8 = undefined;
    const ipv4_san = sanSequence(&buffer, &.{.{ .tag = 0x87, .value = &ipv4 }});
    var material = try Material.create(allocator, std.testing.io, .{
        .trusted_ca = pem,
        .san_matchers = &.{.{ .kind = .exact, .value = "192.168.1.10", .san_type = .ip }},
    });
    defer material.deinit();
    try material.checkSans(ipv4_san);

    var wrong_type = try Material.create(allocator, std.testing.io, .{
        .trusted_ca = pem,
        .san_matchers = &.{.{ .kind = .exact, .value = "192.168.1.10", .san_type = .dns }},
    });
    defer wrong_type.deinit();
    try std.testing.expectError(error.CertificateHostMismatch, wrong_type.checkSans(ipv4_san));

    var legacy = try Material.create(allocator, std.testing.io, .{
        .trusted_ca = pem,
        .san_matchers = &.{.{ .kind = .exact, .value = "192.168.1.10" }},
    });
    defer legacy.deinit();
    try std.testing.expectError(error.CertificateHostMismatch, legacy.checkSans(ipv4_san));

    const ipv6_san = sanSequence(&buffer, &.{.{ .tag = 0x87, .value = &ipv6 }});
    var ipv6_material = try Material.create(allocator, std.testing.io, .{
        .trusted_ca = pem,
        .san_matchers = &.{.{ .kind = .exact, .value = "2001:db8::1", .san_type = .ip }},
    });
    defer ipv6_material.deinit();
    try ipv6_material.checkSans(ipv6_san);

    const dns_san = sanSequence(&buffer, &.{.{ .tag = 0x82, .value = "backend.test" }});
    var dns_material = try Material.create(allocator, std.testing.io, .{
        .trusted_ca = pem,
        .san_matchers = &.{.{ .kind = .exact, .value = "backend.test", .san_type = .dns }},
    });
    defer dns_material.deinit();
    try dns_material.checkSans(dns_san);
    try std.testing.expectError(error.CertificateHostMismatch, wrong_type.checkSans(dns_san));
}

test "xDS IPv6 SAN formatting compresses zero runs" {
    var out: [39]u8 = undefined;
    try std.testing.expectEqualStrings("::", formatIp(&[_]u8{0} ** 16, &out).?);
    try std.testing.expectEqualStrings("2001:db8::1", formatIp(&[_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &out).?);
    try std.testing.expectEqualStrings("1:2:3:4:5:6:7:8", formatIp(&[_]u8{ 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 }, &out).?);
    try std.testing.expectEqualStrings("::1", formatIp(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &out).?);
    // Equal-length zero runs compress the first one (RFC 5952).
    try std.testing.expectEqualStrings("2001:db8::1:0:0:1", formatIp(&[_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1 }, &out).?);
    try std.testing.expect(formatIp(&[_]u8{ 1, 2, 3 }, &out) == null);
}

const std = @import("std");
const resource = @import("decode.zig");
const policy = @import("policy.zig");
const fixture = @import("testing.zig");
const tls_testing = @import("../../../tls/testing.zig");
const gpa = std.testing.allocator;
const prefix = "type.googleapis.com/envoy.extensions.load_balancing_policies.";

test "gRPC CDS owns EDS identity defaults and first DEFAULT circuit threshold" {
    var limits = fixture.Builder{ .allocator = gpa };
    defer limits.deinit();
    try limits.bytes(1, "\x08\x01\x22\x02\x08\x01"); // HIGH limit 1
    try limits.bytes(1, "\x22\x02\x08\x07"); // DEFAULT limit 7
    try limits.bytes(1, "\x22\x02\x08\x09"); // later DEFAULT ignored
    var extra = fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(10, limits.data.items);
    const bytes = try fixture.cluster(gpa, "payments", "payments-eds", extra.data.items);
    var decoded = try resource.decode(gpa, bytes, .{});
    gpa.free(bytes);
    defer decoded.deinit();
    try std.testing.expectEqualStrings("payments", decoded.value.name);
    try std.testing.expectEqualStrings("payments-eds", decoded.value.edsName());
    try std.testing.expectEqual(@as(u32, 7), decoded.value.max_concurrent_requests);
    try std.testing.expect(decoded.value.policy.locality_weighted);
    const defaults = try fixture.cluster(gpa, "default", "", "");
    defer gpa.free(defaults);
    var fallback = try resource.decode(gpa, defaults, .{});
    defer fallback.deinit();
    try std.testing.expectEqualStrings("default", fallback.value.edsName());
    try std.testing.expectEqual(@as(u32, 1024), fallback.value.max_concurrent_requests);
    var invalid_threshold = fixture.Builder{ .allocator = gpa };
    defer invalid_threshold.deinit();
    try invalid_threshold.bytes(1, "\x08\x01\x22\x01\x08"); // malformed HIGH wrapper
    var invalid_extra = fixture.Builder{ .allocator = gpa };
    defer invalid_extra.deinit();
    try invalid_extra.bytes(10, invalid_threshold.data.items);
    const invalid = try fixture.cluster(gpa, "backend", "", invalid_extra.data.items);
    defer gpa.free(invalid);
    try std.testing.expectError(error.TruncatedMessage, resource.decode(gpa, invalid, .{}));
    const Harness = struct {
        fn run(allocator: std.mem.Allocator, image: []const u8) !void {
            var owned = try resource.decode(allocator, image, .{});
            defer owned.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{defaults});
}

test "gRPC CDS ordered typed LB fallback rejects recognized invalid policy" {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const unknown = try fixture.typed(allocator, "type.googleapis.com/custom.Unknown", "");
    const ring = try fixture.typed(allocator, prefix ++ "ring_hash.v3.RingHash", "\x08\x01\x12\x02\x08\x20\x1a\x02\x08\x40");
    const combined = try std.mem.concat(allocator, u8, &.{ unknown, ring });
    const result = try policy.typed(allocator, combined, 32, 4096, 0);
    try std.testing.expectEqualStrings("[{\"ring_hash_experimental\":{\"minRingSize\":32,\"maxRingSize\":64}}]", result.child_json);
    try std.testing.expect(!result.locality_weighted);
    const invalid = try fixture.typed(allocator, prefix ++ "ring_hash.v3.RingHash", "\x12\x00");
    const rr = try fixture.typed(allocator, prefix ++ "round_robin.v3.RoundRobin", "");
    try std.testing.expectError(error.CdsLimitExceeded, policy.typed(allocator, try std.mem.concat(allocator, u8, &.{ rr, rr }), 1, 4096, 0));
    try std.testing.expectError(error.TruncatedMessage, policy.typed(allocator, try std.mem.concat(allocator, u8, &.{ rr, "\x0a\x02a" }), 32, 4096, 0));
    try std.testing.expectError(error.InvalidCdsResource, policy.typed(allocator, try std.mem.concat(allocator, u8, &.{ invalid, rr }), 32, 4096, 0));
    try std.testing.expectError(error.UnsupportedCdsPolicy, policy.typed(allocator, unknown, 32, 4096, 0));
    try std.testing.expectError(error.CdsLimitExceeded, policy.typed(allocator, combined, 1, 4096, 0));
    const pick = try fixture.typed(allocator, prefix ++ "pick_first.v3.PickFirst", "\x08\x01");
    try std.testing.expectEqualStrings("[{\"pick_first\":{\"shuffleAddressList\":true}}]", (try policy.typed(allocator, pick, 32, 4096, 0)).child_json);
    const least = try fixture.typed(allocator, prefix ++ "least_request.v3.LeastRequest", "\x0a\x02\x08\x03");
    try std.testing.expectEqualStrings("[{\"least_request_experimental\":{\"choiceCount\":3}}]", (try policy.typed(allocator, least, 32, 4096, 0)).child_json);
    var wrapper = fixture.Builder{ .allocator = allocator };
    try wrapper.bytes(1, rr);
    const locality = try fixture.typed(allocator, prefix ++ "wrr_locality.v3.WrrLocality", wrapper.data.items);
    try std.testing.expect((try policy.typed(allocator, locality, 32, 4096, 0)).locality_weighted);
    try std.testing.expectError(error.CdsLimitExceeded, policy.typed(allocator, locality, 32, 4096, 16));
}

test "gRPC CDS decodes STATIC clusters with inline assignments" {
    const encoded = try fixture.staticCluster(gpa, "backend", "127.0.0.1", 1001);
    defer gpa.free(encoded);
    var decoded = try resource.decode(gpa, encoded, .{});
    defer decoded.deinit();
    try std.testing.expectEqualStrings("backend", decoded.value.name);
    try std.testing.expectEqual(resource.Discovery.static, decoded.value.discovery);
    try std.testing.expect(!decoded.value.isEds());
    try std.testing.expectEqualStrings("", decoded.value.edsName());
    try std.testing.expect(decoded.value.inline_assignment.len != 0);
    const wrong_name = try fixture.assignment(gpa, "other", "127.0.0.1", 1001);
    defer gpa.free(wrong_name);
    var builder = fixture.Builder{ .allocator = gpa };
    defer builder.deinit();
    try builder.bytes(1, "backend");
    try builder.number(2, 0);
    try builder.bytes(33, wrong_name);
    try std.testing.expectError(error.InvalidCdsResource, resource.decode(gpa, builder.data.items, .{}));
    const missing = try fixture.cluster(gpa, "backend", "", "\x10\x00");
    defer gpa.free(missing);
    try std.testing.expectError(error.InvalidCdsResource, resource.decode(gpa, missing, .{}));
}

test "gRPC CDS decodes STRICT_DNS and LOGICAL_DNS clusters" {
    for ([_]struct { kind: u32, discovery: resource.Discovery }{
        .{ .kind = 1, .discovery = .strict_dns },
        .{ .kind = 2, .discovery = .logical_dns },
    }) |case| {
        const encoded = try fixture.dnsCluster(gpa, "backend", "backend.test", 1001, case.kind);
        defer gpa.free(encoded);
        var decoded = try resource.decode(gpa, encoded, .{});
        defer decoded.deinit();
        try std.testing.expectEqual(case.discovery, decoded.value.discovery);
        try std.testing.expect(decoded.value.isDns());
        try std.testing.expectEqualStrings("", decoded.value.edsName());
        try std.testing.expectEqual(@as(usize, 1), decoded.value.host_endpoints.len);
        try std.testing.expectEqualStrings("backend.test", decoded.value.host_endpoints[0].host);
        try std.testing.expectEqual(@as(u16, 1001), decoded.value.host_endpoints[0].port);
    }
    const bad = try fixture.dnsCluster(gpa, "backend", "", 1001, 1);
    defer gpa.free(bad);
    try std.testing.expectError(error.InvalidCdsResource, resource.decode(gpa, bad, .{}));
    const missing = try fixture.dnsCluster(gpa, "backend", "backend.test", 1001, 4);
    defer gpa.free(missing);
    try std.testing.expectError(error.UnsupportedCdsFeature, resource.decode(gpa, missing, .{}));
    const hosts = [_]fixture.Host{ .{ .host = "a.test", .port = 1001 }, .{ .host = "b.test", .port = 1002 } };
    const strict = try fixture.dnsClusterHosts(gpa, "backend", 1, &hosts);
    defer gpa.free(strict);
    var strict_decoded = try resource.decode(gpa, strict, .{});
    defer strict_decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), strict_decoded.value.host_endpoints.len);
    const logical = try fixture.dnsClusterHosts(gpa, "backend", 2, &hosts);
    defer gpa.free(logical);
    var logical_decoded = try resource.decode(gpa, logical, .{});
    defer logical_decoded.deinit();
    try std.testing.expectEqual(@as(usize, 1), logical_decoded.value.host_endpoints.len);
    try std.testing.expectEqualStrings("a.test", logical_decoded.value.host_endpoints[0].host);
}

test "gRPC CDS decodes inline upstream TLS transport sockets" {
    const pem = try std.fmt.allocPrint(gpa, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer gpa.free(pem);
    const tls = try fixture.upstreamTls(gpa, pem, "localhost");
    defer gpa.free(tls);
    const encoded = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, tls);
    defer gpa.free(encoded);
    var decoded = try resource.decode(gpa, encoded, .{});
    defer decoded.deinit();
    try std.testing.expect(decoded.value.tls != null);
    try std.testing.expectEqualStrings("localhost", decoded.value.tls.?.server_name);
    try std.testing.expect(std.mem.indexOf(u8, decoded.value.tls.?.trusted_ca, "BEGIN CERTIFICATE") != null);
    for ([_]struct { min: u32, max: u32, want: @import("../tls_material.zig").VersionPolicy }{
        .{ .min = 3, .max = 3, .want = .tls12_only },
        .{ .min = 4, .max = 4, .want = .tls13_only },
        .{ .min = 3, .max = 4, .want = .tls12_and_tls13 },
    }) |case| {
        const versioned = try fixture.upstreamTlsWithVersions(gpa, pem, "localhost", .{ .min = case.min, .max = case.max });
        defer gpa.free(versioned);
        const encoded_versioned = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, versioned);
        defer gpa.free(encoded_versioned);
        var versioned_decoded = try resource.decode(gpa, encoded_versioned, .{});
        defer versioned_decoded.deinit();
        try std.testing.expectEqual(case.want, versioned_decoded.value.tls.?.version_policy.?);
    }
    const auto = try fixture.upstreamTlsWithVersions(gpa, pem, "localhost", .{ .min = 0, .max = 0 });
    defer gpa.free(auto);
    const encoded_auto = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, auto);
    defer gpa.free(encoded_auto);
    var auto_decoded = try resource.decode(gpa, encoded_auto, .{});
    defer auto_decoded.deinit();
    try std.testing.expectEqual(@import("../tls_material.zig").VersionPolicy.tls12_and_tls13, auto_decoded.value.tls.?.version_policy.?);
    const legacy = try fixture.upstreamTlsWithVersions(gpa, pem, "localhost", .{ .min = 1, .max = 4 });
    defer gpa.free(legacy);
    const encoded_legacy = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, legacy);
    defer gpa.free(encoded_legacy);
    try std.testing.expectError(error.UnsupportedCdsFeature, resource.decode(gpa, encoded_legacy, .{}));
    const ciphers = try fixture.upstreamTlsWithCiphers(gpa, pem, "localhost", &.{ "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305" });
    defer gpa.free(ciphers);
    const encoded_ciphers = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, ciphers);
    defer gpa.free(encoded_ciphers);
    var ciphers_decoded = try resource.decode(gpa, encoded_ciphers, .{});
    defer ciphers_decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), ciphers_decoded.value.tls.?.tls12_cipher_suites.?.len);
    try std.testing.expectEqual(@import("../tls_material.zig").Tls12CipherSuite.ecdhe_ecdsa_aes_128_gcm_sha256, ciphers_decoded.value.tls.?.tls12_cipher_suites.?[0]);
    try std.testing.expectEqual(@import("../tls_material.zig").Tls12CipherSuite.ecdhe_rsa_chacha20_poly1305_sha256, ciphers_decoded.value.tls.?.tls12_cipher_suites.?[1]);
    const unknown_cipher = try fixture.upstreamTlsWithCiphers(gpa, pem, "localhost", &.{"UNKNOWN-CIPHER"});
    defer gpa.free(unknown_cipher);
    const encoded_unknown = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, unknown_cipher);
    defer gpa.free(encoded_unknown);
    try std.testing.expectError(error.UnsupportedCdsFeature, resource.decode(gpa, encoded_unknown, .{}));
    const sans = try fixture.upstreamTlsWithSans(gpa, pem, "localhost", &.{ .{ .kind = .exact, .value = "localhost" }, .{ .kind = .contains, .value = "calhost" } });
    defer gpa.free(sans);
    const encoded_sans = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, sans);
    defer gpa.free(encoded_sans);
    var sans_decoded = try resource.decode(gpa, encoded_sans, .{});
    defer sans_decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), sans_decoded.value.tls.?.san_matchers.?.len);
    try std.testing.expectEqual(@import("../tls_material.zig").SanMatch.exact, sans_decoded.value.tls.?.san_matchers.?[0].kind);
    try std.testing.expectEqualStrings("localhost", sans_decoded.value.tls.?.san_matchers.?[0].value);
    try std.testing.expectEqual(@import("../tls_material.zig").SanMatch.contains, sans_decoded.value.tls.?.san_matchers.?[1].kind);
}

test "gRPC CDS rejects unsupported discovery security invalid identities and ring ranges" {
    try std.testing.expectError(error.InvalidCdsResource, resource.decode(gpa, "", .{}));
    try std.testing.expectError(error.TruncatedMessage, resource.decode(gpa, "\x0a\x02a", .{}));
    const defaults = try fixture.cluster(gpa, "backend", "", "");
    defer gpa.free(defaults);
    try std.testing.expectError(error.CdsLimitExceeded, resource.decode(gpa, defaults, .{ .max_bytes = 1 }));
    try std.testing.expectError(error.CdsLimitExceeded, resource.decode(gpa, defaults, .{ .max_text_bytes = 1 }));
    const xdstp = try fixture.cluster(gpa, "xdstp://authority/cluster", "", "");
    defer gpa.free(xdstp);
    try std.testing.expectError(error.InvalidCdsResource, resource.decode(gpa, xdstp, .{}));
    for ([_]struct { extra: []const u8, want: anyerror }{
        .{ .extra = "\x10\x00", .want = error.InvalidCdsResource },
        .{ .extra = "\x10\x01", .want = error.InvalidCdsResource },
        .{ .extra = "\x10\x02", .want = error.InvalidCdsResource },
        .{ .extra = "\xc2\x01\x00", .want = error.UnsupportedCdsFeature },
        .{ .extra = "\x30\x01", .want = error.UnsupportedCdsPolicy },
    }) |case| {
        const encoded = try fixture.cluster(gpa, "backend", "", case.extra);
        defer gpa.free(encoded);
        try std.testing.expectError(case.want, resource.decode(gpa, encoded, .{}));
    }
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidCdsResource, policy.legacy(arena.allocator(), 2, "\x08\x00\x0a\x00"));
}

const std = @import("std");
const resource = @import("decode.zig");
const policy = @import("policy.zig");
const fixture = @import("testing.zig");
const tls_testing = @import("../../../tls/testing.zig");
const service_config = @import("../../service_config.zig");
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

test "gRPC CDS decodes SDS certificate and validation references" {
    const tls = try fixture.upstreamTlsSds(gpa, "backend.test", "cert-1", "roots");
    defer gpa.free(tls);
    const encoded = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, tls);
    defer gpa.free(encoded);
    var decoded = try resource.decode(gpa, encoded, .{ .allow_sds = true });
    defer decoded.deinit();
    const refs = decoded.value.tls_sds.?;
    try std.testing.expectEqualStrings("cert-1", refs.certificate.?);
    try std.testing.expectEqualStrings("roots", refs.validation.?);
    try std.testing.expectEqualStrings("backend.test", decoded.value.tls.?.server_name);
    try std.testing.expectEqualStrings("", decoded.value.tls.?.certificate_chain);
    try std.testing.expectEqualStrings("", decoded.value.tls.?.trusted_ca);
    // Direct CDS consumers must opt in; unresolved references fail closed.
    try std.testing.expectError(error.UnsupportedCdsFeature, resource.decode(gpa, encoded, .{}));

    // Inline certificate material and an SDS certificate reference for the
    // same aspect are ambiguous and must fail closed.
    var common = fixture.Builder{ .allocator = gpa };
    defer common.deinit();
    var chain_source = fixture.Builder{ .allocator = gpa };
    defer chain_source.deinit();
    try chain_source.bytes(1, "CERT");
    var key_source = fixture.Builder{ .allocator = gpa };
    defer key_source.deinit();
    try key_source.bytes(1, "KEY");
    var inline_cert = fixture.Builder{ .allocator = gpa };
    defer inline_cert.deinit();
    try inline_cert.bytes(1, chain_source.data.items);
    try inline_cert.bytes(2, key_source.data.items);
    try common.bytes(2, inline_cert.data.items);
    const certificate_config = try fixture.sdsSecretConfig(gpa, "cert-1");
    defer gpa.free(certificate_config);
    try common.bytes(6, certificate_config);
    var context = fixture.Builder{ .allocator = gpa };
    defer context.deinit();
    try context.bytes(1, common.data.items);
    var any = fixture.Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext");
    try any.bytes(2, context.data.items);
    var socket = fixture.Builder{ .allocator = gpa };
    defer socket.deinit();
    try socket.bytes(1, "envoy.transport_sockets.tls");
    try socket.bytes(3, any.data.items);
    const conflict = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, socket.data.items);
    defer gpa.free(conflict);
    try std.testing.expectError(error.UnsupportedCdsFeature, resource.decode(gpa, conflict, .{}));

    // A non-ADS SDS source cannot be resolved on this stream.
    var source = fixture.Builder{ .allocator = gpa };
    defer source.deinit();
    try source.bytes(1, "cert-1");
    try source.bytes(2, "\x2a\x00"); // ConfigSource.self
    var common_self = fixture.Builder{ .allocator = gpa };
    defer common_self.deinit();
    try common_self.bytes(6, source.data.items);
    var context_self = fixture.Builder{ .allocator = gpa };
    defer context_self.deinit();
    try context_self.bytes(1, common_self.data.items);
    var any_self = fixture.Builder{ .allocator = gpa };
    defer any_self.deinit();
    try any_self.bytes(1, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext");
    try any_self.bytes(2, context_self.data.items);
    var socket_self = fixture.Builder{ .allocator = gpa };
    defer socket_self.deinit();
    try socket_self.bytes(1, "envoy.transport_sockets.tls");
    try socket_self.bytes(3, any_self.data.items);
    const self_source = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, socket_self.data.items);
    defer gpa.free(self_source);
    try std.testing.expectError(error.UnsupportedCdsFeature, resource.decode(gpa, self_source, .{}));
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

test "gRPC CDS decodes aggregate cluster extensions" {
    var config = fixture.Builder{ .allocator = gpa };
    defer config.deinit();
    try config.bytes(1, "cluster-a");
    try config.bytes(1, "cluster-b");
    var any = fixture.Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig");
    try any.bytes(2, config.data.items);
    var custom = fixture.Builder{ .allocator = gpa };
    defer custom.deinit();
    try custom.bytes(1, "envoy.clusters.aggregate");
    try custom.bytes(2, any.data.items);
    var extra = fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(38, custom.data.items);
    const encoded = try fixture.cluster(gpa, "aggregate", "", extra.data.items);
    defer gpa.free(encoded);
    var decoded = try resource.decode(gpa, encoded, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(resource.Discovery.aggregate, decoded.value.discovery);
    try std.testing.expect(decoded.value.isAggregate());
    try std.testing.expectEqualStrings("", decoded.value.edsName());
    try std.testing.expectEqual(@as(usize, 2), decoded.value.aggregate_clusters.len);
    try std.testing.expectEqualStrings("cluster-a", decoded.value.aggregate_clusters[0]);
    try std.testing.expectEqualStrings("cluster-b", decoded.value.aggregate_clusters[1]);

    var unknown = fixture.Builder{ .allocator = gpa };
    defer unknown.deinit();
    try unknown.bytes(1, "envoy.clusters.unknown");
    try unknown.bytes(2, any.data.items);
    var unknown_extra = fixture.Builder{ .allocator = gpa };
    defer unknown_extra.deinit();
    try unknown_extra.bytes(38, unknown.data.items);
    const unknown_encoded = try fixture.cluster(gpa, "unknown", "", unknown_extra.data.items);
    defer gpa.free(unknown_encoded);
    try std.testing.expectError(error.UnsupportedCdsFeature, resource.decode(gpa, unknown_encoded, .{}));
}

test "gRPC CDS decodes LRS ORCA propagation selectors" {
    var extra = fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(57, "cpu_utilization");
    try extra.bytes(57, "mem_utilization");
    try extra.bytes(57, "application_utilization");
    try extra.bytes(57, "named_metrics.*");
    try extra.bytes(57, "named_metrics.foo");
    try extra.bytes(57, "unknown_selector");
    const encoded = try fixture.cluster(gpa, "backend", "", extra.data.items);
    defer gpa.free(encoded);
    var decoded = try resource.decode(gpa, encoded, .{});
    defer decoded.deinit();
    const propagation = decoded.value.lrs_propagation;
    try std.testing.expect(propagation.cpu_utilization);
    try std.testing.expect(propagation.memory_utilization);
    try std.testing.expect(propagation.application_utilization);
    try std.testing.expect(propagation.named_metrics_all);
    try std.testing.expectEqual(@as(usize, 1), propagation.named_metrics.len);
    try std.testing.expectEqualStrings("foo", propagation.named_metrics[0]);

    const defaults = try fixture.cluster(gpa, "plain", "", "");
    defer gpa.free(defaults);
    var plain = try resource.decode(gpa, defaults, .{});
    defer plain.deinit();
    const none = plain.value.lrs_propagation;
    try std.testing.expect(!none.cpu_utilization);
    try std.testing.expect(!none.memory_utilization);
    try std.testing.expect(!none.application_utilization);
    try std.testing.expect(!none.named_metrics_all);
    try std.testing.expectEqual(@as(usize, 0), none.named_metrics.len);
}
test "gRPC CDS projects outlier detection into the channel policy" {
    var outlier = fixture.Builder{ .allocator = gpa };
    defer outlier.deinit();
    try outlier.bytes(2, "\x08\x05"); // interval 5s
    try outlier.bytes(3, "\x08\x0f"); // base ejection 15s
    try outlier.wrapper(4, 25); // max ejection percent
    try outlier.wrapper(6, 80); // enforcing success rate
    try outlier.wrapper(7, 3); // success-rate minimum hosts
    try outlier.wrapper(8, 20); // success-rate request volume
    try outlier.wrapper(9, 1500); // success-rate stdev factor
    try outlier.wrapper(16, 70); // failure-percentage threshold
    try outlier.wrapper(17, 50); // enforcing failure percentage
    try outlier.wrapper(19, 4); // failure-percentage minimum hosts
    try outlier.wrapper(20, 10); // failure-percentage request volume
    try outlier.bytes(21, "\x08\x3c"); // max ejection time 60s
    var extra = fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(19, outlier.data.items);
    const bytes = try fixture.cluster(gpa, "backend", "backend-eds", extra.data.items);
    defer gpa.free(bytes);
    var decoded = try resource.decode(gpa, bytes, .{});
    defer decoded.deinit();
    const json = try std.fmt.allocPrint(
        gpa,
        "{{\"loadBalancingConfig\":{s}}}",
        .{decoded.value.policy.child_json},
    );
    defer gpa.free(json);
    var config = try service_config.ServiceConfig.parse(gpa, json);
    defer config.deinit();
    const root = config.load_balancing.root orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(root.* == .outlier_detection);
    const wrapper = root.outlier_detection;
    try std.testing.expectEqual(
        std.Io.Duration.fromSeconds(5),
        wrapper.config.interval,
    );
    try std.testing.expectEqual(
        std.Io.Duration.fromSeconds(15),
        wrapper.config.base_ejection_time,
    );
    try std.testing.expectEqual(
        std.Io.Duration.fromSeconds(60),
        wrapper.config.max_ejection_time,
    );
    try std.testing.expectEqual(@as(u32, 25), wrapper.config.max_ejection_percent);
    const success = wrapper.config.success_rate_ejection.?;
    try std.testing.expectEqual(@as(u32, 1500), success.stdev_factor);
    try std.testing.expectEqual(@as(u32, 80), success.enforcement_percentage);
    try std.testing.expectEqual(@as(u32, 3), success.minimum_hosts);
    try std.testing.expectEqual(@as(u32, 20), success.request_volume);
    const failure = wrapper.config.failure_percentage_ejection.?;
    try std.testing.expectEqual(@as(u32, 70), failure.threshold);
    try std.testing.expectEqual(@as(u32, 50), failure.enforcement_percentage);
    try std.testing.expectEqual(@as(u32, 4), failure.minimum_hosts);
    try std.testing.expectEqual(@as(u32, 10), failure.request_volume);
    try std.testing.expect(wrapper.child.* == .round_robin);
}
test "gRPC CDS decodes HTTP/2 upstream protocol limits" {
    var h2 = fixture.Builder{ .allocator = gpa };
    defer h2.deinit();
    try h2.wrapper(1, 4096); // HPACK table size
    try h2.wrapper(2, 100); // max concurrent streams
    try h2.wrapper(3, 1048576); // initial stream window
    try h2.wrapper(4, 2097152); // initial connection window
    var http = fixture.Builder{ .allocator = gpa };
    defer http.deinit();
    try http.bytes(2, h2.data.items);
    var any = fixture.Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions");
    try any.bytes(2, http.data.items);
    var typed = fixture.Builder{ .allocator = gpa };
    defer typed.deinit();
    try typed.bytes(2, any.data.items);
    var extra = fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(48, typed.data.items);
    const bytes = try fixture.cluster(
        gpa,
        "backend",
        "backend-eds",
        extra.data.items,
    );
    defer gpa.free(bytes);
    var decoded = try resource.decode(gpa, bytes, .{});
    defer decoded.deinit();
    const limits = decoded.value.http2_limits.?;
    try std.testing.expectEqual(@as(?u32, 4096), limits.header_table_size);
    try std.testing.expectEqual(
        @as(?u32, 100),
        limits.max_concurrent_streams,
    );
    try std.testing.expectEqual(
        @as(?u32, 1048576),
        limits.initial_window_size,
    );
    try std.testing.expectEqual(
        @as(?u32, 2097152),
        limits.initial_connection_window_size,
    );
}

test "gRPC CDS decodes inline certificate hash pins" {
    const pem = try std.fmt.allocPrint(gpa, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer gpa.free(pem);
    var trusted = fixture.Builder{ .allocator = gpa };
    defer trusted.deinit();
    try trusted.bytes(1, pem);
    var validation = fixture.Builder{ .allocator = gpa };
    defer validation.deinit();
    try validation.bytes(1, trusted.data.items);
    try validation.bytes(4, "abababababababababababababababababababababababababababababababab");
    var common = fixture.Builder{ .allocator = gpa };
    defer common.deinit();
    try common.bytes(3, validation.data.items);
    var context = fixture.Builder{ .allocator = gpa };
    defer context.deinit();
    try context.bytes(1, common.data.items);
    var any = fixture.Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext");
    try any.bytes(2, context.data.items);
    var socket = fixture.Builder{ .allocator = gpa };
    defer socket.deinit();
    try socket.bytes(1, "envoy.transport_sockets.tls");
    try socket.bytes(3, any.data.items);
    const encoded = try fixture.staticClusterTls(gpa, "backend", "127.0.0.1", 1001, socket.data.items);
    defer gpa.free(encoded);
    var decoded = try resource.decode(gpa, encoded, .{});
    defer decoded.deinit();
    const hashes = decoded.value.tls.?.verify_certificate_hashes.?;
    try std.testing.expectEqual(@as(usize, 1), hashes.len);
    try std.testing.expectEqual(@as(u8, 0xab), hashes[0][0]);
}

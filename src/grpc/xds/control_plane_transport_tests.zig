//! Standard gRPC targets use the first supported bootstrap credential.
const std = @import("std");
const grpc = @import("../mod.zig");
const bootstrap = @import("bootstrap.zig");
const control = @import("control_plane.zig");
const delta = @import("ads/delta.zig");
const tls_testing = @import("../../tls/testing.zig");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const gpa = std.testing.allocator;
const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

const Collector = struct {
    request: ?delta.codec.OwnedRequest = null,
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        self.request = try delta.codec.decodeRequest(gpa, message.payload, .{});
    }
};

fn exchange(listener: anytype) !void {
    var connection = try listener.acceptWithTimeout(.fromSeconds(3));
    defer connection.deinit();
    var duplex = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
    defer duplex.deinit();
    try std.testing.expectEqualStrings(delta.path, duplex.transport.path);
    var collector: Collector = .{};
    defer if (collector.request) |*value| value.deinit();
    while (collector.request == null) {
        var event = try duplex.readRequestEventWithTimeout(.fromSeconds(3), &collector, Collector.consume);
        defer event.deinit();
        if (event == .finished or event == .reset) return error.EndedEarly;
    }
    try std.testing.expect(collector.request.?.value.node != null);
    try std.testing.expectEqualStrings(cds, collector.request.?.value.type_url);
    try std.testing.expectEqualStrings("cluster", collector.request.?.value.subscribe[0]);
    try duplex.startResponse(.{});
    try duplex.finishOk();
}

const Peer = struct {
    fn plain(listener: *grpc.runtime.Server) !void {
        return exchange(listener);
    }
    fn tls(listener: *grpc.runtime.TlsServer) !void {
        return exchange(listener);
    }
    fn rejectTls(listener: *grpc.runtime.Server) !void {
        var connection = listener.acceptWithTimeout(.fromSeconds(3)) catch |err| switch (err) {
            error.InvalidPreface => return,
            else => return err,
        };
        defer connection.deinit();
        var duplex = connection.acceptDuplexWithTimeout(.fromSeconds(3)) catch return;
        defer duplex.deinit();
        return error.UnexpectedPlaintextRpc;
    }
};

fn connect(plane: *control.ControlPlane) !void {
    try plane.discovery().setSubscription(cds, &.{"cluster"});
    try plane.connectWithTimeout(.fromSeconds(3));
    var event = try plane.discovery().nextWithTimeout(.fromSeconds(3));
    defer event.deinit();
    try std.testing.expect(event == .terminal);
    try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
}

fn plaintext(prefix: []const u8, host: []const u8, credentials: []const u8) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"{s}{s}:{d}\",\"channel_creds\":{s}}}],\"node\":{{\"id\":\"node\"}}}}", .{ prefix, host, server.address().getPort(), credentials });
    defer gpa.free(json);
    const configuration = try bootstrap.parse(gpa, json, .{});
    defer configuration.deinit();
    const plane = try control.ControlPlane.init(gpa, io, configuration, .{ .server_open_timeout = .fromSeconds(1) });
    defer plane.deinit();
    try std.testing.expect(!plane.server().usesTls());
    try std.testing.expect(plane.channel.state.canonical_endpoints[0] == .cleartext_host);
    try std.testing.expect(!plane.material.bundle_loaded and plane.material.identity == null);
    try std.testing.expect(plane.refreshInterval() == null);
    var task = io.async(Peer.plain, .{&server});
    defer _ = task.cancel(io) catch {};
    try connect(plane);
    try task.await(io);
}

test "control plane connects plaintext using bare and DNS host and IP targets" {
    const credentials = "[{\"type\":\"unsupported\"},{\"type\":\"insecure\"}]";
    try plaintext("", "127.0.0.1", credentials);
    try plaintext("dns:///", "127.0.0.1", credentials);
    try plaintext("", "localhost", credentials);
    try plaintext("dns:///", "localhost", credentials);
}

test "insecure-first bootstrap credentials ignore later TLS files and providers even for HTTPS aliases" {
    try plaintext("https://", "127.0.0.1", "[{\"type\":\"unsupported\"},{\"type\":\"insecure\"},{\"type\":\"tls\",\"config\":{\"ca_certificate_file\":\"/missing/unselected-ca.pem\",\"certificate_file\":\"/missing/unselected-cert.pem\",\"private_key_file\":\"/missing/unselected-key.pem\"}},{\"type\":\"tls\",\"config\":{\"root_certificate_provider\":\"unselected-provider\"}}]");
}

fn tlsTarget(prefix: []const u8) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    var server = try grpc.runtime.TlsServer.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{ .transport = .{ .identity = .{ .certificate_chain = &.{&certificate_der}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } } } } });
    defer server.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    const pem = try std.fmt.allocPrint(gpa, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer gpa.free(pem);
    try tmp.dir.writeFile(io, .{ .sub_path = "ca.pem", .data = pem });
    var path_buffer: [256]u8 = undefined;
    const ca_path = try tmp.path(&path_buffer, "ca.pem");
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"{s}localhost:{d}\",\"channel_creds\":[{{\"type\":\"unsupported\"}},{{\"type\":\"tls\",\"config\":{{\"root_certificate_provider\":\"roots\"}}}},{{\"type\":\"insecure\"}}]}}],\"certificate_providers\":{{\"roots\":{{\"plugin_name\":\"file_watcher\",\"config\":{{\"ca_certificate_file\":\"{s}\",\"refresh_interval\":\"5s\"}}}}}},\"node\":{{\"id\":\"node\"}}}}", .{ prefix, server.address().getPort(), ca_path });
    defer gpa.free(json);
    const configuration = try bootstrap.parse(gpa, json, .{});
    defer configuration.deinit();
    const plane = try control.ControlPlane.init(gpa, io, configuration, .{ .server_open_timeout = .fromSeconds(1) });
    defer plane.deinit();
    try std.testing.expect(plane.server().usesTls());
    try std.testing.expect(plane.channel.state.canonical_endpoints[0] == .tls_host);
    try std.testing.expect(plane.material.bundle_loaded);
    try std.testing.expectEqual(@as(i96, 5 * std.time.ns_per_s), plane.refreshInterval().?.nanoseconds);
    var task = io.async(Peer.tls, .{&server});
    defer _ = task.cancel(io) catch {};
    try connect(plane);
    try task.await(io);
}

test "control plane uses selected TLS credentials for bare DNS and HTTP alias targets" {
    try tlsTarget("");
    try tlsTarget("dns:///");
    try tlsTarget("http://");
}

test "failed TLS handshake keeps the selected credential despite a later insecure alternative" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    const pem = try std.fmt.allocPrint(gpa, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer gpa.free(pem);
    try tmp.dir.writeFile(io, .{ .sub_path = "ca.pem", .data = pem });
    var path_buffer: [256]u8 = undefined;
    const ca_path = try tmp.path(&path_buffer, "ca.pem");
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"dns:///localhost:{d}\",\"channel_creds\":[{{\"type\":\"tls\",\"config\":{{\"ca_certificate_file\":\"{s}\"}}}},{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"node\"}}}}", .{ server.address().getPort(), ca_path });
    defer gpa.free(json);
    const configuration = try bootstrap.parse(gpa, json, .{});
    defer configuration.deinit();
    const plane = try control.ControlPlane.init(gpa, io, configuration, .{ .server_open_timeout = .fromSeconds(1) });
    defer plane.deinit();
    var task = io.async(Peer.rejectTls, .{&server});
    defer _ = task.cancel(io) catch {};
    try plane.discovery().setSubscription(cds, &.{"cluster"});
    if (plane.connectWithTimeout(.fromSeconds(3))) |_| return error.UnexpectedTlsSuccess else |_| {}
    try std.testing.expect(plane.server().usesTls());
    try std.testing.expectEqualStrings("tls", plane.server().selectedCredential().?.type);
    try std.testing.expect(plane.channel.state.canonical_endpoints[0] == .tls_host);
    try std.testing.expect(plane.discovery().stream == null);
    try task.await(io);
}

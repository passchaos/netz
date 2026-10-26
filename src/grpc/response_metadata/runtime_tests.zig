const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

const Case = struct {
    http_status: u16 = 200,
    headers: []const http2.Hpack.HeaderField,
    body: []const u8 = &.{},
    trailers: []const http2.Hpack.HeaderField = &.{},
    status: grpc.Status = .unknown,
    messages: usize = 0,
    unary_messages: ?usize = null,
    payload: []const u8 = &.{},
    details: bool = false,
};
const cases = [_]Case{
    .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }} },
    .{ .headers = &.{.{ .name = "content-type", .value = "text/html" }}, .body = "<html>proxy error</html>" },
    .{ .http_status = 503, .headers = &.{.{ .name = "content-type", .value = "application/grpc" }}, .body = "proxy error", .status = .unavailable },
    .{ .http_status = 503, .headers = &.{ .{ .name = "content-type", .value = "text/plain" }, .{ .name = "grpc-status", .value = "7" } }, .status = .permission_denied },
    .{ .headers = &.{}, .trailers = &.{.{ .name = "grpc-status", .value = "7" }}, .status = .permission_denied },
    .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }}, .body = "\x00\x00\x00\x00\x06before", .messages = 1, .payload = "before" },
    .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }}, .body = "\x00\x00\x00\x00\x04good", .trailers = &.{.{ .name = "grpc-status", .value = "0" }}, .status = .ok, .messages = 1, .payload = "good" },
    .{ .headers = &.{ .{ .name = "content-type", .value = "text/plain" }, .{ .name = "grpc-encoding", .value = "unknown-proxy-coding" }, .{ .name = "grpc-status", .value = "7" }, .{ .name = "grpc-status-details-bin", .value = "CAc" } }, .status = .permission_denied, .details = true },
    // Aggregate unary decoding already has the terminal metadata available.
    // Streamed readers retain their initial HTTP-error body classification.
    .{ .http_status = 503, .headers = &.{.{ .name = "content-type", .value = "application/grpc" }}, .body = "\x00\x00\x00\x00\x06before", .trailers = &.{.{ .name = "grpc-status", .value = "7" }}, .status = .permission_denied, .unary_messages = 1, .payload = "before" },
    .{ .headers = &.{ .{ .name = "content-type", .value = "text/plain" }, .{ .name = "grpc-status", .value = "99" } } },
    .{ .headers = &.{ .{ .name = "content-type", .value = "text/plain" }, .{ .name = "grpc-status", .value = "0" }, .{ .name = "grpc-status", .value = "7" } } },
};

test "gRPC response fallback matrix over TCP reuses one stream slot" {
    try run(false);
}
test "gRPC response fallback matrix over pinned TLS reuses one stream slot" {
    try run(true);
}

const Collector = struct {
    count: usize = 0,
    expected: []const u8,
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        try std.testing.expectEqualStrings(self.expected, message.payload);
        self.count += 1;
    }
};

fn check(response: anytype, case: Case) !void {
    try std.testing.expectEqual(case.status, response.status);
    try std.testing.expectEqual(case.details, response.status_details != null);
    if (case.details) try std.testing.expectEqualSlices(u8, "\x08\x07", response.status_details.?.bytes);
    if (case.status == .unknown) try std.testing.expect(response.status_message.len != 0);
}

fn run(comptime use_tls: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    const limits: http2.runtime.Limits = .{ .max_concurrent_streams = 1, .max_frame_payload = 64, .max_body_bytes = 4096 };
    var server = if (use_tls)
        try grpc.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .transport = .{ .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } } }, .limits = limits } })
    else
        try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits, 4096);
    defer server.deinit();
    const Shared = struct {
        server: *@TypeOf(server),
        err: ?anyerror = null,
        fn execute(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            for (0..3) |_| for (cases) |case| {
                var request = try connection.readUnaryWithTimeout(.fromSeconds(3));
                defer request.deinit();
                try connection.connection.writeResponse(request.request.stream_id, .{ .status = case.http_status, .headers = case.headers, .body = case.body, .trailers = case.trailers });
            };
        }
    };
    var shared: Shared = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.execute, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = if (use_tls)
        try grpc.runtime.Client.connectTlsHost(allocator, io, "localhost", server.address().ip4.port, .{ .limits = limits, .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() } } })
    else
        try grpc.runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.deinit();
    if (use_tls) try std.testing.expectEqualStrings("h2", client.negotiatedAlpn().?);
    for (cases) |case| {
        var response = try client.unary(.{ .path = "/demo.Fallback/Unary", .authority = "localhost", .message = "", .timeout = .{ .value = 3, .unit = .second } });
        defer response.deinit();
        try check(response, case);
        try std.testing.expectEqual((case.unary_messages orelse case.messages) != 0, response.message != null);
        if (response.message) |message| try std.testing.expectEqualStrings(case.payload, message.payload);
    }
    for (cases) |case| {
        var stream = try client.startStreaming(.{ .path = "/demo.Fallback/Stream", .authority = "localhost", .timeout = .{ .value = 3, .unit = .second } });
        defer stream.deinit();
        try stream.writeMessage("");
        var collector: Collector = .{ .expected = case.payload };
        var response = try stream.finishAndRead(&collector, Collector.consume);
        defer response.deinit();
        try check(response, case);
        try std.testing.expectEqual(case.messages, collector.count);
    }
    for (cases) |case| {
        var stream = try client.startDuplex(.{ .path = "/demo.Fallback/Duplex", .authority = "localhost", .timeout = .{ .value = 3, .unit = .second } });
        defer stream.deinit();
        try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeMessage(""));
        try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.finishRequest());
        var collector: Collector = .{ .expected = case.payload };
        while (true) {
            var event = try stream.readResponseEvent(&collector, Collector.consume);
            defer event.deinit(allocator);
            if (event == .terminal) {
                try check(event.terminal, case);
                break;
            }
        }
        try std.testing.expectEqual(case.messages, collector.count);
    }
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

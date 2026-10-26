const std = @import("std");
const grpc = @import("../mod.zig");
const h2 = @import("../../http2/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

const bytes = "\x08\x07\x12\x06denied\x1a\x08\x0a\x03url\x12\x01\xff";
const invalid_trailers = [_]h2.Hpack.HeaderField{
    .{ .name = "grpc-status", .value = "16" },
    .{ .name = "grpc-status-details-bin", .value = "CAc" },
};

test "gRPC status details RPC matrix over h2c preserves channel reuse" {
    try run(false);
}
test "gRPC status details RPC matrix over pinned TLS preserves channel reuse" {
    try run(true);
}

fn consume(_: void, _: grpc.StreamingMessage) !void {}

fn check(value: grpc.status_details.Owned) !void {
    try std.testing.expectEqualSlices(u8, bytes, value.bytes);
    try std.testing.expectEqual(grpc.Status.permission_denied, value.view.code.?);
    var iterator = value.view.details();
    try std.testing.expectEqualSlices(u8, "\xff", (try iterator.next()).?.value);
}

fn run(comptime use_tls: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    const limits: h2.runtime.Limits = .{ .max_concurrent_streams = 1, .max_frame_payload = 64, .max_body_bytes = 4096 };
    var server = if (use_tls)
        try grpc.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .transport = .{
            .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } } },
            .limits = limits,
        } })
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
            for (0..2) |index| {
                var request = try connection.readUnaryWithTimeout(.fromSeconds(3));
                defer request.deinit();
                if (index == 0) {
                    try std.testing.expectError(error.StatusDetailsMismatch, connection.writeUnary(request.request.stream_id, .{ .status = .unauthenticated, .status_details = bytes, .trailers_only = true }));
                    try connection.writeUnary(request.request.stream_id, .{ .status = .permission_denied, .status_details = bytes, .trailers_only = true });
                } else {
                    // Send a deliberately inconsistent peer response through
                    // the HTTP transport, bypassing gRPC sender validation.
                    try connection.connection.writeResponse(request.request.stream_id, .{ .headers = &.{
                        .{ .name = "content-type", .value = "application/grpc+proto" }, invalid_trailers[0], invalid_trailers[1],
                    } });
                }
            }
            for (0..2) |index| {
                var request = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
                defer request.deinit();
                var response = try connection.startStreamingResponse(request.transport.stream_id, .{});
                defer response.deinit();
                try response.writeMessage("before-error");
                if (index == 0) {
                    try std.testing.expectError(error.InvalidStatusDetails, response.finishWithOptions(.{ .status = .ok, .status_details = bytes }));
                    try response.finishWithOptions(.{ .status = .permission_denied, .status_details = bytes, .retry_pushback_ms = -1 });
                } else try response.transport.finishTrailers(&invalid_trailers);
            }
            for (0..3) |index| {
                var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
                defer stream.deinit();
                while (!stream.requestFinished()) {
                    var event = try stream.readRequestEventWithTimeout(.fromSeconds(3), {}, consume);
                    defer event.deinit();
                }
                if (index == 0) {
                    try std.testing.expectError(error.StatusDetailsMismatch, stream.finishWithOptions(.{ .status = .unauthenticated, .status_details = bytes }));
                    try stream.finishWithOptions(.{ .status = .permission_denied, .status_details = bytes });
                } else {
                    try stream.startResponse(.{});
                    if (index == 1) try stream.finishWithOptions(.{ .status = .permission_denied, .status_details = bytes }) else try stream.transport.finishResponseTrailers(&invalid_trailers);
                }
            }
            var final = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer final.deinit();
            try connection.writeUnary(final.request.stream_id, .{ .message = "reused" });
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
    var unary = try client.unary(.{ .path = "/demo.Errors/Unary", .message = "request", .timeout = .{ .value = 3, .unit = .second } });
    defer unary.deinit();
    try check(unary.status_details.?);
    try std.testing.expectError(error.StatusDetailsMismatch, client.unary(.{ .path = "/demo.Errors/Unary", .message = "request", .timeout = .{ .value = 3, .unit = .second } }));
    for (0..2) |index| {
        var stream = try client.startStreaming(.{ .path = "/demo.Errors/Stream", .timeout = .{ .value = 3, .unit = .second } });
        defer stream.deinit();
        try stream.writeMessage("request");
        try stream.finish();
        if (index == 0) {
            var response = try stream.readResponse({}, consume);
            defer response.deinit();
            try check(response.status_details.?);
            try std.testing.expectEqualStrings("-1", grpc.call.headerValue(response.transport.?.trailers, "grpc-retry-pushback-ms").?);
        } else try std.testing.expectError(error.StatusDetailsMismatch, stream.readResponse({}, consume));
    }
    for (0..3) |index| {
        var stream = try client.startDuplex(.{ .path = "/demo.Errors/Duplex", .timeout = .{ .value = 3, .unit = .second } });
        defer stream.deinit();
        try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.finishRequest());
        while (true) {
            var event = stream.readResponseEvent({}, consume) catch |err| {
                if (index != 2) return err;
                try std.testing.expectEqual(error.StatusDetailsMismatch, err);
                break;
            };
            defer event.deinit(allocator);
            if (event == .terminal) {
                try std.testing.expect(index != 2);
                try check(event.terminal.status_details.?);
                break;
            }
        }
    }
    var final = try client.unary(.{ .path = "/demo.Errors/Unary", .message = "request", .timeout = .{ .value = 3, .unit = .second } });
    defer final.deinit();
    try std.testing.expectEqualStrings("reused", final.message.?.payload);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

const std = @import("std");
const grpc = @import("../../mod.zig");
const http = @import("../../../http2/mod.zig");
const tls = @import("../../../tls/mod.zig");
const frame_wire = @import("../../../http2/runtime/frame/wire.zig");
const adapter = @import("mod.zig");
const allocator = std.testing.allocator;
const options: adapter.Options = .{ .cors_policy = .{ .allowed_origins = &.{"https://app.example"}, .allow_credentials = true } };

test "gRPC-Web HTTP/2 dispatch handles CORS and rejects requests with one peer stream slot" {
    try exercise(false);
    try exercise(true);
}

fn exercise(comptime encrypted: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    const Server = if (encrypted) grpc.runtime.TlsServer else grpc.runtime.Server;
    const limits: http.runtime.Limits = .{ .max_concurrent_streams = 1 };
    var server = if (encrypted)
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_message_size = 4, .transport = .{
            .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
            .limits = limits,
        } })
    else
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits, 4);
    defer server.deinit();
    const Peer = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            try std.testing.expectError(error.Timeout, connection.readWebRequestWithTimeout(options, .zero));
            for ([_]u16{ 204, 403, 400, 405, 415, 406, 413 }) |status| {
                const result = try connection.readWebRequestWithTimeout(options, .fromSeconds(2));
                try std.testing.expectEqual(status, result.handled.status);
                try std.testing.expectEqual(@as(usize, 0), connection.connection.active_peer_streams.items.len);
            }
            var unary = (try connection.readWebRequest(options)).request;
            defer unary.deinit();
            try std.testing.expectEqualStrings("ping", unary.request.message.payload);
            try std.testing.expect(unary.content_type.text);
            try std.testing.expectError(error.InvalidMetadata, unary.writeUnary(.{ .message = "pong", .initial_metadata = &.{.{ .name = "access-control-allow-origin", .value = "*" }} }));
            try unary.writeUnary(.{ .message = "pong" });

            var streamed = (try connection.readWebRequestWithDeadline(options, .fromNow(ioFrom(&connection), .{ .raw = .fromSeconds(2), .clock = .awake }))).request;
            defer streamed.deinit();
            var writer = try streamed.startServerStream(.{});
            defer writer.deinit();
            try writer.writeMessage("one");
            try writer.writeMessage("two");
            try writer.finish(.{ .status = .ok, .retry_pushback_ms = 23 });

            var dropped = (try connection.readWebRequest(options)).request;
            dropped.deinit();
            try std.testing.expectEqual(@as(usize, 0), connection.connection.active_peer_streams.items.len);
            var last = (try connection.readWebRequest(options)).request;
            defer last.deinit();
            try last.writeUnary(.{ .message = "last" });
        }
        fn ioFrom(connection: *grpc.runtime.ServerConnection) std.Io {
            return connection.connection.io;
        }
    };
    var peer: Peer = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = if (encrypted)
        try grpc.runtime.Client.connectTlsHost(allocator, io, "localhost", server.address().ip4.port, .{ .limits = limits, .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() } } })
    else
        try grpc.runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.deinit();
    const prefix = [_]u8{ 0, 0, 0, 0, 4, 'p', 'i', 'n', 'g' };
    {
        var response = try client.connection.request(.{ .method = "OPTIONS", .path = "/demo.Echo/Unary", .authority = "localhost", .headers = &.{
            .{ .name = "origin", .value = "https://app.example" },                              .{ .name = "access-control-request-method", .value = "POST" },
            .{ .name = "access-control-request-headers", .value = "content-type, x-grpc-web" },
        } });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 204), response.status);
        try std.testing.expectEqualStrings("https://app.example", grpc.call.headerValue(response.headers, "access-control-allow-origin").?);
    }
    const cases = [_]struct { method: []const u8 = "POST", media: []const u8 = "application/grpc-web", origin: []const u8 = "https://app.example", accept: []const u8 = "application/grpc-web", body: []const u8 = "", status: u16 }{
        .{ .origin = "https://evil.example", .body = &prefix, .status = 403 },
        .{ .body = "", .status = 400 },
        .{ .method = "GET", .status = 405 },
        .{ .media = "application/grpc", .status = 415 },
        .{ .accept = "application/json", .status = 406 },
        .{ .body = &.{ 0, 0, 0, 0, 5, 'l', 'a', 'r', 'g', 'e' }, .status = 413 },
    };
    for (cases) |case| {
        var response = try client.connection.request(.{ .method = case.method, .path = "/demo.Echo/Unary", .authority = "localhost", .headers = &.{
            .{ .name = "content-type", .value = case.media }, .{ .name = "origin", .value = case.origin }, .{ .name = "accept", .value = case.accept },
        }, .body = case.body });
        defer response.deinit(allocator);
        try std.testing.expectEqual(case.status, response.status);
        if (case.status == 403) try std.testing.expect(grpc.call.headerValue(response.headers, "access-control-allow-origin") == null);
    }
    {
        var response = try client.connection.request(.{ .method = "POST", .path = "/demo.Echo/Unary", .authority = "localhost", .headers = &.{
            .{ .name = "content-type", .value = "application/grpc-web" }, .{ .name = "origin", .value = "https://app.example" }, .{ .name = "accept", .value = "application/grpc-web-text" },
        }, .body = &prefix });
        defer response.deinit(allocator);
        const body = try grpc.web.base64DecodeAlloc(allocator, response.body);
        defer allocator.free(body);
        try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 4, 'p', 'o', 'n', 'g' }, body[0..9]);
    }
    {
        var response = try client.connection.request(.{ .method = "POST", .path = "/demo.Echo/Stream", .authority = "localhost", .headers = &.{
            .{ .name = "content-type", .value = "application/grpc-web-text" }, .{ .name = "origin", .value = "https://app.example" }, .{ .name = "accept", .value = "application/grpc-web" },
        }, .body = "AAAAAAQ=cGluZw==" });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), response.trailers.len);
        try std.testing.expectEqualStrings("one", response.body[5..8]);
        try std.testing.expectEqualStrings("two", response.body[13..16]);
        try std.testing.expectEqual(@as(u8, 0x80), response.body[16]);
        try std.testing.expectEqualStrings("grpc-status:0\r\ngrpc-retry-pushback-ms:23\r\n", response.body[21..]);
    }
    const request: http.runtime.RequestOptions = .{ .method = "POST", .path = "/demo.Echo/Drop", .authority = "localhost", .headers = &.{.{ .name = "content-type", .value = "application/grpc-web" }}, .body = &prefix };
    try std.testing.expectError(error.StreamReset, client.connection.requestWithTimeout(request, .fromSeconds(2)));
    var last = try client.connection.request(request);
    defer last.deinit(allocator);
    try std.testing.expectEqualStrings("last", last.body[5..9]);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "gRPC-Web HTTP/2 allocation failures release admitted request ownership" {
    try std.testing.checkAllAllocationFailures(allocator, allocationCase, .{});
}

fn allocationCase(failing: std.mem.Allocator) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const socket = try listener.accept(io);
    var connection: http.runtime.Connection = .{ .allocator = failing, .io = io, .stream = socket, .role = .server };
    defer connection.close();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "POST" },                           .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },                   .{ .name = ":path", .value = "/demo.Echo/Unary" },
        .{ .name = "content-type", .value = "application/grpc-web-text" }, .{ .name = "origin", .value = "https://app.example" },
    });
    try frame_wire.appendFrame(&connection.frame_reader.buffer, failing, .headers, 4, 1, block.items);
    try frame_wire.appendFrame(&connection.frame_reader.buffer, failing, .data, 1, 1, "AAAAAAQ=cGluZw==");
    var request = (try adapter.readRequest(&connection, options)).request;
    defer request.deinit();
    try std.testing.expectEqualStrings("ping", request.request.message.payload);
    try request.writeUnary(.{ .message = "pong" });
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
}

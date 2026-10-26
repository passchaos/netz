const std = @import("std");
const http = @import("../../../http1/mod.zig");
const grpc = @import("../../mod.zig");
const tls = @import("../../../tls/mod.zig");
const adapter = @import("mod.zig");

const allocator = std.testing.allocator;
const options: adapter.Options = .{ .max_message_size = 1024, .cors_policy = .{
    .allowed_origins = &.{"https://app.example"},
    .allow_credentials = true,
    .exposed_headers = &.{ "grpc-status", "grpc-message", "x-initial" },
} };

test "gRPC-Web HTTP/1.1 preflight unary text streaming and rejection reuse TCP and TLS" {
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
    const Server = if (encrypted) http.runtime.TlsServer else http.runtime.Server;
    var server = if (encrypted)
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
        } })
    else
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
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
            defer connection.close();
            for ([_]u16{ 204, 403, 403, 415, 400 }) |expected| {
                const result = try adapter.readRequest(&connection, options);
                try std.testing.expectEqual(expected, result.handled.status);
            }
            var binary = (try adapter.readRequest(&connection, options)).request;
            defer binary.deinit();
            try std.testing.expectEqualStrings("ping", binary.request.message.payload);
            try std.testing.expect(binary.content_type.text);
            var scratch: [8]u8 = undefined;
            var metadata = try grpc.BinaryMetadataIterator.init(binary.request.headers, "x-tag-bin", &scratch);
            try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, (try metadata.next()).?.value);
            try binary.writeUnary(.{ .message = "pong", .initial_metadata = &.{.{ .name = "x-initial", .value = "visible" }}, .trailing_metadata = &.{.{ .name = "x-end", .value = "7" }} });
            try std.testing.expectError(error.InvalidStreamState, binary.writeUnary(.{ .message = "twice" }));

            var text_request = (try adapter.readRequest(&connection, options)).request;
            defer text_request.deinit();
            try std.testing.expect(!text_request.content_type.text);
            try std.testing.expectEqualStrings("ping", text_request.request.message.payload);
            try text_request.writeUnary(.{ .message = "a" ** 512, .compression = .gzip });

            var streaming = (try adapter.readRequest(&connection, options)).request;
            defer streaming.deinit();
            var writer = try streaming.startServerStream(.{});
            defer writer.deinit();
            try std.testing.expectError(error.GrpcMessageTooLarge, writer.writeMessage("x" ** 1025));
            for ([_][]const u8{ "one", "two", "three" }) |message| try writer.writeMessage(message);
            try std.testing.expectError(error.InvalidMetadata, writer.finish(.{ .status = .ok, .trailing_metadata = &.{.{ .name = "grpc-status", .value = "7" }} }));
            try writer.finish(.{ .status = .ok, .trailing_metadata = &.{.{ .name = "x-end", .value = "stream" }} });

            var rejected = (try adapter.readRequest(&connection, options)).request;
            defer rejected.deinit();
            try rejected.writeUnary(.{ .status = .unauthenticated, .status_message = "bad token", .trailers_only = true, .retry_pushback_ms = -1 });
        }
    };
    var peer: Peer = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = if (encrypted)
        try http.runtime.Client.connectVailTlsHost(allocator, io, "localhost", server.address().ip4.port, .{}, .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .alpn_protocols = &.{"http/1.1"},
        })
    else
        try http.runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    {
        var response = try client.request(.{ .host = "localhost", .method = .OPTIONS, .target = "/demo.Echo/Unary", .headers = &.{
            .{ .name = "Origin", .value = "https://app.example" },
            .{ .name = "Access-Control-Request-Method", .value = "POST" },
            .{ .name = "Access-Control-Request-Headers", .value = "content-type, authorization, x-grpc-web" },
        } });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 204), response.response.status);
        try std.testing.expectEqualStrings("POST", response.response.header("access-control-allow-methods").?);
        try std.testing.expectEqualStrings("true", response.response.header("access-control-allow-credentials").?);
    }
    for ([_]struct { origin: []const u8, media: []const u8, body: []const u8, status: u16 }{
        .{ .origin = "https://evil.example", .media = "application/grpc-web", .body = "bad", .status = 403 },
        .{ .origin = "null", .media = "application/grpc-web", .body = "bad", .status = 403 },
        .{ .origin = "https://app.example", .media = "application/grpc", .body = "bad", .status = 415 },
        .{ .origin = "https://app.example", .media = "application/grpc-web", .body = "", .status = 400 },
    }) |case| {
        var response = try client.request(.{ .host = "localhost", .method = .POST, .target = "/demo.Echo/Unary", .body = case.body, .headers = &.{
            .{ .name = "Origin", .value = case.origin }, .{ .name = "Content-Type", .value = case.media },
        } });
        defer response.deinit(allocator);
        try std.testing.expectEqual(case.status, response.response.status);
        if (case.status == 403) try std.testing.expect(response.response.header("access-control-allow-origin") == null);
    }
    const framed = [_]u8{ 0, 0, 0, 0, 4, 'p', 'i', 'n', 'g' };
    {
        var response = try client.request(.{ .host = "localhost", .method = .POST, .target = "/demo.Echo/Unary", .body = &framed, .headers = &.{
            .{ .name = "Content-Type", .value = "application/grpc-web+proto" }, .{ .name = "Origin", .value = "https://app.example" },
            .{ .name = "Accept", .value = "application/grpc-web-text" },        .{ .name = "X-Tag-Bin", .value = "AQI" },
        } });
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("application/grpc-web-text", response.response.header("content-type").?);
        try std.testing.expectEqualStrings("https://app.example", response.response.header("access-control-allow-origin").?);
        try std.testing.expectEqualStrings("visible", response.response.header("x-initial").?);
        const body = try grpc.web.base64DecodeAlloc(allocator, response.response.body);
        defer allocator.free(body);
        try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 4, 'p', 'o', 'n', 'g' }, body[0..9]);
        try std.testing.expectEqual(@as(u8, 0x80), body[9]);
    }
    {
        var response = try client.request(.{ .host = "localhost", .method = .POST, .target = "/demo.Echo/Unary", .body = "AAAAAAQ=cGluZw==", .headers = &.{
            .{ .name = "Content-Type", .value = "application/grpc-web-text" }, .{ .name = "Accept", .value = "application/grpc-web" },
            .{ .name = "grpc-accept-encoding", .value = "gzip" },
        } });
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("gzip", response.response.header("grpc-encoding").?);
        const len = std.mem.readInt(u32, response.response.body[1..5], .big);
        var decoded = try grpc.decompressMessageAlloc(allocator, .gzip, response.response.body[5..][0..len], 1024);
        defer decoded.deinit(allocator);
        try std.testing.expectEqualStrings("a" ** 512, decoded.bytes);
    }
    {
        var response = try client.request(.{ .host = "localhost", .method = .POST, .target = "/demo.Echo/Stream", .body = &framed, .headers = &.{
            .{ .name = "content-type", .value = "application/grpc-web" }, .{ .name = "accept", .value = "application/grpc-web-text" },
        } });
        defer response.deinit(allocator);
        try std.testing.expectEqual(http.BodyFraming.chunked, response.response.body_framing);
        try std.testing.expectEqual(@as(usize, 0), response.response.trailers.len);
        const body = try grpc.web.base64DecodeAlloc(allocator, response.response.body);
        defer allocator.free(body);
        var offset: usize = 0;
        for ([_][]const u8{ "one", "two", "three" }) |expected| {
            try std.testing.expectEqualStrings(expected, body[offset + 5 ..][0..expected.len]);
            offset += 5 + expected.len;
        }
        try std.testing.expectEqual(@as(u8, 0x80), body[offset]);
        try std.testing.expectEqualStrings("grpc-status:0\r\nx-end:stream\r\n", body[offset + 5 ..]);
    }
    {
        var response = try client.request(.{ .host = "localhost", .method = .POST, .target = "/demo.Echo/Denied", .body = &framed, .headers = &.{
            .{ .name = "content-type", .value = "application/grpc-web" }, .{ .name = "Connection", .value = "close" },
        } });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), response.response.body.len);
        try std.testing.expectEqualStrings("16", response.response.header("grpc-status").?);
        try std.testing.expectEqualStrings("-1", response.response.header("grpc-retry-pushback-ms").?);
        try std.testing.expect(!client.isReusable());
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "gRPC-Web HTTP/1.1 allocation failures retire consumed requests and free ownership" {
    try std.testing.checkAllAllocationFailures(allocator, allocationCase, .{});
}

fn allocationCase(failing: std.mem.Allocator) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const socket = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection: http.runtime.Connection = .{ .io = io, .allocator = failing, .stream = socket };
    defer {
        connection.close();
    }
    try connection.inbuf.appendSlice(failing, "POST /demo.Echo/Unary HTTP/1.1\r\nHost:localhost\r\nContent-Type:application/grpc-web-text\r\nOrigin:https://app.example\r\nContent-Length:16\r\n\r\nAAAAAAQ=cGluZw==");
    const result = adapter.readRequest(&connection, options) catch |err| {
        if (connection.inbuf.items.len == 0) try std.testing.expectEqual(.unusable, connection.writer_state.phase);
        return err;
    };
    var request = result.request;
    try std.testing.expectEqualStrings("ping", request.request.message.payload);
    request.deinit();
    try std.testing.expectEqual(.unusable, connection.writer_state.phase);
}

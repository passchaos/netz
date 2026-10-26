const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

test "gRPC-Web text flushes each short message before the next write and reuses channel" {
    try flushAndReuse(false);
    try flushAndReuse(true);
}

fn flushAndReuse(comptime encrypted: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    const Server = if (encrypted) grpc.runtime.TlsServer else grpc.runtime.Server;
    var server = if (encrypted)
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_message_size = 1024, .transport = .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } } })
    else
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 1024);
    defer server.deinit();
    const messages = [_][]const u8{ "", "aa", "abc" };
    const Shared = struct {
        server: *Server,
        acknowledgments: [messages.len]std.Io.Event = @splat(.unset),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            const Counter = struct {
                count: usize = 0,
                fn consume(counter_self: *@This(), message: grpc.StreamingMessage) !void {
                    try std.testing.expectEqualStrings("ping", message.payload);
                    counter_self.count += 1;
                }
            };
            var counter: Counter = .{};
            var request = try connection.readStreamingWeb(&counter, Counter.consume);
            defer request.deinit();
            try std.testing.expectEqual(@as(usize, 1), counter.count);
            try std.testing.expect(request.content_type.text);
            var writer = try connection.startStreamingWeb(request.request.transport.stream_id, .{}, request.content_type);
            defer writer.deinit();
            for (messages, 0..) |message, index| {
                try writer.writeMessage(message);
                // No sleeps: the client must decode this entire message while
                // the server is waiting, before either another write or FIN.
                try self.acknowledgments[index].waitTimeout(connection.connection.io, .{ .duration = .{
                    .raw = .fromSeconds(2),
                    .clock = .awake,
                } });
            }
            try std.testing.expectError(error.InvalidMetadata, writer.finish(.permission_denied, null, &.{.{ .name = "grpc-status", .value = "0" }}, &.{}));
            try writer.finish(.ok, null, &.{.{ .name = "x-result", .value = "done" }}, &.{});

            // The inverse negotiation on the same channel: decode a text
            // request, then respond in the binary wire requested by Accept.
            var unary = try connection.readUnaryWeb();
            defer unary.deinit();
            try std.testing.expect(!unary.content_type.text);
            try std.testing.expectEqualStrings("ping", unary.request.message.payload);
            try connection.writeUnaryWeb(unary.request.stream_id, .{ .message = "pong" }, unary.content_type);
        }
    };
    var shared: Shared = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = if (encrypted)
        try grpc.runtime.Client.connectTlsHost(allocator, io, "localhost", server.address().ip4.port, .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
        } } })
    else
        try grpc.runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.deinit();
    if (encrypted) try std.testing.expectEqualStrings("h2", client.negotiatedAlpn().?);

    const Collector = struct {
        shared: *Shared,
        io: std.Io,
        bytes: std.ArrayList(u8) = .empty,
        decoded_offset: usize = 0,
        message_count: usize = 0,

        fn begin(_: *@This(), head: http2.runtime.StreamingResponseHead) !void {
            try std.testing.expectEqual(@as(u16, 200), head.status);
            try std.testing.expectEqualStrings("application/grpc-web-text", grpc.call.headerValue(head.headers, "content-type").?);
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.bytes.appendSlice(std.testing.allocator, bytes);
            while (self.message_count < messages.len) {
                const payload = messages[self.message_count];
                const encoded_len = std.base64.standard.Encoder.calcSize(5 + payload.len);
                if (self.bytes.items.len - self.decoded_offset < encoded_len) return;
                var decoded: [16]u8 = undefined;
                // Independent standard base64 decode per flushed message,
                // rather than relying on the production text decoder.
                try std.base64.standard.Decoder.decode(decoded[0 .. 5 + payload.len], self.bytes.items[self.decoded_offset..][0..encoded_len]);
                try std.testing.expectEqual(@as(u8, 0), decoded[0]);
                try std.testing.expectEqual(@as(u32, @intCast(payload.len)), std.mem.readInt(u32, decoded[1..5], .big));
                try std.testing.expectEqualStrings(payload, decoded[5 .. 5 + payload.len]);
                self.shared.acknowledgments[self.message_count].set(self.io);
                self.decoded_offset += encoded_len;
                self.message_count += 1;
            }
        }
    };
    var collector: Collector = .{ .shared = &shared, .io = io };
    defer collector.bytes.deinit(allocator);
    const request_body = [_]u8{ 0, 0, 0, 0, 4, 'p', 'i', 'n', 'g' };
    var response = try client.connection.requestStreamingWithInformationalAndHeadAndTimeout(.{
        .method = "POST",
        .path = "/demo.Echo/Stream",
        .authority = "localhost",
        .headers = &.{
            .{ .name = "content-type", .value = "application/grpc-web" },
            .{ .name = "accept", .value = "application/grpc-web-text" },
        },
        .body = &request_body,
    }, null, .fromSeconds(5), &collector, Collector.begin, Collector.consume);
    defer response.deinit(allocator);
    try std.testing.expectEqual(messages.len, collector.message_count);
    try std.testing.expectEqual(@as(usize, 0), response.trailers.len);
    const terminal_wire = collector.bytes.items[collector.decoded_offset..];
    const terminal_size = try std.base64.standard.Decoder.calcSizeForSlice(terminal_wire);
    const terminal = try allocator.alloc(u8, terminal_size);
    defer allocator.free(terminal);
    try std.base64.standard.Decoder.decode(terminal, terminal_wire);
    try std.testing.expectEqual(@as(u8, 0x80), terminal[0]);
    try std.testing.expectEqual(@as(u32, @intCast(terminal.len - 5)), std.mem.readInt(u32, terminal[1..5], .big));
    try std.testing.expectEqualStrings("grpc-status:0\r\nx-result:done\r\n", terminal[5..]);

    var unary = try client.connection.request(.{
        .method = "POST",
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
        .headers = &.{
            .{ .name = "content-type", .value = "application/grpc-web-text" },
            .{ .name = "accept", .value = "application/grpc-web" },
        },
        .body = "AAAAAAQ=cGluZw==",
    });
    defer unary.deinit(allocator);
    try std.testing.expectEqualStrings("application/grpc-web", grpc.call.headerValue(unary.headers, "content-type").?);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 4, 'p', 'o', 'n', 'g' }, unary.body[0..9]);
    try std.testing.expectEqual(@as(u8, 0x80), unary.body[9]);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC-Web fragmented text uploads preserve bounds and reject only the failing stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{ .max_concurrent_streams = 1 };
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits, 4);
    defer server.deinit();
    const Case = struct { body: []const u8, err: ?anyerror, count: usize, accept: []const u8 = "application/grpc-web" };
    const cases = [_]Case{
        .{ .body = "AAAAAAQ=cGluZw==", .err = null, .count = 1 },
        .{ .body = "AAAAAAU=", .err = error.GrpcMessageTooLarge, .count = 0 },
        .{ .body = "AAAAAAQ=cGlu", .err = error.BufferTooShort, .count = 0 },
        .{ .body = "AAAAAAQ=cGluZw==%", .err = error.InvalidTextEncoding, .count = 1 },
        .{ .body = "AAAAAAQ=cGluZw==AAAAAAQ=cGluZw==", .err = error.InvalidMessageCount, .count = 1 },
        .{ .body = "AAAAAAQ=cGluZw==", .err = error.NoAcceptableWebContentType, .count = 0, .accept = "application/json" },
        .{ .body = "AAAAAAQ=cGluZw==", .err = null, .count = 1 },
    };
    const Shared = struct {
        server: *grpc.runtime.Server,
        err: ?anyerror = null,
        const Counter = struct {
            count: usize = 0,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                try std.testing.expectEqualStrings("ping", message.payload);
                self.count += 1;
            }
        };

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.deinit();
            for (cases) |case| {
                var counter: Counter = .{};
                const result = connection.readStreamingWebWithTimeout(.fromSeconds(2), &counter, Counter.consume);
                if (case.err) |expected| {
                    if (result) |value| {
                        var request = value;
                        request.deinit();
                        return error.TestExpectedError;
                    } else |err| try std.testing.expectEqual(expected, err);
                } else {
                    var request = try result;
                    defer request.deinit();
                    try std.testing.expect(!request.content_type.text);
                    var writer = try connection.startStreamingWeb(request.request.transport.stream_id, .{}, request.content_type);
                    defer writer.deinit();
                    try writer.writeMessage("pong");
                    try writer.finishOk();
                }
                try std.testing.expectEqual(case.count, counter.count);
            }
        }
    };
    var shared: Shared = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try grpc.runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.deinit();
    for (cases) |case| {
        var upload = try client.connection.startRequest(.{
            .method = "POST",
            .path = "/demo.Echo/Stream",
            .authority = "localhost",
            .headers = &.{
                .{ .name = "content-type", .value = "application/grpc-web-text" },
                .{ .name = "accept", .value = case.accept },
            },
        });
        defer upload.deinit();
        var offset: usize = 0;
        while (offset < case.body.len) {
            const take = @min(2, case.body.len - offset);
            try upload.write(case.body[offset..][0..take]);
            offset += take;
        }
        try upload.finish();
        if (case.err != null) {
            try std.testing.expectError(error.StreamReset, upload.readResponseWithTimeout(.fromSeconds(2)));
        } else {
            var response = try upload.readResponseWithTimeout(.fromSeconds(2));
            defer response.deinit(allocator);
            try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 4, 'p', 'o', 'n', 'g' }, response.body[0..9]);
        }
    }
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

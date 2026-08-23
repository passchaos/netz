const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http2_runtime = @import("../../http2/mod.zig").runtime;

const Server = runtime.Server;
const Client = runtime.Client;
const H2Server = runtime.H2Server;
const H2Client = runtime.H2Client;

test "WebSocket compression threshold skips compressor allocation" {
    const allocator = std.testing.allocator;
    const below = "compressible but below the configured threshold";
    const at_threshold = "threshold-compressible-" ** 16;
    const threshold = at_threshold.len;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = at_threshold.len,
            .max_message_bytes = at_threshold.len,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        below_uncompressed: bool = false,
        threshold_compressed: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .compression_threshold = threshold,
            });
            defer connection.close();
            var first = try connection.receiveFrame();
            defer first.deinit(self.server.http.allocator);
            self.below_uncompressed = !first.header.rsv1 and
                std.mem.eql(u8, first.payload, below);

            var second = try connection.receiveFrame();
            defer second.deinit(self.server.http.allocator);
            self.threshold_compressed = second.header.rsv1;
            const decoded = try websocket.decompressMessage(
                self.server.http.allocator,
                second.payload,
                at_threshold.len,
            );
            defer self.server.http.allocator.free(decoded);
            try std.testing.expectEqualStrings(at_threshold, decoded);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .enable_permessage_deflate = true,
        .compression_threshold = threshold,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = at_threshold.len,
            .max_message_bytes = at_threshold.len,
        },
    });
    defer client.close();
    try client.sendText(below);
    // The below-threshold fast path must not initialize or allocate the
    // connection's compressor scratch despite successful negotiation.
    try std.testing.expect(client.compression_send.encoder == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.compression_send.payload.capacity,
    );
    try client.sendText(at_threshold);
    try std.testing.expect(client.compression_send.encoder != null);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.below_uncompressed);
    try std.testing.expect(shared.threshold_compressed);
}

test "WebSocket server compression threshold is direction local" {
    const allocator = std.testing.allocator;
    const payload = "direction-local-compression-" ** 8;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        response_uncompressed: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .compression_threshold = std.math.maxInt(usize),
            });
            defer connection.close();
            var request = try connection.receiveMessage();
            defer request.deinit(self.server.http.allocator);
            try std.testing.expectEqualStrings(payload, request.payload);
            try connection.sendText(payload);
            try std.testing.expect(connection.compression_send.encoder == null);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();
    try client.sendText(payload);
    try std.testing.expect(client.compression_send.encoder != null);
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    shared.response_uncompressed = !response.header.rsv1 and
        std.mem.eql(u8, response.payload, payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.response_uncompressed);
}

test "WebSocket fragmented compression threshold uses aggregate message size" {
    const allocator = std.testing.allocator;
    const below = "fragment-below-threshold";
    const at_threshold = "fragment-threshold-compressible-" ** 8;
    const threshold = at_threshold.len;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = at_threshold.len,
            .max_message_bytes = at_threshold.len,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
            });
            defer connection.close();

            var first = try connection.receiveFrame();
            defer first.deinit(self.server.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, first.header.opcode);
            try std.testing.expect(!first.header.rsv1);
            try std.testing.expect(!first.header.fin);
            try std.testing.expectEqualStrings(below[0 .. below.len / 2], first.payload);

            var second = try connection.receiveFrame();
            defer second.deinit(self.server.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.continuation, second.header.opcode);
            try std.testing.expect(!second.header.rsv1);
            try std.testing.expect(second.header.fin);
            try std.testing.expectEqualStrings(below[below.len / 2 ..], second.payload);

            var compressed: std.ArrayList(u8) = .empty;
            defer compressed.deinit(self.server.http.allocator);
            for (0..2) |index| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(self.server.http.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 1, frame.header.fin);
                try compressed.appendSlice(self.server.http.allocator, frame.payload);
            }
            const decoded = try websocket.decompressMessage(
                self.server.http.allocator,
                compressed.items,
                at_threshold.len,
            );
            defer self.server.http.allocator.free(decoded);
            try std.testing.expectEqualStrings(at_threshold, decoded);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .enable_permessage_deflate = true,
        .compression_threshold = threshold,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = at_threshold.len,
            .max_message_bytes = at_threshold.len,
        },
    });
    defer client.close();
    // Threshold comparison is against the complete logical message, not each
    // application fragment, while preserving the requested frame count.
    try client.sendFragmented(.text, &.{
        below[0 .. below.len / 2],
        below[below.len / 2 ..],
    });
    try std.testing.expect(client.compression_send.encoder == null);
    try client.sendFragmented(.text, &.{
        at_threshold[0 .. at_threshold.len / 2],
        at_threshold[at_threshold.len / 2 ..],
    });
    try std.testing.expect(client.compression_send.encoder != null);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "RFC 8441 compression threshold propagates per direction" {
    const allocator = std.testing.allocator;
    const below = "h2-below-threshold";
    const at_threshold = "h2-threshold-compressible-" ** 10;
    const threshold = at_threshold.len;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(self.server.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .compression_threshold = std.math.maxInt(usize),
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                },
            });
            defer ws.close();

            var first = try ws.receiveFrame();
            defer first.deinit(self.server.allocator);
            try std.testing.expect(!first.header.rsv1);
            try std.testing.expectEqualStrings(below, first.payload);

            var second = try ws.receiveFrame();
            defer second.deinit(self.server.allocator);
            try std.testing.expect(second.header.rsv1);
            const decoded = try websocket.decompressMessage(
                self.server.allocator,
                second.payload,
                at_threshold.len,
            );
            defer self.server.allocator.free(decoded);
            try std.testing.expectEqualStrings(at_threshold, decoded);

            // A receive-only threshold must not disable negotiation or inbound
            // decompression, but it must leave this direction unallocated.
            try ws.sendText(at_threshold);
            try std.testing.expect(ws.compression_send.encoder == null);
            try std.testing.expectError(error.ConnectionClosed, ws.receiveMessage());
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/compression-threshold",
        .enable_permessage_deflate = true,
        .compression_threshold = threshold,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer ws_client.close();

    try ws_client.sendText(below);
    try std.testing.expect(ws_client.compression_send.encoder == null);
    try ws_client.sendText(at_threshold);
    try std.testing.expect(ws_client.compression_send.encoder != null);
    var response = try ws_client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expect(!response.header.rsv1);
    try std.testing.expectEqualStrings(at_threshold, response.payload);

    try ws_client.sendClose(.normal_closure, "bye");
    try std.testing.expectError(error.ConnectionClosed, ws_client.receiveMessage());
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

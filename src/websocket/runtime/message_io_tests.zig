const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Server = runtime.Server;
const Client = runtime.Client;
const Connection = runtime.Connection;

test "WebSocket receiveMessageInto assembles fragments in caller storage" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const max_message_bytes = 64;
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = max_message_bytes,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var storage: [max_message_bytes]u8 = undefined;
            const message = try connection.receiveMessageInto(&storage);
            try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
            try std.testing.expectEqualStrings(
                "hello fragmented",
                message.payload,
            );
            try connection.sendText(message.payload);
            try std.testing.expectError(
                error.BufferTooShort,
                connection.receiveMessageInto(storage[0..8]),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/message-into",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = max_message_bytes,
        },
    });
    defer client.close();

    try client.sendPing("?");
    try client.sendFragmented(
        .text,
        &.{ "hello ", "fragmented" },
    );
    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    var response_storage: [max_message_bytes]u8 = undefined;
    const response = try client.receiveMessageInto(&response_storage);
    try std.testing.expectEqualStrings("hello fragmented", response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessageInto preserves full message space across ping" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const max_message_bytes = 32;
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = max_message_bytes,
            .max_message_bytes = max_message_bytes,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            var storage: [max_message_bytes]u8 = undefined;
            const message = try connection.receiveMessageInto(&storage);
            try std.testing.expectEqual(
                @as(usize, max_message_bytes),
                message.payload.len,
            );
            for (message.payload, 0..) |byte, index| {
                try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/full-with-ping",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = max_message_bytes,
            .max_message_bytes = max_message_bytes,
        },
    });
    defer client.close();

    var payload: [max_message_bytes]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try websocket.writeFrameExtended(
        &encoded,
        allocator,
        .binary,
        payload[0..16],
        .{ .fin = false, .mask_key = .{ 1, 2, 3, 4 } },
    );
    try websocket.writeFrameExtended(
        &encoded,
        allocator,
        .ping,
        "control",
        .{ .mask_key = .{ 5, 6, 7, 8 } },
    );
    try websocket.writeFrameExtended(
        &encoded,
        allocator,
        .continuation,
        payload[16..],
        .{ .mask_key = .{ 9, 10, 11, 12 } },
    );
    try writeAllToStream(io, client.stream, encoded.items);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket sendBinaryInPlace masks caller storage and roundtrips" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const max_message_bytes = 64;
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = max_message_bytes,
            .max_message_bytes = max_message_bytes,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            var storage: [max_message_bytes]u8 = undefined;
            const message = try connection.receiveMessageInto(&storage);
            try std.testing.expectEqual(
                websocket.Opcode.binary,
                message.opcode,
            );
            try std.testing.expectEqualStrings("mutable payload", message.payload);
            try connection.sendBinary(message.payload);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/in-place",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = max_message_bytes,
            .max_message_bytes = max_message_bytes,
        },
    });
    defer client.close();

    var payload: [max_message_bytes]u8 = undefined;
    @memcpy(payload[0.."mutable payload".len], "mutable payload");
    const original = payload[0.."mutable payload".len].*;
    try client.sendBinaryInPlace(payload[0.."mutable payload".len]);
    try std.testing.expect(!std.mem.eql(
        u8,
        &original,
        payload[0.."mutable payload".len],
    ));
    var response_storage: [max_message_bytes]u8 = undefined;
    const response = try client.receiveMessageInto(&response_storage);
    try std.testing.expectEqualStrings("mutable payload", response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket permessage-deflate decodes into caller storage" {
    const allocator = std.testing.allocator;
    const payload =
        "caller-buffer compressed message " **
        8;
    const compressed = try websocket.compressMessage(
        allocator,
        payload,
    );
    defer allocator.free(compressed);
    const scratch = try allocator.alloc(
        u8,
        compressed.len + 9,
    );
    defer allocator.free(scratch);
    const window = try allocator.alloc(
        u8,
        std.compress.flate.max_window_len,
    );
    defer allocator.free(window);
    var output: [payload.len]u8 = undefined;
    const decoded = try websocket.decompressMessageInto(
        &output,
        compressed,
        scratch,
        window,
    );
    try std.testing.expectEqualStrings(payload, decoded);

    try std.testing.expectError(
        error.PayloadTooLarge,
        websocket.decompressMessageInto(
            output[0 .. output.len - 1],
            compressed,
            scratch,
            window,
        ),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        websocket.decompressMessageInto(
            &output,
            compressed,
            scratch[0 .. scratch.len - 1],
            window,
        ),
    );

    // Generated by Python zlib level 9 with wbits=-15 and Z_SYNC_FLUSH, then
    // stripping the RFC 7692 00 00 ff ff suffix. This exercises actual
    // compressed matches rather than only netz's interoperable stored blocks.
    const external_compressed = [_]u8{
        0x4a, 0xad, 0x28, 0x49, 0x2d, 0xca, 0x4b, 0xcc,
        0x51, 0x48, 0xa9, 0xcc, 0x4b, 0xcc, 0xcd, 0x4c,
        0x56, 0x48, 0x49, 0x4d, 0xcb, 0x49, 0x2c, 0x49,
        0x55, 0x28, 0x48, 0xac, 0xcc, 0xc9, 0x4f, 0x4c,
        0x51, 0x48, 0x1d, 0x55, 0x30, 0x92, 0x14, 0x00,
        0x00,
    };
    const external_plain =
        "external dynamic deflate payload " **
        16;
    var external_output: [external_plain.len]u8 = undefined;
    var external_scratch: [external_compressed.len + 9]u8 =
        undefined;
    const external_decoded = try websocket.decompressMessageInto(
        &external_output,
        &external_compressed,
        &external_scratch,
        window,
    );
    try std.testing.expectEqualStrings(
        external_plain,
        external_decoded,
    );
}

test "WebSocket permessage-deflate reuses receive scratch" {
    const allocator = std.testing.allocator;
    const payload = "reusable compressed caller buffer " ** 4;
    const compressed = try websocket.compressMessage(allocator, payload);
    defer allocator.free(compressed);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try websocket.writeFrameExtended(
        &encoded,
        allocator,
        .text,
        compressed,
        .{ .rsv1 = true },
    );
    try websocket.writeFrameExtended(
        &encoded,
        allocator,
        .text,
        compressed,
        .{ .rsv1 = true },
    );

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .permessage_deflate = true,
        .limits = .{
            .max_frame_bytes = 256,
            .max_message_bytes = 256,
        },
    };
    defer connection.inbuf.deinit(allocator);
    defer connection.compression_receive.deinit(allocator);
    try connection.inbuf.appendSlice(allocator, encoded.items);
    var storage: [256]u8 = undefined;
    const first = try connection.receiveMessageInto(&storage);
    try std.testing.expectEqualStrings(payload, first.payload);

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    connection.allocator = failing.allocator();
    failing.fail_index = failing.alloc_index;
    const second = try connection.receiveMessageInto(&storage);
    try std.testing.expectEqualStrings(payload, second.payload);
    try std.testing.expect(!failing.has_induced_failure);
    connection.allocator = allocator;
}

test "WebSocket compressed fragmented messages use caller storage" {
    const allocator = std.testing.allocator;
    const max_message_bytes = 512;
    const request_payload =
        "compressed fragmented caller message " **
        8;
    const response_payload =
        "compressed caller response " **
        8;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = max_message_bytes,
            .max_message_bytes = max_message_bytes,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self.server) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{
                .enable_permessage_deflate = true,
            });
            defer connection.close();
            var storage: [max_message_bytes]u8 = undefined;
            const message = try connection.receiveMessageInto(&storage);
            try std.testing.expectEqual(
                websocket.Opcode.text,
                message.opcode,
            );
            try std.testing.expectEqualStrings(
                request_payload,
                message.payload,
            );
            try connection.sendPing("compressed-control");
            try connection.sendFragmented(
                .text,
                &.{ response_payload[0..73], response_payload[73..] },
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "127.0.0.1",
            .target = "/compressed-message-into",
            .enable_permessage_deflate = true,
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = max_message_bytes,
                .max_message_bytes = max_message_bytes,
            },
        },
    );
    defer client.close();

    try client.sendPing("before-compressed");
    try client.sendFragmented(
        .text,
        &.{ request_payload[0..97], request_payload[97..] },
    );
    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);

    var response_storage: [max_message_bytes]u8 = undefined;
    const response = try client.receiveMessageInto(&response_storage);
    try std.testing.expectEqual(
        websocket.Opcode.text,
        response.opcode,
    );
    try std.testing.expectEqualStrings(
        response_payload,
        response.payload,
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessageInto buffered fast path does not allocate" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = failing.allocator();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try websocket.writeFrame(
        &encoded,
        allocator,
        .binary,
        "allocation-free",
        .{ .mask_key = .{ 1, 2, 3, 4 } },
    );

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    };
    defer connection.inbuf.deinit(allocator);
    try connection.inbuf.appendSlice(allocator, encoded.items);
    failing.fail_index = failing.alloc_index;

    var storage: [32]u8 = undefined;
    const message = try connection.receiveMessageInto(&storage);
    try std.testing.expectEqualStrings("allocation-free", message.payload);
    try std.testing.expect(!failing.has_induced_failure);
}

fn writeAllToStream(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

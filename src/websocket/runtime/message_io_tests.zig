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

test "WebSocket receiveMessageInto rejects compressed connections" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .permessage_deflate = true,
        .limits = .{ .max_message_bytes = 8 },
    };
    var storage: [8]u8 = undefined;
    try std.testing.expectError(
        error.InvalidFrame,
        connection.receiveMessageInto(&storage),
    );
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

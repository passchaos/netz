const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http2_runtime = @import("../../http2/mod.zig").runtime;

const Server = runtime.Server;
const Client = runtime.Client;
const H2Server = runtime.H2Server;
const H2Client = runtime.H2Client;

const invalid_masked_text = [_]u8{
    0x81, 0x82,
    0x01, 0x02,
    0x03, 0x04,
    0xc1, 0x82,
};

fn expectCloseCode(
    allocator: std.mem.Allocator,
    connection: anytype,
    expected: websocket.CloseCode,
) !void {
    var close = try connection.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectEqual(
        expected,
        (try websocket.parseClosePayload(close.payload)).?.code,
    );
}

test "WebSocket TCP receiver closes on protocol error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.receiveFrame() catch |err| {
                if (err != error.UnmaskedClientFrame) shared.err = err;
                return;
            };
            shared.err = error.ProtocolFailure;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/protocol-close",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    // Client frames must be masked. Bypass the normal writer to exercise the
    // receiving endpoint's RFC 6455 failure handshake.
    try writeAllToStream(io, client.stream, &.{ 0x81, 0x00 });
    try expectCloseCode(allocator, &client, .protocol_error);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket caller-buffer receiver closes on invalid UTF-8" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            var storage: [32]u8 = undefined;
            _ = connection.receiveMessageInto(&storage) catch |err| {
                if (err != error.InvalidUtf8) shared.err = err;
                return;
            };
            shared.err = error.ProtocolFailure;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/utf8-close",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    });
    defer client.close();

    try writeAllToStream(io, client.stream, &invalid_masked_text);
    try expectCloseCode(allocator, &client, .invalid_payload_data);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 receiver closes on invalid UTF-8" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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

        fn run(shared: *@This()) void {
            var h2 = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer h2.close();
            var connection = H2Server.accept(
                shared.server.allocator,
                &h2,
                .{ .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 32,
                    .max_message_bytes = 32,
                } },
            ) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.receiveMessage() catch |err| {
                if (err != error.InvalidUtf8) shared.err = err;
                return;
            };
            shared.err = error.ProtocolFailure;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/h2-utf8-close",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    });
    defer client.close();

    try client.tunnel.write(&invalid_masked_text, false);
    try expectCloseCode(allocator, &client, .invalid_payload_data);
    thread.join();
    if (shared.err) |err| return err;
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

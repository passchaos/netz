const builtin = @import("builtin");
const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    if (comptime builtin.os.tag != .linux) {
        std.debug.print("linux io_uring WebSocket example is only available on Linux\n", .{});
        return;
    }

    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.websocket.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.websocket.runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *netz.websocket.runtime.Server) !void {
            var connection = try server_ptr.accept(.{
                .protocols = &.{"chat.v1"},
                .enable_permessage_deflate = true,
            });
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            std.debug.print("io_uring WebSocket server received: {s}\n", .{request.payload});
            try connection.sendFragmented(.text, &.{ "hello ", "through ", "websocket io_uring" });

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            if (close.header.opcode != .close) return error.InvalidFrame;
        }
    };

    var ring = std.os.linux.IoUring.init(16, 0) catch |err| switch (err) {
        error.PermissionDenied, error.SystemOutdated => {
            std.debug.print("io_uring unavailable on this kernel/container: {s}\n", .{@errorName(err)});
            return;
        },
        else => |e| return e,
    };
    defer ring.deinit();

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://127.0.0.1:{d}/uring-ws", .{server.address().ip4.port});
    defer allocator.free(uri);

    var client = try netz.websocket.runtime.Client.connectUriLinuxIoUring(allocator, io, &ring, uri, .{
        .protocols = &.{"chat.v1"},
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("hello websocket io_uring");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    std.debug.print("io_uring WebSocket client received: {s}\n", .{response.payload});
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

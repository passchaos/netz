const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Zig 0.16 exposes std.Io.Uring on Linux, but its std.Io networking
    // vtable currently marks listen/connect/read/write as unavailable.  These
    // protocol runtimes accept any std.Io backend, so this can switch to Uring
    // once Zig wires networking into that backend; today Threaded is the
    // portable backend that can actually drive TCP.
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

            std.debug.print("WebSocket server selected subprotocol {s}\n", .{connection.selected_protocol orelse "(none)"});
            var message = try connection.receiveMessage();
            defer message.deinit(server_ptr.http.allocator);
            std.debug.print("WebSocket server received: {s}\n", .{message.payload});

            // Tungstenite's examples echo text/binary frames; this sends a text
            // response through the same negotiated RFC 6455 connection.
            try connection.sendText("echo from netz websocket");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            if (close.header.opcode != .close) return error.InvalidFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://127.0.0.1:{d}/chat", .{server.address().ip4.port});
    defer allocator.free(uri);

    var client = try netz.websocket.runtime.Client.connectUri(allocator, io, uri, .{
        .protocols = &.{"chat.v1"},
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();

    std.debug.print("WebSocket client selected subprotocol {s}\n", .{client.selected_protocol orelse "(none)"});
    try client.sendText("hello websocket");

    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    std.debug.print("WebSocket client received: {s}\n", .{response.payload});

    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

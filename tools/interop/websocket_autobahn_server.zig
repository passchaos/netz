//! Long-lived RFC 6455 echo endpoint for Autobahn Testsuite fuzzingclient.
//!
//! Each accepted connection has an independent worker because Autobahn can
//! begin its next case before the prior peer's close handshake has completely
//! unwound. Protocol failures are expected test inputs and are handled by the
//! runtime's typed Close response rather than terminating this listener.

const std = @import("std");
const netz = @import("netz");

const max_message_bytes: usize = 20_000_000;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try netz.websocket.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = max_message_bytes,
            .max_message_bytes = max_message_bytes,
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz Autobahn WebSocket server listening on {f}\n",
        .{server.address()},
    );

    while (true) {
        var connection = server.accept(.{
            .enable_permessage_deflate = true,
        }) catch continue;
        const thread = std.Thread.spawn(
            .{},
            echoConnection,
            .{connection},
        ) catch {
            connection.close();
            continue;
        };
        thread.detach();
    }
}

fn echoConnection(initial: netz.websocket.runtime.Connection) void {
    var connection = initial;
    defer connection.close();
    while (true) {
        var message = connection.receiveMessage() catch return;
        defer message.deinit(connection.allocator);
        switch (message.opcode) {
            .text => connection.sendText(message.payload) catch return,
            .binary => connection.sendBinary(message.payload) catch return,
            else => return,
        }
    }
}

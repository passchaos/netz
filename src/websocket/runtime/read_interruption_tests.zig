//! Local executor interruptions preserve WebSocket wire and message ownership.
const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const allocator = std.testing.allocator;
const Mode = enum { frame, message, caller_buffer };
const support = @import("testing/read_interruption.zig");
const Fault = support.Fault;
const InterruptedIo = support.InterruptedIo;

test "WebSocket bounded read interruptions preserve fragmented frames and caller message ownership" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Fault)) |fault| {
            for ([_]bool{ false, true }) |partial| try exercise(mode, fault, partial);
        }
    }
}

fn exercise(mode: Mode, fault: Fault, partial: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base_io = threaded.io();
    InterruptedIo.delegate = base_io;
    defer InterruptedIo.next = null;
    var vtable = base_io.vtable.*;
    vtable.batchAwaitConcurrent = InterruptedIo.awaitConcurrent;
    const io = std.Io{ .userdata = base_io.userdata, .vtable = &vtable };
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base_io, .{ .reuse_address = true });
    defer listener.deinit(base_io);
    const stream = try listener.socket.address.connect(base_io, .{ .mode = .stream });
    var connection = runtime.testing.initDirectConnection(allocator, io, stream, .client, .{ .max_message_bytes = 64 });
    defer connection.close();
    const peer = try listener.accept(base_io);
    defer peer.close(base_io);
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try websocket.writeFrame(&first, allocator, .text, "accepted-\xe2", .{ .fin = false });
    const cut = if (partial) first.items.len - 3 else first.items.len;
    try connection.inbuf.appendSlice(allocator, first.items[0..cut]);
    var output: [64]u8 = undefined;
    if (mode == .frame and !partial) {
        var frame = try connection.receiveFrameWithTimeout(.fromSeconds(1));
        defer frame.deinit(allocator);
        try std.testing.expectEqualStrings("accepted-\xe2", frame.payload);
    }
    InterruptedIo.next = fault;
    const expected = if (fault == .executor) error.ConcurrencyUnavailable else error.Canceled;
    switch (mode) {
        .frame => try std.testing.expectError(expected, connection.receiveFrameWithTimeout(.fromSeconds(1))),
        .message => try std.testing.expectError(expected, connection.receiveMessageWithTimeout(.fromSeconds(1))),
        .caller_buffer => try std.testing.expectError(expected, connection.receiveMessageIntoWithTimeout(&output, .fromSeconds(1))),
    }
    try std.testing.expect(!connection.receive_failed.load(.acquire));
    try std.testing.expect(!connection.close_sent.load(.acquire));
    try std.testing.expect(!connection.write_aborted.load(.acquire));
    if (mode == .message) try std.testing.expect(connection.message_assembler != null);
    if (mode == .caller_buffer) try std.testing.expect(connection.message_into.active());
    var suffix: std.ArrayList(u8) = .empty;
    defer suffix.deinit(allocator);
    try suffix.appendSlice(allocator, first.items[cut..]);
    try websocket.writeFrame(&suffix, allocator, .continuation, "\x98\x83", .{});
    try websocket.writeFrame(&suffix, allocator, .binary, "following", .{});
    var writer = peer.writer(base_io, &.{});
    try writer.interface.writeAll(suffix.items);
    switch (mode) {
        .frame => {
            if (partial) {
                var frame = try connection.receiveFrameWithTimeout(.fromSeconds(1));
                defer frame.deinit(allocator);
                try std.testing.expectEqualStrings("accepted-\xe2", frame.payload);
            }
            var frame = try connection.receiveFrameWithTimeout(.fromSeconds(1));
            defer frame.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.continuation, frame.header.opcode);
            try std.testing.expectEqualStrings("\x98\x83", frame.payload);
        },
        .message => {
            var message = try connection.receiveMessageWithTimeout(.fromSeconds(1));
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("accepted-\xe2\x98\x83", message.payload);
        },
        .caller_buffer => {
            const message = try connection.receiveMessageIntoWithTimeout(&output, .fromSeconds(1));
            try std.testing.expectEqualStrings("accepted-\xe2\x98\x83", message.payload);
        },
    }
    var following = try connection.receiveMessageWithTimeout(.fromSeconds(1));
    defer following.deinit(allocator);
    try std.testing.expectEqualStrings("following", following.payload);
    try connection.sendBinary("still writable");
}

const std = @import("std");
const websocket = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const h3 = @import("../h3.zig");
const http2 = @import("../../../http2/mod.zig").runtime;
const quic = @import("../../../quic/mod.zig");
const common = @import("../common.zig");
const admission = @import("admission.zig");
const allocator = std.testing.allocator;
const support = @import("admission_test_support.zig");
const Read = support.Read;
const Receiver = support.Receiver;
const held = support.held;

fn exercise(connection: anytype, io: std.Io, role: runtime.Role, opcode: websocket.Opcode, payload: []const u8, read: Read, abort_writer: bool) !void {
    connection.close_sent.store(false, .release);
    connection.close_received.store(false, .release);
    connection.write_aborted.store(false, .release);
    connection.receive_failed.store(false, .release);
    connection.incoming_frame_validated = 0;
    connection.incoming_data_kind = .none;
    connection.incoming_text_utf8.reset();
    connection.message_into.reset();
    connection.message_frame_receive = .{};
    if (connection.message_assembler) |*assembler| assembler.deinit();
    connection.message_assembler = null;
    connection.inbuf_consumed = 0;
    connection.inbuf.clearRetainingCapacity();
    if (read != .frame) try websocket.writeFrame(&connection.inbuf, allocator, .binary, "first-", .{ .fin = false, .mask_key = if (role == .server) .{ 1, 2, 3, 4 } else null });
    try websocket.writeFrame(&connection.inbuf, allocator, opcode, payload, .{ .mask_key = if (role == .server) .{ 1, 2, 3, 4 } else null });
    if (opcode == .ping) try websocket.writeFrame(&connection.inbuf, allocator, if (read == .frame) .binary else .continuation, "following", .{ .mask_key = if (role == .server) .{ 5, 6, 7, 8 } else null });
    const Task = Receiver(@TypeOf(connection.*));
    var task = Task{ .connection = connection, .io = io, .read = read };
    try held(&task, false);
    try std.testing.expect(connection.pending_write.isNone());
    try std.testing.expect(connection.pending_auto_control == null);
    try std.testing.expect(connection.automatic_control_waiting.load(.acquire));
    const waiting = connection.automatic_control_admission.?;
    try std.testing.expectEqualSlices(u8, payload, switch (waiting.payload) {
        .frame => |frame| frame.payload,
        .copy => |*copy| copy.bytes[0..copy.len],
    });
    try std.testing.expectEqual(read == .frame, waiting.payload == .frame);
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    if (read == .into) {
        try std.testing.expectEqualStrings("first-", task.out[0..6]);
        var replacement: [32]u8 = undefined;
        try std.testing.expectError(error.BufferTooShort, connection.receiveMessageIntoWithDeadline(&replacement, until));
        try std.testing.expect(connection.automatic_control_waiting.load(.acquire));
        try std.testing.expectEqualStrings("first-", task.out[0..6]);
    }
    if (abort_writer) {
        // A writer may abort while the receiver's deadline is already spent.
        // It must leave the receive-owned frame to its owner for disposal.
        connection.send_mutex.lockUncancelable(io);
        connection.write_aborted.store(true, .release);
        common.clearPendingOutboundLocked(connection);
        connection.send_mutex.unlock(io);
        try std.testing.expect(connection.automatic_control_waiting.load(.acquire));
        connection.send_mutex.lockUncancelable(io);
        defer connection.send_mutex.unlock(io);
        try std.testing.expectError(error.ConnectionClosed, admission.admit(connection, io, role, false));
    } else {
        var progress: runtime.MessageWriteProgress = .{};
        try std.testing.expectError(error.WriteInProgress, connection.sendBinaryWithDeadline("new", &progress, until));
        try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
        // Suppress the reply as if a local Close completed during contention.
        // The peer event still belongs to the same receive mode exactly once.
        connection.close_sent.store(true, .release);
        if (read != .frame and opcode == .close) {
            try std.testing.expectError(error.ConnectionClosed, task.receive(until));
        } else {
            try task.receive(until);
            try std.testing.expectEqual(if (read == .frame) opcode else .binary, task.opcode);
            try std.testing.expectEqualStrings(if (read == .frame) payload else "first-following", task.result[0..task.result_len]);
            if (read == .frame and opcode == .ping) {
                try task.receive(until);
                try std.testing.expectEqual(websocket.Opcode.binary, task.opcode);
                try std.testing.expectEqualStrings("following", task.result[0..task.result_len]);
            }
        }
    }
    try std.testing.expect(connection.automatic_control_admission == null);
    try std.testing.expect(!connection.automatic_control_waiting.load(.acquire));
    try std.testing.expect(connection.pending_auto_control == null);
    try std.testing.expect(!connection.automatic_write_pending.load(.acquire));
}

fn matrix(connection: anytype, io: std.Io, role: runtime.Role) !void {
    defer {
        admission.clear(connection);
        if (connection.pending_auto_control) |*pending| pending.deinit(allocator);
        if (connection.message_assembler) |*assembler| assembler.deinit();
        connection.inbuf.deinit(allocator);
        connection.compression_receive.deinit(allocator);
        connection.compression_send.deinit(allocator);
    }
    var longest = [_]u8{'x'} ** 125;
    for ([_]websocket.Opcode{ .ping, .close }) |opcode| {
        longest[0] = if (opcode == .close) 3 else 'x';
        longest[1] = if (opcode == .close) 233 else 'x';
        for ([_][]const u8{ "", if (opcode == .ping) "peer probe" else "\x03\xe9diagnosis", &longest }) |payload| {
            for (std.enums.values(Read)) |read| try exercise(connection, io, role, opcode, payload, read, false);
        }
    }
    for (std.enums.values(Read)) |read| try exercise(connection, io, role, .ping, "peer probe", read, true);
}

test "WebSocket fresh automatic control admission preserves HTTP1 receive modes and ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    for (std.enums.values(runtime.Role)) |role| {
        var connection = runtime.Connection{ .allocator = allocator, .io = threaded.io(), .stream = undefined, .role = role, .limits = .{ .max_message_bytes = 32 } };
        try matrix(&connection, threaded.io(), role);
    }
}

test "WebSocket fresh automatic control admission preserves HTTP2 receive modes and ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var transport: http2.Connection = undefined;
    transport.io = threaded.io();
    for (std.enums.values(runtime.Role)) |role| {
        var connection = runtime.H2Connection{ .allocator = allocator, .tunnel = .{ .connection = &transport, .stream_id = 1 }, .role = role, .limits = .{ .max_message_bytes = 32 } };
        try matrix(&connection, threaded.io(), role);
    }
}

test "WebSocket fresh automatic control admission preserves HTTP3 receive modes and ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x35} ** quic.protection.secret_len);
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var connection = h3.Connection(role){ .allocator = allocator, .h3 = undefined, .stream_id = 0, .limits = .{ .max_message_bytes = 32 } };
        connection.h3.established.connection = try quic.one_rtt.Connection.init(&endpoint, .{ .peer = endpoint.address(), .receive_keys = keys, .send_keys = keys, .local_connection_id = "control-admission", .peer_connection_id = "control-peer", .local_endpoint = if (role == .client) .client else .server, .enable_pacing = false });
        defer connection.h3.established.connection.deinit();
        try matrix(&connection, threaded.io(), role);
    }
}

test "WebSocket fresh automatic control admission preserves real TCP reply order and aborted ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(runtime.Role)) |role| {
        for ([_]websocket.Opcode{ .ping, .close }) |opcode| {
            for (std.enums.values(Read)) |read| {
                const Scenario = enum { normal, retained_writer, aborted_writer };
                for (std.enums.values(Scenario)) |scenario| {
                    if (scenario == .retained_writer and read != .frame) continue;
                    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
                    defer listener.deinit(io);
                    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
                    const receiver = try listener.accept(io);
                    var peer = runtime.testing.initDirectConnection(allocator, io, sender, if (role == .client) .server else .client, .{});
                    defer peer.close();
                    var connection = runtime.testing.initDirectConnection(allocator, io, receiver, role, .{ .max_message_bytes = 32 });
                    defer connection.close();
                    const payload = if (opcode == .ping) "probe" else "\x03\xe9diagnosis";
                    var wire: std.ArrayList(u8) = .empty;
                    defer wire.deinit(allocator);
                    const mask: ?[4]u8 = if (role == .server) .{ 1, 2, 3, 4 } else null;
                    try websocket.writeFrame(&wire, allocator, opcode, payload, .{ .mask_key = mask });
                    if (opcode == .ping) try websocket.writeFrame(&wire, allocator, .binary, "following", .{ .mask_key = mask });
                    var writer = sender.writer(io, &.{});
                    try writer.interface.writeAll(wire.items);
                    const older_payload = "older application frame";
                    var task = Receiver(runtime.Connection){ .connection = &connection, .io = io, .read = read };
                    if (scenario == .retained_writer) {
                        try support.heldWithPartialWriter(&task, older_payload);
                    } else try held(&task, false);
                    try std.testing.expect(connection.automatic_control_waiting.load(.acquire));
                    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
                    if (scenario == .aborted_writer) {
                        connection.send_mutex.lockUncancelable(io);
                        connection.write_aborted.store(true, .release);
                        common.clearPendingOutboundLocked(&connection);
                        connection.send_mutex.unlock(io);
                        try std.testing.expectError(error.ConnectionClosed, task.receive(until));
                        try std.testing.expect(!admission.pending(&connection));
                        continue;
                    }
                    if (scenario == .retained_writer) {
                        var progress: runtime.MessageWriteProgress = .{};
                        try std.testing.expectError(error.WriteInProgress, connection.sendBinaryWithDeadline("replacement", &progress, until));
                        try connection.sendBinaryWithDeadline(older_payload, &progress, until);
                        try std.testing.expect(connection.automatic_control_waiting.load(.acquire));
                    }
                    if (read != .frame and opcode == .close) {
                        try std.testing.expectError(error.ConnectionClosed, task.receive(until));
                    } else {
                        try task.receive(until);
                        try std.testing.expectEqualStrings(if (read == .frame) payload else "following", task.result[0..task.result_len]);
                    }
                    if (scenario == .retained_writer) {
                        var older = try peer.receiveFrameWithDeadline(until);
                        defer older.deinit(allocator);
                        try std.testing.expectEqual(websocket.Opcode.binary, older.header.opcode);
                        try std.testing.expectEqualStrings(older_payload, older.payload);
                    }
                    var reply = try peer.receiveFrameWithDeadline(until);
                    defer reply.deinit(allocator);
                    try std.testing.expectEqual(if (opcode == .ping) websocket.Opcode.pong else .close, reply.header.opcode);
                    try std.testing.expectEqualStrings(payload, reply.payload);
                    try std.testing.expect(!admission.pending(&connection));
                    if (opcode == .ping) {
                        var progress: runtime.MessageWriteProgress = .{};
                        try connection.sendBinaryWithDeadline("marker", &progress, until);
                        var marker = try peer.receiveFrameWithDeadline(until);
                        defer marker.deinit(allocator);
                        try std.testing.expectEqual(websocket.Opcode.binary, marker.header.opcode);
                        try std.testing.expectEqualStrings("marker", marker.payload);
                    } else {
                        try std.testing.expectError(error.Timeout, peer.receiveFrameWithTimeout(.fromMilliseconds(20)));
                    }
                }
            }
        }
    }
}

test "WebSocket fresh automatic control admission retains each receive mode on cancellation" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(Read)) |read| {
        var connection = runtime.Connection{ .allocator = allocator, .io = io, .stream = undefined, .role = .client, .limits = .{ .max_message_bytes = 32 } };
        defer {
            admission.clear(&connection);
            if (connection.pending_auto_control) |*pending| pending.deinit(allocator);
            if (connection.message_assembler) |*assembler| assembler.deinit();
            connection.inbuf.deinit(allocator);
        }
        try websocket.writeFrame(&connection.inbuf, allocator, .ping, "probe", .{});
        try websocket.writeFrame(&connection.inbuf, allocator, .binary, "following", .{});
        var task = Receiver(runtime.Connection){ .connection = &connection, .io = io, .read = read, .timeout = .fromSeconds(1) };
        try held(&task, true);
        try std.testing.expect(connection.automatic_control_admission != null);
        try std.testing.expect(connection.automatic_control_waiting.load(.acquire));
        connection.close_sent.store(true, .release);
        try task.receive(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        try std.testing.expectEqualStrings(if (read == .frame) "probe" else "following", task.result[0..task.result_len]);
        try std.testing.expect(!admission.pending(&connection));
    }
}

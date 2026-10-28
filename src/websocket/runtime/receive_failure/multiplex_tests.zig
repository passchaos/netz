const std = @import("std");
const runtime = @import("../../runtime.zig");
const h3 = @import("../h3.zig");
const http2 = @import("../../../http2/mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const stream_io = @import("../../../internal/stream_io.zig");
const allocator = std.testing.allocator;

fn failWhileLocked(connection: anytype, io: std.Io) !void {
    try connection.inbuf.appendSlice(allocator, &.{ 0x83, 0 });
    connection.send_mutex.lockUncancelable(io);
    var locked = true;
    defer if (locked) connection.send_mutex.unlock(io);
    const Task = struct {
        connection: @TypeOf(connection),
        io: std.Io,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var frame = self.connection.receiveFrameWithTimeout(.fromMilliseconds(10)) catch |err| {
                self.err = err;
                self.done.set(self.io);
                return;
            };
            frame.deinit(allocator);
            self.done.set(self.io);
        }
    };
    var task = Task{ .connection = connection, .io = io };
    var future = try io.concurrent(Task.run, .{&task});
    defer _ = future.cancel(io);
    const observed = if (task.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } })) |_| true else |err| switch (err) {
        error.Timeout => false,
        else => return err,
    };
    connection.send_mutex.unlock(io);
    locked = false;
    future.await(io);
    try std.testing.expect(observed);
    try std.testing.expectEqual(@as(?anyerror, error.InvalidOpcode), task.err);
    try std.testing.expect(connection.receive_failed.load(.acquire));
    try std.testing.expect(connection.receive_abort_pending.load(.acquire));
}

fn failWithoutMask(connection: anytype, io: std.Io) !void {
    const Entropy = struct {
        fn fail(_: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
            return error.EntropyUnavailable;
        }
    };
    var table = io.vtable.*;
    table.randomSecure = Entropy.fail;
    const observed = std.Io{ .userdata = io.userdata, .vtable = &table };
    if (comptime @hasField(@TypeOf(connection.*), "tunnel")) {
        connection.tunnel.connection.io = observed;
    } else connection.h3.established.connection.endpoint.io = observed;
    defer {
        if (comptime @hasField(@TypeOf(connection.*), "tunnel")) {
            connection.tunnel.connection.io = io;
        } else connection.h3.established.connection.endpoint.io = io;
    }
    try connection.inbuf.appendSlice(allocator, &.{ 0x83, 0 });
    try std.testing.expectError(error.InvalidOpcode, connection.receiveFrameWithTimeout(.fromSeconds(1)));
    try std.testing.expect(connection.receive_failed.load(.acquire));
    try std.testing.expect(connection.write_aborted.load(.acquire));
}

test "WebSocket fatal receive cleanup defers HTTP2 reset without retiring a sibling" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(runtime.Role)) |role| {
        for ([_]bool{ false, true }) |mask_failure| {
            if (mask_failure and role != .client) continue;
            var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
            defer listener.deinit(io);
            const peer = try listener.socket.address.connect(io, .{ .mode = .stream });
            defer peer.close(io);
            const stream = try listener.accept(io);
            var parent = http2.runtime.Connection{ .allocator = allocator, .io = io, .stream = stream, .role = if (role == .client) .client else .server };
            defer parent.close();
            for ([_]u31{ 1, 3 }) |id| {
                if (role == .client) try http2.runtime.testing.addActiveLocalStream(&parent, id) else try http2.runtime.testing.addActivePeerStream(&parent, id);
            }
            var connection = runtime.H2Connection{ .allocator = allocator, .tunnel = .{ .connection = &parent, .stream_id = 1 }, .role = role };
            defer connection.close();
            if (mask_failure) try failWithoutMask(&connection, io) else try failWhileLocked(&connection, io);
            if (!mask_failure) try std.testing.expect(!connection.tunnel.released.load(.acquire));
            var progress: runtime.MessageWriteProgress = .{};
            const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.ConnectionClosed, connection.sendBinaryWithDeadline("late", &progress, until));
            try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
            try std.testing.expect(!connection.receive_abort_pending.load(.acquire));
            try std.testing.expect(connection.tunnel.released.load(.acquire));
            try std.testing.expect(!parent.aggregate_timeout_unusable);
            try std.testing.expect(!parent.terminal_write_failed);
            try std.testing.expect(if (role == .client) parent.active_local_index.contains(3) else parent.active_peer_index.contains(3));
            var storage: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
            var received: usize = 0;
            while (received < storage.len) {
                const count = try stream_io.readSomeWithDeadline(io, peer, storage[received..], until);
                try std.testing.expect(count != 0);
                received += count;
            }
            const reset = try http2.ResetStreamPayload.parse(try http2.Frame.parse(&storage));
            try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
        }
    }
}

test "WebSocket fatal receive cleanup defers HTTP3 cancellation without resetting a sibling" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x47} ** quic.protection.secret_len);
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        for ([_]bool{ false, true }) |mask_failure| {
            if (mask_failure and role != .client) continue;
            var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
            defer endpoint.deinit();
            var peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
            defer peer_endpoint.deinit();
            var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{ .peer = endpoint.address(), .receive_keys = keys, .send_keys = keys, .local_connection_id = "fatal-peer", .peer_connection_id = "fatal-local", .local_endpoint = if (role == .client) .server else .client, .enable_pacing = false });
            defer peer.deinit();
            var established = try quic.handshake.establishPreconfigured(&endpoint, peer_endpoint.address(), if (role == .client) .client else .server, .{ .receive_keys = keys, .send_keys = keys, .local_connection_id = "fatal-local", .peer_connection_id = "fatal-peer", .one_rtt = .{ .enable_pacing = false } });
            var owned = true;
            defer if (owned) established.deinit();
            var connection = h3.Connection(role){ .allocator = allocator, .stream_id = 0, .h3 = if (role == .client) try http3.runtime.HandshakeClient.initEstablished(&endpoint, peer_endpoint.address(), established, .{}) else try http3.runtime.HandshakeServerSession.initEstablished(established, .{}) };
            owned = false;
            defer connection.deinit();
            // Establish both client-initiated bidi transport streams before the
            // wrapper's buffered malformed frame triggers its failure policy.
            const sender = if (role == .client) &connection.h3.established.connection else &peer;
            const receiver = if (role == .client) &peer else &connection.h3.established.connection;
            for ([_]u64{ 0, 4 }) |id| {
                var count: usize = 0;
                try sender.sendStream(id, 0, "seed", false, &count);
                try std.testing.expectEqual(@as(usize, 4), count);
            }
            const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
            while (receiver.availableReceivedStream(4) == null) {
                var packet = try receiver.receivePacketServicingTimersDeadline(until);
                packet.deinit(allocator);
            }
            if (mask_failure) try failWithoutMask(&connection, io) else try failWhileLocked(&connection, io);
            var progress: runtime.MessageWriteProgress = .{};
            const cleanup_until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.ConnectionClosed, connection.sendBinaryWithDeadline("late", &progress, cleanup_until));
            try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
            try std.testing.expect(!connection.receive_abort_pending.load(.acquire));
            while (peer.streamResetReceived(0) == null) {
                var packet = try peer.receivePacketServicingTimersDeadline(cleanup_until);
                packet.deinit(allocator);
            }
            try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.request_cancelled), peer.streamResetReceived(0).?.application_error_code);
            try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.request_cancelled), peer.sendStreamStats(0).?.stopped.?.application_error_code);
            try std.testing.expect(peer.streamResetReceived(4) == null);
            try std.testing.expect(sender.sendStreamStats(4).?.stopped == null);
            try std.testing.expect(connection.h3.established.connection.close_info == null);
        }
    }
}

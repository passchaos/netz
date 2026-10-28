const std = @import("std");
const fixture = @import("testing/record_fixture.zig");

fn sockets(io: std.Io) ![2]std.Io.net.Stream {
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const peer = try listener.socket.address.connect(io, .{ .mode = .stream });
    errdefer peer.close(io);
    return .{ peer, try listener.accept(io) };
}

test "TLS deadline close notify is authenticated EOF and repeated send is harmless" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ false, true }) |old| {
        const pair = try sockets(io);
        defer pair[0].close(io);
        defer pair[1].close(io);
        var sender = try fixture.stream(old, 0x22, 0x11);
        defer sender.deinit();
        var receiver = try fixture.stream(old, 0x11, 0x22);
        defer receiver.deinit();
        if (!old) sender.peer_update_response_pending.store(true, .release);
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        try sender.sendCloseNotifyWithDeadline(io, pair[0], deadline);
        try sender.sendCloseNotifyWithDeadline(io, pair[0], deadline);
        var buffer: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 0), try receiver.readWithDeadline(io, pair[1], &buffer, deadline));
        try std.testing.expect(receiver.receivedCloseNotify());
        if (!old) {
            try std.testing.expectEqual(@as(u64, 1), sender.keyUpdateCounts().sent);
            try std.testing.expectEqual(@as(u64, 1), receiver.keyUpdateCounts().received);
        }
    }
}

const Gate = struct {
    base: std.Io,
    canceled: bool,
    var active: ?*Gate = null;
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (self.canceled) return error.Canceled;
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
};

test "TLS deadline close notify writer admission preserves state on timeout and cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    inline for (.{ false, true }) |old| {
        inline for (.{ false, true }) |canceled| {
            const pair = try sockets(base);
            defer pair[0].close(base);
            defer pair[1].close(base);
            var sender = try fixture.stream(old, 0x22, 0x11);
            defer sender.deinit();
            var receiver = try fixture.stream(old, 0x11, 0x22);
            defer receiver.deinit();
            var gate = Gate{ .base = base, .canceled = canceled };
            var table = base.vtable.*;
            table.futexWait = Gate.wait;
            Gate.active = &gate;
            defer Gate.active = null;
            const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
            sender.write_mutex.lockUncancelable(base);
            var locked = true;
            defer if (locked) sender.write_mutex.unlock(base);
            const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(10) });
            try std.testing.expectError(if (canceled) error.Canceled else error.Timeout, sender.sendCloseNotifyWithDeadline(io, pair[0], deadline));
            try std.testing.expect(!sender.close_notify_sent and !sender.failed);
            try std.testing.expect(!sender.write_mutex.tryLock());
            try std.testing.expectEqual(@as(usize, 0), sender.pending_write_len);
            sender.write_mutex.unlock(base);
            locked = false;
            const next = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) });
            try sender.sendCloseNotifyWithDeadline(base, pair[0], next);
            var buffer: [1]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 0), try receiver.readWithDeadline(base, pair[1], &buffer, next));
            try std.testing.expect(receiver.receivedCloseNotify());
        }
    }
}

const PartialOutput = struct {
    base: std.Io,
    writes: usize = 0,
    bytes: usize = 0,
    var active: ?*PartialOutput = null;
    fn write(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.?;
        self.writes += 1;
        if (self.writes != 1) return error.Canceled;
        const n = try self.base.vtable.netWrite(userdata, socket, header[0..@min(7, header.len)], &.{""}, 0);
        self.bytes += n;
        return n;
    }
};

test "TLS deadline close notify partial output consumes its nonce and retires retries" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    inline for (.{ false, true }) |old| {
        const pair = try sockets(base);
        defer pair[0].close(base);
        defer pair[1].close(base);
        var sender = try fixture.stream(old, 0x22, 0x11);
        defer sender.deinit();
        var probe = PartialOutput{ .base = base };
        var table = base.vtable.*;
        table.netWrite = PartialOutput.write;
        PartialOutput.active = &probe;
        defer PartialOutput.active = null;
        const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        try std.testing.expectError(error.Canceled, sender.sendCloseNotifyWithDeadline(io, pair[0], deadline));
        try std.testing.expect(sender.failed and !sender.close_notify_sent);
        try std.testing.expectEqual(@as(usize, 7), probe.bytes);
        try std.testing.expectEqual(@as(u64, 1), if (old) sender.write_traffic.next_sequence_number else sender.write_sequence);
        const writes = probe.writes;
        try std.testing.expectError(error.ConnectionClosed, sender.sendCloseNotifyWithDeadline(io, pair[0], deadline));
        try std.testing.expectEqual(writes, probe.writes);
    }
}

const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const Backend = @import("../runtime.zig").Backend;
const native = @import("timed_socket.zig");
const stream_io = @import("../internal/stream_io.zig");
const allocator = std.testing.allocator;

test "stream native timed writer selects matching zio tasks and preserves wrapped vtables" {
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    // The backend's mounted main task is also a matching execution context.
    try std.testing.expect(native.available(io));
    const Outside = struct {
        fn run(task_io: std.Io, result: *bool) void {
            result.* = native.available(task_io);
        }
    };
    var outside = true;
    const thread = try std.Thread.spawn(.{}, Outside.run, .{ io, &outside });
    thread.join();
    try std.testing.expect(!outside);
    const other = try zio.Runtime.init(allocator, .{ .enable_main_executor = false, .executors = .exact(1) });
    defer other.deinit();
    const Probe = struct {
        fn run(task_io: std.Io, other_io: std.Io) !void {
            try std.testing.expect(native.available(task_io));
            try std.testing.expect(!native.available(other_io));
            try std.testing.expect(!native.available(zio.Runtime.fromIo(task_io).?.blockingIo()));
            var vtable = task_io.vtable.*;
            const wrapped = std.Io{ .userdata = task_io.userdata, .vtable = &vtable };
            try std.testing.expect(!native.available(wrapped));
        }
    };
    var task = try io.concurrent(Probe.run, .{ io, other.io() });
    try task.await(io);
}

test "stream native timed writer completes real TCP writes under an awake deadline" {
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var listener = try std.Io.net.IpAddress.listen(&.{ .ip4 = .loopback(0) }, io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);
    const Probe = struct {
        fn run(task_io: std.Io, sender: std.Io.net.Stream, receiver: std.Io.net.Stream) !void {
            try std.testing.expect(native.available(task_io));
            const deadline = std.Io.Clock.Timestamp.fromNow(task_io, .{ .clock = .awake, .raw = .fromSeconds(1) });
            var committed: usize = 99;
            try stream_io.writeAllTrackedWithDeadline(task_io, sender, "native-write", &committed, deadline);
            try std.testing.expectEqual(@as(usize, 12), committed);
            var bytes: [12]u8 = undefined;
            var received: usize = 0;
            while (received != bytes.len) received += try stream_io.readSomeWithDeadline(task_io, receiver, bytes[received..], deadline);
            try std.testing.expectEqualStrings("native-write", &bytes);
            try std.testing.expectError(error.Timeout, stream_io.writeSomeWithDeadline(task_io, sender, "expired", .{ .raw = .zero, .clock = .awake }));
        }
    };
    var task = try io.concurrent(Probe.run, .{ io, client, peer });
    try task.await(io);
}

const Pair = struct {
    client: std.Io.net.Stream,
    peer: std.Io.net.Stream,
    fn init(io: std.Io) !Pair {
        var listener = try std.Io.net.IpAddress.listen(&.{ .ip4 = .loopback(0) }, io, .{});
        defer listener.deinit(io);
        const client = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer client.close(io);
        const peer = try listener.accept(io);
        errdefer peer.close(io);
        const small: c_int = 4096;
        try std.posix.setsockopt(client.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&small));
        return .{ .client = client, .peer = peer };
    }
    fn deinit(self: Pair, io: std.Io) void {
        self.client.close(io);
        self.peer.close(io);
    }
    fn drainAndReuse(self: Pair, io: std.Io, committed: usize) !void {
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
        var remaining = committed;
        var buffer: [8192]u8 = undefined;
        while (remaining != 0) {
            const count = try stream_io.readSomeWithDeadline(io, self.peer, buffer[0..@min(remaining, buffer.len)], deadline);
            try std.testing.expect(count != 0);
            for (buffer[0..count]) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
            remaining -= count;
        }
        var sent: usize = 0;
        try stream_io.writeAllTrackedWithDeadline(io, self.client, "after", &sent, deadline);
        var marker: [5]u8 = undefined;
        var received: usize = 0;
        while (received != marker.len) received += try stream_io.readSomeWithDeadline(io, self.peer, marker[received..], deadline);
        try std.testing.expectEqualStrings("after", &marker);
    }
};

test "stream native timed writer timeout joins a blocked write and preserves its exact prefix" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const pair = try Pair.init(io);
    defer pair.deinit(io);
    const payload = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xa5);
    const Probe = struct {
        fn run(task_io: std.Io, sockets: Pair, bytes: []u8) !void {
            try std.testing.expect(native.available(task_io));
            var committed: usize = 99;
            const deadline = std.Io.Clock.Timestamp.fromNow(task_io, .{ .clock = .awake, .raw = .fromMilliseconds(20) });
            try std.testing.expectError(error.Timeout, stream_io.writeAllTrackedWithDeadline(task_io, sockets.client, bytes, &committed, deadline));
            try std.testing.expect(committed > 0 and committed < bytes.len);
            @memset(bytes, 0xee);
            try sockets.drainAndReuse(task_io, committed);
        }
    };
    var task = try io.concurrent(Probe.run, .{ io, pair, payload });
    try task.await(io);
}

test "stream native timed writer cancellation joins caller-owned bytes before return" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const pair = try Pair.init(io);
    defer pair.deinit(io);
    const payload = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xa5);
    const Probe = struct {
        started: std.Io.Event = .unset,
        committed: usize = 0,
        fn run(self: *@This(), task_io: std.Io, sockets: Pair, bytes: []u8) !void {
            const deadline = std.Io.Clock.Timestamp.fromNow(task_io, .{ .clock = .awake, .raw = .fromSeconds(5) });
            self.committed = try stream_io.writeSomeWithDeadline(task_io, sockets.client, bytes, deadline);
            self.started.set(task_io);
            var later: usize = 0;
            defer self.committed += later;
            try stream_io.writeAllTrackedWithDeadline(task_io, sockets.client, bytes[self.committed..], &later, deadline);
        }
    };
    var probe: Probe = .{};
    var task = try io.concurrent(Probe.run, .{ &probe, io, pair, payload });
    defer _ = task.cancel(io) catch {};
    const started_deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        probe.started.waitTimeout(io, .{ .deadline = started_deadline }) catch |err| {
            if (err == error.Timeout and started_deadline.durationFromNow(io).raw.nanoseconds > 0) continue;
            return err;
        };
        break;
    }
    try std.testing.expectError(error.Canceled, task.cancel(io));
    try std.testing.expect(probe.committed > 0 and probe.committed < payload.len);
    @memset(payload, 0xee);
    try pair.drainAndReuse(io, probe.committed);
}

test "stream native timed writer reports an abortive TCP reset without losing socket errors" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const pair = try Pair.init(io);
    defer pair.client.close(io);
    const abortive = std.posix.linger{ .onoff = 1, .linger = 0 };
    try std.posix.setsockopt(pair.peer.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&abortive));
    pair.peer.close(io);
    var descriptors = [_]std.posix.pollfd{.{ .fd = pair.client.socket.handle, .events = std.posix.POLL.ERR | std.posix.POLL.HUP, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&descriptors, 1000));
    const Probe = struct {
        fn run(task_io: std.Io, socket: std.Io.net.Stream) !void {
            var committed: usize = 99;
            const result = stream_io.writeAllTrackedWithDeadline(task_io, socket, "reset", &committed, .fromNow(task_io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
            if (result) |_| return error.TestUnexpectedResult else |err| try std.testing.expect(err == error.ConnectionResetByPeer or err == error.SocketUnconnected);
            try std.testing.expectEqual(@as(usize, 0), committed);
        }
    };
    var task = try io.concurrent(Probe.run, .{ io, pair.client });
    try task.await(io);
}

test "stream native timed scatter writer preserves all slices across vector limits" {
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var listener = try std.Io.net.IpAddress.listen(&.{ .ip4 = .loopback(0) }, io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);
    const Probe = struct {
        fn run(task_io: std.Io, sender: std.Io.net.Stream, receiver: std.Io.net.Stream) !void {
            try std.testing.expect(native.available(task_io));
            var bytes: [37]u8 = undefined;
            var parts: [39][]const u8 = undefined;
            parts[0] = "";
            parts[38] = "";
            for (&bytes, 0..) |*byte, index| {
                byte.* = @intCast(index);
                parts[index + 1] = bytes[index..][0..1];
            }
            const deadline = std.Io.Clock.Timestamp.fromNow(task_io, .{ .clock = .awake, .raw = .fromSeconds(1) });
            var committed: usize = 99;
            try stream_io.writeAllSlicesTrackedWithDeadline(task_io, sender, &parts, &committed, deadline);
            try std.testing.expectEqual(bytes.len, committed);
            var received: [37]u8 = undefined;
            var count: usize = 0;
            while (count != received.len) count += try stream_io.readSomeWithDeadline(task_io, receiver, received[count..], deadline);
            try std.testing.expectEqualSlices(u8, &bytes, &received);
        }
    };
    var task = try io.concurrent(Probe.run, .{ io, client, peer });
    try task.await(io);
}

test "stream native timed scatter writer timeout joins borrowed slices and preserves its exact prefix" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const pair = try Pair.init(io);
    defer pair.deinit(io);
    const payload = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xa5);
    const Probe = struct {
        fn run(task_io: std.Io, sockets: Pair, bytes: []u8) !void {
            try std.testing.expect(native.available(task_io));
            const parts: []const []const u8 = &.{ "", bytes[0..3], bytes[3..700000], "", bytes[700000..2100000], bytes[2100000..], "" };
            var committed: usize = 99;
            try std.testing.expectError(error.Timeout, stream_io.writeAllSlicesTrackedWithDeadline(task_io, sockets.client, parts, &committed, .fromNow(task_io, .{ .clock = .awake, .raw = .fromMilliseconds(20) })));
            try std.testing.expect(committed > 0 and committed < bytes.len);
            @memset(bytes, 0xee);
            try sockets.drainAndReuse(task_io, committed);
        }
    };
    var task = try io.concurrent(Probe.run, .{ io, pair, payload });
    try task.await(io);
}

test "stream native timed scatter writer cancellation joins all borrowed slices" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const pair = try Pair.init(io);
    defer pair.deinit(io);
    const payload = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xa5);
    const Probe = struct {
        started: std.Io.Event = .unset,
        committed: usize = 0,
        fn run(self: *@This(), task_io: std.Io, sockets: Pair, bytes: []u8) !void {
            const deadline = std.Io.Clock.Timestamp.fromNow(task_io, .{ .clock = .awake, .raw = .fromSeconds(5) });
            self.committed = try stream_io.writeSomeWithDeadline(task_io, sockets.client, bytes[0..4096], deadline);
            self.started.set(task_io);
            const tail = bytes[self.committed..];
            const parts: []const []const u8 = &.{ tail[0..700000], "", tail[700000..2100000], tail[2100000..] };
            var later: usize = 0;
            defer self.committed += later;
            try stream_io.writeAllSlicesTrackedWithDeadline(task_io, sockets.client, parts, &later, deadline);
        }
    };
    var probe: Probe = .{};
    var task = try io.concurrent(Probe.run, .{ &probe, io, pair, payload });
    defer _ = task.cancel(io) catch {};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        probe.started.waitTimeout(io, .{ .deadline = deadline }) catch |err| {
            if (err == error.Timeout and deadline.durationFromNow(io).raw.nanoseconds > 0) continue;
            return err;
        };
        break;
    }
    try std.testing.expectError(error.Canceled, task.cancel(io));
    try std.testing.expect(probe.committed > 0 and probe.committed < payload.len);
    @memset(payload, 0xee);
    try pair.drainAndReuse(io, probe.committed);
}

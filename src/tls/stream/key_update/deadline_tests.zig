const std = @import("std");
const fixture = @import("../testing/record_fixture.zig");
const support = @import("../../../internal/testing/write_interruption.zig");
const allocator = std.testing.allocator;

const Sockets = struct {
    local: std.Io.net.Stream,
    peer: std.Io.net.Stream,
    fn init(io: std.Io) !Sockets {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
        defer listener.deinit(io);
        const local = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer local.close(io);
        return .{ .local = local, .peer = try listener.accept(io) };
    }
    fn deinit(self: *Sockets, io: std.Io) void {
        self.local.close(io);
        self.peer.close(io);
    }
};

const Resume = enum { write, read, explicit };

test "TLS bounded KeyUpdate reply preserves ciphertext and epoch across write interruption" {
    inline for (std.enums.values(Resume)) |resume_mode| {
        try interruptedReply(.before_write, resume_mode);
        try interruptedReply(.after_prefix_timer_rejected, resume_mode);
    }
}

fn interruptedReply(stage: support.Stage, resume_mode: Resume) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var sockets = try Sockets.init(base);
    defer sockets.deinit(base);
    var sender = try fixture.stream(false, 0x22, 0x11);
    defer sender.deinit();
    var receiver = try fixture.stream(false, 0x11, 0x22);
    defer receiver.deinit();
    sender.peer_update_response_pending.store(true, .release);
    var probe = support.Probe{ .delegate = base, .stage = stage, .prefix_len = 6 };
    support.Probe.active = &probe;
    var vtable = base.vtable.*;
    vtable.groupConcurrent = support.Probe.groupConcurrent;
    vtable.netWrite = support.Probe.netWrite;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var committed: usize = 99;
    try std.testing.expectError(error.ConcurrencyUnavailable, sender.writeAllWithDeadline(io, sockets.local, "payload", &committed, .fromNow(base, .{ .raw = .fromSeconds(1), .clock = .awake })));
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expect(sender.pending_write_key_update);
    try std.testing.expectEqual(@as(u64, 1), sender.write_sequence);
    try std.testing.expectEqual(@as(u64, 0), sender.keyUpdateCounts().sent);
    try std.testing.expect(!sender.failed);
    const encoded_len = sender.pending_write_len;
    try std.testing.expectEqual(@as(usize, if (stage == .before_write) 0 else 6), sender.pending_write_offset);
    probe.armed = false;
    switch (resume_mode) {
        .write => {},
        .explicit => {
            try sender.finishPendingWrite(io, sockets.local, &committed);
            try std.testing.expectEqual(@as(usize, 0), committed);
        },
        .read => {
            try receiver.writeAll(base, sockets.peer, "inbound");
            var input: [7]u8 = undefined;
            const count = try sender.readWithDeadline(io, sockets.local, &input, .fromNow(base, .{ .raw = .fromSeconds(1), .clock = .awake }));
            try std.testing.expectEqualStrings("inbound", input[0..count]);
        },
    }
    try sender.writeAllWithDeadline(io, sockets.local, "payload", &committed, .fromNow(base, .{ .raw = .fromSeconds(1), .clock = .awake }));
    try std.testing.expectEqual(@as(usize, 7), committed);
    try std.testing.expectEqual(@as(usize, encoded_len + 7 + 22), probe.written);
    try std.testing.expectEqual(@as(usize, 0), sender.pending_write_len);
    try std.testing.expectEqual(@as(u64, 1), sender.keyUpdateCounts().sent);
    try std.testing.expectEqual(@as(u64, 1), sender.write_sequence);
    var output: [7]u8 = undefined;
    const count = try receiver.readWithDeadline(base, sockets.peer, &output, .fromNow(base, .{ .raw = .fromSeconds(1), .clock = .awake }));
    try std.testing.expectEqualStrings("payload", output[0..count]);
    try std.testing.expectEqual(@as(u64, 1), receiver.keyUpdateCounts().received);
}

const BlockedWriter = struct {
    var active: *BlockedWriter = undefined;
    io: std.Io,
    blocked: bool = true,
    cancelled: bool = false,
    wait: std.Io.Event = .unset,
    fn write(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active;
        if (self.blocked) {
            self.wait.wait(self.io) catch |err| {
                self.cancelled = true;
                return err;
            };
        }
        return self.io.vtable.netWrite(userdata, handle, header, parts, splat);
    }
};

test "TLS bounded read cancels a blocked KeyUpdate reply and resumes authenticated traffic" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var sockets = try Sockets.init(base);
    defer sockets.deinit(base);
    var local = try fixture.stream(false, 0x22, 0x11);
    defer local.deinit();
    var peer = try fixture.stream(false, 0x11, 0x22);
    defer peer.deinit();
    try peer.updateTrafficKeys(base, sockets.peer, true);
    try peer.writeAll(base, sockets.peer, "inbound");
    var writer: BlockedWriter = .{ .io = base };
    BlockedWriter.active = &writer;
    var vtable = base.vtable.*;
    vtable.netWrite = BlockedWriter.write;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var input: [7]u8 = undefined;
    const started = std.Io.Clock.Timestamp.now(base, .awake);
    try std.testing.expectError(error.Timeout, local.readWithDeadline(io, sockets.local, &input, .fromNow(base, .{ .raw = .fromMilliseconds(20), .clock = .awake })));
    try std.testing.expect(started.untilNow(base).raw.nanoseconds < std.Io.Duration.fromMilliseconds(500).nanoseconds);
    try std.testing.expect(writer.cancelled);
    try std.testing.expect(!local.failed);
    try std.testing.expect(local.pending_write_key_update);
    try std.testing.expectEqual(@as(u64, 1), local.keyUpdateCounts().received);
    try std.testing.expectEqual(@as(u64, 0), local.keyUpdateCounts().sent);
    writer.blocked = false;
    const count = try local.readWithDeadline(io, sockets.local, &input, .fromNow(base, .{ .raw = .fromSeconds(1), .clock = .awake }));
    try std.testing.expectEqualStrings("inbound", input[0..count]);
    try std.testing.expectEqual(@as(u64, 1), local.keyUpdateCounts().received);
    try std.testing.expectEqual(@as(u64, 1), local.keyUpdateCounts().sent);
    try local.writeAll(base, sockets.local, "reply");
    var reply: [5]u8 = undefined;
    const reply_len = try peer.readWithDeadline(base, sockets.peer, &reply, .fromNow(base, .{ .raw = .fromSeconds(1), .clock = .awake }));
    try std.testing.expectEqualStrings("reply", reply[0..reply_len]);
    try std.testing.expect(!peer.keyUpdateCounts().awaiting_peer_response);
}

test "TLS bounded write rejects concurrent ownership without consuming an epoch" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try fixture.stream(false, 0x22, 0x11);
    defer sender.deinit();
    sender.write_mutex.lockUncancelable(io);
    defer sender.write_mutex.unlock(io);
    const socket: std.Io.net.Stream = undefined;
    var committed: usize = 99;
    try std.testing.expectError(error.WriteInProgress, sender.writeAllWithDeadline(io, socket, "payload", &committed, .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake })));
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(usize, 0), sender.pending_write_len);
    try std.testing.expectEqual(@as(u64, 0), sender.write_sequence);
}

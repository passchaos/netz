const std = @import("std");
const queues = @import("../relay_queue.zig");
const Relay = queues.Relay;
const gpa = std.testing.allocator;

fn init(relay: *Relay, io: std.Io) !void {
    relay.* = .{
        .allocator = gpa,
        .io = io,
        // Queue-only fixture: transport operations are never called.
        .tcp = undefined,
        .stream_id = 0,
        .last_activity_ns = 0,
        .idle_timeout = .fromSeconds(1),
        .buffer_size = 1,
    };
    relay.outbound = .init(&relay.outbound_storage);
    errdefer relay.discardOutbound();
    for (0..3) |index| {
        const payload = try gpa.dupe(u8, &.{@intCast(index)});
        errdefer gpa.free(payload);
        try relay.outbound.putOne(io, .{ .data = payload });
    }
    try relay.outbound.putOne(io, .fin);
}

const Sender = struct {
    fail_at: usize,
    refusals: usize = 3,
    seen: [3]u8 = undefined,
    count: usize = 0,
    fin: bool = false,
    fatal: bool = false,

    fn send(self: *Sender, _: *Relay, item: queues.Outbound) queues.SendResult {
        if (self.count == self.fail_at and self.refusals != 0) {
            self.refusals -= 1;
            return if (self.fatal) .fatal else .blocked;
        }
        switch (item) {
            .data => |bytes| {
                self.seen[self.count] = bytes[0];
                self.count += 1;
            },
            .fin => self.fin = true,
        }
        return .complete;
    }
};

test "proxy relay FIFO retains first middle last and FIN backpressure" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    for (0..4) |fail_at| {
        var relay: Relay = undefined;
        try init(&relay, threaded.io());
        defer relay.discardOutbound();
        var sender = Sender{ .fail_at = fail_at };
        for (0..3) |_| {
            relay.flushOutbound(&sender, Sender.send);
            try std.testing.expect(relay.pending_out != null);
            try std.testing.expect(!sender.fin);
        }
        relay.flushOutbound(&sender, Sender.send);
        try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, &sender.seen);
        try std.testing.expectEqual(@as(usize, 3), sender.count);
        try std.testing.expect(sender.fin);
        try std.testing.expect(relay.pending_out == null);
    }
}

test "proxy relay FIFO teardown frees pending and queued successors" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    for (0..3) |fail_at| {
        var relay: Relay = undefined;
        try init(&relay, threaded.io());
        defer relay.discardOutbound();
        var sender = Sender{ .fail_at = fail_at };
        relay.flushOutbound(&sender, Sender.send);
        try std.testing.expect(relay.pending_out != null);
        relay.outbound.close(relay.io);
        relay.discardOutbound();
        try std.testing.expect(relay.pending_out == null);
    }
}

test "proxy relay FIFO fatal send releases current item and preserves teardown" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    for (0..4) |fail_at| {
        var relay: Relay = undefined;
        try init(&relay, threaded.io());
        defer relay.discardOutbound();
        var sender = Sender{ .fail_at = fail_at, .fatal = true };
        relay.flushOutbound(&sender, Sender.send);
        try std.testing.expect(relay.closed.load(.acquire));
        try std.testing.expect(relay.pending_out == null);
        try std.testing.expect(!sender.fin);
        try std.testing.expectEqual(fail_at, sender.count);
    }
}

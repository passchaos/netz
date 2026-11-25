//! Expired raw timeouts precede a backend's timed I/O capability check.
const std = @import("std");
const runtime = @import("../runtime.zig");
const dispatcher_mod = @import("../endpoint_dispatcher.zig");
const Form = enum { parsed, owned, buffer, owned_batch, batch_buffer, many, versions, dispatch_owned, dispatch_visitor, dispatch_many };

const Probe = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    waits: usize = 0,
    observed_deadline: ?std.Io.Clock.Timestamp = null,
    scripted_clock: bool = false,
    real_reads: usize = 0,

    fn io(self: *@This()) std.Io {
        const base = self.backend.io();
        self.table = base.vtable.*;
        self.table.batchAwaitConcurrent = awaitConcurrent;
        self.table.now = now;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    fn context(userdata: ?*anyopaque) *@This() {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        const parent: *align(@alignOf(std.Io.Threaded)) Probe = @fieldParentPtr("backend", backend);
        return @alignCast(parent);
    }

    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = context(userdata);
        if (!self.scripted_clock) return clock.now(self.backend.io());
        if (clock == .awake) return .{ .nanoseconds = 1_000_000_000 };
        self.real_reads += 1;
        return .{ .nanoseconds = 100_000_000_000 + (self.real_reads - 1) * 500 };
    }

    fn awaitConcurrent(userdata: ?*anyopaque, _: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const self = context(userdata);
        self.waits += 1;
        self.observed_deadline = timeout.toTimestamp(self.backend.io());
        return error.ConcurrencyUnavailable;
    }
};

fn receive(form: Form, endpoint: *runtime.Endpoint, dispatcher: *dispatcher_mod.Dispatcher, storage: []u8, slots: usize, timeout: std.Io.Timeout) !usize {
    const Visitor = struct {
        fn visit(_: void, _: dispatcher_mod.RoutedPacketView) error{}!void {}
    };
    const allocator = endpoint.allocator;
    var views: [2]runtime.ReceivedBytesView = undefined;
    var events: [2]dispatcher_mod.VisitEvent = undefined;
    switch (form) {
        .parsed => {
            var value = try endpoint.receiveWithTimeout(timeout);
            defer value.deinit(allocator);
        },
        .owned => {
            var value = try endpoint.receiveBytesTimeout(timeout);
            defer value.deinit(allocator);
        },
        .buffer => _ = try endpoint.receiveBytesIntoTimeout(storage, timeout),
        .owned_batch => {
            var value = try endpoint.receiveBytesBatchTimeout(timeout);
            defer value.deinit(allocator);
        },
        .batch_buffer => _ = try endpoint.receiveBytesBatchIntoTimeout(storage, timeout),
        .many => return endpoint.receiveManyBytesIntoTimeout(storage, views[0..slots], timeout),
        .versions => {
            var value = try endpoint.receiveBytesHandlingVersionNegotiationWithTimeout(&.{1}, timeout);
            defer value.deinit(allocator);
        },
        .dispatch_owned => {
            var value = try dispatcher.receiveTimeout(&.{1}, timeout);
            defer value.deinit(allocator);
        },
        .dispatch_visitor => {
            var value = try dispatcher.receiveVisitingTimeout(&.{1}, storage, timeout, {}, Visitor.visit);
            defer value.deinit(allocator);
        },
        .dispatch_many => return dispatcher.receiveManyVisitingTimeout(&.{1}, storage, events[0..slots], timeout, {}, Visitor.visit),
    }
    return 1;
}

test "QUIC receive caller-owned deadlines reject expiry before I/O admission" {
    var probe: Probe = .{ .backend = .init(std.testing.allocator, .{}) };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var endpoint = try runtime.Endpoint.bind(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    endpoint.io = probe.io();
    defer endpoint.io = base;
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    const timeouts = [_]std.Io.Timeout{
        .{ .duration = .{ .clock = .awake, .raw = .zero } },
        .{ .duration = .{ .clock = .awake, .raw = .fromNanoseconds(-1) } },
        .{ .deadline = .{ .clock = .awake, .raw = .zero } },
        .{ .deadline = .{ .clock = .real, .raw = .zero } },
    };
    var storage: [256]u8 = @splat(0x5a);
    inline for (std.meta.tags(Form)) |form| {
        for (timeouts) |timeout| {
            for ([_]usize{ 2, 0 }) |slots| {
                try std.testing.expectError(error.Timeout, receive(form, &endpoint, &dispatcher, if (slots == 0) &.{} else &storage, slots, timeout));
                try std.testing.expectEqual(@as(usize, 0), probe.waits);
                try std.testing.expectEqualSlices(u8, &(@as([256]u8, @splat(0x5a))), &storage);
            }
        }
    }
}

test "QUIC receive caller-owned deadlines preserve live-budget admission errors" {
    var probe: Probe = .{ .backend = .init(std.testing.allocator, .{}) };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var endpoint = try runtime.Endpoint.bind(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    endpoint.io = probe.io();
    defer endpoint.io = base;
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    var storage: [256]u8 = undefined;
    inline for (std.meta.tags(Form)) |form| {
        try std.testing.expectError(error.ConcurrencyUnavailable, receive(form, &endpoint, &dispatcher, &storage, 2, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(10) } }));
    }
    try std.testing.expectEqual(std.meta.tags(Form).len, probe.waits);
}

test "QUIC receive caller-owned deadlines bound socket ownership admission" {
    var probe: Probe = .{ .backend = .init(std.testing.allocator, .{}) };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var endpoint = try runtime.Endpoint.bind(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    endpoint.io = probe.io();
    defer endpoint.io = base;
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    endpoint.socket_receive_mutex.lockUncancelable(base);
    defer endpoint.socket_receive_mutex.unlock(base);
    var storage: [256]u8 = @splat(0x5a);
    inline for (std.meta.tags(Form)) |form| {
        try std.testing.expectError(error.Timeout, receive(form, &endpoint, &dispatcher, &storage, 2, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(20) } }));
        try std.testing.expect(!endpoint.socket_receive_mutex.tryLock());
        try std.testing.expectEqual(@as(usize, 0), probe.waits);
        try std.testing.expectEqualSlices(u8, &(@as([256]u8, @splat(0x5a))), &storage);
    }
}

test "QUIC receive caller-owned deadlines retain queued input on expiry" {
    var probe: Probe = .{ .backend = .init(std.testing.allocator, .{}) };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var endpoint = try runtime.Endpoint.bind(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    {
        const bytes = try std.testing.allocator.dupe(u8, "pending");
        errdefer std.testing.allocator.free(bytes);
        try endpoint.pending_received.append(std.testing.allocator, .{ .from = .{ .ip4 = .loopback(1) }, .bytes = bytes });
    }
    endpoint.io = probe.io();
    defer endpoint.io = base;
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    var storage: [256]u8 = undefined;
    inline for (std.meta.tags(Form)) |form| {
        try std.testing.expectError(error.Timeout, receive(form, &endpoint, &dispatcher, &storage, 2, .{ .deadline = .{ .clock = .awake, .raw = .zero } }));
        try std.testing.expectEqual(@as(usize, 0), endpoint.pending_receive_index);
        try std.testing.expectEqual(@as(usize, 1), endpoint.pending_received.items.len);
        try std.testing.expectEqualStrings("pending", endpoint.pending_received.items[0].bytes);
        try std.testing.expectEqual(@as(usize, 0), probe.waits);
    }
}

test "QUIC receive caller-owned deadlines translate raw clocks without renewing budget" {
    var probe: Probe = .{ .backend = .init(std.testing.allocator, .{}), .scripted_clock = true };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var endpoint = try runtime.Endpoint.bind(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    endpoint.io = probe.io();
    defer endpoint.io = base;
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    var storage: [256]u8 = undefined;
    try std.testing.expectError(error.ConcurrencyUnavailable, receive(.many, &endpoint, &dispatcher, &storage, 2, .{ .duration = .{ .clock = .real, .raw = .fromSeconds(1) } }));
    try std.testing.expectEqual(@as(usize, 2), probe.real_reads);
    try std.testing.expectEqual(std.Io.Clock.awake, probe.observed_deadline.?.clock);
    try std.testing.expectEqual(@as(i96, 1_999_999_500), probe.observed_deadline.?.raw.nanoseconds);
}

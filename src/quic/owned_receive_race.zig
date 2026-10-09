//! Cancellation-safe race between two owning QUIC endpoint receives.
//!
//! `std.Io.Select` may discard a task's returned value when completion races
//! with cancellation on some backends. Each task therefore publishes its
//! `OwnedBytes` into caller-owned slot state before returning a resource-free
//! tag to the select.

const std = @import("std");
const runtime = @import("runtime.zig");

const ReceiveResult = runtime.ReceiveTimeoutError!runtime.OwnedBytes;

const Slot = struct {
    endpoint: *runtime.Endpoint,
    result: ?ReceiveResult = null,

    fn receive(self: *Slot, timeout: std.Io.Timeout) void {
        self.result = self.endpoint.receiveBytesTimeout(timeout);
    }

    fn take(self: *Slot) ReceiveResult {
        const result = self.result orelse unreachable;
        self.result = null;
        return result;
    }

    fn deinit(self: *Slot) void {
        const result = self.result orelse return;
        self.result = null;
        if (result) |datagram_value| {
            var datagram = datagram_value;
            datagram.deinit(
                (datagram.received_on orelse self.endpoint).allocator,
            );
        } else |_| {}
    }
};

pub fn receive(
    pending: *?runtime.OwnedBytes,
    io: std.Io,
    primary: *runtime.Endpoint,
    alternate: *runtime.Endpoint,
    timeout: std.Io.Timeout,
) runtime.ReceiveTimeoutError!runtime.OwnedBytes {
    if (pending.*) |datagram| {
        pending.* = null;
        return datagram;
    }
    std.debug.assert(primary != alternate);

    var primary_slot = Slot{ .endpoint = primary };
    defer primary_slot.deinit();
    var alternate_slot = Slot{ .endpoint = alternate };
    defer alternate_slot.deinit();
    const Wake = union(enum) {
        primary: void,
        alternate: void,
    };
    var wake_storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_storage);
    const bounded = timeout.toDeadline(io);
    select.async(.primary, Slot.receive, .{ &primary_slot, bounded });
    select.async(.alternate, Slot.receive, .{ &alternate_slot, bounded });
    const first = select.await() catch |err| {
        while (select.cancel()) |_| {}
        return err;
    };
    while (select.cancel()) |_| {}

    const selected = switch (first) {
        .primary => primary_slot.take(),
        .alternate => alternate_slot.take(),
    };
    const other = switch (first) {
        .primary => alternate_slot.take(),
        .alternate => primary_slot.take(),
    };
    const datagram = selected catch |selected_err| {
        return other catch return selected_err;
    };
    if (other) |other_datagram| {
        std.debug.assert(pending.* == null);
        pending.* = other_datagram;
    } else |_| {}
    return datagram;
}

test "owning endpoint race preserves both ready datagrams on zio" {
    const allocator = std.testing.allocator;
    var backend = try @import("../runtime.zig").Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    const limits: runtime.Limits = .{ .max_datagram_size = 128 };
    var primary = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer primary.deinit();
    var alternate = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer alternate.deinit();
    var sender = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer sender.deinit();

    var pending: ?runtime.OwnedBytes = null;
    defer if (pending) |*datagram| {
        datagram.deinit((datagram.received_on orelse &primary).allocator);
    };
    var retained_count: usize = 0;
    for (0..32) |_| {
        try sender.sendBytes(primary.address(), "primary");
        try sender.sendBytes(alternate.address(), "alternate");
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        });
        var first = try receive(
            &pending,
            io,
            &primary,
            &alternate,
            .{ .deadline = deadline },
        );
        const first_is_primary = std.mem.eql(u8, first.bytes, "primary");
        const first_is_alternate = std.mem.eql(u8, first.bytes, "alternate");
        try std.testing.expect(first_is_primary != first_is_alternate);
        first.deinit((first.received_on orelse &primary).allocator);
        retained_count += @intFromBool(pending != null);

        var second = try receive(
            &pending,
            io,
            &primary,
            &alternate,
            .{ .deadline = deadline },
        );
        defer second.deinit((second.received_on orelse &primary).allocator);
        try std.testing.expect(if (first_is_primary)
            std.mem.eql(u8, second.bytes, "alternate")
        else
            std.mem.eql(u8, second.bytes, "primary"));
    }
    try std.testing.expect(retained_count != 0);
}

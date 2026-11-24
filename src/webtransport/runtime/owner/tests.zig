//! Rejected application owners cannot advance Session control or cleanup.
const std = @import("std");
const Backend = @import("../../../runtime.zig").Backend;
const control = @import("../session_control.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const Pair = @import("../session_control/test_support/handshake_pair.zig").Pair;

const Send = enum { one, timeout, deadline, many, many_timeout, many_deadline };
const Read = enum { one, timeout, deadline, into, into_timeout, into_deadline, many, many_timeout, many_deadline, owned_many, owned_many_timeout, owned_many_deadline };

const Output = struct {
    bytes: [16]u8 = @splat(0xaa),
    slices: [1][]u8 = undefined,
    received: usize = 7,
};

fn read(session: anytype, kind: Read, until: std.Io.Clock.Timestamp, output: *Output) !void {
    output.slices = .{&output.bytes};
    switch (kind) {
        .one, .timeout, .deadline => {
            var payload = switch (kind) {
                .one => try session.receiveDatagram(),
                .timeout => try session.receiveDatagramWithTimeout(.fromSeconds(1)),
                .deadline => try session.receiveDatagramWithDeadline(until),
                else => unreachable,
            };
            defer payload.deinit(std.testing.allocator);
        },
        .into => _ = try session.receiveDatagramInto(&output.bytes),
        .into_timeout => _ = try session.receiveDatagramIntoWithTimeout(&output.bytes, .fromSeconds(1)),
        .into_deadline => _ = try session.receiveDatagramIntoWithDeadline(&output.bytes, until),
        .many => try session.receiveDatagramsInto(&output.slices, &output.received),
        .many_timeout => try session.receiveDatagramsIntoWithTimeout(&output.slices, &output.received, .fromSeconds(1)),
        .many_deadline => try session.receiveDatagramsIntoWithDeadline(&output.slices, &output.received, until),
        .owned_many, .owned_many_timeout, .owned_many_deadline => {
            var batch = switch (kind) {
                .owned_many => try session.receiveManyDatagrams(1),
                .owned_many_timeout => try session.receiveManyDatagramsWithTimeout(1, .fromSeconds(1)),
                .owned_many_deadline => try session.receiveManyDatagramsWithDeadline(1, until),
                else => unreachable,
            };
            defer batch.deinit();
        },
    }
}

fn expectUnchanged(pair: *Pair, role: @import("../session_control/test_support/handshake_pair.zig").Role, packet_number: u64, kind: Read, output: *Output) !void {
    try std.testing.expect(!pair.control(role).flow_violation);
    try std.testing.expect(!pair.control(role).capsule_error_pending);
    try std.testing.expect(!pair.control(role).state.closed);
    try std.testing.expectEqual(packet_number, pair.connection(role).next_packet_number);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &output.bytes);
    try std.testing.expectEqual(@intFromPtr(&output.bytes), @intFromPtr(output.slices[0].ptr));
    try std.testing.expectEqual(@as(usize, 16), output.slices[0].len);
    if (kind == .many or kind == .many_timeout or kind == .many_deadline) try std.testing.expectEqual(@as(usize, 0), output.received);
}

test "WebTransport operation admission rejects callback sends before buffered CLOSE" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    for (std.enums.values(Send)) |kind| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        var bytes: [64]u8 = undefined;
        try pair.sendCapsules(.client, try control.writeCloseInto(&bytes, 91, "borrowed"));
        const connection = pair.connection(.client);
        const before = connection.recvStreamStats(0).?.bytes_read;
        const packet_number = connection.next_packet_number;
        pair.client.h3.callback_reader_active = true;
        defer pair.client.h3.callback_reader_active = false;
        var committed: usize = 7;
        const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        const result = switch (kind) {
            .one => pair.client.sendDatagram("late"),
            .timeout => pair.client.sendDatagramWithTimeout("late", .fromSeconds(1)),
            .deadline => pair.client.sendDatagramWithDeadline("late", until),
            .many => pair.client.sendDatagrams(&.{"late"}, &committed),
            .many_timeout => pair.client.sendDatagramsWithTimeout(&.{"late"}, &committed, .fromSeconds(1)),
            .many_deadline => pair.client.sendDatagramsWithDeadline(&.{"late"}, &committed, until),
        };
        try std.testing.expectError(error.ConcurrentRead, result);
        if (kind == .many or kind == .many_timeout or kind == .many_deadline) try std.testing.expectEqual(@as(usize, 0), committed);
        try std.testing.expectEqual(before, connection.recvStreamStats(0).?.bytes_read);
        try std.testing.expectEqual(packet_number, connection.next_packet_number);
        try std.testing.expect(!pair.client.control.state.closed);
        pair.client.h3.callback_reader_active = false;
        const event = (try pair.poll(.client)).?;
        try std.testing.expect(event == .closed);
        try std.testing.expectEqualStrings("borrowed", event.closed.reason);
    }
}

test "WebTransport operation admission rejects callback receives before flow cleanup" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    for (std.enums.values(Read)) |kind| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        pair.client.streams.flow_violation = true;
        pair.client.h3.callback_reader_active = true;
        defer pair.client.h3.callback_reader_active = false;
        var output: Output = .{};
        const packet_number = pair.connection(.client).next_packet_number;
        const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        try std.testing.expectError(error.ConcurrentRead, read(&pair.client, kind, until, &output));
        try expectUnchanged(&pair, .client, packet_number, kind, &output);
    }
}

test "WebTransport operation admission rejects dispatcher receives before flow cleanup" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ .client, .server }) |role| {
        for (std.enums.values(Read)) |kind| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            session.streams.flow_violation = true;
            session.h3.dispatcher_bound = true;
            defer session.h3.dispatcher_bound = false;
            var output: Output = .{};
            const packet_number = pair.connection(role).next_packet_number;
            const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.InvalidDispatcherState, read(session, kind, until, &output));
            try expectUnchanged(&pair, role, packet_number, kind, &output);
        }
    }
}

test "WebTransport operation admission defers lifecycle cleanup during a borrowed callback" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    var pair: Pair = undefined;
    try pair.init(backend.io());
    defer pair.deinit();
    pair.client.streams.flow_violation = true;
    pair.client.h3.callback_reader_active = true;
    defer pair.client.h3.callback_reader_active = false;
    const packet_number = pair.connection(.client).next_packet_number;
    _ = lifecycle.observe(&pair.client.control, &pair.client.h3, &pair.client.streams);
    try std.testing.expect(!pair.client.control.flow_violation);
    try std.testing.expect(!pair.client.control.capsule_error_pending);
    try std.testing.expectEqual(packet_number, pair.connection(.client).next_packet_number);
    pair.client.h3.callback_reader_active = false;
    _ = lifecycle.observe(&pair.client.control, &pair.client.h3, &pair.client.streams);
    try std.testing.expect(pair.client.control.flow_violation);
    try std.testing.expect(pair.client.control.state.closed);
}

test "WebTransport operation admission preserves Session events during a borrowed callback" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const Event = enum { poll, poll_deadline, receive, timeout, deadline };
    const Worker = struct {
        fn run(session: anytype, kind: Event, until: std.Io.Clock.Timestamp) !void {
            switch (kind) {
                .poll => _ = try session.pollSessionEvent(),
                .poll_deadline => _ = try session.pollSessionEventWithCleanupDeadline(until),
                .receive => _ = try session.receiveSessionEvent(),
                .timeout => _ = try session.receiveSessionEventWithTimeout(.fromSeconds(1)),
                .deadline => _ = try session.receiveSessionEventWithDeadline(until),
            }
        }
    };
    for (std.enums.values(Event)) |kind| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        var bytes: [64]u8 = undefined;
        try pair.sendCapsules(.client, try control.writeCloseInto(&bytes, 91, "event owner"));
        pair.client.h3.callback_reader_active = true;
        defer pair.client.h3.callback_reader_active = false;
        const before = pair.connection(.client).recvStreamStats(0).?.bytes_read;
        const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        try std.testing.expectError(error.ConcurrentRead, Worker.run(&pair.client, kind, until));
        try std.testing.expectEqual(before, pair.connection(.client).recvStreamStats(0).?.bytes_read);
        try std.testing.expect(!pair.client.control.state.closed);
        try std.testing.expect(pair.client.pending_session_event == null);
        pair.client.h3.callback_reader_active = false;
        const event = (try pair.poll(.client)).?;
        try std.testing.expect(event == .closed);
        try std.testing.expectEqualStrings("event owner", event.closed.reason);
    }
}

test "WebTransport operation admission keeps local CLOSE and DRAIN retry state untouched" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const Local = enum { drain, drain_timeout, drain_deadline, close, close_timeout, close_deadline };
    for (std.enums.values(Local)) |kind| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        pair.client.h3.callback_reader_active = true;
        defer pair.client.h3.callback_reader_active = false;
        const packet_number = pair.connection(.client).next_packet_number;
        const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        const result = switch (kind) {
            .drain => pair.client.drain(),
            .drain_timeout => pair.client.drainWithTimeout(.fromSeconds(1)),
            .drain_deadline => pair.client.drainWithDeadline(until),
            .close => pair.client.close(91, "rejected"),
            .close_timeout => pair.client.closeWithTimeout(91, "rejected", .fromSeconds(1)),
            .close_deadline => pair.client.closeWithDeadline(91, "rejected", until),
        };
        try std.testing.expectError(error.ConcurrentRead, result);
        try std.testing.expect(pair.client.pending_drain == null and pair.client.pending_close == null);
        try std.testing.expect(!pair.client.control.local_drain_started and !pair.client.control.local_close_started);
        try std.testing.expectEqual(packet_number, pair.connection(.client).next_packet_number);
        pair.client.h3.callback_reader_active = false;
        try pair.client.sendDatagram("still open");
        var payload = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
        defer payload.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("still open", payload.datagram.payload);
    }
}

test "WebTransport operation admission rejects dispatcher Session waits before cleanup" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const Event = enum { receive, timeout, deadline, cleanup_deadline };
    const Worker = struct {
        fn run(session: anytype, kind: Event, until: std.Io.Clock.Timestamp) !void {
            switch (kind) {
                .receive => _ = try session.receiveSessionEvent(),
                .timeout => _ = try session.receiveSessionEventWithTimeout(.fromSeconds(1)),
                .deadline => _ = try session.receiveSessionEventWithDeadline(until),
                .cleanup_deadline => _ = try session.pollSessionEventWithCleanupDeadline(until),
            }
        }
    };
    inline for (.{ .client, .server }) |role| {
        for (std.enums.values(Event)) |kind| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            session.h3.dispatcher_bound = true;
            defer session.h3.dispatcher_bound = false;
            session.streams.flow_violation = true;
            const packet_number = pair.connection(role).next_packet_number;
            const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.InvalidDispatcherState, Worker.run(session, kind, until));
            try std.testing.expect(!pair.control(role).flow_violation);
            try std.testing.expect(!pair.control(role).state.closed);
            try std.testing.expectEqual(packet_number, pair.connection(role).next_packet_number);
        }
    }
}

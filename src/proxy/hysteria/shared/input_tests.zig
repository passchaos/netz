//! Shared receive credit follows an accepted immutable target-write loan.
const std = @import("std");
const Relay = @import("../../internal/relay_queue.zig").Relay;
const Fixture = @import("../../internal/relay_queue/inbound_tests.zig").Fixture;
const ByteBucket = @import("../../internal/byte_bucket.zig").ByteBucket;
const native_protocol = @import("../../../internal/testing/native_protocol_io.zig");
const allocator = std.testing.allocator;
const Mode = enum { canceled, partial, sibling };

pub fn run(comptime Pump: type, comptime Connection: type, comptime service: anytype, comptime settle: anytype, comptime destroy: anytype, comptime notify: anytype) !void {
    const Case = struct {
        fn testCase(base: std.Io) !void {
            inline for (.{ Mode.canceled, Mode.partial, Mode.sibling }) |mode| try exercise(Pump, Connection, service, settle, destroy, notify, base, mode);
        }
    };
    try native_protocol.runStream(Case.testCase);
}

fn exercise(comptime Pump: type, comptime Connection: type, comptime service: anytype, comptime settle: anytype, comptime destroy: anytype, comptime notify: anytype, base: std.Io, comptime mode: Mode) !void {
    var first: Fixture = undefined;
    try first.init(base, 16);
    defer first.deinit();
    _ = first.input.stop();
    var second: Fixture = undefined;
    try second.init(base, 16);
    defer second.deinit();
    _ = second.input.stop();
    var running: std.atomic.Value(bool) = .init(true);
    var pump: Pump = .{
        .allocator = allocator,
        .io = first.observed(),
        .endpoint = undefined,
        .config = .{ .password = "credit", .identity = undefined },
        .limiter = undefined,
        .shared = undefined,
        .receive_storage = &.{},
        .versions = .{ 1, 2 },
        .stop_flag = &running,
    };
    const now = first.clock.now_ns.load(.acquire);
    var connection: Connection = .{
        .pump = &pump,
        .handle = 1,
        .established = undefined,
        .peer = .{ .ip4 = .loopback(1234) },
        .created_ns = now,
        .last_activity_ns = now,
        .send_bucket = ByteBucket.init(0, now),
        .recv_bucket = ByteBucket.initWithBurst(1, 6, now),
        .datagram_buffer = &.{},
    };
    defer {
        for (connection.relays.items) |relay| destroy(&connection, relay);
        connection.relays.deinit(allocator);
    }
    try connection.relays.ensureTotalCapacity(allocator, 2);
    const first_relay = try Relay.createWithOptions(allocator, first.observed(), first.sender, 1, .{
        .idle_timeout = .fromSeconds(1),
        .buffer_size = 16,
        .notify_context = &pump,
        .notify = notify,
    });
    first.owns_sender = false;
    connection.relays.appendAssumeCapacity(first_relay);
    const second_relay = try Relay.createWithOptions(allocator, second.observed(), second.sender, 3, .{
        .idle_timeout = .fromSeconds(1),
        .buffer_size = 16,
        .notify_context = &pump,
        .notify = notify,
    });
    second.owns_sender = false;
    connection.relays.appendAssumeCapacity(second_relay);
    try first_relay.queueInbound("abcdef");
    try second_relay.queueInbound("UVWXYZ");
    if (mode == .sibling) {
        connection.recv_bucket = ByteBucket.init(0, now);
        second.gate.maximum = 6;
        second.gate.release.set(base);
    }
    service(&connection, false);
    try first.entered();
    if (mode == .sibling) {
        try second.readExact("UVWXYZ");
        const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) });
        const result = while (true) {
            if (second_relay.takeInputCompletion()) |result| break result;
            if (deadline.durationFromNow(base).raw.nanoseconds <= 0) return error.TestExpectedCompletion;
            try std.Io.sleep(base, .fromMilliseconds(1), .awake);
        };
        settle(&connection, result);
        try std.testing.expectEqual(@as(usize, 6), result.committed_bytes);
        try std.testing.expect(result.failure == null);
        try std.testing.expect(second_relay.inputDrained());
        try std.testing.expect(first_relay.input.in_flight);
        try std.testing.expectEqual(@as(usize, 0), first.gate.writes.load(.acquire));
        try std.testing.expect(!first_relay.closed.load(.acquire));
        return;
    }
    try std.testing.expectEqual(@as(u64, 0), connection.recv_bucket.tokens);
    try std.testing.expectEqual(@as(usize, 6), first_relay.input.reserved_bytes);
    try std.testing.expect(!second_relay.input.in_flight);
    if (mode == .partial) {
        first.gate.release.set(base);
        const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) });
        const result = while (true) {
            if (first_relay.takeInputCompletion()) |result| break result;
            if (deadline.durationFromNow(base).raw.nanoseconds <= 0) return error.TestExpectedCompletion;
            try std.Io.sleep(base, .fromMilliseconds(1), .awake);
        };
        try std.testing.expectEqual(@as(usize, 3), result.committed_bytes);
        settle(&connection, result);
        try std.testing.expectEqual(@as(u64, 3), connection.recv_bucket.tokens);
        try first.readExact("abc");
    }
    _ = connection.relays.orderedRemove(0);
    destroy(&connection, first_relay);
    const expected: u64 = if (mode == .partial) 3 else 6;
    try std.testing.expectEqual(expected, connection.recv_bucket.tokens);
    service(&connection, false);
    try second.entered();
    try std.testing.expectEqual(@as(u64, 0), connection.recv_bucket.tokens);
    try std.testing.expectEqual(@as(usize, @intCast(expected)), second_relay.input.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 0), second.gate.writes.load(.acquire));
    _ = connection.relays.pop();
    destroy(&connection, second_relay);
    try std.testing.expectEqual(expected, connection.recv_bucket.tokens);
}

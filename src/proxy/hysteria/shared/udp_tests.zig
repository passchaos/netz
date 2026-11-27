//! Receive credit covers every accepted datagram until joined completion.
const std = @import("std");
const Fixture = @import("../../internal/udp_session/tests.zig").Fixture;
const Session = @import("../../internal/udp_session.zig").Session;
const ByteBucket = @import("../../internal/byte_bucket.zig").ByteBucket;
const Native = @import("../../../internal/testing/deadline_send_io.zig").Native;
const native = @import("../../../internal/testing/native_protocol_io.zig");
const protocol = @import("../v3_protocol.zig");
const allocator = std.testing.allocator;
const Mode = enum { canceled, partial, committed, rejected, full, sibling, receive_failure };

pub fn run(comptime Pump: type, comptime Connection: type, comptime Assoc: type, comptime forward: anytype, comptime settle: anytype, comptime destroy: anytype, comptime service: anytype) !void {
    const Case = struct {
        fn testCase(base: std.Io) !void {
            inline for (.{ Mode.canceled, Mode.partial, Mode.committed, Mode.rejected, Mode.full, Mode.sibling, Mode.receive_failure }) |mode| try exercise(Pump, Connection, Assoc, forward, settle, destroy, service, base, mode);
        }
    };
    try native.run(Case.testCase);
}

fn exercise(comptime Pump: type, comptime Connection: type, comptime Assoc: type, comptime forward: anytype, comptime settle: anytype, comptime destroy: anytype, comptime service: anytype, base: std.Io, comptime mode: Mode) !void {
    var first: Fixture = undefined;
    try first.init(base, 64);
    defer first.deinit();
    first.session.stop();
    var second: Fixture = undefined;
    try second.init(base, 64);
    defer second.deinit();
    second.session.stop();
    var clock: Native = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .delegate_io = base };
    defer clock.backend.deinit();
    first.gate.delegate = clock.io();
    second.gate.delegate = clock.io();
    var running: std.atomic.Value(bool) = .init(true);
    var pump: Pump = .{
        .allocator = allocator,
        .io = first.observed(),
        .endpoint = undefined,
        .config = .{ .password = "udp-credit", .identity = undefined },
        .limiter = undefined,
        .shared = undefined,
        .receive_storage = &.{},
        .versions = .{ 1, 2 },
        .stop_flag = &running,
    };
    const capacity: u64 = if (mode == .full) 6 * (Session.send_capacity + 1) else 6;
    var connection: Connection = .{
        .pump = &pump,
        .handle = 1,
        .established = undefined,
        .peer = .{ .ip4 = .loopback(1234) },
        .created_ns = 0,
        .last_activity_ns = 0,
        .send_bucket = ByteBucket.init(0, 0),
        .recv_bucket = ByteBucket.initWithBurst(1, capacity, 0),
        .datagram_buffer = &.{},
    };
    defer {
        for (connection.assocs.items) |assoc| destroy(&connection, assoc);
        connection.assocs.deinit(allocator);
    }
    inline for (.{ &first, &second }, 1..) |fixture, id| {
        const assoc = try allocator.create(Assoc);
        errdefer allocator.destroy(assoc);
        assoc.* = .{ .id = id, .stream_id = id, .socket = fixture.socket, .last_activity_ns = 0 };
        try assoc.target_io.init(allocator, fixture.observed(), fixture.socket, .{ .maximum_datagram_bytes = 64, .resolve_timeout = .fromSeconds(1), .notify_context = fixture, .notify = notify(Fixture) });
        errdefer assoc.target_io.deinit();
        try connection.assocs.append(allocator, assoc);
        fixture.owns_socket = false;
    }
    const first_assoc = connection.assocs.items[0];
    if (mode == .sibling) connection.recv_bucket = ByteBucket.init(0, 0);
    forward(&connection, 1, "127.0.0.1", first.peer.address.getPort(), "abcdef");
    try first.entered();
    if (mode == .full) {
        for (1..Session.send_capacity) |_| forward(&connection, 1, "127.0.0.1", first.peer.address.getPort(), "abcdef");
        try std.testing.expectEqual(@as(u64, 6), connection.recv_bucket.tokens);
        forward(&connection, 1, "127.0.0.1", first.peer.address.getPort(), "reject");
        try std.testing.expectEqual(@as(u64, 6), connection.recv_bucket.tokens);
    } else if (mode != .sibling) {
        try std.testing.expectEqual(@as(u64, 0), connection.recv_bucket.tokens);
        forward(&connection, 2, "127.0.0.1", second.peer.address.getPort(), "UVWXYZ");
        try std.testing.expect(connection.assocs.items[1].target_io.takeSent() == null);
        for (&connection.assocs.items[1].target_io.send_slots) |*slot| try std.testing.expect(!slot.active);
    }
    if (mode == .receive_failure) {
        connection.send_bucket = ByteBucket.initWithBurst(1, 64, 0);
        connection.send_bucket.tokens = 0;
        first.gate.fail_receive_after_packet.store(true, .release);
        try first.peer.send(base, &first.socket.address, "last");
        const until = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(2) });
        while (true) {
            first.changed.reset();
            if (first_assoc.target_io.receive_failed.load(.acquire)) break;
            try first.changed.waitTimeout(base, .{ .deadline = until });
        }
        try std.testing.expect(first_assoc.target_io.hasReceived());
        service(&connection, false);
        try std.testing.expect(first_assoc.closed);
        try std.testing.expect(!first_assoc.target_io.hasReceived());
        try std.testing.expectEqual(@as(usize, 1), first_assoc.pending_replies.count);
        const message = try protocol.parseUdpMessage(first_assoc.pending_replies.peek().?);
        try std.testing.expectEqualSlices(u8, "last", message.data);
        try std.testing.expectEqual(@as(u32, 1), message.session_id);
        try std.testing.expectEqualStrings("127.0.0.1", message.host);
        try std.testing.expectEqual(first.peer.address.getPort(), message.port);
    } else if (mode == .sibling) {
        second.gate.release.set(base);
        forward(&connection, 2, "127.0.0.1", second.peer.address.getPort(), "UVWXYZ");
        const result = try completed(&second, &connection.assocs.items[1].target_io);
        settle(&connection, result);
        try second.readExact("UVWXYZ");
        try std.testing.expectEqual(@as(usize, 6), result.committed_bytes);
        try std.testing.expect(result.failure == null);
        try std.testing.expect(first_assoc.target_io.takeSent() == null);
    } else if (mode == .partial or mode == .committed or mode == .rejected) {
        first.gate.maximum = if (mode == .partial) 3 else 6;
        first.gate.positive_error = mode != .rejected;
        first.gate.reject = mode == .rejected;
        first.gate.release.set(base);
        const result = try completed(&first, &first_assoc.target_io);
        const committed: usize = if (mode == .partial) 3 else if (mode == .committed) 6 else 0;
        try std.testing.expectEqual(committed, result.committed_bytes);
        settle(&connection, result);
        try std.testing.expectEqual(@as(u64, 6 - committed), connection.recv_bucket.tokens);
        if (committed != 0) try first.readExact("abcdef"[0..committed]);
    }
    _ = connection.assocs.orderedRemove(0);
    destroy(&connection, first_assoc);
    if (mode != .sibling) {
        const expected: u64 = if (mode == .partial) 3 else if (mode == .committed) 0 else capacity;
        try std.testing.expectEqual(expected, connection.recv_bucket.tokens);
    }
}

fn notify(comptime T: type) *const fn (?*anyopaque) void {
    return struct {
        fn call(context: ?*anyopaque) void {
            const fixture: *T = @ptrCast(@alignCast(context.?));
            fixture.changed.set(fixture.base);
        }
    }.call;
}
fn completed(fixture: *Fixture, session: *Session) !Session.Completion {
    const deadline = std.Io.Clock.Timestamp.fromNow(fixture.base, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (true) {
        fixture.changed.reset();
        if (session.takeSent()) |result| return result;
        try fixture.changed.waitTimeout(fixture.base, .{ .deadline = deadline });
    }
}

pub fn idleOwners(comptime Pump: type, comptime Connection: type, comptime Assoc: type, comptime service: anytype, comptime destroy: anytype) !void {
    const Case = struct {
        fn testCase(base: std.Io) !void {
            var fixture: Fixture = undefined;
            try fixture.init(base, 64);
            defer fixture.deinit();
            fixture.session.stop();
            var running: std.atomic.Value(bool) = .init(true);
            var pump: Pump = .{
                .allocator = allocator,
                .io = fixture.observed(),
                .endpoint = undefined,
                .config = .{ .password = "udp-idle", .identity = undefined },
                .limiter = undefined,
                .shared = undefined,
                .receive_storage = &.{},
                .versions = .{ 1, 2 },
                .stop_flag = &running,
            };
            const now = @as(i64, @intCast(std.Io.Clock.awake.now(base).nanoseconds));
            var connection: Connection = .{
                .pump = &pump,
                .handle = 1,
                .established = undefined,
                .peer = .{ .ip4 = .loopback(1234) },
                .created_ns = now,
                .last_activity_ns = now,
                .send_bucket = ByteBucket.init(0, now),
                .recv_bucket = ByteBucket.init(0, now),
                .datagram_buffer = &.{},
            };
            defer {
                for (connection.assocs.items) |assoc| destroy(&connection, assoc);
                connection.assocs.deinit(allocator);
            }
            const initial_calls = fixture.gate.receive_calls.load(.acquire);
            const owner_count = 32;
            for (0..owner_count) |id| {
                const socket = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).bind(base, .{ .mode = .dgram, .protocol = .udp });
                errdefer socket.close(base);
                const assoc = try allocator.create(Assoc);
                errdefer allocator.destroy(assoc);
                assoc.* = .{ .id = @intCast(id), .stream_id = id, .socket = socket, .last_activity_ns = now };
                try assoc.target_io.init(allocator, fixture.observed(), socket, .{ .maximum_datagram_bytes = 64, .resolve_timeout = .fromSeconds(1) });
                errdefer assoc.target_io.deinit();
                try connection.assocs.append(allocator, assoc);
            }
            const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(2) });
            while (true) {
                fixture.gate.receive_entered.reset();
                if (fixture.gate.receive_calls.load(.acquire) == initial_calls + owner_count) break;
                try fixture.gate.receive_entered.waitTimeout(base, .{ .deadline = deadline });
            }
            const before = fixture.gate.receive_calls.load(.acquire);
            const start = std.Io.Clock.awake.now(base);
            service(&connection, false);
            const elapsed = start.durationTo(std.Io.Clock.awake.now(base)).nanoseconds;
            try std.testing.expectEqual(before, fixture.gate.receive_calls.load(.acquire));
            for (connection.assocs.items) |assoc| try std.testing.expect(!assoc.closed);
            std.debug.print("record=udp-idle-service associations={d} target_receive_calls=0 service_ns={d} session_bytes={d}\n", .{ owner_count, elapsed, @sizeOf(Session) });
        }
    };
    try native.run(Case.testCase);
}

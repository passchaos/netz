const std = @import("std");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const test_limits: runtime.Limits = .{
    .http3 = .{
        .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        },
        // Force both HTTP/3 DATA and Capsule Protocol state to span packets.
        .max_stream_frame_data = 3,
    },
};

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
}

const AcceptTask = struct {
    server: *runtime.Server,
    io: std.Io,
    path: []const u8,
    accepted: ?runtime.AcceptedSession = null,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var pending = try self.server.receiveSessionRequestWithDeadline(
            futureDeadline(self.io),
        );
        errdefer pending.deinit();
        try std.testing.expectEqualStrings(self.path, pending.path());
        self.accepted = try pending.accept();
    }
};

fn connectAndAccept(
    allocator: std.mem.Allocator,
    io: std.Io,
    server: *runtime.Server,
    path: []const u8,
) !struct {
    client: runtime.ClientSession,
    accepted: runtime.AcceptedSession,
} {
    var task = AcceptTask{
        .server = server,
        .io = io,
        .path = path,
    };
    const thread = try std.Thread.spawn(.{}, AcceptTask.run, .{&task});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.ClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = path,
            .limits = test_limits,
        },
    );
    errdefer client.deinit();

    thread.join();
    joined = true;
    if (task.err) |err| return err;
    return .{
        .client = client,
        .accepted = task.accepted orelse return error.TestUnexpectedResult,
    };
}

test "WebTransport dev control exchanges server drain and client close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var pair = try connectAndAccept(
        allocator,
        io,
        &server,
        "/server-drain",
    );
    defer pair.client.deinit();
    defer pair.accepted.deinit(allocator);

    try pair.accepted.drain();
    try std.testing.expect(
        (try pair.client.receiveSessionEventWithDeadline(
            futureDeadline(io),
        )) == .draining,
    );

    try pair.client.close(41, "client complete");
    const closed = try pair.accepted.receiveSessionEventWithDeadline(
        futureDeadline(io),
    );
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(@as(u32, 41), closed.closed.code);
    try std.testing.expectEqualStrings(
        "client complete",
        closed.closed.reason,
    );
}

test "WebTransport dev control exchanges client drain and server close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var pair = try connectAndAccept(
        allocator,
        io,
        &server,
        "/client-drain",
    );
    defer pair.client.deinit();
    defer pair.accepted.deinit(allocator);

    try pair.client.drain();
    try std.testing.expect(
        (try pair.accepted.receiveSessionEventWithDeadline(
            futureDeadline(io),
        )) == .draining,
    );

    try pair.accepted.close(42, "server complete");
    const closed = try pair.client.receiveSessionEventWithDeadline(
        futureDeadline(io),
    );
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(@as(u32, 42), closed.closed.code);
    try std.testing.expectEqualStrings(
        "server complete",
        closed.closed.reason,
    );
}

test "WebTransport dev fragmented capsules resume after timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var pair = try connectAndAccept(
        allocator,
        io,
        &server,
        "/fragmented-control",
    );
    defer pair.client.deinit();
    defer pair.accepted.deinit(allocator);

    var drain_bytes: std.ArrayList(u8) = .empty;
    defer drain_bytes.deinit(allocator);
    try (webtransport.Capsule{ .drain_session = {} }).write(
        &drain_bytes,
        allocator,
    );
    const split = drain_bytes.items.len - 1;

    try pair.client.sendSessionData(drain_bytes.items[0..split], false);
    try std.testing.expectError(
        error.Timeout,
        pair.accepted.receiveSessionEventWithTimeout(.fromMilliseconds(20)),
    );
    try pair.client.sendSessionData(drain_bytes.items[split..], false);
    try std.testing.expect(
        (try pair.accepted.receiveSessionEventWithDeadline(
            futureDeadline(io),
        )) == .draining,
    );

    try server.sendSessionData(
        pair.accepted.request.from,
        pair.accepted.session_id,
        drain_bytes.items[0..split],
        false,
    );
    try std.testing.expectError(
        error.Timeout,
        pair.client.receiveSessionEventWithTimeout(.fromMilliseconds(20)),
    );
    try server.sendSessionData(
        pair.accepted.request.from,
        pair.accepted.session_id,
        drain_bytes.items[split..],
        false,
    );
    try std.testing.expect(
        (try pair.client.receiveSessionEventWithDeadline(
            futureDeadline(io),
        )) == .draining,
    );

    try pair.client.close(43, "fragmented complete");
    const closed = try pair.accepted.receiveSessionEventWithDeadline(
        futureDeadline(io),
    );
    try std.testing.expect(closed == .closed);
}

test "WebTransport dev control validates timeout and deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    try std.testing.expectError(
        error.Timeout,
        server.receiveSessionRequestWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveSessionRequestWithDeadline(.{
            .raw = .zero,
            .clock = .real,
        }),
    );

    var pair = try connectAndAccept(
        allocator,
        io,
        &server,
        "/invalid-deadline",
    );
    defer pair.client.deinit();
    defer pair.accepted.deinit(allocator);
    var buffer: [16]u8 = undefined;

    try std.testing.expectError(
        error.Timeout,
        server.receiveSessionDataWithTimeout(
            pair.accepted.request.from,
            pair.accepted.session_id,
            &buffer,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveSessionDataWithDeadline(
            pair.accepted.request.from,
            pair.accepted.session_id,
            &buffer,
            .{ .raw = .zero, .clock = .real },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        pair.accepted.receiveSessionEventWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        pair.accepted.receiveSessionEventWithDeadline(.{
            .raw = .zero,
            .clock = .real,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        pair.client.receiveSessionDataWithTimeout(&buffer, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        pair.client.receiveSessionDataWithDeadline(
            &buffer,
            .{ .raw = .zero, .clock = .real },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        pair.client.receiveSessionEventWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        pair.client.receiveSessionEventWithDeadline(.{
            .raw = .zero,
            .clock = .real,
        }),
    );

    try pair.client.close(44, "done");
    _ = try pair.accepted.receiveSessionEventWithDeadline(futureDeadline(io));
}

test "WebTransport dev malformed capsule cancels the CONNECT stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var pair = try connectAndAccept(
        allocator,
        io,
        &server,
        "/malformed-control",
    );
    defer pair.client.deinit();
    defer pair.accepted.deinit(allocator);

    // Encoding a known DRAIN type through the unknown arm deliberately gives
    // it a forbidden non-empty payload while keeping valid varint framing.
    var malformed: std.ArrayList(u8) = .empty;
    defer malformed.deinit(allocator);
    try (webtransport.Capsule{ .unknown = .{
        .capsule_type = webtransport.CapsuleType.drain_webtransport_session,
        .payload = "x",
    } }).write(&malformed, allocator);
    try pair.client.sendSessionData(malformed.items, false);
    try std.testing.expectError(
        error.InvalidCapsule,
        pair.accepted.receiveSessionEventWithDeadline(futureDeadline(io)),
    );

    try std.testing.expectError(
        error.RequestCancelled,
        pair.client.receiveSessionEventWithDeadline(futureDeadline(io)),
    );
}

test "WebTransport dev DATAGRAM receive preserves queued control data" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var pair = try connectAndAccept(
        allocator,
        io,
        &server,
        "/datagram-control",
    );
    defer pair.client.deinit();
    defer pair.accepted.deinit(allocator);

    try pair.client.drain();
    try pair.client.sendDatagram("after-control");

    var datagram = try server.receiveDatagramWithDeadline(futureDeadline(io));
    defer datagram.deinit(allocator);
    try std.testing.expectEqual(
        pair.accepted.sessionId().value,
        datagram.datagram.session_id.value,
    );
    try std.testing.expectEqualStrings(
        "after-control",
        datagram.datagram.payload,
    );
    try std.testing.expect(
        (try pair.accepted.receiveSessionEventWithDeadline(
            futureDeadline(io),
        )) == .draining,
    );
}

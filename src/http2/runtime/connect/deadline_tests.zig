//! The CONNECT budget covers actual socket output, including CONTINUATION.
const std = @import("std");
const builtin = @import("builtin");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const websocket = @import("../../../websocket/runtime.zig");
const wire = @import("../frame/wire.zig");
const frame_io = @import("../frame/io.zig");

const allocator = std.testing.allocator;
const large_value = "x" ** (256 * 1024);

const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;

test "HTTP/2 CONNECT deadline bounds blocked opening HEADERS and CONTINUATION" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    try fixture.startRescue();
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    const result = fixture.connection.openExtendedConnectAttemptWithTimeout(.{
        .method = "CONNECT",
        .path = "/blocked",
        .authority = "localhost",
        .protocol = "websocket",
        .headers = &.{.{ .name = "x-large", .value = large_value }},
    }, .fromMilliseconds(30));
    if (result) |value| {
        var attempt = value;
        attempt.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.Timeout, err);
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
}

const Admission = enum { accept, reject_headers, reject_body, drop };

test "WebSocket RFC 8441 deadline bounds blocked acceptance HEADERS" {
    try blockedAdmission(.accept);
}

test "WebSocket RFC 8441 deadline bounds blocked rejection HEADERS" {
    try blockedAdmission(.reject_headers);
}

test "WebSocket RFC 8441 deadline bounds blocked rejection DATA" {
    try blockedAdmission(.reject_body);
}

test "WebSocket RFC 8441 deadline bounds pending stream destruction" {
    try blockedAdmission(.drop);
}

test "HTTP/2 CONNECT deadline bounds blocked duplex DATA output" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    const id = try runtime.testing.reserveNextClientStreamId(&fixture.connection);
    var tunnel: runtime.Tunnel = .{ .connection = &fixture.connection, .stream_id = id };
    try fixture.startRescue();
    var progress: runtime.TunnelWriteProgress = .{};
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    try std.testing.expectError(error.Timeout, tunnel.writeWithTimeout(large_value, false, &progress, .fromMilliseconds(30)));
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
}

test "HTTP/2 CONNECT response deadline bounds blocked credit refund" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    try fixture.startRescue();
    const FillAfterOpening = struct {
        io: std.Io,
        sender: std.Io.net.Stream,
        peer: std.Io.net.Stream,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var opening = try frame_io.readOwned(allocator, self.io, self.peer, 4096);
            defer opening.deinit(allocator);
            try std.testing.expectEqual(http2.FrameType.headers, opening.frame.header.frame_type);
            // Once the opening head is accepted, saturate the outbound socket
            // without reading more peer bytes. This blocks cleanup output.
            const filler = "z" ** 4096;
            for (0..3) |round| {
                while (true) {
                    const rc = std.posix.system.sendto(self.sender.socket.handle, filler.ptr, filler.len, std.posix.MSG.DONTWAIT | std.posix.MSG.NOSIGNAL, null, 0);
                    switch (std.posix.errno(rc)) {
                        .SUCCESS, .INTR => continue,
                        .AGAIN => break,
                        else => |err| return std.posix.unexpectedErrno(err),
                    }
                }
                if (round != 2) try std.Io.sleep(self.io, .fromMilliseconds(20), .awake);
            }
        }
    };
    var fill = FillAfterOpening{ .io = fixture.connection.io, .sender = fixture.connection.stream, .peer = fixture.peer };
    const thread = try std.Thread.spawn(.{}, FillAfterOpening.run, .{&fill});
    var joined = false;
    defer if (!joined) thread.join();
    // A complete rejection head and DATA leave aggregate-owned credit behind
    // when the unfinished response expires. The literal uses :status name 8.
    try wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .headers, 4, 1, "\x08\x03403");
    try wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .data, 0, 1, "body");
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    const result = fixture.connection.openExtendedConnectAttemptWithTimeout(.{ .method = "CONNECT", .path = "/refund", .authority = "localhost", .protocol = "websocket" }, .fromMilliseconds(120));
    if (result) |value| {
        var attempt = value;
        attempt.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.Timeout, err);
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    thread.join();
    joined = true;
    if (fill.err) |err| return err;
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
}

test "HTTP/2 CONNECT response deadlines validate before output or stream mutation" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    try runtime.testing.addActivePeerStream(&fixture.connection, 1);
    const request: runtime.ExtendedConnectRequest = .{ .stream_id = 1, .headers = &.{}, .method = "CONNECT", .path = "/deadline", .scheme = "http", .authority = "localhost", .protocol = "websocket" };
    for ([_]std.Io.Clock{ .awake, .real }) |clock| {
        const deadline = std.Io.Clock.Timestamp.fromNow(fixture.connection.io, .{ .clock = clock, .raw = .fromMilliseconds(if (clock == .awake) -1 else 1000) });
        try std.testing.expectError(error.Timeout, fixture.connection.acceptExtendedConnectWithDeadline(request, &.{}, deadline));
        try std.testing.expectError(error.Timeout, fixture.connection.rejectExtendedConnectWithDeadline(1, 403, &.{}, deadline));
        try std.testing.expectError(error.Timeout, fixture.connection.rejectExtendedConnectWithBodyWithDeadline(1, 403, &.{}, "body", &.{}, deadline));
    }
    try std.testing.expectError(error.Timeout, fixture.connection.acceptExtendedConnectWithTimeout(request, &.{}, .fromMilliseconds(0)));
    try std.testing.expectError(error.Timeout, fixture.connection.rejectExtendedConnectWithTimeout(1, 403, &.{}, .fromMilliseconds(0)));
    try std.testing.expectError(error.Timeout, fixture.connection.rejectExtendedConnectWithBodyWithTimeout(1, 403, &.{}, "body", &.{}, .fromMilliseconds(0)));
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activePeerStreamCount());
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.hpack_encoder.dynamic_table.used);
}

test "HTTP/2 CONNECT staged output allocation failures preserve HPACK and admitted stream" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var failures: usize = 0;
    for (0..32) |fail_index| {
        var fixture = try BlockedOutput.init(threaded.io(), .server);
        defer fixture.deinit();
        try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        const request: runtime.ExtendedConnectRequest = .{ .stream_id = 1, .headers = &.{}, .method = "CONNECT", .path = "/allocation", .scheme = "http", .authority = "localhost", .protocol = "websocket" };
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        fixture.connection.allocator = failing.allocator();
        // This literal exceeds the frame staging stack buffer but fits the
        // unread TCP buffer, so the success boundary does not need a rescue.
        const result = fixture.connection.acceptExtendedConnectWithTimeout(request, &.{.{ .name = "x-owned", .value = "y" ** 512 }}, .fromSeconds(1));
        fixture.connection.allocator = allocator;
        if (result) |_| {
            try std.testing.expect(failures > 0);
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            failures += 1;
            try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
            try std.testing.expectEqual(@as(usize, 1), fixture.connection.activePeerStreamCount());
            try std.testing.expectEqual(@as(usize, 0), fixture.connection.hpack_encoder.dynamic_table.used);
            _ = try fixture.connection.acceptExtendedConnectWithTimeout(request, &.{}, .fromSeconds(1));
        }
    }
    return error.TestUnexpectedResult;
}

fn blockedAdmission(admission: Admission) !void {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    try runtime.testing.addActivePeerStream(&fixture.connection, 1);
    try fixture.startRescue();
    var pending: websocket.PendingH2Upgrade = .{
        .allocator = allocator,
        .connection = &fixture.connection,
        .options = .{},
        .deadline = .fromNow(fixture.connection.io, .{ .clock = .awake, .raw = .fromMilliseconds(30) }),
        .request = .{ .stream_id = 1, .headers = &.{}, .method = "CONNECT", .path = "/blocked", .scheme = "http", .authority = "localhost", .protocol = "websocket" },
        .selected_protocol = null,
        .selected_extension = null,
        .negotiated_extension = .{},
    };
    var owned = true;
    defer if (owned) pending.deinit();
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    const headers = &[_]http2.Hpack.HeaderField{.{ .name = "x-large", .value = large_value }};
    switch (admission) {
        .accept => {
            const result = pending.acceptWithHeaders(headers);
            if (result) |value| {
                owned = false;
                var ws = value;
                ws.close();
                return error.TestUnexpectedResult;
            } else |err| try std.testing.expectEqual(error.Timeout, err);
        },
        .reject_headers, .reject_body => {
            const result = if (admission == .reject_headers) pending.reject(403, headers) else pending.rejectWithBody(403, &.{}, large_value, &.{});
            if (result) |_| {
                owned = false;
                return error.TestUnexpectedResult;
            } else |err| try std.testing.expectEqual(error.Timeout, err);
        },
        .drop => {
            // An already-expired admitted stream must not start an unbounded
            // RST_STREAM write in an infallible adapter destructor.
            pending.deadline = .fromNow(fixture.connection.io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
            pending.deinit();
            owned = false;
            try std.testing.expectEqual(@as(usize, 0), fixture.connection.activePeerStreamCount());
            try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
            var bytes: [16]u8 = undefined;
            const rc = std.posix.system.recvfrom(fixture.peer.socket.handle, &bytes, bytes.len, std.posix.MSG.DONTWAIT, null, null);
            try std.testing.expectEqual(std.posix.E.AGAIN, std.posix.errno(rc));
        },
    }
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
}

const std = @import("std");
const websocket = @import("../mod.zig");
const h3 = @import("h3.zig");
const http3 = @import("../../http3/mod.zig");

const DropNextDatagram = struct {
    armed: std.atomic.Value(bool) = .init(false),
    dropped: std.atomic.Value(usize) = .init(0),

    fn shouldDrop(context: *anyopaque, _: []const u8) bool {
        const self: *DropNextDatagram = @ptrCast(@alignCast(context));
        if (self.armed.cmpxchgStrong(
            true,
            false,
            .acq_rel,
            .acquire,
        ) == null) {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return true;
        }
        return false;
    }
};

test "WebSocket HTTP3 recovery drain retransmits a dropped Close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x77, 0x73, 0x72, 0x01, 0x77, 0x73, 0x72, 0x02 };
    const client_cid = [_]u8{ 0x77, 0x73, 0x72, 0x03 };
    const server_cid = [_]u8{ 0x77, 0x73, 0x72, 0x04 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var drop: DropNextDatagram = .{};

    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe2} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        pending_before_drain: usize = 0,
        recovery_drained: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(
                .{},
                .fromSeconds(2),
            );
            defer connection.deinit();
            try std.testing.expectError(
                error.Timeout,
                connection.waitForRecoveryIdleWithTimeout(.zero),
            );
            var close = (try connection.receiveCloseFrameWithTimeout(
                .fromSeconds(3),
            )) orelse return error.TestUnexpectedResult;
            defer close.deinit(allocator);
            try std.testing.expectEqual(
                websocket.CloseCode.normal_closure,
                close.code,
            );
            try std.testing.expectEqualStrings(
                "recover websocket close",
                close.reason,
            );
            self.pending_before_drain = connection.h3.established.connection
                .pendingRecoveryCount();
            try connection.waitForRecoveryIdleWithTimeout(.fromSeconds(2));
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.h3.established.connection.pendingRecoveryCount(),
            );
            self.recovery_drained = true;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client_limits = limits;
    client_limits.quic.send_interceptor = .{
        .context = &drop,
        .should_drop = DropNextDatagram.shouldDrop,
    };
    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        client_limits,
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .random = [_]u8{0xe3} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
        } },
        .{ .authority = "localhost", .path = "/recovery-drain" },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.waitForRecoveryIdleWithTimeout(.zero),
    );
    drop.armed.store(true, .release);
    const packets_before_close =
        client.h3.established.connection.stats().packets_sent;
    var closed = try client.closeWithTimeout(
        .{
            .code = .normal_closure,
            .reason = "recover websocket close",
        },
        .fromSeconds(3),
    );
    defer closed.deinit(allocator);
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        closed.closed.?.code,
    );
    try std.testing.expectEqualStrings(
        "recover websocket close",
        closed.closed.?.reason,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        drop.dropped.load(.acquire),
    );
    try std.testing.expect(
        client.h3.established.connection.stats().packets_sent >
            packets_before_close + 1,
    );
    try std.testing.expect(
        client.h3.established.connection.stats().packets_lost >= 1,
    );
    try std.testing.expect(
        client.h3.established.connection.ackDelayDeadline() == null,
    );
    try client.waitForRecoveryIdleWithDeadline(.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    }));
    try std.testing.expectEqual(
        @as(usize, 0),
        client.h3.established.connection.pendingRecoveryCount(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.pending_before_drain != 0);
    try std.testing.expect(shared.recovery_drained);
}

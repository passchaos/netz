const std = @import("std");
const quic = @import("../../quic/mod.zig");
const runtime = @import("../runtime.zig");
const webtransport = @import("../mod.zig");

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

test "WebTransport recovery drain retransmits a dropped session close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x72, 0x65, 0x63, 0x01 };
    const server_cid = [_]u8{ 0x72, 0x65, 0x63, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd2} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var drop: DropNextDatagram = .{};

    var server = try runtime.StatefulProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{ .local_settings = settings },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer server.deinit();

    const Shared = struct {
        const Stage = enum { accept, receive_close, drain_fin };

        server: *runtime.StatefulProtectedServer,
        io: std.Io,
        stage: Stage = .accept,
        pending_before_drain: usize = 0,
        recovery_drained: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                std.debug.print(
                    "WebTransport recovery drain server failed during {s}: {s}\n",
                    .{ @tagName(self.stage), @errorName(err) },
                );
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer session.deinit();
            session.h3.dispatcher_bound = true;
            try std.testing.expectError(
                error.InvalidDispatcherState,
                session.waitForRecoveryIdleWithTimeout(.fromSeconds(1)),
            );
            session.h3.dispatcher_bound = false;
            try std.testing.expectError(
                error.Timeout,
                session.waitForRecoveryIdleWithTimeout(.zero),
            );
            self.stage = .receive_close;
            const closed = try session.receiveSessionEventWithTimeout(
                .fromSeconds(3),
            );
            try std.testing.expect(closed == .closed);
            try std.testing.expectEqual(@as(u32, 73), closed.closed.code);
            try std.testing.expectEqualStrings(
                "recover final close",
                closed.closed.reason,
            );
            self.pending_before_drain = session.h3.established.connection
                .pendingRecoveryCount();
            self.stage = .drain_fin;
            try session.waitForRecoveryIdleWithDeadline(.fromNow(self.io, .{
                .raw = .fromSeconds(2),
                .clock = .awake,
            }));
            try std.testing.expect(
                !session.h3.established.connection.pendingDeliveryRecovery(),
            );
            self.recovery_drained = true;
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.StatefulProtectedClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/recovery-drain",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
                .send_interceptor = .{
                    .context = &drop,
                    .should_drop = DropNextDatagram.shouldDrop,
                },
            } } },
            .h3 = .{ .local_settings = settings },
            .transport = .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .local_transport_parameters = quic.practical_transport_parameters,
                .peer_transport_parameters = quic.practical_transport_parameters,
                .one_rtt = .{ .enable_pacing = false },
            },
        },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.waitForRecoveryIdleWithTimeout(.zero),
    );
    drop.armed.store(true, .release);
    const packets_before_close = client.stats().packets_sent;
    try client.close(73, "recover final close");
    try std.testing.expectEqual(
        @as(usize, 1),
        drop.dropped.load(.acquire),
    );
    try std.testing.expect(
        client.session.h3.established.connection.pendingRecoveryCount() != 0,
    );
    const peer_fin = try client.receiveSessionEventWithTimeout(
        .fromSeconds(2),
    );
    try std.testing.expect(peer_fin == .closed);
    try std.testing.expectEqual(@as(u32, 0), peer_fin.closed.code);
    try std.testing.expect(
        client.session.h3.established.connection.ackDelayDeadline() == null,
    );
    try client.waitForRecoveryIdleWithTimeout(.fromSeconds(2));
    try std.testing.expectEqual(
        @as(usize, 0),
        client.session.h3.established.connection.pendingRecoveryCount(),
    );
    try std.testing.expect(
        client.stats().packets_sent > packets_before_close + 1,
    );
    try std.testing.expect(client.stats().packets_lost >= 1);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.pending_before_drain != 0);
    try std.testing.expect(shared.recovery_drained);
}

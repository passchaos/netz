const std = @import("std");
const webtransport = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const DeadlineIo = @import("io.zig").DeadlineIo;
const native_protocol_io = @import("../../../../internal/testing/native_protocol_io.zig");

test "WebTransport terminal event survives cleanup timeout" {
    try native_protocol_io.run(terminalCleanup);
}

fn terminalCleanup(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const Stage = enum { connect, await_peer_fin, force_cleanup_timeout, resume_cleanup, join };
    var stage: Stage = .connect;
    errdefer std.debug.print(
        "WebTransport terminal cleanup test failed during {s}\n",
        .{@tagName(stage)},
    );

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x4f, 0x01, 0x57, 0x54, 0x4f, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x4f, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x4f, 0x04 };
    const limits: runtime.Limits = .{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } } };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xf7} ** 32,
            .x25519_secret_key = [_]u8{0xf8} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try session.close(313, "peer terminal retained");
            // Keep the QUIC owner alive to service ACK/PTO recovery until the
            // client resumes cleanup and closes its CONNECT send direction.
            // Returning immediately after the first UDP submission would make
            // this reliability test depend on that datagram never being lost.
            const event = try session.receiveSessionEventWithTimeout(
                .fromSeconds(5),
            );
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 0), event.closed.code);
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try io.concurrent(Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-terminal-event-timeout",
            .limits = limits,
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .initial_one_rtt_config = .{ .enable_pacing = true },
                .random = [_]u8{0xf5} ** 32,
                .x25519_secret_key = [_]u8{0xf6} ** 32,
            } },
        },
    );
    defer client.deinit();

    stage = .await_peer_fin;
    while ((client.h3.established.connection.recvStreamStats(
        client.session_id.value,
    ) orelse return error.TestUnexpectedResult).final_size == null) {
        var packet = try client.h3.established.connection
            .receivePacketServicingTimersTimeout(.{
            .duration = .{
                .raw = .fromSeconds(5),
                .clock = .awake,
            },
        });
        defer packet.deinit(allocator);
        try client.processPacket(&packet);
    }

    var fixed = DeadlineIo.init(allocator, client.h3.established.connection.endpoint.io);
    defer fixed.deinit();
    client.h3.established.connection.endpoint.io = fixed.io();
    defer client.h3.established.connection.endpoint.io = fixed.native.baseIo();
    quic.one_rtt.testing.exhaustPacingAt(
        &client.h3.established.connection,
        @intCast(fixed.native.now_ns.load(.acquire)),
    );
    stage = .force_cleanup_timeout;
    try std.testing.expectError(
        error.Timeout,
        client.receiveSessionEventWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.native.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expect(runtime.testing.hasPendingSessionEvent(&client));
    try std.testing.expectEqual(@as(usize, 0), fixed.native.send_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), fixed.native.duration_sleep_calls.load(.acquire));
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        100_000,
        @intCast(fixed.native.now_ns.load(.acquire)),
    );
    stage = .resume_cleanup;
    const event = try client.receiveSessionEventWithTimeout(.fromSeconds(5));
    try std.testing.expect(fixed.native.send_calls.load(.acquire) > 0);
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 313), event.closed.code);
    try std.testing.expectEqualStrings(
        "peer terminal retained",
        event.closed.reason,
    );

    stage = .join;
    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport deadline cleanup retains completed stream prefix" {
    try native_protocol_io.run(streamCleanup);
}

fn streamCleanup(io: std.Io) !void {
    const allocator = std.testing.allocator;
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-dl-srv",
        .peer_connection_id = "wt-dl-cli",
        .local_endpoint = .client,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 2 },
    );
    defer registry.deinit();
    _ = try registry.registerLocal(4, .bidirectional);
    _ = try registry.registerLocal(8, .bidirectional);
    try connection.send(&.{.{ .stream = .{
        .stream_id = 4,
        .data = "first",
    } }});
    try connection.send(&.{.{ .stream = .{
        .stream_id = 8,
        .data = "second",
    } }});

    var fixed = DeadlineIo.init(allocator, endpoint.io);
    defer fixed.deinit();
    fixed.expire_after_send_call = 1;
    endpoint.io = fixed.io();
    defer endpoint.io = fixed.native.baseIo();
    try std.testing.expectError(
        error.Timeout,
        @import("../../session_control.zig").terminateStreamsWithDeadline(
            &connection,
            &registry,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.native.now_ns.load(.acquire) + 1),
            },
        ),
    );
    try std.testing.expect(registry.get(4).?.send_reset != null);
    try std.testing.expect(registry.get(8).?.send_reset == null);

    endpoint.io = fixed.native.baseIo();
    try @import("../../session_control.zig").terminateStreamsWithDeadline(
        &connection,
        &registry,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        registry.get(4).?.send_reset.?.http3_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        registry.get(8).?.send_reset.?.http3_code,
    );
    try std.testing.expect(quic.one_rtt.testing.localStreamReleaseRequested(
        &connection,
        4,
    ));
    try std.testing.expect(quic.one_rtt.testing.localStreamReleaseRequested(
        &connection,
        8,
    ));
}

const std = @import("std");
const webtransport = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const DeadlineIo = @import("io.zig").DeadlineIo;
const native_protocol_io = @import("../../../../internal/testing/native_protocol_io.zig");

test "WebTransport authenticated close deadline resumes capsule and stream cleanup" {
    try native_protocol_io.run(authenticatedClose);
}

fn authenticatedClose(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x44, 0x01, 0x57, 0x54, 0x44, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x44, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x44, 0x04 };
    const limits: runtime.Limits = .{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } } };
    const h3_session: http3.runtime.HandshakeSessionOptions = .{
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 1,
    };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd7} ** 32,
                .x25519_secret_key = [_]u8{0xd8} ** 32,
            },
            .session = h3_session,
        },
    );
    defer server.deinit();

    const reason = "0123456789" ** 12;
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
            const event = try session.receiveSessionEventWithTimeout(
                .fromSeconds(5),
            );
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 117), event.closed.code);
            try std.testing.expectEqualStrings(reason, event.closed.reason);
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
            .path = "/wt-close-deadline",
            .limits = limits,
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .initial_one_rtt_config = .{
                        .max_datagram_size = 1400,
                        .enable_pacing = true,
                    },
                    .random = [_]u8{0xd5} ** 32,
                    .x25519_secret_key = [_]u8{0xd6} ** 32,
                },
                .session = h3_session,
            },
        },
    );
    defer client.deinit();

    const packets_before_invalid_deadline = client.getStats().packets_sent;
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(117, reason, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );
    try std.testing.expect(!runtime.testing.localCloseSent(&client));
    try std.testing.expectEqual(
        packets_before_invalid_deadline,
        client.getStats().packets_sent,
    );

    const bidi = try client.openBidirectionalStream();
    try client.sendStream(bidi, "bidi", false);
    const uni = try client.openUnidirectionalStream();
    try client.sendStream(uni, "uni", false);

    var fixed = DeadlineIo.init(allocator, client.h3.endpoint.io);
    defer fixed.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = fixed.native.baseIo();
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.native.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(117, reason, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.native.now_ns.load(.acquire) + 1),
        }),
    );
    const progress = runtime.testing.pendingCloseProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(!runtime.testing.localCloseSent(&client));
    try std.testing.expect(fixed.native.send_calls.load(.acquire) > 0);
    try std.testing.expectEqual(@as(usize, 0), fixed.native.duration_sleep_calls.load(.acquire));
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendStream(bidi, "must-not-interleave", false),
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        client.closeWithDeadline(118, "different", .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.native.now_ns.load(.acquire) + 1),
        }),
    );
    const remaining = progress.total - progress.committed;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        100_000,
        @intCast(fixed.native.now_ns.load(.acquire)),
    );
    fixed.expire_after_send_call = fixed.native.send_calls.load(.acquire) + remaining + 1;
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(117, reason, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.native.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );
    try std.testing.expect(runtime.testing.localCloseSent(&client));
    const bidi_state = client.streams.get(bidi) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(bidi_state.send_reset != null);
    try std.testing.expect(bidi_state.stop_sent == null);
    const uni_state_before_resume = client.streams.get(uni) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(uni_state_before_resume.send_reset == null);

    client.h3.endpoint.io = fixed.native.baseIo();
    try client.closeWithTimeout(117, reason, .fromSeconds(5));
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        bidi_state.send_reset.?.http3_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        bidi_state.stop_sent.?.http3_code,
    );
    const uni_state = client.streams.get(uni) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        uni_state.send_reset.?.http3_code,
    );
    try std.testing.expect(uni_state.stop_sent == null);
    const packets_after_close = client.getStats().packets_sent;
    try client.closeWithTimeout(999, "already closed", .fromSeconds(1));
    try std.testing.expectEqual(
        packets_after_close,
        client.getStats().packets_sent,
    );

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport authenticated drain deadline resumes exact capsule" {
    try native_protocol_io.run(authenticatedDrain);
}

fn authenticatedDrain(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x49, 0x01, 0x57, 0x54, 0x49, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x49, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x49, 0x04 };
    const limits: runtime.Limits = .{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } } };
    const h3_session: http3.runtime.HandshakeSessionOptions = .{
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 1,
        .paced_body_chunk_bytes = 1,
    };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xdb} ** 32,
                .x25519_secret_key = [_]u8{0xdc} ** 32,
            },
            .session = h3_session,
        },
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
            const drain = try session.receiveSessionEventWithTimeout(
                .fromSeconds(5),
            );
            try std.testing.expect(drain == .draining);
            const close = try session.receiveSessionEventWithTimeout(
                .fromSeconds(5),
            );
            try std.testing.expect(close == .closed);
            try std.testing.expectEqual(@as(u32, 0), close.closed.code);
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
            .path = "/wt-drain-deadline",
            .limits = limits,
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .initial_one_rtt_config = .{
                        .max_datagram_size = 1400,
                        .enable_pacing = true,
                    },
                    .random = [_]u8{0xd9} ** 32,
                    .x25519_secret_key = [_]u8{0xda} ** 32,
                },
                .session = h3_session,
            },
        },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.drainWithDeadline(.{ .clock = .real, .raw = .zero }),
    );
    try std.testing.expect(
        runtime.testing.pendingDrainProgress(&client) == null,
    );

    var fixed = DeadlineIo.init(allocator, client.h3.endpoint.io);
    defer fixed.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = fixed.native.baseIo();
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.native.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.drainWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.native.now_ns.load(.acquire) + 1),
        }),
    );
    const progress = runtime.testing.pendingDrainProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendStream(try client.streams.prepareLocal(.bidirectional), "must-not-interleave", false),
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        client.close(9, "must-not-interleave"),
    );

    client.h3.endpoint.io = fixed.native.baseIo();
    try client.drainWithTimeout(.fromSeconds(5));
    try std.testing.expect(
        runtime.testing.pendingDrainProgress(&client) == null,
    );
    try std.testing.expect(client.control.local_drain_sent);
    const stream_id = try client.openBidirectionalStream();
    try client.sendStream(stream_id, "after drain", true);
    try client.closeWithTimeout(0, "", .fromSeconds(5));

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport server close deadline resumes one exact capsule" {
    try native_protocol_io.run(serverClose);
}

fn serverClose(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x45, 0x01, 0x57, 0x54, 0x45, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x45, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x45, 0x04 };
    const limits: runtime.Limits = .{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } } };
    const h3_session: http3.runtime.HandshakeSessionOptions = .{
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 1,
    };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xe7} ** 32,
                .x25519_secret_key = [_]u8{0xe8} ** 32,
            },
            .session = h3_session,
        },
    );
    defer server.deinit();

    const reason = "server-close-" ** 10;
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
            var fixed = DeadlineIo.init(allocator, session.h3.established.connection.endpoint.io);
            defer fixed.deinit();
            session.h3.established.connection.endpoint.io = fixed.io();
            defer session.h3.established.connection.endpoint.io = fixed.native.baseIo();
            quic.one_rtt.testing.setPacingBudgetAt(
                &session.h3.established.connection,
                64,
                @intCast(fixed.native.now_ns.load(.acquire)),
            );
            try std.testing.expectError(
                error.Timeout,
                session.closeWithDeadline(211, reason, .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(fixed.native.now_ns.load(.acquire) + 1),
                }),
            );
            const progress = runtime.testing.pendingCloseProgress(&session) orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(progress.committed > 0);
            try std.testing.expect(progress.committed < progress.total);
            try std.testing.expect(!runtime.testing.localCloseSent(&session));
            try std.testing.expect(fixed.native.send_calls.load(.acquire) > 0);
            try std.testing.expectEqual(@as(usize, 0), fixed.native.duration_sleep_calls.load(.acquire));

            session.h3.established.connection.endpoint.io = fixed.native.baseIo();
            try session.closeWithTimeout(211, reason, .fromSeconds(5));
            try std.testing.expect(
                runtime.testing.pendingCloseProgress(&session) == null,
            );
            try std.testing.expect(runtime.testing.localCloseSent(&session));
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
            .path = "/wt-server-close-deadline",
            .limits = limits,
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xe5} ** 32,
                    .x25519_secret_key = [_]u8{0xe6} ** 32,
                },
                .session = h3_session,
            },
        },
    );
    defer client.deinit();

    const event = try client.receiveSessionEventWithTimeout(.fromSeconds(5));
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 211), event.closed.code);
    try std.testing.expectEqualStrings(reason, event.closed.reason);

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

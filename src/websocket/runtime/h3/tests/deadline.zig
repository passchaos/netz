const std = @import("std");
const NativeSendIo = @import("../../../../internal/testing/deadline_send_io.zig").Native;
const native_protocol_io = @import("../../../../internal/testing/native_protocol_io.zig");
const websocket = @import("../../../mod.zig");
const h3 = @import("../../h3.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const tls_testing = @import("../../../../tls/mod.zig").testing;
const tls_stream = @import("../../../../tls/mod.zig").stream;
const header_fields = @import("headers.zig");
const large_header_value = header_fields.large_header_value;
const countHeaders = header_fields.countHeaders;
const findHeader = header_fields.findHeader;

test "WebSocket HTTP3 bounds paced admission with 80 headers at 1200 MTU" {
    try native_protocol_io.run(pacedLargeHeaders);
}

fn pacedLargeHeaders(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 };
    const client_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const server_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 1200,
        .max_frames_per_datagram = 16,
    } };
    var request_headers: [80]http3.Qpack.HeaderField = undefined;
    var response_headers: [80]http3.Qpack.HeaderField = undefined;
    for (&request_headers) |*header| {
        header.* = .{
            .name = "x-many-request",
            .value = large_header_value,
            .never_indexed = true,
        };
    }
    for (&response_headers) |*header| {
        header.* = .{
            .name = "x-many-response",
            .value = large_header_value,
            .never_indexed = true,
        };
    }

    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe2} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        response_headers: []const http3.Qpack.HeaderField,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{ .allowed_origins = &.{"https://example.test"} },
                .fromSeconds(3),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/many-headers",
                pending.target(),
            );
            try std.testing.expectEqualStrings(
                "localhost",
                pending.authority() orelse return error.TestUnexpectedResult,
            );
            try std.testing.expect(pending.peerAddress().?.getPort() != 0);
            try std.testing.expectEqual(
                @as(usize, 80),
                countHeaders(pending.headers(), "x-many-request"),
            );
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.header("origin") orelse
                    return error.TestUnexpectedResult,
            );
            const absolute = pending.deadline orelse
                return error.TestUnexpectedResult;
            const original_io = pending.h3.established.connection.endpoint.io;
            {
                var fixed: NativeSendIo = .{
                    .backend = .init(allocator, .{ .async_limit = .nothing }),
                    .delegate_io = original_io,
                    .now_ns = .init(@intCast(absolute.raw.nanoseconds - 1)),
                };
                defer fixed.backend.deinit();
                pending.h3.established.connection.endpoint.io = fixed.io();
                defer pending.h3.established.connection.endpoint.io = original_io;
                quic.one_rtt.testing.exhaustPacingAt(
                    &pending.h3.established.connection,
                    @intCast(fixed.now_ns.load(.acquire)),
                );
                const packet_number =
                    pending.h3.established.connection.next_packet_number;
                try std.testing.expectError(
                    error.Timeout,
                    pending.acceptWithHeaders(self.response_headers),
                );
                try std.testing.expectEqual(@as(usize, 0), fixed.send_calls.load(.acquire));
                try std.testing.expectEqual(@as(usize, 0), fixed.duration_sleep_calls.load(.acquire));
                try std.testing.expectEqual(
                    packet_number,
                    pending.h3.established.connection.next_packet_number,
                );
                try std.testing.expect(
                    pending.h3.outbound_bodies.find(pending.streamId()) == null,
                );
            }
            quic.one_rtt.testing.setPacingBudgetAt(
                &pending.h3.established.connection,
                pending.h3.established.connection.congestionWindow(),
                @intCast(std.Io.Clock.awake.now(original_io).nanoseconds),
            );
            var connection = try pending.acceptWithHeaders(
                self.response_headers,
            );
            pending_owned = false;
            defer connection.deinit();
            try connection.h3.waitForRecoveryIdleWithTimeout(
                .fromSeconds(2),
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .response_headers = &response_headers,
    };
    var thread = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var attempt = try h3.Client.connectAttemptWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xe3} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
        } },
        .{
            .authority = "localhost",
            .path = "/many-headers",
            .origin = "https://example.test",
            .extra_headers = &request_headers,
        },
        .fromSeconds(3),
    );
    try std.testing.expect(attempt.accepted());
    try std.testing.expectEqual(
        @as(usize, 80),
        countHeaders(attempt.response.headers, "x-many-response"),
    );
    var connection = try attempt.requireAccepted();
    defer connection.deinit();

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 close deadline resumes a partially sent frame" {
    try native_protocol_io.run(closeFrameDeadline);
}

fn closeFrameDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    const client_cid = [_]u8{ 0x29, 0x2a, 0x2b, 0x2c };
    const server_cid = [_]u8{ 0x2d, 0x2e, 0x2f, 0x30 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x31} ** 32,
                .x25519_secret_key = [_]u8{0x32} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const reason = "0123456789" ** 12;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{ .limits = .{
                .max_frame_bytes = 256,
                .max_message_bytes = 256,
            } });
            defer connection.deinit();
            var close = (try connection.receiveCloseFrameWithTimeout(
                .fromSeconds(5),
            )) orelse return error.TestUnexpectedResult;
            defer close.deinit(allocator);
            try std.testing.expectEqual(
                websocket.CloseCode.normal_closure,
                close.code,
            );
            try std.testing.expectEqualStrings(reason, close.reason);
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x33} ** 32,
                .x25519_secret_key = [_]u8{0x34} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{ .authority = "localhost", .path = "/close-deadline" },
    );
    defer client.deinit();

    const delegate_fixed_io = client.h3.endpoint.io;
    var fixed: NativeSendIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = delegate_fixed_io,
        .now_ns = .init(1_000_000),
        .advance_after_send_ns = 2 * std.time.ns_per_s,
    };
    defer fixed.backend.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = delegate_fixed_io;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(
            .{ .code = .normal_closure, .reason = reason },
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
            },
        ),
    );
    const progress = h3.testing.pendingCloseProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(!client.close_sent.load(.acquire));
    try std.testing.expect(fixed.send_calls.load(.acquire) > 0);
    try std.testing.expectEqual(@as(usize, 0), fixed.duration_sleep_calls.load(.acquire));
    const send_calls_before_mismatch = fixed.send_calls.load(.acquire);
    try std.testing.expectError(
        error.WriteInProgress,
        client.closeWithDeadline(
            .{ .code = .going_away, .reason = "different" },
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + std.time.ns_per_s),
            },
        ),
    );
    try std.testing.expectEqual(
        progress,
        h3.testing.pendingCloseProgress(&client).?,
    );
    try std.testing.expectEqual(
        send_calls_before_mismatch,
        fixed.send_calls.load(.acquire),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.initiateKeyUpdate(),
    );

    client.h3.endpoint.io = delegate_fixed_io;
    var closed = try client.closeWithTimeout(
        .{ .code = .normal_closure, .reason = reason },
        .fromSeconds(5),
    );
    defer closed.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        closed.closed.?.code,
    );
    try std.testing.expectEqualStrings(reason, closed.closed.?.reason);
    try std.testing.expect(h3.testing.pendingCloseProgress(&client) == null);
    try std.testing.expect(client.close_sent.load(.acquire));
    client.h3.endpoint.io = fixed.io();
    const send_calls_after_close = fixed.send_calls.load(.acquire);
    try std.testing.expectError(
        error.ConnectionClosed,
        client.pingWithDeadline("after-close", .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + std.time.ns_per_s),
        }),
    );
    try std.testing.expectEqual(send_calls_after_close, fixed.send_calls.load(.acquire));
    client.h3.endpoint.io = delegate_fixed_io;

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 ping deadline resumes a partially sent frame" {
    try native_protocol_io.run(pingFrameDeadline);
}

fn pingFrameDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_cid = [_]u8{ 0x49, 0x4a, 0x4b, 0x4c };
    const server_cid = [_]u8{ 0x4d, 0x4e, 0x4f, 0x50 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x51} ** 32,
                .x25519_secret_key = [_]u8{0x52} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "0123456789" ** 12;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .compression_threshold = 1,
                .limits = .{
                    .max_frame_bytes = payload.len,
                    .max_message_bytes = payload.len,
                },
            });
            defer connection.deinit();
            var frame = try connection.receiveFrameWithDeadline(
                .fromNow(connection.h3.established.connection.endpoint.io, .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                }),
            );
            defer frame.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, frame.header.opcode);
            try std.testing.expectEqualStrings(payload, frame.payload);
            try connection.sendPong(payload);
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(5),
            );
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("after-ping", message.payload);
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x53} ** 32,
                .x25519_secret_key = [_]u8{0x54} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{ .authority = "localhost", .path = "/ping-deadline" },
    );
    defer client.deinit();

    const delegate_fixed_io = client.h3.endpoint.io;
    var fixed: NativeSendIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = delegate_fixed_io,
        .now_ns = .init(1_000_000),
        .advance_after_send_ns = 2 * std.time.ns_per_s,
    };
    defer fixed.backend.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = delegate_fixed_io;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.pingWithDeadline(payload, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    const progress = h3.testing.pendingPingProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(fixed.send_calls.load(.acquire) > 0);
    try std.testing.expectEqual(@as(usize, 0), fixed.duration_sleep_calls.load(.acquire));
    const send_calls_before_mismatch = fixed.send_calls.load(.acquire);
    try std.testing.expectError(
        error.WriteInProgress,
        client.pingWithTimeout("different", .fromSeconds(1)),
    );
    try std.testing.expectEqual(
        progress,
        h3.testing.pendingPingProgress(&client).?,
    );
    try std.testing.expectEqual(
        send_calls_before_mismatch,
        fixed.send_calls.load(.acquire),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromSeconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.initiateKeyUpdate(),
    );

    client.h3.endpoint.io = delegate_fixed_io;
    var pong = try client.pingWithTimeout(payload, .fromSeconds(5));
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
    try std.testing.expect(h3.testing.pendingPingProgress(&client) == null);
    try client.sendText("after-ping");

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 bounded auto Pong resumes and returns one Ping" {
    try native_protocol_io.run(autoPongDeadline);
}

fn autoPongDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x71} ** 32,
                .x25519_secret_key = [_]u8{0x72} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "automatic-pong-" ** 8;
    const Shared = struct {
        server: *h3.Server,
        accepted: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.deinit();
            self.accepted.set(
                self.server.transport.quic_server.endpoint.io,
            );
            var pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer pong.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqualStrings(payload, pong.payload);
            try connection.sendText("after-auto-pong");
            var second_pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer second_pong.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.pong,
                second_pong.header.opcode,
            );
            try std.testing.expectEqualStrings(payload, second_pong.payload);
            try connection.sendText("after-auto-pong-into");
            var close = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer close.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.close,
                close.header.opcode,
            );
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x73} ** 32,
                .x25519_secret_key = [_]u8{0x74} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{
            .authority = "localhost",
            .path = "/auto-pong-deadline",
            .limits = .{
                .max_frame_bytes = 256,
                .max_message_bytes = 256,
            },
        },
    );
    defer client.deinit();
    try shared.accepted.wait(io);
    var encoded_ping: [websocket.max_frame_header_len + 125]u8 = undefined;
    const ping_bytes = try websocket.writeFrameInto(
        &encoded_ping,
        .ping,
        payload,
        .{},
    );
    try h3.testing.bufferInitial(&client, ping_bytes);

    const delegate_fixed_io = client.h3.endpoint.io;
    var fixed: NativeSendIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = delegate_fixed_io,
        .now_ns = .init(1_000_000),
        .advance_after_send_ns = 2 * std.time.ns_per_s,
    };
    defer fixed.backend.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = delegate_fixed_io;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveFrameWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    const progress = h3.testing
        .pendingAutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.pong, progress.opcode);
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(progress.retains_frame);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );

    client.h3.endpoint.io = delegate_fixed_io;
    var ping = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
    try std.testing.expectEqualStrings(payload, ping.payload);
    try std.testing.expect(
        h3.testing.pendingAutomaticControlProgress(&client) == null,
    );
    var message = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings("after-auto-pong", message.payload);

    // The caller-buffer path must resume its own retained automatic control
    // before checking for unrelated pending writers. The old ordering returned
    // WriteInProgress forever here.
    try h3.testing.bufferInitial(&client, ping_bytes);
    fixed.now_ns.store(@intCast(
        quic.one_rtt.testing.pacingBlockedUntil(
            &client.h3.established.connection,
        ) orelse @as(u64, @intCast(fixed.now_ns.load(.acquire))),
    ), .release);
    client.h3.endpoint.io = fixed.io();
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    var into_storage: [256]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageIntoWithDeadline(&into_storage, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    const into_progress = h3.testing
        .pendingAutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.pong, into_progress.opcode);
    try std.testing.expect(into_progress.committed > 0);
    try std.testing.expect(into_progress.committed < into_progress.total);

    client.h3.endpoint.io = delegate_fixed_io;
    const into_message = try client.receiveMessageIntoWithTimeout(
        &into_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqual(websocket.Opcode.text, into_message.opcode);
    try std.testing.expectEqualStrings(
        "after-auto-pong-into",
        into_message.payload,
    );
    try std.testing.expect(
        h3.testing.pendingAutomaticControlProgress(&client) == null,
    );

    var close_payload_storage: [125]u8 = undefined;
    const close_payload = try websocket.writeClosePayloadInto(
        &close_payload_storage,
        .{ .code = .going_away, .reason = "restart" },
    );
    var encoded_close: [websocket.max_frame_header_len + 125]u8 = undefined;
    const close_bytes = try websocket.writeFrameInto(
        &encoded_close,
        .close,
        close_payload,
        .{},
    );
    try h3.testing.bufferInitial(&client, close_bytes);
    client.h3.endpoint.io = fixed.io();
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveFrameWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    const close_progress = h3.testing
        .pendingAutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.close, close_progress.opcode);
    try std.testing.expect(close_progress.committed > 0);
    try std.testing.expect(close_progress.committed < close_progress.total);
    try std.testing.expect(close_progress.retains_frame);
    try std.testing.expect(!client.close_sent.load(.acquire));

    client.h3.endpoint.io = delegate_fixed_io;
    var close = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    const close_detail = (try websocket.parseClosePayload(close.payload)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.CloseCode.going_away, close_detail.code);
    try std.testing.expectEqualStrings("restart", close_detail.reason);
    try std.testing.expect(client.close_sent.load(.acquire));

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 Pong deadline resumes a partially sent frame" {
    try native_protocol_io.run(pongFrameDeadline);
}

fn pongFrameDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c };
    const client_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x85} ** 32,
                .x25519_secret_key = [_]u8{0x86} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "0123456789" ** 12;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.deinit();
            var pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer pong.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqualStrings(payload, pong.payload);
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x87} ** 32,
                .x25519_secret_key = [_]u8{0x88} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{ .authority = "localhost", .path = "/pong-deadline" },
    );
    defer client.deinit();

    const delegate_fixed_io = client.h3.endpoint.io;
    var fixed: NativeSendIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = delegate_fixed_io,
        .now_ns = .init(1_000_000),
        .advance_after_send_ns = 2 * std.time.ns_per_s,
    };
    defer fixed.backend.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = delegate_fixed_io;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    var progress: h3.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendPongWithDeadline(payload, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    const send_calls = fixed.send_calls.load(.acquire);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendPongWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(send_calls, fixed.send_calls.load(.acquire));

    client.h3.endpoint.io = delegate_fixed_io;
    try client.sendPongWithTimeout(payload, &progress, .fromSeconds(5));
    try std.testing.expect(progress.frame_committed);

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 bounded in-place send masks once" {
    try native_protocol_io.run(inPlaceDeadline);
}

fn inPlaceDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
    const client_cid = [_]u8{ 0xb9, 0xba, 0xbb, 0xbc };
    const server_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc1} ** 32,
                .x25519_secret_key = [_]u8{0xc2} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const plain = "0123456789" ** 12;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .limits = .{
                    .max_frame_bytes = plain.len,
                    .max_message_bytes = plain.len,
                },
            });
            defer connection.deinit();
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(10),
            );
            defer message.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expectEqualStrings(plain, message.payload);
            try connection.sendText("in-place-ok");
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc3} ** 32,
                .x25519_secret_key = [_]u8{0xc4} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{
            .authority = "localhost",
            .path = "/in-place-deadline",
            .limits = .{
                .max_frame_bytes = plain.len,
                .max_message_bytes = plain.len,
            },
        },
    );
    defer client.deinit();

    var payload: [plain.len]u8 = undefined;
    @memcpy(&payload, plain);
    var progress: h3.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryInPlaceWithDeadline(&payload, &progress, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqualStrings(plain, &payload);

    const delegate_fixed_io = client.h3.endpoint.io;
    var fixed: NativeSendIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = delegate_fixed_io,
        .now_ns = .init(1_000_000),
        .advance_after_send_ns = 2 * std.time.ns_per_s,
    };
    defer fixed.backend.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = delegate_fixed_io;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryInPlaceWithDeadline(&payload, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!std.mem.eql(u8, plain, &payload));
    const send_calls = fixed.send_calls.load(.acquire);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinaryInPlaceWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(send_calls, fixed.send_calls.load(.acquire));

    client.h3.endpoint.io = delegate_fixed_io;
    try client.sendBinaryInPlaceWithTimeout(
        &payload,
        &progress,
        .fromSeconds(10),
    );
    try std.testing.expect(progress.frame_committed);
    var response = try client.receiveMessageWithTimeout(.fromSeconds(10));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("in-place-ok", response.payload);

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 message deadline resumes one masked frame" {
    try native_protocol_io.run(messageFrameDeadline);
}

fn messageFrameDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x71} ** 32,
                .x25519_secret_key = [_]u8{0x72} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "0123456789" ** 12;
    var first_part: [101]u8 = undefined;
    var second_part: [103]u8 = undefined;
    for (&first_part, 0..) |*byte, index| {
        byte.* = @truncate(index *% 37 +% 11);
    }
    for (&second_part, 0..) |*byte, index| {
        byte.* = @truncate(index *% 53 +% 19);
    }
    const parts = [_][]const u8{
        first_part[0..37],
        &.{},
        first_part[37..],
        second_part[0..51],
        second_part[51..],
    };
    const parts_len = first_part.len + second_part.len;
    const Shared = struct {
        server: *h3.Server,
        first_part: []const u8,
        second_part: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 1,
                .limits = .{
                    .max_frame_bytes = parts_len,
                    .max_message_bytes = parts_len,
                },
            });
            defer connection.deinit();
            try std.testing.expect(
                connection.compression_send_context_takeover,
            );
            try std.testing.expect(
                connection.compression_receive_context_takeover,
            );
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(10),
            );
            defer message.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expectEqualStrings(payload, message.payload);
            var pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer pong.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqualStrings("queued", pong.payload);
            var slices_message = try connection.receiveMessageWithTimeout(
                .fromSeconds(10),
            );
            defer slices_message.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.binary,
                slices_message.opcode,
            );
            try std.testing.expectEqual(parts_len, slices_message.payload.len);
            try std.testing.expectEqualSlices(
                u8,
                self.first_part,
                slices_message.payload[0..self.first_part.len],
            );
            try std.testing.expectEqualSlices(
                u8,
                self.second_part,
                slices_message.payload[self.first_part.len..],
            );
            const response_parts = [_][]const u8{
                "server-",
                &.{},
                "slices",
            };
            var progress: h3.MessageWriteProgress = .{};
            try connection.sendBinarySlicesWithTimeout(
                &response_parts,
                &progress,
                .fromSeconds(5),
            );
            try std.testing.expect(progress.frame_committed);
        }
    };
    var shared = Shared{
        .server = &server,
        .first_part = &first_part,
        .second_part = &second_part,
    };
    var thread = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x73} ** 32,
                .x25519_secret_key = [_]u8{0x74} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{
            .authority = "localhost",
            .path = "/message-deadline",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 1,
            .limits = .{
                .max_frame_bytes = parts_len,
                .max_message_bytes = parts_len,
            },
        },
    );
    defer client.deinit();
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);

    var invalid_progress: h3.MessageWriteProgress = .{
        .committed_bytes = 99,
        .total_bytes = 99,
        .frame_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryWithDeadline(payload, &invalid_progress, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqual(
        h3.MessageWriteProgress{},
        invalid_progress,
    );

    const delegate_fixed_io = client.h3.endpoint.io;
    var fixed: NativeSendIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = delegate_fixed_io,
        .now_ns = .init(1_000_000),
        .advance_after_send_ns = 2 * std.time.ns_per_s,
    };
    defer fixed.backend.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = delegate_fixed_io;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    var progress: h3.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryWithDeadline(payload, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(client.compression_send.previewPending());
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinaryWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(
        (h3.testing.pendingMessageProgress(&client) orelse
            return error.TestUnexpectedResult).committed_bytes,
        progress.committed_bytes,
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromSeconds(1)),
    );
    try h3.testing.queueAutomaticControl(&client, .pong, "queued");

    client.h3.endpoint.io = delegate_fixed_io;
    try client.sendBinaryWithTimeout(payload, &progress, .fromSeconds(10));
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(h3.testing.pendingMessageProgress(&client) == null);
    try std.testing.expect(!client.compression_send.previewPending());
    try std.testing.expect(
        h3.testing.pendingAutomaticControlProgress(&client) != null,
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageWithTimeout(.fromMilliseconds(100)),
    );
    try std.testing.expect(
        h3.testing.pendingAutomaticControlProgress(&client) == null,
    );
    fixed.now_ns.store(@intCast(
        quic.one_rtt.testing.pacingBlockedUntil(
            &client.h3.established.connection,
        ) orelse
            @as(u64, @intCast(fixed.now_ns.load(.acquire))),
    ), .release);
    client.h3.endpoint.io = fixed.io();
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    progress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinarySlicesWithDeadline(&parts, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    const different_parts = [_][]const u8{ &first_part, &second_part };
    const send_calls_before_mismatch = fixed.send_calls.load(.acquire);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinarySlicesWithTimeout(
            &different_parts,
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(send_calls_before_mismatch, fixed.send_calls.load(.acquire));
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave-slices"),
    );

    client.h3.endpoint.io = delegate_fixed_io;
    try client.sendBinarySlicesWithTimeout(
        &parts,
        &progress,
        .fromSeconds(10),
    );
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(h3.testing.pendingMessageProgress(&client) == null);

    var server_message = try client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer server_message.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, server_message.opcode);
    try std.testing.expectEqualStrings(
        "server-slices",
        server_message.payload,
    );

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 fragmented deadline resumes exact suffix" {
    try native_protocol_io.run(fragmentedDeadline);
}

fn fragmentedDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0x99, 0x9a, 0x9b, 0x9c };
    const server_cid = [_]u8{ 0x9d, 0x9e, 0x9f, 0xa0 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "fragmented-context-takeover-" ** 16;
    const fragments = [_][]const u8{
        payload[0..73],
        &.{},
        payload[73..181],
        payload[181..317],
        payload[317..],
    };
    const total = payload.len;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 1,
                .limits = .{
                    .max_frame_bytes = total,
                    .max_message_bytes = total,
                },
            });
            defer connection.deinit();
            try std.testing.expect(
                connection.compression_receive_context_takeover,
            );
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(10),
            );
            defer message.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expect(message.was_compressed);
            try std.testing.expectEqualStrings(payload, message.payload);
            try connection.sendText("fragmented-ok");
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{
            .authority = "localhost",
            .path = "/fragmented-deadline",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 1,
            .limits = .{
                .max_frame_bytes = total,
                .max_message_bytes = total,
            },
        },
    );
    defer client.deinit();
    try std.testing.expect(client.compression_send_context_takeover);

    const delegate_fixed_io = client.h3.endpoint.io;
    var fixed: NativeSendIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = delegate_fixed_io,
        .now_ns = .init(1_000_000),
        .advance_after_send_ns = 2 * std.time.ns_per_s,
    };
    defer fixed.backend.deinit();
    client.h3.endpoint.io = fixed.io();
    defer client.h3.endpoint.io = delegate_fixed_io;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    var progress: h3.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendFragmentedWithDeadline(.binary, &fragments, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(client.compression_send.previewPending());
    const different = [_][]const u8{payload};
    const send_calls = fixed.send_calls.load(.acquire);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendFragmentedWithTimeout(
            .binary,
            &different,
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(send_calls, fixed.send_calls.load(.acquire));

    client.h3.endpoint.io = delegate_fixed_io;
    try client.sendFragmentedWithTimeout(
        .binary,
        &fragments,
        &progress,
        .fromSeconds(10),
    );
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(!client.compression_send.previewPending());
    var response = try client.receiveMessageWithTimeout(.fromSeconds(10));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("fragmented-ok", response.payload);

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

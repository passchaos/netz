const std = @import("std");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const webtransport = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const NativeIo = @import("../../../../internal/testing/deadline_send_io.zig").Native;
const native_protocol_io = @import("../../../../internal/testing/native_protocol_io.zig");
const operation_timeout: std.Io.Duration = .fromSeconds(5);

test "WebTransport caller-owned H3 bounds acceptance and flushes response ACK" {
    try native_protocol_io.run(acceptanceDeadline);
}

fn acceptanceDeadline(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xe0, 0x01, 0x57, 0x54, 0xe0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xe0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xe0, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xe3} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
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
            var h3 = try self.server.h3.accept();
            var h3_owned = true;
            defer if (h3_owned) h3.deinit();
            var denied = try runtime.HandshakeServer
                .receiveSessionRequestFromSessionWithTimeout(
                &h3,
                self.server.limits,
                operation_timeout,
            );
            var denied_owned = true;
            defer if (denied_owned) denied.deinit();
            try std.testing.expectEqualStrings(
                "https://cross-origin.example",
                denied.origin().?,
            );
            try std.testing.expectError(error.InvalidOrigin, denied.accept());
            var rejected = try denied.forbidden();
            denied_owned = false;
            rejected.deinit();
            // Remove handshake and rejection traffic from the ACK threshold.
            // The next successful CONNECT response must be acknowledged on
            // its own before the client returns the promoted session.
            try h3.waitForRecoveryIdleWithTimeout(.fromSeconds(1));

            var allowed = try runtime.HandshakeServer
                .receiveSessionRequestFromSessionWithTimeout(
                &h3,
                self.server.limits,
                operation_timeout,
            );
            var allowed_owned = true;
            defer if (allowed_owned) allowed.deinit();
            const absolute = allowed.deadline orelse
                return error.TestUnexpectedResult;
            const original_io = allowed.h3.established.connection.endpoint.io;
            {
                var fixed: NativeIo = .{
                    .backend = .init(allocator, .{ .async_limit = .nothing }),
                    .delegate_io = original_io,
                    .now_ns = .init(@intCast(absolute.raw.nanoseconds - 1)),
                };
                defer fixed.backend.deinit();
                const endpoint = allowed.h3.established.connection.endpoint;
                endpoint.io = fixed.io();
                defer endpoint.io = original_io;
                quic.one_rtt.testing.exhaustPacingAt(
                    &allowed.h3.established.connection,
                    @intCast(fixed.now_ns.load(.acquire)),
                );
                const packet_number =
                    allowed.h3.established.connection.next_packet_number;
                try std.testing.expectError(error.Timeout, allowed.accept());
                try std.testing.expectEqual(@as(usize, 0), fixed.send_calls.load(.acquire));
                try std.testing.expectEqual(@as(usize, 0), fixed.duration_sleep_calls.load(.acquire));
                try std.testing.expectEqual(
                    packet_number,
                    allowed.h3.established.connection.next_packet_number,
                );
                try std.testing.expect(
                    allowed.h3.streaming_requests.find(
                        allowed.session_id.value,
                    ) != null,
                );
                try std.testing.expect(
                    allowed.h3.outbound_bodies.find(
                        allowed.session_id.value,
                    ) == null,
                );
                try std.testing.expect(
                    !allowed.h3.connect_datagrams.contains(
                        allowed.session_id.value,
                    ),
                );
            }
            quic.one_rtt.testing.setPacingBudgetAt(
                &allowed.h3.established.connection,
                allowed.h3.established.connection.congestionWindow(),
                @intCast(std.Io.Clock.awake.now(original_io).nanoseconds),
            );
            var accepted = try allowed.accept();
            allowed_owned = false;
            h3_owned = false;
            defer accepted.deinit();
            try std.testing.expect(
                accepted.h3.established.connection.pendingRecoveryCount() != 0,
            );
            try accepted.waitForRecoveryIdleWithTimeout(
                .fromMilliseconds(300),
            );
        }
    };
    var shared = Shared{ .server = &server };
    var thread = try io.concurrent(Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.cancel(io);

    var h3_client = try http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        server.limits.http3,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
            },
            .session = .{
                .local_settings = webtransport.defaultSettings(.{}),
            },
        },
    );
    var h3_client_owned = true;
    defer if (h3_client_owned) h3_client.deinit();
    var denied_attempt = try runtime.HandshakeClientSession
        .connectSessionAttemptWithTimeout(
        &h3_client,
        .{
            .authority = "localhost",
            .path = "/denied-origin",
            .origin = "https://cross-origin.example",
        },
        operation_timeout,
    );
    var denied_attempt_owned = true;
    defer if (denied_attempt_owned) denied_attempt.deinit();
    try std.testing.expect(!denied_attempt.accepted());
    try std.testing.expectEqual(@as(u16, 403), denied_attempt.status());
    denied_attempt.deinit();
    denied_attempt_owned = false;
    // Start the accepted CONNECT with no older client recovery traffic able to
    // carry or trigger the response ACK.
    try h3_client.waitForRecoveryIdleWithTimeout(.fromSeconds(1));

    var accepted = try runtime.HandshakeClientSession.connectSessionWithTimeout(
        &h3_client,
        .{
            .authority = "LOCALHOST:443",
            .path = "/same-origin",
            .origin = "https://localhost",
        },
        operation_timeout,
    );
    h3_client_owned = false;
    defer accepted.deinit();

    thread.await(io);
    joined = true;
    if (shared.err) |err| return err;
}

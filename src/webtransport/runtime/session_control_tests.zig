const std = @import("std");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");

test "WebTransport classifies terminal close send failures" {
    inline for (&.{
        error.RequestCancelled,
        error.RequestRejected,
        error.StreamStopped,
        error.StreamStateError,
        error.UnexpectedStream,
        error.ConnectionClosed,
        error.ConnectionUnusable,
    }) |err| {
        try std.testing.expect(
            runtime.testing.classifyTerminalSessionBodySendError(err),
        );
    }
    inline for (&.{
        error.Timeout,
        error.Canceled,
        error.PacingLimited,
        error.CongestionLimited,
        error.FlowControlBlocked,
        error.DatagramTooLarge,
    }) |err| {
        try std.testing.expect(
            !runtime.testing.classifyTerminalSessionBodySendError(err),
        );
    }
}

test "WebTransport control records permanent local close failure" {
    var control = try @import("session_control.zig").Control.init(
        std.testing.allocator,
        .init(0),
    );
    defer control.deinit();
    try control.beginLocalClose();
    control.recordLocalCloseFailure(0x10203040);
    try std.testing.expect(!control.local_close_started);
    try std.testing.expect(control.local_close_failed);
    try std.testing.expect(!control.local_close_sent);
    try std.testing.expect(control.state.closed);
    try std.testing.expectEqual(
        @as(?u32, 0x10203040),
        control.state.close_code,
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        control.ensureOpen(),
    );
}

test "WebTransport permanent CLOSE send failure becomes terminal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x46, 0x11, 0x57, 0x54, 0x46, 0x12 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x46, 0x13 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x46, 0x14 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb7} ** 32,
            .x25519_secret_key = [_]u8{0xb8} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try self.release.wait(self.server.h3.quic_server.endpoint.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-terminal-close-send",
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb5} ** 32,
                .x25519_secret_key = [_]u8{0xb6} ** 32,
            } },
        },
    );
    defer client.deinit();

    client.h3.abandonExtendedConnect(client.session_id.value);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.closeWithTimeout(401, "retired", .fromSeconds(1)),
    );
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );
    try std.testing.expect(runtime.testing.localCloseFailed(&client));
    try std.testing.expect(!runtime.testing.localCloseSent(&client));
    try std.testing.expect(client.control.state.closed);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.openBidirectionalStream(),
    );
    // The CONNECT direction is terminal, so a later close only resumes
    // associated-stream cleanup and never rebuilds the discarded capsule.
    try client.closeWithTimeout(999, "ignored", .fromSeconds(1));
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport server permanent CLOSE send failure becomes terminal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x46, 0x21, 0x57, 0x54, 0x46, 0x22 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x46, 0x23 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x46, 0x24 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xc7} ** 32,
            .x25519_secret_key = [_]u8{0xc8} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        ready: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        failed: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try session.h3.finishRequest(session.session_id.value);
            try std.testing.expectError(
                error.UnexpectedStream,
                session.closeWithTimeout(402, "retired", .fromSeconds(1)),
            );
            try std.testing.expect(
                runtime.testing.pendingCloseProgress(&session) == null,
            );
            try std.testing.expect(runtime.testing.localCloseFailed(&session));
            try std.testing.expect(!runtime.testing.localCloseSent(&session));
            try std.testing.expect(session.control.state.closed);
            try std.testing.expectError(
                error.InvalidSessionState,
                session.sendDatagram("late"),
            );
            try session.closeWithTimeout(999, "ignored", .fromSeconds(1));
            self.failed = true;
            self.ready.set(self.server.h3.quic_server.endpoint.io);
            try self.release.wait(self.server.h3.quic_server.endpoint.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-server-terminal-close-send",
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            } },
        },
    );
    defer client.deinit();
    try shared.ready.wait(io);
    try std.testing.expect(shared.failed);
    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake sessions exchange drain and close capsules" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x43, 0x01, 0x57, 0x54, 0x43, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x43, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x43, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd3} ** 32,
                .x25519_secret_key = [_]u8{0xd4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectEqualStrings(
                "/wt-control",
                session.request.request.path,
            );

            try session.drain();
            // DRAIN is advisory: opening and using streams remains legal.
            const stream_id = try session.openUnidirectionalStream();
            try session.sendStream(stream_id, "after drain", true);

            const event = try session.receiveSessionEvent();
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 77), event.closed.code);
            try std.testing.expectEqualStrings("client done", event.closed.reason);
            try std.testing.expectError(
                error.InvalidSessionState,
                session.openBidirectionalStream(),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-control",
            .limits = .{
                .http3 = .{
                    .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 8,
                    },
                },
            },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xd1} ** 32,
                    .x25519_secret_key = [_]u8{0xd2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    const drain = try client.receiveSessionEvent();
    try std.testing.expect(drain == .draining);

    var stream_buffer: [32]u8 = undefined;
    const stream = try client.readStream(&stream_buffer);
    try std.testing.expect(stream == .data);
    try std.testing.expectEqualStrings(
        "after drain",
        stream_buffer[0..stream.data.bytes],
    );
    if (!stream.data.fin) {
        const fin = try client.readStream(&stream_buffer);
        try std.testing.expect(fin == .data);
        try std.testing.expectEqual(stream.data.stream_id, fin.data.stream_id);
        try std.testing.expectEqual(@as(usize, 0), fin.data.bytes);
        try std.testing.expect(fin.data.fin);
    }

    try client.close(77, "client done");
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendDatagram("late"),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake clean CONNECT FIN is normal close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x46, 0x01, 0x57, 0x54, 0x46, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x46, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x46, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            // A zero-length DATA frame followed by FIN carries no close capsule
            // and is therefore semantically equivalent to close(0, "").
            try session.h3.sendResponseBodyPaced(
                session.session_id.value,
                &.{},
                true,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-fin",
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xe1} ** 32,
                    .x25519_secret_key = [_]u8{0xe2} ** 32,
                },
            },
        },
    );
    defer client.deinit();
    const event = try client.receiveSessionEvent();
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 0), event.closed.code);
    try std.testing.expectEqualStrings("", event.closed.reason);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake rejects FIN during Capsule type varint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server_cid = [_]u8{ 0x57, 0x54, 0x56, 0x00 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xa3} ** 32,
            .x25519_secret_key = [_]u8{0xa4} ** 32,
        } },
    );
    defer server.deinit();

    // Each value is one byte short of the length selected by its first two
    // bits. The enclosing HTTP/3 DATA frame is complete; only the Capsule type
    // varint is truncated when the CONNECT response direction reaches FIN.
    const truncated_types = [_][]const u8{
        &.{0x40},
        &.{ 0x80, 0x00, 0x00 },
        &.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };
    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            for (truncated_types) |truncated| {
                var session = try server_ptr.accept();
                defer session.deinit();
                try session.h3.sendResponseBodyPaced(
                    session.session_id.value,
                    truncated,
                    true,
                );

                const event = try session.receiveSessionEvent();
                // The sender observes its own untracked CONNECT FIN first.
                // Still verify that the peer rejects the truncated Capsule
                // with H3_MESSAGE_ERROR on the opposite transport direction.
                try std.testing.expect(event == .closed);
                const connection = &session.h3.established.connection;
                const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
                while (connection.recvStreamStats(session.session_id.value).?.reset == null) try session.h3.receiveDetachedRequestProgressWithDeadline(session.session_id.value, deadline);
                const reset = connection.recvStreamStats(session.session_id.value).?.reset.?;
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.message_error),
                    reset.application_error_code,
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for (truncated_types, 0..) |_, index| {
        const marker: u8 = @intCast(index + 1);
        const original_dcid =
            [_]u8{ 0x57, 0x54, 0x56, marker, 0x57, 0x54, 0x56, marker };
        const client_cid = [_]u8{ 0x57, 0x54, 0x57, marker };
        {
            var client = try runtime.HandshakeClientSession.connect(
                allocator,
                io,
                .{ .ip4 = .loopback(0) },
                server.address(),
                .{
                    .authority = "localhost",
                    .path = "/wt-truncated-capsule-type",
                    .h3 = .{ .handshake = .{
                        .original_destination_connection_id = &original_dcid,
                        .local_connection_id = &client_cid,
                        .server_name = "localhost",
                        .random = [_]u8{0xa1} ** 32,
                        .x25519_secret_key = [_]u8{0xa2} ** 32,
                    } },
                },
            );
            defer client.deinit();
            try std.testing.expectError(
                error.InvalidCapsule,
                client.receiveSessionEvent(),
            );
        }
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake session receives peer QUIC close details" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x51, 0x01, 0x57, 0x54, 0x51, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x51, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x51, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
        },
    );
    defer server.deinit();

    const DropFirstCloseIo = struct {
        delegate: std.Io,
        send_calls: usize = 0,
        dropped: usize = 0,

        fn now(
            context: ?*anyopaque,
            clock: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return self.delegate.vtable.now(
                self.delegate.userdata,
                clock,
            );
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            if (self.dropped == 0) {
                self.dropped = messages.len;
                return .{ null, messages.len };
            }
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const Shared = struct {
        server: *runtime.HandshakeServer,
        close_observed: std.Io.Event = .unset,
        close_send_calls: usize = 0,
        dropped_close_packets: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            const endpoint = session.h3.established.connection.send_endpoint;
            const original_io = endpoint.io;
            var dropping = DropFirstCloseIo{ .delegate = original_io };
            var vtable = original_io.vtable.*;
            vtable.now = DropFirstCloseIo.now;
            vtable.netSend = DropFirstCloseIo.netSend;
            endpoint.io = .{ .userdata = &dropping, .vtable = &vtable };
            defer {
                endpoint.io = original_io;
                self.close_send_calls = dropping.send_calls;
                self.dropped_close_packets = dropping.dropped;
            }
            try session.h3.established.connection.closeApplication(
                0,
                "interop complete",
            );
            // A CONNECTION_CLOSE packet is not acknowledged and UDP may drop
            // the initial datagram. A production closing endpoint continues
            // receiving and rate-limits close responses to subsequent peer
            // packets; this deliberately one-way test peer has no such loop,
            // so retry at a low cadence while keeping the connection state
            // alive until the client observes one copy.
            while (true) {
                self.close_observed.waitTimeout(
                    original_io,
                    .{ .duration = .{
                        .raw = .fromMilliseconds(100),
                        .clock = .awake,
                    } },
                ) catch |err| switch (err) {
                    error.Timeout => {
                        try session.h3.established.connection.resendClose();
                        continue;
                    },
                    else => return err,
                };
                break;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.close_observed.set(io);
        thread.join();
    };

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-quic-close",
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xf1} ** 32,
                    .x25519_secret_key = [_]u8{0xf2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    switch (try client.receivePeerConnectionCloseWithTimeout(
        .fromSeconds(5),
    )) {
        .application => |close| {
            try std.testing.expectEqual(@as(u64, 0), close.error_code);
            try std.testing.expectEqualStrings(
                "interop complete",
                close.reason_phrase,
            );
        },
        .transport => return error.TestUnexpectedResult,
    }

    shared.close_observed.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.dropped_close_packets);
    try std.testing.expect(shared.close_send_calls >= 2);
}

test "WebTransport session control encodes bounds and rejects malformed close" {
    const control = @import("session_control.zig");
    var buffer: [4 + control.max_close_reason + 16]u8 = undefined;
    const close = try control.writeCloseInto(&buffer, 9, "done");
    const parsed = try webtransport.Capsule.parse(close);
    try std.testing.expectEqual(@as(u32, 9), parsed.capsule.close_session.code);
    try std.testing.expectEqualStrings("done", parsed.capsule.close_session.reason);

    var oversized: [control.max_close_reason + 1]u8 = undefined;
    @memset(&oversized, 'x');
    try std.testing.expectError(
        error.InvalidCapsule,
        control.writeCloseInto(&buffer, 1, &oversized),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        control.writeCloseInto(&buffer, 1, "\xff"),
    );

    // Keep the protocol code visible at the public boundary.
    try std.testing.expectEqual(
        @as(u64, 0x170d7b68),
        webtransport.ApplicationErrorCode.session_gone,
    );
    try std.testing.expectEqual(
        @as(u64, 0x10e),
        @import("../../http3/mod.zig").ApplicationErrorCode.message_error,
    );
    _ = quic;
}

test "WebTransport terminal sweep discovers buffered associated streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc7} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-sweep-server",
        .peer_connection_id = "wt-sweep-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 0, .max_peer_uni = 0 },
    );
    defer registry.deinit();

    var bidi_storage: [16]u8 = undefined;
    const bidi = try webtransport.BidirectionalStreamHeader.writeInto(
        &bidi_storage,
        session_id,
    );
    var uni: std.ArrayList(u8) = .empty;
    defer uni.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &uni,
        allocator,
        session_id,
    );
    var other_session: std.ArrayList(u8) = .empty;
    defer other_session.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &other_session,
        allocator,
        .init(4),
    );
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{ .stream_id = 4, .data = bidi } },
            .{ .stream = .{ .stream_id = 2, .data = uni.items } },
            .{ .stream = .{ .stream_id = 6, .data = other_session.items } },
            .{ .stream = .{ .stream_id = 8, .data = &.{0x41} } },
            .{ .stream = .{ .stream_id = 10, .data = &.{0x00} } },
        },
        null,
        .not_ect,
    );
    try std.testing.expect(registry.get(4) == null);
    try std.testing.expect(registry.get(2) == null);

    try std.testing.expectEqual(
        @import("session_control.zig").TerminateProgress.submitted,
        try @import("session_control.zig").terminateStreamsOnce(
            &connection,
            &registry,
        ),
    );
    try std.testing.expect(registry.get(4) == null);
    try std.testing.expect(registry.get(2) == null);
    try std.testing.expect(registry.get(6) == null);
    try std.testing.expect(registry.get(8) == null);
    try std.testing.expect(registry.get(10) == null);

    while (try @import("session_control.zig").terminateStreamsOnce(
        &connection,
        &registry,
    ) == .submitted) {}

    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.sendStreamStats(4).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(4).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(2).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expect(connection.recvStreamStats(6).?.stop_sending_sent == null);
    try std.testing.expect(connection.recvStreamStats(8).?.stop_sending_sent == null);
    try std.testing.expect(connection.recvStreamStats(10).?.stop_sending_sent == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.availableReceivedStream(4).?.len,
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(bidi.len)),
        connection.recvStreamStats(4).?.bytes_read,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.availableReceivedStream(2).?.len,
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(uni.items.len)),
        connection.recvStreamStats(2).?.bytes_read,
    );

    // The blocking cleanup path uses the same discovery without relying on
    // registry capacity; STOP_SENDING then consumes the association prefix.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{ .stream_id = 12, .data = bidi } }},
        null,
        .not_ect,
    );
    try @import("session_control.zig").terminateStreams(
        &connection,
        &registry,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.sendStreamStats(12).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(12).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.availableReceivedStream(12).?.len,
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(bidi.len)),
        connection.recvStreamStats(12).?.bytes_read,
    );
}

test "WebTransport session control parses split framed capsules and skips unknown" {
    const control_module = @import("session_control.zig");

    var unknown_capsule: [64]u8 = undefined;
    const unknown = try @import("../../http3/capsule.zig").writeInto(
        &unknown_capsule,
        0x1234,
        "ignored",
    );
    var drain_capsule: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_capsule);
    var payload: [96]u8 = undefined;
    @memcpy(payload[0..unknown.len], unknown);
    @memcpy(payload[unknown.len..][0..drain.len], drain);

    var frame: [128]u8 = undefined;
    const frame_type = try quic.varint.encodeInto(
        &frame,
        @import("../../http3/mod.zig").FrameType.data,
    );
    const frame_length = try quic.varint.encodeInto(
        frame[frame_type.len..],
        unknown.len + drain.len,
    );
    const header_len = frame_type.len + frame_length.len;
    @memcpy(
        frame[header_len..][0 .. unknown.len + drain.len],
        payload[0 .. unknown.len + drain.len],
    );
    const bytes = frame[0 .. header_len + unknown.len + drain.len];

    // Feed every split point through the parser using a local helper that
    // mirrors transport availability. No complete value is buffered by the
    // state machine while the unknown capsule is skipped.
    for (1..bytes.len) |split| {
        var candidate = try control_module.Control.init(
            std.testing.allocator,
            .init(0),
        );
        defer candidate.deinit();
        const first = try candidate.feed(bytes[0..split]);
        try std.testing.expect(first == null);
        const second = try candidate.feed(bytes[split..]);
        try std.testing.expect(second.? == .draining);
    }
}

test "WebTransport CONNECT control accepts DATA and skips unknown HTTP/3 frames" {
    const control_module = @import("session_control.zig");
    var drain_storage: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_storage);
    var encoded: [64]u8 = undefined;
    var len: usize = 0;

    const extension_type = try quic.varint.encodeInto(encoded[len..], 0x21);
    len += extension_type.len;
    const extension_length = try quic.varint.encodeInto(encoded[len..], 2);
    len += extension_length.len;
    encoded[len..][0..2].* = .{ 0xff, 0xff };
    len += 2;
    const data_type = try quic.varint.encodeInto(
        encoded[len..],
        http3.FrameType.data,
    );
    len += data_type.len;
    const data_length = try quic.varint.encodeInto(encoded[len..], drain.len);
    len += data_length.len;
    @memcpy(encoded[len..][0..drain.len], drain);
    len += drain.len;

    var control = try control_module.Control.init(
        std.testing.allocator,
        .init(0),
    );
    defer control.deinit();
    const event = (try control.feed(encoded[0..len])).?;
    try std.testing.expect(event == .draining);
}

test "WebTransport CONNECT control rejects forbidden HTTP/3 frame types" {
    const control_module = @import("session_control.zig");
    const forbidden = [_]u64{
        http3.FrameType.headers,
        http3.FrameType.cancel_push,
        http3.FrameType.settings,
        http3.FrameType.push_promise,
        http3.FrameType.goaway,
        http3.FrameType.origin,
        http3.FrameType.max_push_id,
        http3.FrameType.priority_update_request,
        http3.FrameType.priority_update_push,
        http3.FrameType.webtransport_stream,
        0x02,
        0x06,
        0x08,
        0x09,
    };

    for (forbidden) |frame_type| {
        var encoded: [8]u8 = undefined;
        const frame = try quic.varint.encodeInto(&encoded, frame_type);
        var control = try control_module.Control.init(
            std.testing.allocator,
            .init(0),
        );
        defer control.deinit();
        if (frame.len > 1) {
            try std.testing.expect(
                (try control.feed(frame[0 .. frame.len - 1])) == null,
            );
        }
        try std.testing.expectError(
            error.UnexpectedFrame,
            control.feed(frame[frame.len - 1 ..]),
        );
    }
}

test "WebTransport session control rejects CONNECT data after peer close" {
    const allocator = std.testing.allocator;
    const control_module = @import("session_control.zig");
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-post-close-server",
        .peer_connection_id = "wt-post-close-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var peer_connection = try quic.one_rtt.Connection.init(&peer, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-post-close-client",
        .peer_connection_id = "wt-post-close-server",
        .enable_pacing = false,
    });
    defer peer_connection.deinit();

    var close_storage: [64]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        77,
        "done",
    );
    var h3_data: [96]u8 = undefined;
    var h3_len: usize = 0;
    const frame_type = try quic.varint.encodeInto(
        h3_data[h3_len..],
        http3.FrameType.data,
    );
    h3_len += frame_type.len;
    const frame_length = try quic.varint.encodeInto(
        h3_data[h3_len..],
        close.len + 1,
    );
    h3_len += frame_length.len;
    @memcpy(h3_data[h3_len..][0..close.len], close);
    h3_len += close.len;
    h3_data[h3_len] = 0xff;
    h3_len += 1;

    try peer_connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = h3_data[0..h3_len],
    } }});
    var request_packet = try connection.receivePacket();
    defer request_packet.deinit(allocator);
    var control = try control_module.Control.init(allocator, .init(0));
    defer control.deinit();
    const event = (try control.pollOnce(&connection)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 77), event.closed.code);
    try std.testing.expectEqualStrings("done", event.closed.reason);
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.availableReceivedStream(0).?.len,
    );

    try std.testing.expectError(
        error.InvalidCapsule,
        control.pollOnce(&connection),
    );
    try std.testing.expect(control.handledPostTerminalData());
    try std.testing.expect(control.local_close_failed);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.availableReceivedStream(0).?.len,
    );
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.message_error),
        connection.sendStreamStats(0).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.message_error),
        connection.recvStreamStats(0).?.stop_sending_sent.?
            .application_error_code,
    );

    var rejection = try peer_connection.receivePacket();
    defer rejection.deinit(allocator);
    var saw_reset = false;
    var saw_stop = false;
    for (rejection.frames) |frame| switch (frame) {
        .reset_stream => |reset| {
            try std.testing.expectEqual(
                @as(u64, http3.ApplicationErrorCode.message_error),
                reset.application_error_code,
            );
            saw_reset = true;
        },
        .stop_sending => |stop| {
            try std.testing.expectEqual(
                @as(u64, http3.ApplicationErrorCode.message_error),
                stop.application_error_code,
            );
            saw_stop = true;
        },
        else => {},
    };
    try std.testing.expect(saw_reset);
    try std.testing.expect(saw_stop);
}

test "Protected session control retains close after drain event" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var drain_storage: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_storage);
    var close_storage: [64]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        17,
        "after drain",
    );
    var joined: [80]u8 = undefined;
    @memcpy(joined[0..drain.len], drain);
    @memcpy(joined[drain.len..][0..close.len], close);

    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var reader = protected.Reader.init(
        try control_module.Control.init(no_alloc.allocator(), .init(0)),
    );
    defer reader.deinit();
    const first = (try reader.consume(
        joined[0 .. drain.len + close.len],
    )).?;
    try std.testing.expect(first == .draining);
    const second = (try reader.pollPending()).?;
    try std.testing.expect(second == .closed);
    try std.testing.expectEqual(@as(u32, 17), second.closed.code);
    try std.testing.expectEqualStrings(
        "after drain",
        second.closed.reason,
    );
}

test "Protected session control retains maximum close after drain event" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var reason: [control_module.max_close_reason]u8 = undefined;
    @memset(&reason, 'x');
    var drain_storage: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_storage);
    var close_storage: [4 + control_module.max_close_reason + 16]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        29,
        &reason,
    );
    var joined: [protected.buffer_capacity]u8 = undefined;
    try std.testing.expect(drain.len + close.len <= joined.len);
    @memcpy(joined[0..drain.len], drain);
    @memcpy(joined[drain.len..][0..close.len], close);

    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var reader = protected.Reader.init(
        try control_module.Control.init(no_alloc.allocator(), .init(0)),
    );
    defer reader.deinit();
    try std.testing.expectError(
        error.OutOfMemory,
        reader.consume(joined[0 .. drain.len + close.len]),
    );
    try std.testing.expect(!reader.control.peer_drain_reported);
    try std.testing.expect(reader.pending_heap == null);
    reader.control.allocator = std.testing.allocator;
    const first = (try reader.consume(joined[0 .. drain.len + close.len])).?;
    try std.testing.expect(first == .draining);
    try std.testing.expectEqual(
        close.len,
        reader.pending_heap.?.len,
    );
    const second = (try reader.pollPending()).?;
    try std.testing.expect(reader.pending_heap == null);
    try std.testing.expect(second == .closed);
    try std.testing.expectEqual(@as(u32, 29), second.closed.code);
    try std.testing.expectEqualSlices(u8, &reason, second.closed.reason);
}

test "WebTransport session control uses bounded close reason storage" {
    const control_module = @import("session_control.zig");

    const inline_reason = [_]u8{'s'} ** 128;
    var inline_capsule_storage: [4 + control_module.max_close_reason + 16]u8 =
        undefined;
    const inline_capsule = try control_module.writeCloseInto(
        &inline_capsule_storage,
        31,
        &inline_reason,
    );
    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var inline_control = try control_module.Control.init(
        no_alloc.allocator(),
        .init(0),
    );
    defer inline_control.deinit();
    const inline_result = try inline_control.feedCapsulePayload(inline_capsule);
    try std.testing.expect(inline_result.event.? == .closed);
    try std.testing.expectEqualSlices(
        u8,
        &inline_reason,
        inline_result.event.?.closed.reason,
    );
    try std.testing.expect(inline_control.close_reason_heap == null);

    const heap_reason = [_]u8{'h'} ** 129;
    var heap_capsule_storage: [4 + control_module.max_close_reason + 16]u8 =
        undefined;
    const heap_capsule = try control_module.writeCloseInto(
        &heap_capsule_storage,
        32,
        &heap_reason,
    );
    var heap_control = try control_module.Control.init(
        no_alloc.allocator(),
        .init(0),
    );
    defer heap_control.deinit();
    try std.testing.expectError(
        error.OutOfMemory,
        heap_control.feedCapsulePayload(heap_capsule),
    );
    try std.testing.expect(heap_control.close_reason_heap == null);
    heap_control.allocator = std.testing.allocator;
    const heap_result = try heap_control.feedCapsulePayload(heap_capsule);
    try std.testing.expect(heap_result.event.? == .closed);
    try std.testing.expectEqualSlices(
        u8,
        &heap_reason,
        heap_result.event.?.closed.reason,
    );
    try std.testing.expectEqual(
        heap_reason.len,
        heap_control.close_reason_heap.?.len,
    );

    const invalid_reason = [_]u8{'i'} ** 129;
    const invalid_capsule = try control_module.writeCloseInto(
        &heap_capsule_storage,
        33,
        &invalid_reason,
    );
    invalid_capsule[invalid_capsule.len - 1] = 0xff;
    var invalid_control = try control_module.Control.init(
        std.testing.allocator,
        .init(0),
    );
    defer invalid_control.deinit();
    try std.testing.expectError(
        error.InvalidCapsule,
        invalid_control.feedCapsulePayload(invalid_capsule),
    );
    try std.testing.expect(invalid_control.close_reason_heap == null);
}

test "Protected session control clean FIN closes only at capsule boundary" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var clean = protected.Reader.init(
        try control_module.Control.init(std.testing.allocator, .init(0)),
    );
    defer clean.deinit();
    const closed = (try clean.finish()).?;
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(@as(u32, 0), closed.closed.code);
    try std.testing.expectEqualStrings("", closed.closed.reason);

    var partial = protected.Reader.init(
        try control_module.Control.init(std.testing.allocator, .init(0)),
    );
    defer partial.deinit();
    var close_storage: [64]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        31,
        "partial",
    );
    try std.testing.expect((try partial.consume(close[0..3])) == null);
    try std.testing.expectError(error.InvalidCapsule, partial.finish());
}

test {
    _ = @import("session_control/tests/close_deadline.zig");
    _ = @import("session_control/tests/cleanup_deadline.zig");
}

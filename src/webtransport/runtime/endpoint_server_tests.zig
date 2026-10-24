const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const runtime = @import("../runtime.zig");
const webtransport = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

test "WebTransport endpoint server exposes stable session API" {
    try std.testing.expect(@hasDecl(runtime, "EndpointServer"));
    try std.testing.expect(@hasDecl(runtime, "EndpointServerEvent"));
    try std.testing.expect(@hasDecl(
        runtime,
        "EndpointAcceptedSession",
    ));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "receive"));
    try std.testing.expect(@hasDecl(
        runtime.EndpointServer,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointServer,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "accept"));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "reject"));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "sessionById"));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "removeSession"));
    try std.testing.expect(@hasDecl(
        runtime.HandshakeServer,
        "bindForEndpoint",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "remoteAddressValidated",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "stableId",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "rttNanos",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "negotiatedAlpn",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "initiateKeyUpdate",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "localKeyUpdateCount",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "peerKeyUpdateCount",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "keyUpdateAwaitingAck",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "trySendDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointAcceptedSession,
        "trySendDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        http3.runtime.EndpointServer,
        "promotedSession",
    ));
}

test "WebTransport endpoint session capacity is explicit and bounded" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = net.IpAddress{ .ip4 = .loopback(0) };
    const options = http3.runtime.HandshakeServerOptions{
        .handshake = .{ .local_connection_id = "wt-capacity-config" },
    };
    try std.testing.expectError(
        error.InvalidSessionState,
        runtime.HandshakeServer.bind(
            allocator,
            io,
            address,
            .{ .max_sessions_per_connection = 2 },
            options,
        ),
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        runtime.HandshakeServer.bindForEndpoint(
            allocator,
            io,
            address,
            .{ .max_sessions_per_connection = 0 },
            options,
        ),
    );
    if (@bitSizeOf(usize) > 62) {
        try std.testing.expectError(
            error.InvalidSessionState,
            runtime.HandshakeServer.bindForEndpoint(
                allocator,
                io,
                address,
                .{
                    .max_sessions_per_connection = @as(usize, @intCast(quic.varint.max_value)) + 1,
                },
                options,
            ),
        );
    }
}

test "WebTransport endpoint accepted session forwards authenticated metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const settings = webtransport.defaultSettings(.{});

    var certificate_der_storage: [tls_testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der_storage,
        tls_testing.certificate_base64,
    );
    const certificate_der = certificate_der_storage;
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = "wt-meta-server",
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .random = [_]u8{0x21} ** 32,
                .x25519_secret_key = [_]u8{0x22} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 1,
        .max_connections = 1,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    defer endpoint.deinit();

    const ClientMetadata = struct {
        session_id: webtransport.SessionId,
        local_address: net.IpAddress,
        exporter: [48]u8,
    };

    const Shared = struct {
        io: std.Io,
        server_address: net.IpAddress,
        public_key: [65]u8,
        certificate_der: [tls_testing.certificate_der_len]u8,
        settings: http3.Settings,
        metadata_ready: std.Io.Event = .unset,
        peer_close_observed: std.Io.Event = .unset,
        metadata: ?ClientMetadata = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.metadata_ready.set(self.io);
                self.peer_close_observed.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var client = try runtime.HandshakeClientSession.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.server_address,
                .{
                    .authority = "localhost",
                    .path = "/endpoint-metadata",
                    .limits = .{ .http3 = .{
                        .quic = .{ .max_datagram_size = 4096 },
                    } },
                    .h3 = .{
                        .handshake = .{
                            .original_destination_connection_id = "wt-meta-origin",
                            .local_connection_id = "wt-meta-client",
                            .server_name = "localhost",
                            .server_auth = .{
                                .pinned_ecdsa_p256_public_key = self.public_key,
                            },
                            .random = [_]u8{0x23} ** 32,
                            .x25519_secret_key = [_]u8{0x24} ** 32,
                            .handshake_recovery = .{
                                .initial_pto_ms = 20,
                                .max_pto_ms = 40,
                                .max_duration_ms = 2_000,
                            },
                        },
                        .session = .{ .local_settings = self.settings },
                    },
                },
            );
            defer client.deinit();

            try std.testing.expectEqual(
                self.server_address,
                client.remoteAddress(),
            );
            try std.testing.expect(client.remoteAddressValidated());
            try std.testing.expect(client.rttNanos() != null);
            try std.testing.expectEqualStrings("h3", client.negotiatedAlpn());
            try std.testing.expectEqual(
                @TypeOf(client.negotiatedCipherSuite()).aes_128_gcm_sha256,
                client.negotiatedCipherSuite(),
            );
            try std.testing.expectEqual(
                @TypeOf(client.negotiatedTranscriptHash()).sha256,
                client.negotiatedTranscriptHash(),
            );
            const server_chain = client.peerCertificates() orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(@as(usize, 1), server_chain.len);
            try std.testing.expectEqualSlices(
                u8,
                &self.certificate_der,
                server_chain[0],
            );
            try std.testing.expect(@intFromPtr(server_chain[0].ptr) !=
                @intFromPtr(&self.certificate_der[0]));

            var client_exporter: [48]u8 = undefined;
            try client.exportKeyingMaterial(
                "EXPORTER-netz-webtransport-endpoint",
                "endpoint-metadata",
                &client_exporter,
            );
            self.metadata = .{
                .session_id = client.sessionId(),
                .local_address = client.h3.address(),
                .exporter = client_exporter,
            };
            self.metadata_ready.set(self.io);

            const event = client.receiveSessionEventWithTimeout(
                .fromSeconds(1),
            ) catch |err| switch (err) {
                // The server deliberately initiates a key update immediately
                // before closing. This test exercises the endpoint-side
                // metadata mutation, not peer close delivery; either terminal
                // event or a bounded timeout is sufficient to release the
                // worker without turning a lost close datagram into a hang.
                error.Timeout => null,
                else => return err,
            };
            if (event) |value| {
                try std.testing.expect(value == .closed);
                try std.testing.expectEqual(@as(u32, 79), value.closed.code);
                try std.testing.expectEqualStrings(
                    "endpoint metadata done",
                    value.closed.reason,
                );
            }
            self.peer_close_observed.set(self.io);
        }
    };
    var shared = Shared{
        .io = io,
        .server_address = server.address(),
        .public_key = public_key,
        .certificate_der = certificate_der,
        .settings = settings,
    };
    const client_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.metadata_ready.set(io);
        shared.peer_close_observed.set(io);
        client_thread.join();
    };

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var stream_buffer: [1]u8 = undefined;
    var accepted_handle: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    var accepted: ?*runtime.EndpointAcceptedSession = null;
    while (accepted == null) {
        if (shared.metadata_ready.isSet() and shared.metadata == null) {
            client_thread.join();
            joined = true;
            if (shared.err) |err| return err;
            return error.TestUnexpectedResult;
        }
        const maybe_event = try endpoint.receiveOnce(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(20) },
            &stream_buffer,
        );
        if (maybe_event == null) continue;
        var event = maybe_event.?;
        defer event.deinit(allocator);
        switch (event) {
            .connected => {},
            .closed => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
            .session_request => |handle| {
                const pending = endpoint.pendingSession(handle) orelse
                    return error.TestUnexpectedResult;
                try std.testing.expectEqualStrings(
                    "/endpoint-metadata",
                    pending.path(),
                );
                const value = try endpoint.accept(handle);
                accepted_handle = handle;
                accepted = value;
            },
            .session_event, .unrouted => return error.TestUnexpectedResult,
        }
    }

    const session = accepted.?;
    try shared.metadata_ready.wait(io);
    const client_metadata = shared.metadata orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(session.sessionId(), client_metadata.session_id);
    try std.testing.expectEqual(
        client_metadata.local_address,
        session.remoteAddress(),
    );
    try std.testing.expect(session.remoteAddressValidated());
    // A client can complete this local handshake before the server receives an
    // ACK that yields its first RTT sample. The endpoint accessor must mirror
    // that optional transport state rather than inventing a measurement.
    try std.testing.expectEqual(
        session.stats().smoothed_rtt_ns,
        session.rttNanos(),
    );
    try std.testing.expectEqualStrings("h3", session.negotiatedAlpn());
    try std.testing.expectEqual(
        @TypeOf(session.negotiatedCipherSuite()).aes_128_gcm_sha256,
        session.negotiatedCipherSuite(),
    );
    try std.testing.expectEqual(
        @TypeOf(session.negotiatedTranscriptHash()).sha256,
        session.negotiatedTranscriptHash(),
    );
    try std.testing.expectEqual(
        @as(?[]const []const u8, null),
        session.peerCertificates(),
    );
    try std.testing.expectEqual(@as(u64, 0), session.localKeyUpdateCount());
    try std.testing.expectEqual(@as(u64, 0), session.peerKeyUpdateCount());
    try std.testing.expect(!session.keyUpdateAwaitingAck());

    var server_exporter: [48]u8 = undefined;
    var client_exporter: [48]u8 = undefined;
    try session.exportKeyingMaterial(
        "EXPORTER-netz-webtransport-endpoint",
        "endpoint-metadata",
        &server_exporter,
    );
    client_exporter = client_metadata.exporter;
    try std.testing.expectEqualSlices(
        u8,
        &server_exporter,
        &client_exporter,
    );

    try session.initiateKeyUpdate();
    try std.testing.expectEqual(@as(u64, 1), session.localKeyUpdateCount());
    try std.testing.expect(session.keyUpdateAwaitingAck());

    try session.close(79, "endpoint metadata done");
    try shared.peer_close_observed.wait(io);
    const handle = accepted_handle orelse return error.TestUnexpectedResult;
    try std.testing.expect(endpoint.removeConnection(handle));

    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport endpoint server validates receive deadlines" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "wt-deadline" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();
    var buffer: [1]u8 = undefined;

    try std.testing.expectError(
        error.Timeout,
        endpoint.receiveWithDeadline(
            &.{quic.Version.version_1.wireValue()},
            .{ .clock = .real, .raw = .zero },
            &buffer,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        endpoint.receiveWithDeadline(
            &.{quic.Version.version_1.wireValue()},
            .fromNow(io, .{ .clock = .awake, .raw = .zero }),
            &buffer,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        endpoint.receiveWithTimeout(
            &.{quic.Version.version_1.wireValue()},
            .zero,
            &buffer,
        ),
    );
}

test "WebTransport endpoint packet error replaces stale timer with close expiry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{ .local_connection_id = "wt-packet-root" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xeb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xec} ** quic.protection.secret_len,
    );
    const client_cid = "wt-packet-client";
    const server_cid = "wt-packet-server";
    var client = try http3.runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        endpoint.address(),
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = client_cid,
            .peer_connection_id = server_cid,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer client.deinit();
    const session = try allocator.create(
        http3.runtime.HandshakeServerSession,
    );
    var session_owned = true;
    defer if (session_owned) {
        session.deinit();
        allocator.destroy(session);
    };
    session.* = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server.h3.quic_server.endpoint,
        client.address(),
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 91;
    try endpoint.h3.dispatcher.registerConnection(
        handle,
        &session.established.connection,
    );
    const slot = try endpoint.h3.sessions.getOrPut(allocator, handle);
    try std.testing.expect(!slot.found_existing);
    slot.value_ptr.* = .{
        .dispatcher = endpoint.h3.dispatcher,
        .allocator = allocator,
        .handle = handle,
        .session = session,
    };
    session_owned = false;

    try session.established.connection.send(&.{.{ .ping = {} }});
    try endpoint.h3.dispatcher.refreshConnectionTimer(handle);
    const before = endpoint.h3.dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, before.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pto,
        before.timer.kind,
    );

    try client.established.connection.send(&.{.{ .stream = .{
        .stream_id = 2,
        .data = &.{@intFromEnum(http3.StreamType.control)},
        .fin = true,
    } }});
    var buffer: [1]u8 = undefined;
    try std.testing.expectError(
        error.ClosedCriticalStream,
        endpoint.receiveOnce(
            &.{quic.Version.version_1.wireValue()},
            .{ .clock = .awake, .raw = .fromSeconds(1) },
            &buffer,
        ),
    );
    try std.testing.expect(session.established.connection.closing());
    const connection_timer = session.established.connection
        .nextTimerDeadline() orelse return error.TestUnexpectedResult;
    const endpoint_timer = endpoint.h3.dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, endpoint_timer.connection_id);
    try std.testing.expectEqual(connection_timer, endpoint_timer.timer);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.close,
        endpoint_timer.timer.kind,
    );
    try std.testing.expect(
        endpoint_timer.timer.deadline_ns != before.timer.deadline_ns,
    );
    const serviced = (try endpoint.h3.dispatcher.serviceNextTimerAt(
        endpoint_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.close,
        serviced.timer.kind,
    );
    try std.testing.expect(session.established.connection.closed());
}

test "WebTransport server deadline spans QUIC TLS and Extended CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb5} ** 32,
            .x25519_secret_key = [_]u8{0xb6} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        io: std.Io,
        handshake_complete: std.Io.Event = .unset,
        send_connect: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.handshake_complete.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h3_client = try http3.runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.server.address(),
                .{ .quic = .{ .max_datagram_size = 4096 } },
                .{
                    .handshake = .{
                        .original_destination_connection_id = &original_dcid,
                        .local_connection_id = &client_cid,
                        .server_name = "localhost",
                        .random = [_]u8{0xb7} ** 32,
                        .x25519_secret_key = [_]u8{0xb8} ** 32,
                    },
                    .session = .{
                        .local_settings = webtransport.defaultSettings(.{}),
                    },
                },
            );
            defer h3_client.deinit();
            self.handshake_complete.set(self.io);
            try self.send_connect.wait(self.io);
            _ = try h3_client.startRequest(.{
                .method = "CONNECT",
                .path = "/late-connect",
                .scheme = "https",
                .authority = "localhost",
                .headers = &.{
                    .{ .name = ":protocol", .value = "webtransport" },
                    http3.capsule.protocol_header,
                },
            }, null);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const client_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.send_connect.set(io);
        client_thread.join();
    };

    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(300), .clock = .awake },
    );
    const ReceiveResult = runtime.ReceiveTimeoutError!runtime.PendingHandshakeSession;
    const Wake = union(enum) {
        server: ReceiveResult,
        client_handshake: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer while (select.cancel()) |wake| switch (wake) {
        .server => |result| if (result) |pending_value| {
            var pending = pending_value;
            pending.deinit();
        } else |_| {},
        .client_handshake => {},
    };
    select.async(
        .server,
        runtime.HandshakeServer.receiveSessionRequestWithDeadline,
        .{ &server, deadline },
    );
    select.async(
        .client_handshake,
        std.Io.Event.wait,
        .{ &shared.handshake_complete, io },
    );
    const wake = try select.await();
    switch (wake) {
        .server => |result| {
            if (result) |pending_value| {
                var pending = pending_value;
                pending.deinit();
                return error.TestUnexpectedResult;
            } else |err| return err;
        },
        .client_handshake => |result| try result,
    }

    // The QUIC/TLS phase completed under `deadline`. Deliberately spend the
    // rest of that same absolute budget before allowing Extended CONNECT; a
    // server that restarted a relative timeout here would incorrectly accept.
    const remaining = deadline.durationFromNow(io).raw.nanoseconds;
    if (remaining > 0) {
        try std.Io.sleep(
            io,
            .{ .nanoseconds = remaining + 10 * std.time.ns_per_ms },
            .awake,
        );
    }
    shared.send_connect.set(io);
    try std.testing.expectError(
        error.Timeout,
        switch (try select.await()) {
            .server => |result| result,
            .client_handshake => return error.TestUnexpectedResult,
        },
    );

    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport URI connect forwards HTTP3 total handshake timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/timeout",
        .{silent.address().ip4.port},
    );
    defer allocator.free(uri);

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClientSession.connectUri(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            uri,
            .{ .h3 = .{
                .connect_timeout = .fromMilliseconds(20),
                .handshake = .{
                    .original_destination_connection_id = "wt-timeout-origin",
                    .local_connection_id = "wt-timeout-client",
                    .handshake_recovery = .{
                        .initial_pto_ms = 1_000,
                        .max_pto_ms = 4_000,
                        .max_retries = 3,
                    },
                },
            } },
        ),
    );
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds < 500 * std.time.ns_per_ms);
}

test "WebTransport URI connect exposes an absolute handshake deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClientSession.connectUriWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            "https://localhost/",
            .{ .h3 = .{ .handshake = .{
                .original_destination_connection_id = "wt-deadline-origin",
                .local_connection_id = "wt-deadline-client",
            } } },
            .fromNow(io, .{ .raw = .zero, .clock = .awake }),
        ),
    );
}

test "WebTransport direct connect composes caller and phase deadlines" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const options: runtime.HandshakeConnectOptions = .{
        .authority = "localhost",
        .h3 = .{
            .connect_timeout = .zero,
            .handshake = .{
                .original_destination_connection_id = "wt-direct-origin",
                .local_connection_id = "wt-direct-client",
            },
        },
    };
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClientSession.connectWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            options,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
}

test "WebTransport URI deadline retains shorter HTTP3 phase timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClientSession.connectUriWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            "https://localhost/",
            .{ .h3 = .{
                .connect_timeout = .zero,
                .handshake = .{
                    .original_destination_connection_id = "wt-uri-phase-origin",
                    .local_connection_id = "wt-uri-phase-client",
                },
            } },
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
}

test "WebTransport connect timeout rejects a non-positive budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.HandshakeClientSession.connectUriWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "https://localhost/",
            .{ .h3 = .{ .handshake = .{
                .original_destination_connection_id = "wt-timeout-origin",
                .local_connection_id = "wt-timeout-client",
            } } },
            .zero,
        ),
    );
}

test "WebTransport URI deadline includes Extended CONNECT response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const original_dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        deadline: std.Io.Clock.Timestamp,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveSessionRequest();
            defer pending.deinit();
            // Receiving the CONNECT request proves QUIC/TLS completed before
            // the caller's deadline. Keep the response pending until after
            // that exact timestamp so this test cannot accidentally measure
            // a slow handshake as a response-phase timeout.
            try self.deadline.wait(
                self.server.h3.quic_server.endpoint.io,
            );
            try std.Io.sleep(
                self.server.h3.quic_server.endpoint.io,
                .fromMilliseconds(25),
                .awake,
            );
        }
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    var shared = Shared{ .server = &server, .deadline = deadline };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/deadline",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    try std.testing.expectError(
        error.Timeout,
        runtime.HandshakeClientSession.connectUriWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            uri,
            .{ .h3 = .{
                .connect_timeout = .fromSeconds(1),
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .random = [_]u8{0x81} ** 32,
                    .x25519_secret_key = [_]u8{0x82} ** 32,
                    .server_auth = .{
                        .pinned_ecdsa_p256_public_key = public_key,
                    },
                },
            } },
            deadline,
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport endpoint server rotates ready sessions fairly" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "wt-fair-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    // The scheduler only passes these stable addresses to the synthetic
    // readiness callback. Clearing the map before EndpointServer.deinit keeps
    // the intentionally uninitialized protocol objects out of ownership code.
    var accepted_storage: [3]runtime.EndpointAcceptedSession = undefined;
    defer endpoint.sessions.clearRetainingCapacity();
    const handles = [_]quic.endpoint_dispatcher.ConnectionHandle{ 11, 22, 33 };
    var keys: [handles.len]runtime.EndpointSessionKey = undefined;
    for (handles, 0..) |handle, index| {
        keys[index] = .{
            .handle = handle,
            .session_id = .init(@intCast(index * 4)),
        };
        try endpoint.sessions.put(
            allocator,
            keys[index],
            &accepted_storage[index],
        );
    }

    var order: [handles.len]quic.endpoint_dispatcher.ConnectionHandle =
        undefined;
    for (&order) |*handle| {
        handle.* = (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &handles,
        )) orelse return error.TestUnexpectedResult;
    }
    for (order, 0..) |handle, index| {
        for (order[0..index]) |earlier| {
            try std.testing.expect(handle != earlier);
        }
    }
    try std.testing.expectEqual(
        order[0],
        (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &handles,
        )).?,
    );

    // Skipping idle entries must still advance from the actual producer.
    const only_middle = [_]quic.endpoint_dispatcher.ConnectionHandle{
        order[1],
    };
    try std.testing.expectEqual(
        order[1],
        (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &only_middle,
        )).?,
    );
    try std.testing.expectEqual(
        order[2],
        (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &handles,
        )).?,
    );

    // A cursor invalidated by removal falls back to a complete scan rather
    // than suppressing ready sessions until another insertion reshuffles the
    // hash table.
    const stale = order[2];
    var stale_key: runtime.EndpointSessionKey = undefined;
    for (keys) |key| {
        if (key.handle == stale) stale_key = key;
    }
    try std.testing.expect(endpoint.sessions.remove(stale_key));
    endpoint.last_session_event_key = stale_key;
    const after_removal =
        (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &handles,
        )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(after_removal != stale);
}

test "WebTransport endpoint server owns concurrent real sessions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const settings = webtransport.defaultSettings(.{});

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } } },
        .{
            .handshake = .{
                .local_connection_id = "wt-endpoint-template",
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 2,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    defer endpoint.deinit();
    const dispatcher_address = @intFromPtr(endpoint.h3.dispatcher);

    const ClientTask = struct {
        io: std.Io,
        address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        path: []const u8,
        datagram: []const u8,
        response_datagram: []const u8,
        settings: http3.Settings,
        random: [32]u8,
        secret: [32]u8,
        client: ?runtime.HandshakeClientSession = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            self.client = try runtime.HandshakeClientSession.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{
                    .authority = "localhost",
                    .path = self.path,
                    .limits = .{ .http3 = .{ .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 16,
                    } } },
                    .h3 = .{
                        .handshake = .{
                            .original_destination_connection_id = self.original_dcid,
                            .local_connection_id = self.local_cid,
                            .server_name = "localhost",
                            .random = self.random,
                            .x25519_secret_key = self.secret,
                            .handshake_recovery = .{
                                .initial_pto_ms = 20,
                                .max_pto_ms = 40,
                                .max_duration_ms = 2_000,
                            },
                        },
                        .session = .{ .local_settings = self.settings },
                    },
                },
            );
            try self.client.?.sendDatagram(self.datagram);
            var response = try self.client.?.receiveDatagramWithTimeout(
                .fromSeconds(3),
            );
            defer response.deinit(allocator);
            try std.testing.expectEqualStrings(
                self.response_datagram,
                response.datagram.payload,
            );
            const stream_id = try self.client.?.openBidirectionalStream();
            try self.client.?.sendStream(
                stream_id,
                self.datagram,
                true,
            );
            var stream_response = try self.client.?.receiveStreamWithTimeout(
                .fromSeconds(3),
            );
            defer stream_response.deinit();
            try std.testing.expectEqualStrings(
                self.response_datagram,
                stream_response.payload,
            );
            try self.client.?.close(77, self.datagram);
        }
    };
    var clients = [_]ClientTask{
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "wt-endpoint-one",
            .local_cid = "wt-client-one",
            .path = "/one",
            .datagram = "one",
            .response_datagram = "echo-one",
            .settings = settings,
            .random = [_]u8{0xe3} ** 32,
            .secret = [_]u8{0xe4} ** 32,
        },
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "wt-endpoint-two",
            .local_cid = "wt-client-two",
            .path = "/two",
            .datagram = "two",
            .response_datagram = "echo-two",
            .settings = settings,
            .random = [_]u8{0xe5} ** 32,
            .secret = [_]u8{0xe6} ** 32,
        },
    };
    const first_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const second_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        first_thread.join();
        second_thread.join();
        for (&clients) |*client| if (client.client) |*value| value.deinit();
    };

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var accepted_handles: [2]quic.endpoint_dispatcher.ConnectionHandle = undefined;
    var accepted_count: usize = 0;
    var received_datagrams: usize = 0;
    var received_streams: usize = 0;
    var received_closes: usize = 0;
    var stream_one_bytes: usize = 0;
    var stream_two_bytes: usize = 0;
    var stream_buffer: [128]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(5),
    });
    while (accepted_count < clients.len or
        received_datagrams < clients.len or
        received_streams < clients.len or
        received_closes < clients.len)
    {
        var event = try endpoint.receiveWithDeadline(
            &versions,
            deadline,
            &stream_buffer,
        );
        defer event.deinit(allocator);
        switch (event) {
            .connected => {},
            .closed => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
            .session_request => |handle| {
                const pending = endpoint.pendingSession(handle) orelse
                    return error.TestUnexpectedResult;
                const path = pending.path();
                if (!std.mem.eql(u8, path, "/one") and
                    !std.mem.eql(u8, path, "/two"))
                {
                    return error.TestUnexpectedResult;
                }
                const accepted = try endpoint.accept(handle);
                try std.testing.expectEqual(
                    handle,
                    accepted.handle,
                );
                try std.testing.expectEqual(
                    dispatcher_address,
                    @intFromPtr(accepted.dispatcher),
                );
                try std.testing.expectEqual(
                    @intFromPtr(endpoint.h3.session(handle).?),
                    @intFromPtr(accepted.h3),
                );
                accepted_handles[accepted_count] = handle;
                accepted_count += 1;
            },
            .session_event => |*value| switch (value.event) {
                .datagram => |datagram| {
                    const accepted = endpoint.sessionById(
                        value.handle,
                        value.session_id,
                    ) orelse
                        return error.TestUnexpectedResult;
                    const expected = if (std.mem.eql(
                        u8,
                        accepted.request.request.path,
                        "/one",
                    )) "one" else "two";
                    try std.testing.expectEqualStrings(
                        expected,
                        datagram.datagram.payload,
                    );
                    try accepted.trySendDatagramWithTimeout(
                        if (std.mem.eql(
                            u8,
                            expected,
                            "one",
                        )) "echo-one" else "echo-two",
                        .fromSeconds(1),
                    );
                    received_datagrams += 1;
                },
                .stream => |stream| {
                    if (stream != .data) {
                        return error.TestUnexpectedResult;
                    }
                    const accepted = endpoint.sessionById(
                        value.handle,
                        value.session_id,
                    ) orelse
                        return error.TestUnexpectedResult;
                    const is_one = std.mem.eql(
                        u8,
                        accepted.request.request.path,
                        "/one",
                    );
                    const expected = if (is_one) "one" else "two";
                    const received = if (is_one)
                        &stream_one_bytes
                    else
                        &stream_two_bytes;
                    try std.testing.expectEqualStrings(
                        expected[received.*..][0..stream.data.bytes],
                        stream_buffer[0..stream.data.bytes],
                    );
                    received.* += stream.data.bytes;
                    if (stream.data.fin) {
                        try std.testing.expectEqual(expected.len, received.*);
                        try accepted.sendStream(
                            stream.data.stream_id,
                            if (is_one) "echo-one" else "echo-two",
                            true,
                        );
                        received_streams += 1;
                    }
                },
                .session => |session_event| {
                    if (session_event != .closed or
                        session_event.closed.code != 77)
                    {
                        return error.TestUnexpectedResult;
                    }
                    const accepted = endpoint.sessionById(
                        value.handle,
                        value.session_id,
                    ) orelse
                        return error.TestUnexpectedResult;
                    const expected = if (std.mem.eql(
                        u8,
                        accepted.request.request.path,
                        "/one",
                    )) "one" else "two";
                    try std.testing.expectEqualStrings(
                        expected,
                        session_event.closed.reason,
                    );
                    received_closes += 1;
                },
            },
            .unrouted => return error.TestUnexpectedResult,
        }
    }

    first_thread.join();
    second_thread.join();
    joined = true;
    for (&clients) |*client| {
        if (client.err) |err| return err;
        if (client.client) |*value| value.deinit();
        client.client = null;
    }
    try std.testing.expectEqual(@as(usize, 2), endpoint.sessionCount());
    try std.testing.expectEqual(@as(usize, 2), endpoint.connectionCount());
    for (accepted_handles) |handle| {
        try std.testing.expect(endpoint.removeConnection(handle));
    }
    try std.testing.expectEqual(@as(usize, 0), endpoint.connectionCount());
}

test "WebTransport endpoint multiplexes two Sessions on one HTTP3 connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const client_settings = webtransport.defaultSettings(.{});
    const limits = runtime.Limits{
        .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .max_session_streams = 8,
        .max_sessions_per_connection = 2,
    };
    var server = try runtime.HandshakeServer.bindForEndpoint(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = "wt-multi-template",
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 1,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    defer endpoint.deinit();

    const Shared = struct {
        io: std.Io,
        address: net.IpAddress,
        limits: http3.runtime.Limits,
        settings: http3.Settings,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h3 = try http3.runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                self.limits,
                .{
                    .handshake = .{
                        .original_destination_connection_id = "wt-multi-origin",
                        .local_connection_id = "wt-multi-client",
                        .server_name = "localhost",
                        .random = [_]u8{0x93} ** 32,
                        .x25519_secret_key = [_]u8{0x94} ** 32,
                        .handshake_recovery = .{
                            .initial_pto_ms = 20,
                            .max_pto_ms = 40,
                            .max_duration_ms = 2_000,
                        },
                    },
                    .session = .{ .local_settings = self.settings },
                },
            );
            defer h3.deinit();
            const headers = [_]http3.Qpack.HeaderField{
                .{ .name = ":protocol", .value = "webtransport-h3" },
                http3.capsule.protocol_header,
            };
            const session_ids = [_]u62{
                try h3.startRequest(.{
                    .method = "CONNECT",
                    .path = "/first",
                    .scheme = "https",
                    .authority = "localhost",
                    .headers = &headers,
                }, null),
                try h3.startRequest(.{
                    .method = "CONNECT",
                    .path = "/second",
                    .scheme = "https",
                    .authority = "localhost",
                    .headers = &headers,
                }, null),
            };
            try std.testing.expectEqualSlices(u62, &.{ 0, 4 }, &session_ids);
            const malformed_id = try h3.startRequest(.{
                .method = "CONNECT",
                .path = "/malformed",
                .scheme = "https",
                .authority = "localhost",
                .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
            }, null);
            try std.testing.expectEqual(@as(u62, 8), malformed_id);
            const excess_session_id = try h3.startRequest(.{
                .method = "CONNECT",
                .path = "/excess",
                .scheme = "https",
                .authority = "localhost",
                .headers = &headers,
            }, null);
            try std.testing.expectEqual(@as(u62, 12), excess_session_id);
            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .clock = .awake,
                .raw = .fromSeconds(5),
            });
            for (session_ids) |session_id| {
                var accepted = false;
                while (!accepted) {
                    var event = (try h3.receiveResponseEventWithDeadline(
                        session_id,
                        deadline,
                    )) orelse continue;
                    defer event.deinit(allocator);
                    switch (event) {
                        .head => |head| {
                            if (head != .response or
                                head.response.status != 200)
                            {
                                return error.TestUnexpectedResult;
                            }
                            accepted = true;
                        },
                        else => {},
                    }
                }
                try h3.detachResponseStream(session_id);
            }
            try std.testing.expectEqual(
                @as(u64, 2),
                h3.control.settings.peer.webtransport_max_sessions,
            );
            while (true) {
                const maybe_event = h3.receiveResponseEventWithDeadline(malformed_id, deadline) catch |err| {
                    try std.testing.expectEqual(error.RequestCancelled, err);
                    break;
                };
                if (maybe_event) |value| {
                    var unexpected = value;
                    defer unexpected.deinit(allocator);
                    return error.TestUnexpectedResult;
                }
            }
            try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, h3.established.connection.recvStreamStats(malformed_id).?.reset.?.application_error_code);
            while (true) {
                const maybe_event = h3.receiveResponseEventWithDeadline(
                    excess_session_id,
                    deadline,
                ) catch |err| {
                    try std.testing.expectEqual(error.RequestRejected, err);
                    break;
                };
                if (maybe_event) |event_value| {
                    var event = event_value;
                    defer event.deinit(allocator);
                    return error.TestUnexpectedResult;
                }
            }

            try h3.sendConnectDatagram(session_ids[0], "first");
            try h3.sendConnectDatagram(session_ids[1], "second");
            var received = [_]bool{ false, false };
            while (!received[0] or !received[1]) {
                var progressed = false;
                for (session_ids, 0..) |session_id, index| {
                    if (received[index]) continue;
                    if (try h3.pollConnectDatagram(session_id)) |value| {
                        var datagram = value;
                        defer datagram.deinit(allocator);
                        const expected = if (index == 0)
                            "echo-first"
                        else
                            "echo-second";
                        try std.testing.expectEqualStrings(
                            expected,
                            datagram.payload,
                        );
                        received[index] = true;
                        progressed = true;
                    }
                }
                if (!progressed) {
                    try h3.receiveDetachedResponseProgressWithDeadline(
                        session_ids[0],
                        deadline,
                    );
                }
            }

            var first_prefix_storage: [16]u8 = undefined;
            const first_prefix = try webtransport.BidirectionalStreamHeader
                .writeInto(&first_prefix_storage, .init(session_ids[0]));
            var second_prefix_storage: [16]u8 = undefined;
            const second_prefix = try webtransport.BidirectionalStreamHeader
                .writeInto(&second_prefix_storage, .init(session_ids[1]));
            const first_stream_id = try h3.tryOpenClientBidirectionalStream();
            const second_stream_id = try h3.tryOpenClientBidirectionalStream();
            try h3.established.connection.send(&.{
                .{ .stream = .{
                    .stream_id = first_stream_id,
                    .data = first_prefix,
                } },
                .{ .stream = .{
                    .stream_id = first_stream_id,
                    .offset = first_prefix.len,
                    .data = "stream-first",
                    .fin = true,
                } },
                .{ .stream = .{
                    .stream_id = second_stream_id,
                    .data = second_prefix,
                } },
                .{ .stream = .{
                    .stream_id = second_stream_id,
                    .offset = second_prefix.len,
                    .data = "stream-second",
                    .fin = true,
                } },
            });

            for (session_ids, 0..) |session_id, index| {
                var capsule: std.ArrayList(u8) = .empty;
                defer capsule.deinit(allocator);
                try (webtransport.Capsule{ .close_session = .{
                    .code = @intCast(71 + index),
                    .reason = if (index == 0) "first" else "second",
                } }).write(&capsule, allocator);
                try h3.sendRequestBody(session_id, capsule.items, true);
            }
            try self.done.wait(self.io);
        }
    };
    var shared = Shared{
        .io = io,
        .address = server.address(),
        .limits = limits.http3,
        .settings = client_settings,
    };
    const client_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.done.set(io);
        client_thread.join();
    };

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var accepted_count: usize = 0;
    var datagram_count: usize = 0;
    var stream_count: usize = 0;
    var close_count: usize = 0;
    var malformed_count: usize = 0;
    var connection_handle: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    var stream_buffer: [64]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(8),
    });
    while (accepted_count != 2 or datagram_count != 2 or
        stream_count != 2 or close_count != 2 or malformed_count != 1)
    {
        var event = endpoint.receiveWithDeadline(
            &versions,
            deadline,
            &stream_buffer,
        ) catch |err| switch (err) {
            error.InvalidConnect => {
                malformed_count += 1;
                continue;
            },
            else => return err,
        };
        defer event.deinit(allocator);
        switch (event) {
            .connected => |handle| connection_handle = handle,
            .closed => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
            .session_request => |handle| {
                if (connection_handle) |expected| {
                    try std.testing.expectEqual(expected, handle);
                } else {
                    connection_handle = handle;
                }
                const pending = endpoint.pendingSession(handle) orelse
                    return error.TestUnexpectedResult;
                const path = pending.path();
                try std.testing.expect(
                    std.mem.eql(u8, path, "/first") or
                        std.mem.eql(u8, path, "/second"),
                );
                _ = try endpoint.accept(handle);
                accepted_count += 1;
            },
            .session_event => |*value| {
                const accepted = endpoint.sessionById(
                    value.handle,
                    value.session_id,
                ) orelse return error.TestUnexpectedResult;
                const is_first = std.mem.eql(
                    u8,
                    accepted.request.request.path,
                    "/first",
                );
                switch (value.event) {
                    .datagram => |datagram| {
                        try std.testing.expectEqualStrings(
                            if (is_first) "first" else "second",
                            datagram.datagram.payload,
                        );
                        try accepted.trySendDatagramWithTimeout(
                            if (is_first) "echo-first" else "echo-second",
                            .fromSeconds(1),
                        );
                        datagram_count += 1;
                    },
                    .stream => |stream| {
                        if (stream != .data or !stream.data.fin) {
                            return error.TestUnexpectedResult;
                        }
                        try std.testing.expectEqualStrings(
                            if (is_first) "stream-first" else "stream-second",
                            stream_buffer[0..stream.data.bytes],
                        );
                        stream_count += 1;
                    },
                    .session => |session| {
                        if (session != .closed) {
                            return error.TestUnexpectedResult;
                        }
                        try std.testing.expectEqual(
                            @as(u32, if (is_first) 71 else 72),
                            session.closed.code,
                        );
                        try std.testing.expectEqualStrings(
                            if (is_first) "first" else "second",
                            session.closed.reason,
                        );
                        close_count += 1;
                    },
                }
            },
            .unrouted => return error.TestUnexpectedResult,
        }
    }
    const handle = connection_handle orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), endpoint.sessionCount());
    try std.testing.expectEqual(
        @as(usize, 2),
        endpoint.sessionCountForConnection(handle),
    );
    const first_session = endpoint.sessionById(handle, .init(0)) orelse
        return error.TestUnexpectedResult;
    const second_session = endpoint.sessionById(handle, .init(4)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(first_session.stableId() != 0);
    try std.testing.expectEqual(
        first_session.stableId(),
        second_session.stableId(),
    );
    shared.done.set(io);
    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(try endpoint.removeSession(handle, .init(0)));
    try std.testing.expectEqual(
        @as(usize, 1),
        endpoint.sessionCountForConnection(handle),
    );
    try std.testing.expect(try endpoint.removeSession(handle, .init(4)));
    try std.testing.expectEqual(@as(usize, 0), endpoint.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint.connectionCount());
    try std.testing.expect(endpoint.removeConnection(handle));
}

test "WebTransport endpoint serve loop shuts down from a session event" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const settings = webtransport.defaultSettings(.{});
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = "wt-serve-template",
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 1,
        .inbox_capacity = 8,
    });
    defer endpoint.deinit();

    const Context = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        accepted: bool = false,
        received: bool = false,

        fn handle(
            self: *@This(),
            endpoint_server: *runtime.EndpointServer,
            event: runtime.ServeEvent,
        ) !void {
            switch (event) {
                .connected => {},
                .handshake_failed, .connect_rejected, .connection_failed, .session_failed => return error.TestUnexpectedResult,
                .closed => return error.TestUnexpectedResult,
                .session_request => |pending| {
                    _ = try endpoint_server.accept(pending.handle);
                    self.accepted = true;
                },
                .session_event => |value| switch (value.event.*) {
                    .datagram => |datagram| {
                        try std.testing.expectEqualStrings(
                            "serve-loop",
                            datagram.datagram.payload,
                        );
                        self.received = true;
                        self.shutdown.set(self.io);
                    },
                    .stream, .session => return error.TestUnexpectedResult,
                },
            }
        }
    };
    const Shared = struct {
        endpoint: *runtime.EndpointServer,
        context: Context,
        err: ?anyerror = null,

        fn init(
            endpoint_ptr: *runtime.EndpointServer,
            io_value: std.Io,
            shutdown: *std.Io.Event,
        ) @This() {
            return .{
                .endpoint = endpoint_ptr,
                .context = .{ .io = io_value, .shutdown = shutdown },
            };
        }

        fn run(self: *@This()) void {
            self.endpoint.serveUntil(
                Context,
                &self.context,
                Context.handle,
                .{
                    .shutdown = self.context.shutdown,
                    .supported_versions = &.{
                        quic.Version.version_1.wireValue(),
                        quic.Version.version_2.wireValue(),
                    },
                    .poll_interval = .{
                        .clock = .awake,
                        .raw = .fromMilliseconds(2),
                    },
                    .stream_buffer_size = 128,
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shutdown: std.Io.Event = .unset;
    var shared = Shared.init(&endpoint, io, &shutdown);
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        server_thread.join();
    };

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/serve",
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = "wt-serve-origin",
                    .local_connection_id = "wt-serve-client",
                    .server_name = "localhost",
                    .random = [_]u8{0xf3} ** 32,
                    .x25519_secret_key = [_]u8{0xf4} ** 32,
                },
                .session = .{ .local_settings = settings },
            },
        },
    );
    defer client.deinit();
    try client.sendDatagram("serve-loop");

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.context.accepted);
    try std.testing.expect(shared.context.received);
}

test "WebTransport endpoint isolates accepted and rejected connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const settings = webtransport.defaultSettings(.{});
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = "wt-policy-template",
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 2,
        .inbox_capacity = 8,
    });
    var endpoint_owned = true;
    defer if (endpoint_owned) endpoint.deinit();

    const ClientTask = struct {
        io: std.Io,
        address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        path: []const u8,
        expected_status: u16,
        settings: http3.Settings,
        random: [32]u8,
        secret: [32]u8,
        client: ?runtime.HandshakeClientSession = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var attempt = try runtime.HandshakeClientSession.connectAttempt(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{
                    .authority = "localhost",
                    .path = self.path,
                    .h3 = .{
                        .handshake = .{
                            .original_destination_connection_id = self.original_dcid,
                            .local_connection_id = self.local_cid,
                            .server_name = "localhost",
                            .random = self.random,
                            .x25519_secret_key = self.secret,
                        },
                        .session = .{ .local_settings = self.settings },
                    },
                },
            );
            if (attempt.status() != self.expected_status) {
                attempt.deinit();
                return error.TestUnexpectedResult;
            }
            if (attempt.accepted()) {
                self.client = try attempt.requireAccepted();
                try self.client.?.sendDatagram("accepted");
            } else {
                attempt.deinit();
            }
        }
    };
    var clients = [_]ClientTask{
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "wt-policy-accept",
            .local_cid = "wt-client-accept",
            .path = "/accept",
            .expected_status = 200,
            .settings = settings,
            .random = [_]u8{0xa3} ** 32,
            .secret = [_]u8{0xa4} ** 32,
        },
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "wt-policy-reject",
            .local_cid = "wt-client-reject",
            .path = "/reject",
            .expected_status = 403,
            .settings = settings,
            .random = [_]u8{0xa5} ** 32,
            .secret = [_]u8{0xa6} ** 32,
        },
    };
    const first_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const second_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        if (endpoint_owned) {
            endpoint.deinit();
            endpoint_owned = false;
        }
        first_thread.join();
        second_thread.join();
        for (&clients) |*client| if (client.client) |*value| value.deinit();
    };

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var handles: [2]quic.endpoint_dispatcher.ConnectionHandle = undefined;
    var request_count: usize = 0;
    var received_datagram = false;
    var stream_buffer: [64]u8 = undefined;
    while (request_count < clients.len or !received_datagram) {
        var event = try endpoint.receive(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
            &stream_buffer,
        );
        defer event.deinit(allocator);
        switch (event) {
            .connected => {},
            .closed => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
            .session_request => |handle| {
                const pending = endpoint.pendingSession(handle) orelse
                    return error.TestUnexpectedResult;
                handles[request_count] = handle;
                request_count += 1;
                if (std.mem.eql(u8, pending.path(), "/accept")) {
                    _ = try endpoint.accept(handle);
                } else if (std.mem.eql(u8, pending.path(), "/reject")) {
                    try endpoint.reject(handle, 403, &.{});
                } else return error.TestUnexpectedResult;
            },
            .session_event => |value| switch (value.event) {
                .datagram => |datagram| {
                    try std.testing.expectEqualStrings(
                        "accepted",
                        datagram.datagram.payload,
                    );
                    received_datagram = true;
                },
                .stream, .session => return error.TestUnexpectedResult,
            },
            .unrouted => return error.TestUnexpectedResult,
        }
    }

    first_thread.join();
    second_thread.join();
    joined = true;
    for (&clients) |*client| {
        if (client.err) |err| return err;
        if (client.client) |*value| value.deinit();
        client.client = null;
    }
    try std.testing.expectEqual(@as(usize, 1), endpoint.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint.rejectedSessionCount());
    for (handles) |handle| {
        try std.testing.expect(endpoint.removeConnection(handle));
    }
    try std.testing.expectEqual(@as(usize, 0), endpoint.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint.rejectedSessionCount());
}

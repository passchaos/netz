const std = @import("std");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");
const tls_testing = @import("../../tls/testing.zig");
const netz_runtime = @import("../../runtime.zig");

test "HTTP/3 shared pool routes two origins through one endpoint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };

    var server_a = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "shared-pool-server-a",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server_a.deinit();
    var server_b = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "shared-pool-server-b",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server_b.deinit();

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        expected_path: []const u8,
        expected_body: []const u8 = &.{},
        body: []const u8,
        responses_sent: *std.atomic.Value(usize),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.acceptWithTimeout(
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            if (!std.mem.eql(u8, request.request.path, self.expected_path)) {
                self.err = error.TestUnexpectedResult;
                return;
            }
            if (!std.mem.eql(u8, request.request.body, self.expected_body)) {
                self.err = error.TestUnexpectedResult;
                return;
            }
            if (self.expected_body.len != 0 and
                (request.request.trailers.len != 1 or
                    !std.mem.eql(
                        u8,
                        request.request.trailers[0].name,
                        "x-upload",
                    ) or
                    !std.mem.eql(
                        u8,
                        request.request.trailers[0].value,
                        "complete",
                    )))
            {
                self.err = error.TestUnexpectedResult;
                return;
            }
            session.sendResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{
                    .name = "x-origin",
                    .value = self.body,
                }},
                .body = self.body,
            }) catch |err| {
                self.err = err;
                return;
            };
            _ = self.responses_sent.fetchAdd(1, .release);
        }
    };
    var responses_sent = std.atomic.Value(usize).init(0);
    var worker_a = ServerWorker{
        .server = &server_a,
        .expected_path = "/a",
        .expected_body = "upload-a",
        .body = "origin-a",
        .responses_sent = &responses_sent,
    };
    var worker_b = ServerWorker{
        .server = &server_b,
        .expected_path = "/b",
        .body = "origin-b",
        .responses_sent = &responses_sent,
    };
    const thread_a = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_a});
    var joined_a = false;
    defer if (!joined_a) thread_a.join();
    const thread_b = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_b});
    var joined_b = false;
    defer if (!joined_b) thread_b.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .max_connections = 2,
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 1200,
                .enable_pacing = false,
            },
        }, .connect_timeout = .fromSeconds(3) },
    });
    defer pool.deinit();
    var receive_storage: [8 * 4096]u8 = undefined;
    var receive_events: [8]runtime.SharedHandshakeClientPool.Event = undefined;
    var no_events: [0]runtime.SharedHandshakeClientPool.Event = .{};
    try std.testing.expectError(
        error.BufferTooShort,
        pool.receiveManyOnce(
            &receive_storage,
            &no_events,
            .fromSeconds(1),
        ),
    );
    var too_many_events: [
        quic.runtime.max_receive_batch_messages + 1
    ]runtime.SharedHandshakeClientPool.Event = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        pool.receiveManyOnce(
            &receive_storage,
            &too_many_events,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectError(
        error.InvalidPoolOptions,
        pool.receiveManyOnce(
            &receive_storage,
            &receive_events,
            .zero,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        try pool.receiveManyOnce(
            &receive_storage,
            &receive_events,
            .fromMilliseconds(1),
        ),
    );
    const uri_a = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/a",
        .{server_a.address().ip4.port},
    );
    defer allocator.free(uri_a);
    const uri_b = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/b",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b);

    var lease_a = try pool.acquireUri(uri_a);
    var lease_a_active = true;
    defer if (lease_a_active) lease_a.discard();
    var lease_b = try pool.acquireUri(uri_b);
    var lease_b_active = true;
    defer if (lease_b_active) lease_b.discard();
    try std.testing.expectEqual(pool.address(), lease_a.client().address());
    try std.testing.expectEqual(pool.address(), lease_b.client().address());
    try std.testing.expect(!lease_a.client().owns_endpoint);
    try std.testing.expect(!lease_b.client().owns_endpoint);
    try std.testing.expect(lease_a.client().dispatcherBound());
    try std.testing.expect(lease_b.client().dispatcherBound());
    try std.testing.expectError(
        error.InvalidDispatcherState,
        lease_a.client().receiveProgress(),
    );
    try std.testing.expectError(
        error.InvalidDispatcherState,
        lease_a.client().request(.{
            .method = "GET",
            .path = "/blocking",
        }),
    );
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());

    const stream_a = try lease_a.tryStartRequest(.{
        .method = "POST",
        .path = "/a",
        .authority = "localhost",
    }, "upload-a".len);
    try lease_a.trySendRequestBodyParts(
        stream_a,
        &.{ "up", "load", "-", "a" },
        false,
    );
    try lease_a.tryFinishRequestTrailers(stream_a, &.{.{
        .name = "x-upload",
        .value = "complete",
    }});
    const stream_b = try lease_b.sendRequest(.{
        .method = "GET",
        .path = "/b",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 0), stream_a);
    try std.testing.expectEqual(@as(u62, 0), stream_b);
    const response_deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .clock = .awake, .raw = .fromSeconds(2) },
    );
    while (responses_sent.load(.acquire) != 2) {
        if (response_deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.Thread.yield() catch {};
    }

    var body_a: ["origin-a".len]u8 = undefined;
    var body_b: ["origin-b".len]u8 = undefined;
    var body_a_len: usize = 0;
    var body_b_len: usize = 0;
    var finished_a = false;
    var finished_b = false;
    var max_batch_count: usize = 0;
    while (!finished_a or !finished_b) {
        const count = try pool.receiveManyOnce(
            &receive_storage,
            &receive_events,
            .fromSeconds(2),
        );
        try std.testing.expect(count != 0);
        max_batch_count = @max(max_batch_count, count);
        @memset(&receive_storage, 0xaa);
        for (receive_events[0..count]) |*event| {
            defer event.deinit(allocator);
            switch (event.*) {
                .response => |*response| {
                    const lease = if (response.connection_handle ==
                        lease_a.connectionHandle())
                        &lease_a
                    else if (response.connection_handle ==
                        lease_b.connectionHandle())
                        &lease_b
                    else
                        return error.TestUnexpectedResult;
                    const output = if (lease == &lease_a)
                        body_a[body_a_len..]
                    else
                        body_b[body_b_len..];
                    const message = switch (response.response) {
                        .message => |*value| value,
                        .reset => return error.TestUnexpectedResult,
                    };
                    switch (message.value) {
                        .head => |head| {
                            if (head != .response) {
                                return error.TestUnexpectedResult;
                            }
                            try std.testing.expectEqual(
                                @as(u16, 200),
                                head.response.status,
                            );
                            try std.testing.expectEqualStrings(
                                if (lease == &lease_a)
                                    "origin-a"
                                else
                                    "origin-b",
                                headerValue(
                                    head.response.headers,
                                    "x-origin",
                                ) orelse return error.TestUnexpectedResult,
                            );
                        },
                        .data_available => {
                            const read = (try pool.readResponseDataOnce(
                                response.connection_handle,
                                message.stream_id,
                                output,
                            )) orelse 0;
                            if (lease == &lease_a)
                                body_a_len += read
                            else
                                body_b_len += read;
                        },
                        .finished => {
                            if (lease == &lease_a)
                                finished_a = true
                            else
                                finished_b = true;
                        },
                        .push_promise, .trailers => return error.TestUnexpectedResult,
                    }
                },
                .progress, .timer, .consumed => {},
                .push, .closed, .unrouted => return error.TestUnexpectedResult,
            }
        }
    }
    try std.testing.expect(max_batch_count > 1);
    try std.testing.expectEqualStrings("origin-a", body_a[0..body_a_len]);
    try std.testing.expectEqualStrings("origin-b", body_b[0..body_b_len]);

    const handle_a = lease_a.connectionHandle();
    lease_a.release();
    lease_a_active = false;
    lease_b.release();
    lease_b_active = false;
    var reused = try pool.acquireUri(uri_a);
    defer reused.discard();
    try std.testing.expect(reused.was_reused);
    try std.testing.expectEqual(handle_a, reused.connectionHandle());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);

    thread_a.join();
    joined_a = true;
    thread_b.join();
    joined_b = true;
    if (worker_a.err) |err| return err;
    if (worker_b.err) |err| return err;
}

fn headerValue(headers: anytype, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "HTTP/3 shared pool migrates from IPv4 to IPv6 on zio" {
    try testSharedPoolCrossFamilyMigration(.ipv6);
}

test "HTTP/3 shared pool migrates from IPv6 to IPv4 on zio" {
    try testSharedPoolCrossFamilyMigration(.ipv4);
}

fn testSharedPoolCrossFamilyMigration(
    comptime target_family: quic.one_rtt.PreferredAddressFamily,
) !void {
    const allocator = std.testing.allocator;
    var backend = try netz_runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };

    var preferred_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        switch (target_family) {
            .ipv4 => .{ .ip4 = .loopback(0) },
            .ipv6 => .{ .ip6 = .loopback(0) },
        },
        limits.quic,
    );
    defer preferred_endpoint.deinit();
    const preferred_cid = "pool-preferred-cid";
    var transport = quic.practical_transport_parameters;
    var preferred_address = quic.PreferredAddress{
        .connection_id = preferred_cid,
        .stateless_reset_token = [_]u8{0x6b} **
            quic.stateless_reset.token_len,
    };
    switch (target_family) {
        .ipv4 => {
            preferred_address.ipv4_address =
                preferred_endpoint.address().ip4.bytes;
            preferred_address.ipv4_port =
                preferred_endpoint.address().ip4.port;
        },
        .ipv6 => {
            preferred_address.ipv6_address =
                preferred_endpoint.address().ip6.bytes;
            preferred_address.ipv6_port =
                preferred_endpoint.address().ip6.port;
        },
    }
    transport.preferred_address = preferred_address;
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        switch (target_family) {
            .ipv4 => .{ .ip6 = .loopback(0) },
            .ipv6 => .{ .ip4 = .loopback(0) },
        },
        limits,
        .{ .handshake = .{
            .local_connection_id = "pool-migration-srv",
            .local_transport_parameters = transport,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer server.deinit();

    const ServerWorker = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        server: *runtime.HandshakeServer,
        preferred_endpoint: *quic.runtime.Endpoint,
        responses_sent: usize = 0,
        request_on_preferred_path: bool = false,
        preferred_cid_routed: bool = false,
        pending: ?quic.runtime.OwnedBytes = null,
        result: anyerror!void = {},

        fn run(self: *@This()) void {
            self.result = self.runFallible();
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer session.deinit();
            try session.established.connection.registerLocalPreferredEndpoint(
                self.preferred_endpoint,
            );
            try session.ensureSettingsSent();

            var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
                self.allocator,
                &self.server.quic_server.endpoint,
            );
            defer dispatcher.deinit();
            const handle: quic.endpoint_dispatcher.ConnectionHandle = 1;
            try dispatcher.registerConnection(
                handle,
                &session.established.connection,
            );
            try session.bindDispatcher();

            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(5),
                .clock = .awake,
            });
            while (self.responses_sent != 2) {
                while (try session.pollRequestEventOnce()) |event_value| {
                    var event = event_value;
                    defer event.deinit(self.allocator);
                    if (event != .message) return error.TestUnexpectedResult;
                    switch (event.message.value) {
                        .head => |head| {
                            if (head != .request) {
                                return error.TestUnexpectedResult;
                            }
                            if (!std.mem.eql(
                                u8,
                                head.request.path,
                                if (self.responses_sent == 0)
                                    "/migrated"
                                else
                                    "/reused",
                            )) return error.TestUnexpectedResult;
                            self.request_on_preferred_path =
                                self.request_on_preferred_path or
                                session.established.connection.sendEndpoint() ==
                                    self.preferred_endpoint;
                            try session.trySendResponseLiteral(
                                event.message.stream_id,
                                .{
                                    .status = 200,
                                    .body = if (self.responses_sent == 0)
                                        "migrated"
                                    else
                                        "reused",
                                    .request_method = head.request.method,
                                },
                            );
                            self.responses_sent += 1;
                            try dispatcher.refreshConnectionTimer(handle);
                        },
                        .finished => {},
                        else => return error.TestUnexpectedResult,
                    }
                }
                if (self.responses_sent == 2) break;

                var routed = try self.receiveTransport(&dispatcher, deadline);
                defer routed.deinit(self.allocator);
                switch (routed) {
                    .packet => |*packet| {
                        if (packet.connection_id_sequence == 1) {
                            self.preferred_cid_routed = true;
                        }
                        try session.processRequestPacket(&packet.packet);
                        _ = try session.established.connection
                            .sendPendingPathResponses();
                        try dispatcher.refreshConnectionTimer(handle);
                    },
                    .timer, .consumed, .discarded_long_header => {},
                    .pending_handshake, .new_initial, .unrouted => return error.TestUnexpectedResult,
                }
            }
        }

        fn receiveTransport(
            self: *@This(),
            dispatcher: *quic.endpoint_dispatcher.Dispatcher,
            deadline: std.Io.Clock.Timestamp,
        ) !quic.endpoint_dispatcher.Event {
            while (true) {
                if (try dispatcher.poll()) |event| return event;
                var datagram = try self.receiveEither(
                    .{ .deadline = earlierDeadline(
                        self.io,
                        deadline,
                        dispatcher.nextTimerDeadline(),
                    ) },
                );
                const received_on = datagram.received_on orelse
                    &self.server.quic_server.endpoint;
                if (received_on == self.preferred_endpoint and
                    datagram.bytes.len != 0 and
                    (datagram.bytes[0] & 0x80) != 0)
                {
                    datagram.deinit(received_on.allocator);
                    continue;
                }
                return dispatcher.dispatch(datagram);
            }
        }

        fn receiveEither(
            self: *@This(),
            timeout: std.Io.Timeout,
        ) !quic.runtime.OwnedBytes {
            if (self.pending) |datagram| {
                self.pending = null;
                return datagram;
            }
            const ReceiveResult = quic.runtime.ReceiveTimeoutError!quic.runtime.OwnedBytes;
            const Wake = union(enum) {
                primary: ReceiveResult,
                preferred: ReceiveResult,
            };
            var wake_storage: [2]Wake = undefined;
            var select: std.Io.Select(Wake) = .init(self.io, &wake_storage);
            defer while (select.cancel()) |wake| switch (wake) {
                .primary, .preferred => |result| if (result) |datagram| {
                    if (self.pending == null) {
                        self.pending = datagram;
                    } else {
                        var extra = datagram;
                        extra.deinit(
                            (extra.received_on orelse
                                &self.server.quic_server.endpoint).allocator,
                        );
                    }
                } else |_| {},
            };
            select.async(
                .primary,
                quic.runtime.Endpoint.receiveBytesTimeout,
                .{ &self.server.quic_server.endpoint, timeout },
            );
            select.async(
                .preferred,
                quic.runtime.Endpoint.receiveBytesTimeout,
                .{ self.preferred_endpoint, timeout },
            );
            return switch (try select.await()) {
                .primary => |result| try result,
                .preferred => |result| try result,
            };
        }

        fn earlierDeadline(
            event_io: std.Io,
            caller: std.Io.Clock.Timestamp,
            scheduled: ?quic.endpoint_timers.EndpointTimerDeadline,
        ) std.Io.Clock.Timestamp {
            const timer = scheduled orelse return caller;
            const timer_deadline = std.Io.Clock.Timestamp{
                .clock = .awake,
                .raw = .fromNanoseconds(
                    std.math.cast(i96, timer.timer.deadline_ns) orelse
                        std.math.maxInt(i96),
                ),
            };
            return if (timer_deadline.durationFromNow(event_io).raw.nanoseconds <
                caller.durationFromNow(event_io).raw.nanoseconds)
                timer_deadline
            else
                caller;
        }
    };
    var worker = ServerWorker{
        .allocator = allocator,
        .io = io,
        .server = &server,
        .preferred_endpoint = &preferred_endpoint,
    };
    var server_task = io.async(ServerWorker.run, .{&worker});
    var server_joined = false;
    defer if (!server_joined) server_task.cancel(io);
    defer if (worker.pending) |*datagram| {
        datagram.deinit(
            (datagram.received_on orelse &server.quic_server.endpoint).allocator,
        );
    };

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = switch (target_family) {
            .ipv4 => .{ .ip6 = .loopback(0) },
            .ipv6 => .{ .ip4 = .loopback(0) },
        },
        .migration_local_address = switch (target_family) {
            .ipv4 => .{ .ip4 = .loopback(0) },
            .ipv6 => .{ .ip6 = .loopback(0) },
        },
        .limits = limits,
        .max_connections = 1,
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 1200,
                .enable_pacing = false,
            },
        }, .connect_timeout = .fromSeconds(3) },
        .idle = .{
            .max_idle_total = 1,
            .max_idle_per_origin = 1,
        },
    });
    defer pool.deinit();
    try std.testing.expect(switch (target_family) {
        .ipv4 => pool.migrationAddress().? == .ip4,
        .ipv6 => pool.migrationAddress().? == .ip6,
    });

    const uri = switch (target_family) {
        .ipv4 => try std.fmt.allocPrint(
            allocator,
            "https://[::1]:{d}/",
            .{server.address().ip6.port},
        ),
        .ipv6 => try std.fmt.allocPrint(
            allocator,
            "https://127.0.0.1:{d}/",
            .{server.address().ip4.port},
        ),
    };
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    var lease_active = true;
    defer if (lease_active) lease.discard();
    const handle = lease.connectionHandle();
    const preferred = lease.client().established.connection
        .peerPreferredAddress() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        preferred_endpoint.address(),
        switch (target_family) {
            .ipv4 => quic.one_rtt.Connection
                .preferredAddressIp4(preferred).?,
            .ipv6 => quic.one_rtt.Connection
                .preferredAddressIp6(preferred).?,
        },
    );
    const challenge = [_]u8{ 0x6c, 1, 2, 3, 4, 5, 6, 7 };
    try lease.beginPreferredAddressMigration(challenge, target_family);
    const migration_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
    while (!lease.client().established.connection.peerAddressValidated()) {
        var event = try pool.receiveWithDeadline(migration_deadline);
        defer event.deinit(allocator);
        if (event == .unrouted or event == .closed) {
            return error.TestUnexpectedResult;
        }
    }
    try std.testing.expectEqual(
        preferred_endpoint.address(),
        lease.client().established.connection.peerAddress(),
    );
    try std.testing.expectEqual(
        pool.migrationAddress().?,
        lease.client().established.connection.sendEndpoint().address(),
    );

    try expectPoolResponse(&pool, &lease, "/migrated", "migrated");
    lease.release();
    lease_active = false;
    var reused = try pool.acquireUri(uri);
    defer reused.discard();
    try std.testing.expect(reused.was_reused);
    try std.testing.expectEqual(handle, reused.connectionHandle());
    try expectPoolResponse(&pool, &reused, "/reused", "reused");

    server_task.await(io);
    server_joined = true;
    try worker.result;
    try std.testing.expectEqual(@as(usize, 2), worker.responses_sent);
    try std.testing.expect(worker.request_on_preferred_path);
    try std.testing.expect(worker.preferred_cid_routed);
}

fn expectPoolResponse(
    pool: anytype,
    lease: anytype,
    path: []const u8,
    expected_body: []const u8,
) !void {
    const allocator = std.testing.allocator;
    const stream_id = try lease.sendRequest(.{
        .method = "GET",
        .path = path,
        .authority = "localhost",
    });
    var body: [32]u8 = undefined;
    var body_len: usize = 0;
    var storage: [4 * 4096]u8 = undefined;
    var events: [4]runtime.SharedHandshakeClientPool.Event = undefined;
    var finished = false;
    while (!finished) {
        const count = try pool.receiveManyOnce(
            &storage,
            &events,
            .fromSeconds(3),
        );
        try std.testing.expect(count != 0);
        for (events[0..count]) |*event| {
            defer event.deinit(allocator);
            switch (event.*) {
                .response => |*response| {
                    if (response.connection_handle != lease.connectionHandle()) {
                        return error.TestUnexpectedResult;
                    }
                    const message = switch (response.response) {
                        .message => |*value| value,
                        .reset => return error.TestUnexpectedResult,
                    };
                    if (message.stream_id != stream_id) {
                        return error.TestUnexpectedResult;
                    }
                    switch (message.value) {
                        .head => |head| {
                            if (head != .response or head.response.status != 200) {
                                return error.TestUnexpectedResult;
                            }
                        },
                        .data_available => {
                            const read = (try pool.readResponseDataOnce(
                                response.connection_handle,
                                stream_id,
                                body[body_len..],
                            )) orelse 0;
                            body_len += read;
                        },
                        .finished => finished = true,
                        .push_promise, .trailers => return error.TestUnexpectedResult,
                    }
                },
                .progress, .timer, .consumed => {},
                .push, .closed, .unrouted => return error.TestUnexpectedResult,
            }
        }
    }
    try std.testing.expectEqualStrings(expected_body, body[0..body_len]);
}

test "HTTP/3 shared pool validates migration endpoint options" {
    const allocator = std.testing.allocator;
    var backend = try netz_runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    const key_pair = try tls_testing.serverKeyPair();

    try std.testing.expectError(
        error.InvalidPoolOptions,
        runtime.SharedHandshakeClientPool.init(allocator, io, .{
            .local_address = .{ .ip4 = .loopback(0) },
            .migration_local_address = .{ .ip4 = .loopback(0) },
            .client = .{ .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
                },
            } },
        }),
    );

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
            },
        } },
    });
    defer pool.deinit();
    try std.testing.expectEqual(
        @as(?std.Io.net.IpAddress, null),
        pool.migrationAddress(),
    );
}

test "HTTP/3 shared pool restores the original path after migration timeout on zio" {
    const allocator = std.testing.allocator;
    var backend = try netz_runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var silent_preferred = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        limits.quic,
    );
    defer silent_preferred.deinit();
    var transport = quic.practical_transport_parameters;
    transport.preferred_address = .{
        .ipv6_address = silent_preferred.address().ip6.bytes,
        .ipv6_port = silent_preferred.address().ip6.port,
        .connection_id = "pool-timeout-cid",
        .stateless_reset_token = [_]u8{0x7b} **
            quic.stateless_reset.token_len,
    };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "pool-timeout-srv",
            .local_transport_parameters = transport,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer server.deinit();

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        result: anyerror!void = {},

        fn run(self: *@This()) void {
            self.result = self.runFallible();
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer session.deinit();
            try session.ensureSettingsSent();
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(10),
            );
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/fallback",
                request.request.path,
            );
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .body = "fallback",
                .request_method = request.request.method,
            });
        }
    };
    var worker = ServerWorker{ .server = &server };
    var server_task = io.async(ServerWorker.run, .{&worker});
    var server_joined = false;
    defer if (!server_joined) server_task.cancel(io);

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .migration_local_address = .{ .ip6 = .loopback(0) },
        .limits = limits,
        .max_connections = 1,
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 1200,
                .enable_pacing = false,
            },
        }, .connect_timeout = .fromSeconds(3) },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    defer lease.discard();
    const original_peer = lease.client().established.connection.peerAddress();
    const original_endpoint = lease.client().established.connection
        .sendEndpoint();
    const sent_before = lease.client().established.connection.stats()
        .packets_sent;
    try lease.beginPreferredAddressMigration(
        [_]u8{ 0x7c, 1, 2, 3, 4, 5, 6, 7 },
        .ipv6,
    );
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(8),
        .clock = .awake,
    });
    while (!lease.client().established.connection.peerAddressValidated()) {
        var event = try pool.receiveWithDeadline(deadline);
        defer event.deinit(allocator);
        if (event == .unrouted or event == .closed) {
            return error.TestUnexpectedResult;
        }
    }
    try std.testing.expectEqual(
        original_peer,
        lease.client().established.connection.peerAddress(),
    );
    try std.testing.expectEqual(
        original_endpoint,
        lease.client().established.connection.sendEndpoint(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        lease.client().established.connection.failedPathValidationCount(),
    );
    try std.testing.expect(
        lease.client().established.connection.stats().packets_sent >=
            sent_before + quic.path_validation
                .default_max_challenge_transmissions,
    );
    try expectPoolResponse(&pool, &lease, "/fallback", "fallback");

    server_task.await(io);
    server_joined = true;
    try worker.result;
}

test "HTTP/3 shared pool releases failed handshake capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var silent = try @import("../../quic/mod.zig").runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .client = .{
            .connect_timeout = .fromMilliseconds(20),
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .handshake_recovery = .{
                    .initial_pto_ms = 100,
                    .max_pto_ms = 100,
                    .max_retries = 1,
                },
            },
        },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/timeout",
        .{silent.address().ip4.port},
    );
    defer allocator.free(uri);

    try std.testing.expectError(error.HandshakeTimeout, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
}

test "HTTP/3 shared pool batches two streaming uploads" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "shared-batch-server",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Worker = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.acceptWithTimeout(
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var saw_first = false;
            var saw_second = false;
            for (0..2) |_| {
                var request = session.receiveRequestWithTimeout(
                    .fromSeconds(2),
                ) catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                if (std.mem.eql(u8, request.request.path, "/first")) {
                    if (!std.mem.eql(u8, request.request.body, "one")) {
                        self.err = error.TestUnexpectedResult;
                        return;
                    }
                    saw_first = true;
                } else if (std.mem.eql(
                    u8,
                    request.request.path,
                    "/second",
                )) {
                    if (!std.mem.eql(u8, request.request.body, "two")) {
                        self.err = error.TestUnexpectedResult;
                        return;
                    }
                    saw_second = true;
                } else {
                    self.err = error.TestUnexpectedResult;
                    return;
                }
            }
            if (!saw_first or !saw_second) {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = limits,
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 1200,
                .enable_pacing = false,
            },
        }, .connect_timeout = .fromSeconds(3) },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/batch",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    var lease_active = true;
    defer if (lease_active) lease.discard();

    const first = try lease.tryStartRequest(.{
        .method = "POST",
        .path = "/first",
        .authority = "localhost",
    }, 3);
    const second = try lease.tryStartRequest(.{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
    }, 3);
    const progress = try lease.trySendRequestBodyBatch(&.{
        .{ .stream_id = first, .data = "one", .fin = true },
        .{ .stream_id = second, .data = "two", .fin = true },
    });
    try std.testing.expectEqual(@as(usize, 2), progress.sent_count);
    try std.testing.expect(progress.send_error == null);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    lease.discard();
    lease_active = false;
}

test "HTTP/3 shared pool enforces leased capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{ .handshake = .{
            .local_connection_id = "shared-cap-server",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Worker = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.acceptWithTimeout(
                .fromSeconds(3),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequestWithTimeout(
                .fromSeconds(2),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = .{ .quic = .{ .max_datagram_size = 4096 } },
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        } },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/capacity",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var lease = try pool.acquireUri(uri);
    var lease_active = true;
    defer if (lease_active) lease.discard();
    const stream_id = try lease.sendRequest(.{
        .method = "GET",
        .path = "/capacity",
        .authority = "localhost",
    });
    try lease.tryCancelRequest(
        stream_id,
        @import("../mod.zig").ApplicationErrorCode.request_cancelled,
    );
    try std.testing.expectError(error.ConnectionLimitReached, pool.acquireUri(
        "https://127.0.0.1:443/other",
    ));
    lease.discard();
    lease.discard();
    lease.release();
    lease_active = false;
    try std.testing.expect(!lease.active);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.routeCount());

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

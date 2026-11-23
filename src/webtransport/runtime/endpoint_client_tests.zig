const std = @import("std");
const runtime = @import("../runtime.zig");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");

const net = std.Io.net;

test "WebTransport endpoint client exposes multi-Session core API" {
    try std.testing.expect(@hasDecl(runtime, "EndpointClient"));
    try std.testing.expect(@hasDecl(runtime, "EndpointClientError"));
    try std.testing.expect(@hasDecl(runtime, "StableConnectionId"));
    try std.testing.expect(@hasDecl(runtime.EndpointClient, "stableId"));
    try std.testing.expect(@hasDecl(runtime.EndpointClient, "openSession"));
    try std.testing.expect(@hasDecl(
        runtime.EndpointClient,
        "openSessionAttempt",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointClient,
        "removeSession",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointClientSession,
        "openBidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointClientSession,
        "sendDatagram",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointClientSession,
        "stableId",
    ));
}

test "WebTransport endpoint client rejects an empty local Session budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.InvalidSessionState,
        runtime.EndpointClient.connect(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            .{
                .max_sessions = 0,
                .h3 = http3.runtime.HandshakeClientOptions{
                    .handshake = .{
                        .original_destination_connection_id = "wt-client-origin",
                        .local_connection_id = "wt-client-local",
                        .server_name = "localhost",
                    },
                },
            },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        runtime.EndpointClient.connectWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            .{
                .h3 = http3.runtime.HandshakeClientOptions{
                    .handshake = .{
                        .original_destination_connection_id = "wt-client-origin",
                        .local_connection_id = "wt-client-local",
                        .server_name = "localhost",
                    },
                },
            },
            .zero,
        ),
    );
}

test "WebTransport endpoint client rotates ready Sessions fairly" {
    const allocator = std.testing.allocator;
    var client = runtime.EndpointClient{
        .allocator = allocator,
        .h3 = undefined,
        .max_sessions = 3,
    };
    defer client.sessions.deinit(allocator);
    var storage: [3]runtime.EndpointClientSession = undefined;
    const ids = [_]u62{ 0, 4, 8 };
    for (ids, 0..) |session_id, index| {
        try client.sessions.put(allocator, session_id, &storage[index]);
    }

    var order: [ids.len]u62 = undefined;
    for (&order) |*session_id| {
        session_id.* = (try runtime.EndpointClient.testing
            .pollReadySessionId(&client, &ids)) orelse
            return error.TestUnexpectedResult;
    }
    for (order, 0..) |session_id, index| {
        for (order[0..index]) |earlier| {
            try std.testing.expect(session_id != earlier);
        }
    }
    try std.testing.expectEqual(
        order[0],
        (try runtime.EndpointClient.testing.pollReadySessionId(
            &client,
            &ids,
        )).?,
    );

    const stale = order[0];
    try std.testing.expect(client.sessions.remove(stale));
    client.last_ready_session_id = stale;
    const after_removal = (try runtime.EndpointClient.testing
        .pollReadySessionId(&client, &ids)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(after_removal != stale);
}

test "WebTransport endpoint client multiplexes two authenticated Sessions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const limits = runtime.Limits{
        .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .max_session_streams = 8,
        .max_sessions_per_connection = 2,
        .require_session_flow_control = true,
        .application_protocols = .{ .values = &.{ "p1", "p2" } },
    };
    var server = try runtime.HandshakeServer.bindForEndpoint(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "wt-ec-server",
            .random = [_]u8{0xa1} ** 32,
            .x25519_secret_key = [_]u8{0xa2} ** 32,
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
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
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var client = try runtime.EndpointClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{
                    .limits = self.limits,
                    .max_sessions = 2,
                    .require_session_flow_control = true,
                    .h3 = .{
                        .handshake = .{
                            .original_destination_connection_id = "wt-ec-origin",
                            .local_connection_id = "wt-ec-client",
                            .server_name = "localhost",
                            .random = [_]u8{0xa3} ** 32,
                            .x25519_secret_key = [_]u8{0xa4} ** 32,
                            .handshake_recovery = .{
                                .initial_pto_ms = 20,
                                .max_pto_ms = 40,
                                .max_duration_ms = 2_000,
                            },
                        },
                    },
                },
            );
            defer client.deinit();
            try std.testing.expect(client.require_session_flow_control);
            try std.testing.expectEqual(self.address, client.remoteAddress());
            try std.testing.expect(client.remoteAddressValidated());
            try std.testing.expectEqualStrings("h3", client.negotiatedAlpn());
            var exporter: [32]u8 = undefined;
            try client.exportKeyingMaterial(
                "EXPORTER-netz-endpoint-client",
                "multi-session",
                &exporter,
            );
            try std.testing.expectError(
                error.Timeout,
                client.openSessionAttemptWithTimeout(.{
                    .authority = "localhost",
                    .path = "/timeout",
                }, .zero),
            );
            var rejected = try client.openSessionAttempt(.{
                .authority = "localhost",
                .path = "/client-rejected",
            });
            defer rejected.deinit(&client);
            switch (rejected) {
                .accepted => return error.TestUnexpectedResult,
                .rejected => |value| {
                    try std.testing.expectEqual(@as(u16, 404), value.status());
                    try std.testing.expectEqualStrings(
                        "endpoint-client",
                        value.header("x-admission").?,
                    );
                    try std.testing.expectEqual(@as(usize, 0), value.body.len);
                },
            }
            try std.testing.expectEqual(@as(usize, 0), client.sessionCount());
            const first = try client.openSession(.{
                .authority = "localhost",
                .path = "/client-first",
                .application_protocols = .{ .values = &.{"p2"}, .required = true },
                .max_streams = 8,
            });
            const second = try client.openSession(.{
                .authority = "localhost",
                .path = "/client-second",
                .application_protocols = .{ .values = &.{"p1"}, .required = true },
                .max_streams = 8,
            });
            try std.testing.expect(first.applicationProtocol().?.eql("p2"));
            try std.testing.expect(second.applicationProtocol().?.eql("p1"));
            const stable_id = client.stableId();
            try std.testing.expect(stable_id != 0);
            try std.testing.expectEqual(
                stable_id,
                try first.stableId(&client),
            );
            try std.testing.expectEqual(
                stable_id,
                try second.stableId(&client),
            );
            try std.testing.expect(client.rttNanos() != null);
            try std.testing.expectEqual(@as(u62, 4), first.id().value);
            try std.testing.expectEqual(@as(u62, 8), second.id().value);
            try std.testing.expectEqual(@as(usize, 2), client.sessionCount());
            try std.testing.expectError(
                error.SessionLimitExceeded,
                client.openSession(.{
                    .authority = "localhost",
                    .path = "/client-excess",
                }),
            );

            try first.sendDatagram(&client, "first");
            try second.sendDatagram(&client, "second");
            var datagrams_seen = [_]bool{ false, false };
            var any_buffer: [32]u8 = undefined;
            for (0..2) |_| {
                var ready = try client.receiveAnyWithTimeout(
                    &any_buffer,
                    .fromSeconds(3),
                );
                defer ready.deinit(allocator);
                if (ready.event != .datagram) {
                    return error.TestUnexpectedResult;
                }
                const index: usize = if (ready.session_id.value ==
                    first.id().value) 0 else if (ready.session_id.value ==
                    second.id().value) 1 else return error.TestUnexpectedResult;
                try std.testing.expect(!datagrams_seen[index]);
                try std.testing.expectEqualStrings(
                    if (index == 0) "echo-first" else "echo-second",
                    ready.event.datagram.payload,
                );
                datagrams_seen[index] = true;
            }

            const first_stream = try first.openBidirectionalStream(&client);
            const second_stream = try second.openBidirectionalStream(&client);
            try first.sendStreamSlices(
                &client,
                first_stream,
                &.{ "stream-", "first" },
                true,
            );
            try second.sendStream(
                &client,
                second_stream,
                "stream-second",
                true,
            );
            var stream_bytes = [_]usize{ 0, 0 };
            var streams_finished = [_]bool{ false, false };
            while (!streams_finished[0] or !streams_finished[1]) {
                var ready = try client.receiveAnyWithTimeout(
                    &any_buffer,
                    .fromSeconds(3),
                );
                defer ready.deinit(allocator);
                if (ready.event != .stream or
                    ready.event.stream != .data)
                {
                    return error.TestUnexpectedResult;
                }
                const index: usize = if (ready.session_id.value ==
                    first.id().value) 0 else if (ready.session_id.value ==
                    second.id().value) 1 else return error.TestUnexpectedResult;
                const expected = if (index == 0)
                    "echo-stream-first"
                else
                    "echo-stream-second";
                const stream = ready.event.stream.data;
                try std.testing.expectEqualStrings(
                    expected[stream_bytes[index]..][0..stream.bytes],
                    any_buffer[0..stream.bytes],
                );
                stream_bytes[index] += stream.bytes;
                if (stream.fin) {
                    try std.testing.expectEqual(
                        expected.len,
                        stream_bytes[index],
                    );
                    streams_finished[index] = true;
                }
            }
            try first.close(&client, 81, "first");
            try second.close(&client, 82, "second");
            try self.done.wait(self.io);
            const removal_deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            });
            try std.testing.expect(try client.removeSessionWithDeadline(first.id(), removal_deadline));
            try std.testing.expect(try client.removeSessionWithDeadline(second.id(), removal_deadline));
            try std.testing.expectEqual(@as(usize, 0), client.sessionCount());
        }
    };

    var shared = Shared{
        .io = io,
        .address = server.address(),
        .limits = limits.http3,
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
    var accepted: usize = 0;
    var datagrams: usize = 0;
    var streams: usize = 0;
    var closes: usize = 0;
    var first_stream_bytes: usize = 0;
    var second_stream_bytes: usize = 0;
    var stream_buffer: [32]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(8),
    });
    while (accepted != 2 or datagrams != 2 or streams != 2 or closes != 2) {
        var event = endpoint.receiveWithDeadline(
            &versions,
            deadline,
            &stream_buffer,
        ) catch |err| {
            if (shared.err) |client_err| return client_err;
            return err;
        };
        defer event.deinit(allocator);
        switch (event) {
            .connected => {},
            .closed => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
            .session_request => |handle| {
                const pending = endpoint.pendingSession(handle) orelse
                    return error.TestUnexpectedResult;
                if (std.mem.eql(
                    u8,
                    pending.path(),
                    "/client-rejected",
                )) {
                    try endpoint.reject(handle, 404, &.{.{
                        .name = "x-admission",
                        .value = "endpoint-client",
                    }});
                    continue;
                }
                try std.testing.expect(
                    std.mem.eql(u8, pending.path(), "/client-first") or
                        std.mem.eql(u8, pending.path(), "/client-second"),
                );
                const expected_protocol = if (std.mem.eql(u8, pending.path(), "/client-first")) "p2" else "p1";
                const accepted_session = try endpoint.accept(handle);
                try std.testing.expect(accepted_session.applicationProtocol().?.eql(expected_protocol));
                accepted += 1;
            },
            .session_event => |*value| {
                const session = endpoint.sessionById(
                    value.handle,
                    value.session_id,
                ) orelse return error.TestUnexpectedResult;
                const first = std.mem.eql(
                    u8,
                    session.request.request.path,
                    "/client-first",
                );
                switch (value.event) {
                    .datagram => |datagram| {
                        try std.testing.expectEqualStrings(
                            if (first) "first" else "second",
                            datagram.datagram.payload,
                        );
                        try session.trySendDatagramWithTimeout(
                            if (first) "echo-first" else "echo-second",
                            .fromSeconds(1),
                        );
                        datagrams += 1;
                    },
                    .stream => |stream| {
                        if (stream != .data) {
                            return error.TestUnexpectedResult;
                        }
                        const expected = if (first)
                            "stream-first"
                        else
                            "stream-second";
                        const received = if (first)
                            &first_stream_bytes
                        else
                            &second_stream_bytes;
                        try std.testing.expectEqualStrings(
                            expected[received.*..][0..stream.data.bytes],
                            stream_buffer[0..stream.data.bytes],
                        );
                        received.* += stream.data.bytes;
                        if (stream.data.fin) {
                            try std.testing.expectEqual(
                                expected.len,
                                received.*,
                            );
                            try session.sendStream(
                                stream.data.stream_id,
                                if (first)
                                    "echo-stream-first"
                                else
                                    "echo-stream-second",
                                true,
                            );
                            streams += 1;
                        }
                    },
                    .session => |session_event| {
                        if (session_event != .closed) {
                            return error.TestUnexpectedResult;
                        }
                        try std.testing.expectEqual(
                            @as(u32, if (first) 81 else 82),
                            session_event.closed.code,
                        );
                        closes += 1;
                    },
                }
            },
            .unrouted => return error.TestUnexpectedResult,
        }
    }
    shared.done.set(io);
    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

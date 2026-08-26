const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

const net = std.Io.net;

test "HTTP/3 endpoint server owns concurrent handshakes and requests" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = "server-template",
            .random = [_]u8{0xd1} ** 32,
            .x25519_secret_key = [_]u8{0xd2} ** 32,
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer server.deinit();
    var endpoint_server = try runtime.EndpointServer.init(
        &server,
        .{ .max_pending_handshakes = 2, .inbox_capacity = 8 },
    );
    var endpoint_server_owned = true;
    defer if (endpoint_server_owned) endpoint_server.deinit();

    const ClientTask = struct {
        io: std.Io,
        address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        random: [32]u8,
        secret: [32]u8,
        client: ?runtime.HandshakeClient = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            self.client = try runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{ .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 16,
                } },
                .{ .handshake = .{
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
                } },
            );
        }
    };
    var clients = [_]ClientTask{
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "endpoint-one",
            .local_cid = "client-one",
            .random = [_]u8{0xd3} ** 32,
            .secret = [_]u8{0xd4} ** 32,
        },
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "endpoint-two",
            .local_cid = "client-two",
            .random = [_]u8{0xd5} ** 32,
            .secret = [_]u8{0xd6} ** 32,
        },
    };
    const thread_a = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const thread_b = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        if (endpoint_server_owned) {
            endpoint_server.deinit();
            endpoint_server_owned = false;
        }
        thread_a.join();
        thread_b.join();
        for (&clients) |*client| {
            if (client.client) |*value| value.deinit();
        }
    };

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var connected: usize = 0;
    while (connected < clients.len) {
        var event = try endpoint_server.receive(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
        );
        defer event.deinit(allocator);
        switch (event) {
            .connected => connected += 1,
            .handshake_failed => |failure| return failure.err,
            .request, .unrouted => return error.TestUnexpectedResult,
        }
    }

    thread_a.join();
    thread_b.join();
    joined = true;
    for (&clients) |*client| {
        if (client.err) |err| return err;
        var value = client.client orelse return error.TestUnexpectedResult;
        defer value.deinit();
        try std.testing.expectEqualStrings("h3", value.negotiatedAlpn());
        client.client = null;
    }
    try std.testing.expectEqual(@as(usize, 2), endpoint_server.connectionCount());
}

test "HTTP/3 endpoint total connection limit releases on removal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "capacity-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 2,
        .max_connections = 1,
        .inbox_capacity = 2,
    });
    defer endpoint.deinit();

    var connection = try quic.one_rtt.Connection.init(
        &server.quic_server.endpoint,
        .{
            .peer = .{ .ip4 = .loopback(9001) },
            .receive_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xc1} ** quic.protection.secret_len,
            ),
            .send_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xc2} ** quic.protection.secret_len,
            ),
            .local_connection_id = "capacity-active",
            .peer_connection_id = "capacity-peer",
        },
    );
    defer connection.deinit();
    try endpoint.dispatcher.registerConnection(99, &connection);

    const bytes = try allocator.dupe(u8, "capacity-initial");
    var initial = quic.endpoint_dispatcher.Event{ .new_initial = .{
        .datagram = .{
            .from = .{ .ip4 = .loopback(9002) },
            .bytes = bytes,
        },
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = bytes[0..8],
        .source_connection_id = bytes[8..],
        .first_packet_len = bytes.len,
    } };
    defer initial.deinit(allocator);
    try std.testing.expectError(
        error.PendingHandshakeLimitReached,
        endpoint.handshakes.admit(&initial),
    );
    try std.testing.expect(initial == .new_initial);
    try std.testing.expect(try endpoint.dispatcher.unregisterConnection(99));
    // The same Initial can enter the bounded inbox after a live slot is freed.
    _ = try endpoint.handshakes.admit(&initial);
    try std.testing.expect(initial == .consumed);
}

test "HTTP/3 endpoint transport loop observes shutdown while idle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "endpoint-idle" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    const Context = struct {
        calls: usize = 0,
        fn handle(
            self: *@This(),
            _: *runtime.EndpointServer,
            _: *runtime.EndpointTransportEvent,
        ) !void {
            self.calls += 1;
        }
    };
    const Shared = struct {
        endpoint: *runtime.EndpointServer,
        shutdown: *std.Io.Event,
        context: Context = .{},
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.endpoint.serveTransportUntil(
                Context,
                &self.context,
                Context.handle,
                &.{quic.Version.version_1.wireValue()},
                .{ .clock = .awake, .raw = .fromMilliseconds(2) },
                self.shutdown,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shutdown: std.Io.Event = .unset;
    var shared = Shared{ .endpoint = &endpoint, .shutdown = &shutdown };
    const started = std.Io.Clock.awake.now(io);
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    shutdown.set(io);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            std.time.ns_per_s,
    );
}

const std = @import("std");
const netz = @import("netz");
const counting_allocator = @import("counting_allocator.zig");

const quic = netz.quic;
const iterations = 64;
const timeout = std.Io.Duration.fromSeconds(3);
const versions = [_]u32{
    quic.Version.version_1.wireValue(),
    quic.Version.version_2.wireValue(),
};

pub const Summary = struct {
    connections: usize = 0,
    stream_round_trips: usize = 0,
    version_2_connections: usize = 0,
    aes_256_connections: usize = 0,
    retained_live_bytes: usize = 0,
    peak_live_bytes: usize = 0,
};

pub fn run() !Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var telemetry = counting_allocator.Allocator.init(allocator);
    const endpoint_allocator = telemetry.allocator();
    var endpoint = try quic.runtime.Endpoint.bind(
        endpoint_allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    var endpoint_owned = true;
    defer if (endpoint_owned) endpoint.deinit();
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try quic.endpoint_server.Server.init(
        endpoint_allocator,
        &endpoint,
        .{
            .local_connection_id = &.{},
            .alpn_protocol = "netz-endpoint-soak",
            .available_versions = &.{ .version_1, .version_2 },
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
            .key_exchange_groups = &.{.x25519},
            .cipher_suites = &.{
                .aes_128_gcm_sha256,
                .aes_256_gcm_sha384,
            },
            .identity = .{
                .certificate_chain = &.{&public_key},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .local_transport_parameters = transportParameters(),
            .initial_one_rtt_config = oneRttConfig(),
            .handshake_recovery = recovery(),
        },
        .{
            .max_pending_handshakes = 1,
            .max_connections = 1,
            .inbox_capacity = 8,
            .handshake_timeout_ms = 2_000,
            .automatic_connection_id_replenishment = false,
        },
    );
    var server_owned = true;
    defer if (server_owned) server.deinit();

    var summary = Summary{};
    var retained_baseline: ?usize = null;
    for (0..iterations) |iteration| {
        var client = ClientTask{
            .allocator = allocator,
            .io = io,
            .server_address = server.address(),
            .public_key = public_key,
            .iteration = iteration,
        };
        const thread = try std.Thread.spawn(.{}, ClientTask.run, .{&client});
        var joined = false;
        defer if (!joined) {
            server.deinit();
            server_owned = false;
            thread.join();
        };

        const handle = try echoOne(
            &server,
            endpoint_allocator,
            io,
            iteration,
            &summary,
        );
        thread.join();
        joined = true;
        if (client.err) |err| return err;
        try std.testing.expect(try server.removeConnection(handle));
        try expectEmpty(&server);

        const live = telemetry.liveBytes();
        if (iteration < 4) {
            // Warm every version/cipher combination before fixing the
            // retained-capacity baseline.
            retained_baseline = live;
        } else if (retained_baseline) |baseline| {
            try std.testing.expectEqual(baseline, live);
        } else {
            unreachable;
        }
    }
    summary.retained_live_bytes = retained_baseline.?;
    summary.peak_live_bytes = telemetry.peakBytes();

    server.deinit();
    server_owned = false;
    endpoint.deinit();
    endpoint_owned = false;
    try std.testing.expectEqual(@as(usize, 0), telemetry.liveBytes());
    return summary;
}

const ClientTask = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server_address: std.Io.net.IpAddress,
    public_key: [65]u8,
    iteration: usize,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var endpoint = try quic.runtime.Endpoint.bind(
            self.allocator,
            self.io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        defer endpoint.deinit();
        const version: quic.Version = if (self.iteration & 1 == 0)
            .version_1
        else
            .version_2;
        const suite: quic.tls.cipher_suite.Suite =
            if (self.iteration & 2 == 0)
                .aes_128_gcm_sha256
            else
                .aes_256_gcm_sha384;
        var original_dcid = [_]u8{0x90} ** 8;
        var local_cid = [_]u8{0xa0} ** 8;
        std.mem.writeInt(u16, original_dcid[0..2], @intCast(self.iteration), .big);
        std.mem.writeInt(u16, local_cid[0..2], @intCast(self.iteration), .big);
        var random = [_]u8{0xb0} ** 32;
        var secret = [_]u8{0xc0} ** 32;
        random[0] +%= @truncate(self.iteration);
        secret[0] +%= @truncate(self.iteration);
        var established = try quic.handshake.connectWithTimeout(
            &endpoint,
            self.server_address,
            .{
                .version = version,
                .available_versions = &.{version},
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &local_cid,
                .server_name = "localhost",
                .alpn_protocols = &.{"netz-endpoint-soak"},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = self.public_key,
                },
                .random = random,
                .x25519_secret_key = secret,
                .key_exchange_groups = &.{.x25519},
                .cipher_suites = &.{suite},
                .local_transport_parameters = transportParameters(),
                .initial_one_rtt_config = oneRttConfig(),
                .handshake_recovery = recovery(),
            },
            timeout,
        );
        defer established.deinit();
        try std.testing.expectEqual(version, established.connection.config.version);
        try std.testing.expectEqual(suite, established.negotiatedCipherSuite());

        const payload = payloadFor(self.iteration);
        var committed: usize = 0;
        try established.connection.sendStreamWithTimeout(
            0,
            0,
            &payload,
            true,
            &committed,
            timeout,
        );
        try std.testing.expectEqual(payload.len, committed);
        var response: [payload.len]u8 = undefined;
        const received = try established.connection.receiveStreamIdWithTimeout(
            0,
            &response,
            timeout,
        );
        const data = switch (received) {
            .data => |value| value,
            .reset => return error.UnexpectedStreamReset,
        };
        try std.testing.expect(data.fin);
        try std.testing.expectEqual(payload.len, data.bytes);
        try std.testing.expectEqualSlices(u8, &payload, &response);
    }
};

fn echoOne(
    server: *quic.endpoint_server.Server,
    event_allocator: std.mem.Allocator,
    io: std.Io,
    iteration: usize,
    summary: *Summary,
) !quic.endpoint_dispatcher.ConnectionHandle {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = timeout,
        .clock = .awake,
    });
    var handle: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    while (true) {
        var event = try server.receiveWithDeadline(&versions, deadline);
        defer event.deinit(event_allocator);
        switch (event) {
            .connected => |connected| {
                if (handle != null) return error.DuplicateConnection;
                handle = connected;
                const established = server.connection(connected) orelse
                    return error.MissingConnection;
                summary.connections += 1;
                summary.version_2_connections += @intFromBool(
                    established.connection.config.version == .version_2,
                );
                summary.aes_256_connections += @intFromBool(
                    established.negotiatedCipherSuite() ==
                        .aes_256_gcm_sha384,
                );
            },
            .packet => |*packet| {
                const connected = handle orelse return error.MissingConnection;
                try std.testing.expectEqual(
                    connected,
                    packet.connection_handle,
                );
                var payload: [4]u8 = undefined;
                const received = (try server.pollStreamId(
                    connected,
                    0,
                    &payload,
                )) orelse continue;
                const data = switch (received) {
                    .data => |value| value,
                    .reset => return error.UnexpectedStreamReset,
                };
                try std.testing.expect(data.fin);
                try std.testing.expectEqual(payload.len, data.bytes);
                const expected = payloadFor(iteration);
                try std.testing.expectEqualSlices(u8, &expected, &payload);
                _ = try server.acknowledgePacketIfNeeded(packet);
                try server.trySend(connected, &.{.{ .stream = .{
                    .stream_id = 0,
                    .data = &payload,
                    .fin = true,
                } }});
                summary.stream_round_trips += 1;
                return connected;
            },
            .timer => {},
            .handshake_failed => |failure| return failure.err,
            .unrouted => |unrouted| switch (unrouted) {
                .unrouted => |value| if (value.kind != .unknown_short_header) {
                    return error.UnexpectedUnroutedPacket;
                },
                else => return error.UnexpectedUnroutedPacket,
            },
        }
    }
}

fn expectEmpty(server: *const quic.endpoint_server.Server) !void {
    try std.testing.expectEqual(@as(usize, 0), server.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), server.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 0), server.connectionRouteCount());
    try std.testing.expectEqual(
        @as(usize, 0),
        server.pendingHandshakeRouteCount(),
    );
}

fn payloadFor(iteration: usize) [4]u8 {
    return .{ 's', 'o', 'a', @truncate(iteration) };
}

fn transportParameters() quic.TransportParameters {
    return .{
        .initial_max_data = 64,
        .initial_max_stream_data_bidi_local = 64,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_streams_bidi = 1,
    };
}

fn oneRttConfig() quic.handshake.OneRttConfig {
    return .{
        .enable_pacing = false,
        .automatic_ecn_policy = .disabled,
    };
}

fn recovery() @FieldType(quic.handshake.ClientOptions, "handshake_recovery") {
    return .{
        .initial_pto_ms = 20,
        .max_pto_ms = 40,
        .max_retries = 6,
        .max_duration_ms = 2_000,
    };
}

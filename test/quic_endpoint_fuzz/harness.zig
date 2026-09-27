const std = @import("std");
const netz = @import("netz");
const client_mod = @import("client.zig");
const model = @import("model.zig");

const quic = netz.quic;
const Server = quic.endpoint_server.Server;
const Handle = quic.endpoint_dispatcher.ConnectionHandle;
const versions = [_]u32{
    quic.Version.version_1.wireValue(),
    quic.Version.version_2.wireValue(),
};

pub fn runSequence(input: []const u8) !model.Summary {
    const sequence = input[0..@min(input.len, model.max_sequence_bytes)];
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try Server.init(
        allocator,
        &endpoint,
        .{
            .local_connection_id = &.{},
            .alpn_protocol = "netz-endpoint-fuzz",
            .available_versions = &.{ .version_1, .version_2 },
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
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
            .local_transport_parameters = .{
                .initial_max_data = 64,
                .initial_max_stream_data_bidi_local = 64,
                .initial_max_stream_data_bidi_remote = 64,
                .initial_max_streams_bidi = 1,
            },
            .initial_one_rtt_config = .{
                .enable_pacing = false,
                .automatic_ecn_policy = .disabled,
            },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_retries = 6,
                .max_duration_ms = 2_000,
            },
        },
        .{
            .max_pending_handshakes = model.capacity,
            .max_connections = model.capacity,
            .inbox_capacity = 8,
            .handshake_timeout_ms = 2_000,
            .automatic_connection_id_replenishment = false,
        },
    );
    var server_owned = true;
    defer if (server_owned) server.deinit();

    var clients: [model.client_count]client_mod.Task = undefined;
    for (&clients, 0..) |*client, index| {
        client.* = .{
            .allocator = allocator,
            .io = io,
            .server_address = server.address(),
            .public_key = public_key,
            .input = sequence,
            .client_index = index,
        };
    }
    var threads: [model.client_count]std.Thread = undefined;
    var started: usize = 0;
    defer {
        for (&clients) |*client| {
            client.start.set(io);
            client.release.set(io);
        }
        if (started != 0 and server_owned) {
            server.deinit();
            server_owned = false;
        }
        for (threads[0..started]) |thread| thread.join();
    }
    for (&clients, &threads) |*client, *thread| {
        thread.* = try std.Thread.spawn(.{}, client_mod.Task.run, .{client});
        started += 1;
    }

    var state = State{ .input = sequence };
    for (clients[0..model.capacity]) |*client| client.start.set(io);
    try driveUntilRoundTrips(&server, &state, model.capacity);
    for (clients[0..model.capacity]) |*client| {
        try client.round_trip_done.wait(io);
        if (client.err) |err| return err;
    }
    var active = [_]usize{ 0, 1 };

    for (model.capacity..model.client_count) |replacement| {
        clients[replacement].start.set(io);
        try driveUntilCapacityRejection(&server, &state);
        try std.testing.expectEqual(model.capacity, server.connectionCount());
        try std.testing.expectEqual(@as(usize, 0), server.pendingHandshakeCount());

        const slot = model.victimSelector(sequence, replacement);
        const victim = active[slot];
        const victim_handle = state.handles[victim] orelse
            return error.MissingConnectionHandle;
        try std.testing.expect(try server.removeConnection(victim_handle));
        state.handles[victim] = null;
        state.summary.removals += 1;
        clients[victim].release.set(io);

        const stale_before = state.summary.stale_packets;
        try driveUntilRoundTrips(&server, &state, replacement + 1);
        while (state.summary.stale_packets == stale_before) {
            try driveOne(&server, &state);
        }
        try clients[replacement].round_trip_done.wait(io);
        if (clients[replacement].err) |err| return err;
        active[slot] = replacement;
    }

    for (active) |client_index| {
        const handle = state.handles[client_index] orelse
            return error.MissingConnectionHandle;
        try std.testing.expect(try server.removeConnection(handle));
        state.summary.removals += 1;
        clients[client_index].release.set(io);
    }
    try std.testing.expectEqual(@as(usize, 0), server.connectionCount());
    for (&clients) |*client| try client.done.wait(io);
    for (threads) |thread| thread.join();
    started = 0;
    for (clients) |client| if (client.err) |err| return err;

    try std.testing.expectEqual(model.client_count, state.summary.connected);
    try std.testing.expectEqual(
        model.client_count - model.capacity,
        state.summary.capacity_rejections,
    );
    try std.testing.expectEqual(model.client_count, state.summary.removals);
    try std.testing.expectEqual(
        model.client_count,
        state.summary.stream_round_trips,
    );
    try std.testing.expectEqual(model.capacity, state.summary.max_live_connections);
    return state.summary;
}

const State = struct {
    input: []const u8,
    handles: [model.client_count]?Handle = .{null} ** model.client_count,
    summary: model.Summary = .{},
};

fn driveUntilRoundTrips(
    server: *Server,
    state: *State,
    expected: usize,
) !void {
    while (state.summary.stream_round_trips < expected) {
        try driveOne(server, state);
    }
}

fn driveUntilCapacityRejection(server: *Server, state: *State) !void {
    const expected = state.summary.capacity_rejections + 1;
    while (state.summary.capacity_rejections < expected) {
        try driveOne(server, state);
    }
}

fn driveOne(server: *Server, state: *State) !void {
    var event = try server.receiveWithTimeout(&versions, model.endpoint_timeout);
    defer event.deinit(std.testing.allocator);
    switch (event) {
        .connected => |handle| {
            const established = server.connection(handle) orelse
                return error.MissingConnection;
            state.summary.connected += 1;
            state.summary.max_live_connections = @max(
                state.summary.max_live_connections,
                server.connectionCount(),
            );
            state.summary.version_2_connections += @intFromBool(
                established.connection.config.version == .version_2,
            );
            state.summary.aes_256_connections += @intFromBool(
                established.negotiatedCipherSuite() == .aes_256_gcm_sha384,
            );
            try std.testing.expect(server.connectionCount() <= model.capacity);
        },
        .packet => |*packet| {
            var payload: [4]u8 = undefined;
            const received = (try server.pollStreamId(
                packet.connection_handle,
                0,
                &payload,
            )) orelse return;
            const data = switch (received) {
                .data => |value| value,
                .reset => return error.UnexpectedStreamReset,
            };
            try std.testing.expect(data.fin);
            try std.testing.expectEqual(payload.len, data.bytes);
            const client_index = payload[0];
            if (client_index >= model.client_count) return error.InvalidPayload;
            try std.testing.expectEqualSlices(
                u8,
                &model.payload(state.input, client_index),
                &payload,
            );
            if (state.handles[client_index] != null) {
                return error.DuplicateClientConnection;
            }
            state.handles[client_index] = packet.connection_handle;
            _ = try server.acknowledgePacketIfNeeded(packet);
            try server.trySend(packet.connection_handle, &.{.{ .stream = .{
                .stream_id = 0,
                .data = &payload,
                .fin = true,
            } }});
            state.summary.stream_round_trips += 1;
        },
        .timer => {},
        .handshake_failed => |failure| return failure.err,
        .unrouted => |unrouted| switch (unrouted) {
            .new_initial => state.summary.capacity_rejections += 1,
            .unrouted => |value| {
                if (value.kind != .unknown_short_header) {
                    return error.UnexpectedUnroutedPacket;
                }
                state.summary.stale_packets += 1;
            },
            else => return error.UnexpectedUnroutedPacket,
        },
    }
}

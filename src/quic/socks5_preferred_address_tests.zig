const std = @import("std");
const quic = @import("mod.zig");
const endpoint_server = @import("endpoint_server.zig");
const socks5 = @import("../proxy/socks5.zig");
const tls_testing = @import("../tls/testing.zig");

const net = std.Io.net;

test "SOCKS5 QUIC migrates from IPv4 relay to IPv6 preferred address" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var primary = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer primary.deinit();
    var preferred = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer preferred.deinit();
    const server_key = try tls_testing.serverKeyPair();
    const server_public = server_key.public_key.toUncompressedSec1();
    var server = try endpoint_server.Server.init(
        allocator,
        &primary,
        .{
            .local_connection_id = &.{},
            .alpn_protocol = "netz-socks5-preferred-test",
            .random = [_]u8{0xb1} ** 32,
            .x25519_secret_key = [_]u8{0xb2} ** 32,
            .key_exchange_groups = &.{.x25519},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .identity = .{
                .certificate_chain = &.{&server_public},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = server_key,
                } },
            },
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        },
        .{
            .max_pending_handshakes = 1,
            .max_connections = 1,
            .inbox_capacity = 16,
            .handshake_timeout_ms = 2_000,
            .automatic_connection_id_replenishment = false,
            .stateless_reset_key = [_]u8{0xb5} **
                quic.stateless_reset.static_key_len,
            .preferred_endpoint = &preferred,
            .preferred_additional_address = primary.address(),
        },
    );
    defer server.deinit();

    var control_listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer control_listener.deinit(io);
    const control_client = try control_listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    const control_server = try control_listener.accept(io);
    defer control_server.close(io);
    const bind4 = net.IpAddress{ .ip4 = .loopback(0) };
    const bind6 = net.IpAddress{ .ip6 = .loopback(0) };
    const client_socket = try bind4.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    var relay4 = try bind4.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer relay4.close(io);
    var relay6 = try bind6.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer relay6.close(io);
    var association = socks5.UdpAssociation.init(
        io,
        .{ .io = io, .stream = control_client, .deadline = null },
        client_socket,
        relay4.address,
    );
    const logical_peer = net.IpAddress{ .ip4 = .{
        .bytes = .{ 198, 18, 0, 1 },
        .port = primary.address().getPort(),
    } };
    var client_endpoint = try quic.runtime.Endpoint
        .fromSocks5AssociationForDomain(
        allocator,
        &association,
        "preferred.internal",
        primary.address().getPort(),
        logical_peer,
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    var relay_state = RelayState{
        .io = io,
        .relay4 = &relay4,
        .relay6 = &relay6,
        .primary = primary.address(),
        .preferred = preferred.address(),
    };
    const relay4_thread = try std.Thread.spawn(.{}, RelayState.run4, .{&relay_state});
    const relay6_thread = try std.Thread.spawn(.{}, RelayState.run6, .{&relay_state});
    var relays_joined = false;

    const challenge = [_]u8{ 0xc1, 1, 2, 3, 4, 5, 6, 7 };
    var client_state = ClientState{
        .allocator = allocator,
        .io = io,
        .endpoint = &client_endpoint,
        .logical_peer = logical_peer,
        .preferred = preferred.address(),
        .public_key = server_public,
        .challenge = challenge,
    };
    const client_thread = try std.Thread.spawn(.{}, ClientState.run, .{&client_state});
    var client_joined = false;
    defer if (!client_joined) client_thread.join();
    defer if (!relays_joined) {
        relay_state.stop.store(true, .release);
        relay4_thread.join();
        relay6_thread.join();
    };

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    var saw_ping = false;
    while (!saw_ping) {
        if (client_state.done.isSet()) {
            if (client_state.err) |err| return err;
            return error.TestUnexpectedResult;
        }
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        const poll_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = .fromMilliseconds(50),
            .clock = .awake,
        });
        var event = server.receiveWithDeadline(
            &versions,
            poll_deadline,
        ) catch |err| switch (err) {
            error.Timeout => continue,
            else => |other| return other,
        };
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*packet| {
                for (packet.packet.frames) |frame| {
                    if (frame == .ping and
                        packet.connection_id_sequence == 1)
                    {
                        const established = server.connection(
                            packet.connection_handle,
                        ) orelse return error.TestUnexpectedResult;
                        try std.testing.expectEqual(
                            &preferred,
                            established.connection.sendEndpoint(),
                        );
                        saw_ping = true;
                        try server.trySend(
                            packet.connection_handle,
                            &.{.{ .ping = {} }},
                        );
                    }
                }
                _ = try server.acknowledgePacketIfNeeded(packet);
            },
            .connected, .timer => {},
            .handshake_failed => |failure| return failure.err,
            .unrouted => return error.TestUnexpectedResult,
        }
    }

    client_thread.join();
    client_joined = true;
    if (client_state.err) |err| return err;
    relay_state.stop.store(true, .release);
    relay4_thread.join();
    relay6_thread.join();
    relays_joined = true;
    if (relay_state.err) |err| return err;
    try std.testing.expect(relay_state.saw_domain.load(.acquire));
    try std.testing.expect(relay_state.saw_ipv6.load(.acquire));
}

const ClientState = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: *quic.runtime.Endpoint,
    logical_peer: net.IpAddress,
    preferred: net.IpAddress,
    public_key: [65]u8,
    challenge: [8]u8,
    err: ?anyerror = null,
    done: std.Io.Event = .unset,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
        self.done.set(self.io);
    }

    fn runFallible(self: *@This()) !void {
        var established = try quic.handshake.connectWithTimeout(
            self.endpoint,
            self.logical_peer,
            .{
                .original_destination_connection_id = "socks-pref-odc",
                .local_connection_id = "socks-client",
                .server_name = "localhost",
                .alpn_protocols = &.{"netz-socks5-preferred-test"},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = self.public_key,
                },
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
                .key_exchange_groups = &.{.x25519},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .local_transport_parameters = .{
                    .active_connection_id_limit = 2,
                },
                .initial_one_rtt_config = .{ .enable_pacing = false },
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
            .fromSeconds(2),
        );
        defer established.deinit();
        const advertised = established.connection.peerPreferredAddress() orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            self.preferred,
            quic.one_rtt.Connection.preferredAddressIp6(advertised).?,
        );
        try established.connection.beginPeerPreferredAddressMigration(
            self.challenge,
            .ipv6,
        );
        try established.connection.sendPendingPathChallenge();
        const migration_deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
            .raw = .fromSeconds(2),
            .clock = .awake,
        });
        while (!established.connection.peerAddressValidated()) {
            var packet = try established.connection
                .receivePacketServicingTimersDeadline(migration_deadline);
            defer packet.deinit(self.allocator);
            _ = try established.connection.sendAckForPacketIfNeeded(
                packet.packet.packet_number,
                packet.frames,
            );
        }
        try std.testing.expectEqual(
            self.preferred,
            established.connection.peerAddress(),
        );
        try established.connection.send(&.{.{ .ping = {} }});
        const ping_deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
            .raw = .fromSeconds(2),
            .clock = .awake,
        });
        var saw_ping = false;
        while (!saw_ping) {
            var response = try established.connection
                .receivePacketServicingTimersDeadline(ping_deadline);
            defer response.deinit(self.allocator);
            try std.testing.expect(response.from.eql(&self.preferred));
            for (response.frames) |frame| {
                saw_ping = saw_ping or frame == .ping;
            }
            _ = try established.connection.sendAckForPacketIfNeeded(
                response.packet.packet_number,
                response.frames,
            );
        }
    }
};

const RelayState = struct {
    io: std.Io,
    relay4: *net.Socket,
    relay6: *net.Socket,
    primary: net.IpAddress,
    preferred: net.IpAddress,
    stop: std.atomic.Value(bool) = .init(false),
    mutex: std.Io.Mutex = .init,
    client: ?net.IpAddress = null,
    err: ?anyerror = null,
    saw_domain: std.atomic.Value(bool) = .init(false),
    saw_ipv6: std.atomic.Value(bool) = .init(false),

    fn run4(self: *@This()) void {
        self.run4Fallible() catch |err| self.recordError(err);
    }

    fn run6(self: *@This()) void {
        self.run6Fallible() catch |err| self.recordError(err);
    }

    fn run4Fallible(self: *@This()) !void {
        var storage: [8192]u8 = undefined;
        var framed_storage: [8192]u8 = undefined;
        while (!self.stop.load(.acquire)) {
            const message = self.relay4.receiveTimeout(
                self.io,
                &storage,
                awakeTimeout(.fromMilliseconds(20)),
            ) catch |err| switch (err) {
                error.Timeout => continue,
                else => return err,
            };
            if (message.from.eql(&self.primary)) {
                const client = self.clientAddress() orelse
                    return error.TestUnexpectedResult;
                const framed = try socks5.udp.encodeDatagram(
                    &framed_storage,
                    .{ .ip = self.primary },
                    message.data,
                );
                try self.relay4.send(self.io, &client, framed);
                continue;
            }
            self.setClient(message.from);
            const datagram = try socks5.udp.decodeDatagram(message.data);
            switch (datagram.source) {
                .domain => |domain| {
                    try std.testing.expectEqualStrings(
                        "preferred.internal",
                        domain.host,
                    );
                    try std.testing.expectEqual(
                        self.primary.getPort(),
                        domain.port,
                    );
                    self.saw_domain.store(true, .release);
                    try self.relay4.send(
                        self.io,
                        &self.primary,
                        datagram.payload,
                    );
                },
                .ip => |target| switch (target) {
                    .ip4 => try self.relay4.send(
                        self.io,
                        &target,
                        datagram.payload,
                    ),
                    .ip6 => {
                        try std.testing.expect(target.eql(&self.preferred));
                        self.saw_ipv6.store(true, .release);
                        try self.relay6.send(
                            self.io,
                            &target,
                            datagram.payload,
                        );
                    },
                },
            }
        }
    }

    fn run6Fallible(self: *@This()) !void {
        var storage: [8192]u8 = undefined;
        var framed_storage: [8192]u8 = undefined;
        while (!self.stop.load(.acquire)) {
            const message = self.relay6.receiveTimeout(
                self.io,
                &storage,
                awakeTimeout(.fromMilliseconds(20)),
            ) catch |err| switch (err) {
                error.Timeout => continue,
                else => return err,
            };
            try std.testing.expect(message.from.eql(&self.preferred));
            const client = self.clientAddress() orelse
                return error.TestUnexpectedResult;
            const framed = try socks5.udp.encodeDatagram(
                &framed_storage,
                .{ .ip = self.preferred },
                message.data,
            );
            try self.relay4.send(self.io, &client, framed);
        }
    }

    fn setClient(self: *@This(), address: net.IpAddress) void {
        self.mutex.lockUncancelable(self.io);
        self.client = address;
        self.mutex.unlock(self.io);
    }

    fn clientAddress(self: *@This()) ?net.IpAddress {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.client;
    }

    fn recordError(self: *@This(), err: anyerror) void {
        self.mutex.lockUncancelable(self.io);
        if (self.err == null) self.err = err;
        self.mutex.unlock(self.io);
        self.stop.store(true, .release);
    }
};

fn awakeTimeout(duration: std.Io.Duration) std.Io.Timeout {
    return .{ .duration = .{ .raw = duration, .clock = .awake } };
}

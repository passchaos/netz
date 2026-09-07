const std = @import("std");
const quic = @import("../mod.zig");
const handshake = @import("../handshake.zig");

const ReceivedClientInitialForTest = struct {
    from: std.Io.net.IpAddress,
    packet: quic.protection.OpenedInitialPacket,
    crypto_data: []u8,
    initial_secrets: quic.protection.InitialSecrets,
    coalesced_tail: []u8,

    fn deinit(self: *ReceivedClientInitialForTest, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.crypto_data);
        allocator.free(self.coalesced_tail);
        self.* = undefined;
    }
};

fn receiveClientInitialForTest(
    endpoint: *quic.runtime.Endpoint,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    retry_destination_connection_id: []const u8,
    version: quic.Version,
) handshake.Error!ReceivedClientInitialForTest {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    if (datagram.bytes.len < quic.initial_exchange.min_initial_udp_datagram_size) return error.InvalidInitialPacket;

    const header = try quic.LongHeader.parse(datagram.bytes);
    if (header.packet_type != .initial) return error.InvalidInitialPacket;
    if (retry_destination_connection_id.len == 0) {
        // RFC 9000 Section 7.2 requires a first client Initial to use a random
        // Destination Connection ID of at least 8 bytes.  A Retry follow-up is
        // different: its DCID is the server-chosen Retry SCID, which can be
        // shorter, so the accept path below validates exact equality instead.
        if (header.destination_connection_id.len < 8) return error.InvalidInitialPacket;
    } else if (!std.mem.eql(u8, header.destination_connection_id, retry_destination_connection_id)) {
        return error.InvalidInitialPacket;
    }

    if (header.version != version.wireValue()) return error.InvalidInitialPacket;
    const initial_secrets = try quic.protection.deriveInitialSecretsForVersion(version.wireValue(), header.destination_connection_id);
    const initial_info = try quic.protection.peekProtectedLongPacketInfo(
        datagram.bytes,
    );
    if (initial_info.packet_type != .initial) return error.InvalidInitialPacket;
    var flight = try quic.initial_exchange.openInitialCryptoFlight(
        endpoint,
        datagram.from,
        datagram.bytes[0..initial_info.len],
        initial_secrets.client,
        .{
            .expected_packet_number = expected_packet_number,
            .max_crypto_buffer = max_crypto_buffer,
            .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
        },
    );
    errdefer flight.deinit(endpoint.allocator);
    const coalesced_tail = try endpoint.allocator.dupe(
        u8,
        datagram.bytes[initial_info.len..],
    );
    errdefer endpoint.allocator.free(coalesced_tail);
    return .{
        .from = datagram.from,
        .packet = flight.first_packet,
        .crypto_data = flight.crypto_data,
        .initial_secrets = initial_secrets,
        .coalesced_tail = coalesced_tail,
    };
}

fn clampSecret(value: [32]u8) [32]u8 {
    var secret = value;
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    return secret;
}

test "QUIC server accept timeout bounds the first Initial wait" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();

    try std.testing.expectError(
        error.HandshakeTimeout,
        handshake.acceptWithTimeout(
            &endpoint,
            .{ .local_connection_id = "server-deadline" },
            .fromMilliseconds(10),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        handshake.acceptWithTimeout(
            &endpoint,
            .{ .local_connection_id = "server-deadline" },
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        handshake.acceptWithDeadline(
            &endpoint,
            .{ .local_connection_id = "server-deadline" },
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .real }),
        ),
    );
}

test "QUIC client timeout bounds an unresponsive peer" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();

    try std.testing.expectError(
        error.HandshakeTimeout,
        handshake.connectWithTimeout(
            &endpoint,
            silent.address(),
            .{
                .original_destination_connection_id = "timeout0",
                .local_connection_id = "client01",
                .handshake_recovery = .{
                    .initial_pto_ms = 1_000,
                    .max_pto_ms = 4_000,
                    .max_retries = 3,
                },
            },
            .fromMilliseconds(10),
        ),
    );
    try std.testing.expectError(
        error.HandshakeTimeout,
        handshake.connectWithTimeout(
            &endpoint,
            silent.address(),
            .{
                .original_destination_connection_id = "timeout0",
                .local_connection_id = "client01",
            },
            .zero,
        ),
    );
}

test "QUIC Initial deadline validation consumes owned datagram" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();

    const first = quic.runtime.OwnedBytes{
        .from = .{ .ip4 = .loopback(4433) },
        .bytes = try allocator.dupe(u8, "owned-initial"),
    };
    try std.testing.expectError(
        error.Timeout,
        handshake.acceptFromInitialWithTimeout(
            &endpoint,
            first,
            .{ .local_connection_id = "server-deadline" },
            .zero,
        ),
    );
}

test "QUIC server deadline retains stricter recovery bound" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();

    const configured = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(10), .clock = .awake },
    );
    const caller = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    const bounded = try handshake.testing.serverOptionsBeforeForTest(
        io,
        .{
            .local_connection_id = "server-deadline",
            .handshake_recovery = .{ .deadline = configured },
        },
        caller,
    );
    try std.testing.expectEqual(configured, bounded.handshake_recovery.deadline.?);

    const client_bounded = try handshake.testing.clientOptionsBeforeForTest(
        io,
        .{
            .original_destination_connection_id = "client-origin",
            .local_connection_id = "client-deadline",
            .handshake_recovery = .{ .deadline = configured },
        },
        caller,
    );
    try std.testing.expectEqual(
        configured,
        client_bounded.handshake_recovery.deadline.?,
    );
}

test "QUIC integrated handshake establishes 1-RTT stream exchange" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 };
    const client_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const server_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.endpoint, shared.cid) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(endpoint: *quic.runtime.Endpoint, cid: []const u8) !void {
            var established = try handshake.accept(endpoint, .{
                .local_connection_id = cid,
                .random = [_]u8{0x62} ** 32,
                .x25519_secret_key = [_]u8{0x64} ** 32,
            });
            defer established.deinit();
            try std.testing.expectEqualStrings("h3", established.alpn);

            var request = try established.connection.receivePacket();
            defer request.deinit(endpoint.allocator);
            try std.testing.expectEqualStrings("GET /", request.frames[0].stream.data);

            const response = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "OK", .fin = true } }};
            try established.connection.send(&response);
        }
    };

    var shared = Shared{ .endpoint = &server_endpoint, .cid = &server_cid };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(&client_endpoint, server_endpoint.address(), .{
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .random = [_]u8{0x61} ** 32,
        .x25519_secret_key = [_]u8{0x63} ** 32,
    });
    defer established.deinit();
    try std.testing.expectEqualStrings("h3", established.alpn);

    const request = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "GET /", .fin = true } }};
    try established.connection.send(&request);
    var response = try established.connection.receivePacket();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqualStrings("OK", response.frames[0].stream.data);
}

test "QUIC server handshake consumes a dispatcher-owned Initial" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = "dispatch";
    const client_cid = "client";
    const server_cid = "server";
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
                allocator,
                self.endpoint,
            );
            defer dispatcher.deinit();
            const versions = [_]u32{
                quic.Version.version_1.wireValue(),
                quic.Version.version_2.wireValue(),
            };
            var event = try dispatcher.receive(&versions);
            defer event.deinit(allocator);
            try std.testing.expect(event == .new_initial);
            const initial = event.takeNewInitial() orelse
                return error.TestUnexpectedResult;
            var established = try handshake.acceptFromInitial(
                self.endpoint,
                initial,
                .{
                    .local_connection_id = server_cid,
                    .random = [_]u8{0xa8} ** 32,
                    .x25519_secret_key = [_]u8{0xa9} ** 32,
                },
            );
            defer established.deinit();
            try std.testing.expectEqualStrings("h3", established.alpn);
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = original_dcid,
            .local_connection_id = client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xaa} ** 32,
            .x25519_secret_key = [_]u8{0xab} ** 32,
        },
    );
    defer established.deinit();
    thread.join();
    if (shared.err) |err| return err;
}

test "QUIC server handshake receives its later flight from one socket owner" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = "dispatch";
    const client_cid = "client";
    const server_cid = "server";
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{ original_dcid, server_cid },
        client_endpoint.address(),
        8,
    );
    defer inbox.deinit();

    const Client = struct {
        endpoint: *quic.runtime.Endpoint,
        server: std.Io.net.IpAddress,
        done: std.atomic.Value(bool) = .init(false),
        established: ?handshake.EstablishedConnection = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.established = handshake.connect(self.endpoint, self.server, .{
                .original_destination_connection_id = original_dcid,
                .local_connection_id = client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xac} ** 32,
                .x25519_secret_key = [_]u8{0xad} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            }) catch |err| {
                self.err = err;
                self.done.store(true, .release);
                return;
            };
            self.done.store(true, .release);
        }
    };
    const Server = struct {
        endpoint: *quic.runtime.Endpoint,
        inbox: *quic.handshake_inbox.Inbox,
        initial: quic.runtime.OwnedBytes,
        done: std.atomic.Value(bool) = .init(false),
        established: ?handshake.EstablishedConnection = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.established = handshake.acceptFromInitialSource(
                self.endpoint,
                self.inbox.datagramSource(),
                self.initial,
                .{
                    .local_connection_id = server_cid,
                    .random = [_]u8{0xae} ** 32,
                    .x25519_secret_key = [_]u8{0xaf} ** 32,
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                },
            ) catch |err| {
                self.err = err;
                self.done.store(true, .release);
                return;
            };
            self.done.store(true, .release);
        }
    };

    var client = Client{
        .endpoint = &client_endpoint,
        .server = server_endpoint.address(),
    };
    const client_thread = try std.Thread.spawn(.{}, Client.run, .{&client});

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var admission = try dispatcher.receive(&versions);
    defer admission.deinit(allocator);
    try std.testing.expect(admission == .new_initial);
    const initial = admission.takeNewInitial() orelse
        return error.TestUnexpectedResult;
    try dispatcher.registerPendingHandshake(71, &inbox);
    var server = Server{
        .endpoint = &server_endpoint,
        .inbox = &inbox,
        .initial = initial,
    };
    const server_thread = try std.Thread.spawn(.{}, Server.run, .{&server});

    var owner_err: ?anyerror = null;
    owner: while (!server.done.load(.acquire)) {
        var datagram = server_endpoint.receiveBytesTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromMilliseconds(20),
            },
        }) catch |err| switch (err) {
            // Periodic wakeups bound this owner loop even when a peer exits
            // early and no further UDP datagram can arrive.
            error.Timeout => continue,
            else => {
                owner_err = err;
                break :owner;
            },
        };
        var event = dispatcher.dispatch(datagram) catch |err| {
            // `dispatch` consumes or frees its owned input on every error.
            datagram = undefined;
            owner_err = err;
            break :owner;
        };
        datagram = undefined;
        if (event != .pending_handshake) {
            event.deinit(allocator);
            owner_err = error.TestUnexpectedResult;
            break :owner;
        }
        event.deinit(allocator);
    }

    // Closing the pending source gives the server thread a deterministic exit
    // if the client failed before sending its Finished flight.
    if (!server.done.load(.acquire)) inbox.close();
    client_thread.join();
    server_thread.join();
    if (owner_err) |err| return err;
    if (client.err) |err| return err;
    if (server.err) |err| return err;
    var client_established = client.established orelse
        return error.TestUnexpectedResult;
    defer client_established.deinit();
    var server_established = server.established orelse
        return error.TestUnexpectedResult;
    defer server_established.deinit();
    try dispatcher.promotePendingHandshake(
        71,
        72,
        &server_established.connection,
    );
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    try std.testing.expect(try dispatcher.unregisterConnection(72));
}

test "QUIC client handshake receives through one socket owner" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = "client-dispatch";
    const client_cid = "client-route";
    const server_cid = "server-route";
    var client_inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{client_cid},
        server_endpoint.address(),
        32,
    );
    defer client_inbox.deinit();
    var server_inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{ original_dcid, server_cid },
        client_endpoint.address(),
        32,
    );
    defer server_inbox.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });

    const Server = struct {
        endpoint: *quic.runtime.Endpoint,
        inbox: *quic.handshake_inbox.Inbox,
        initial: quic.runtime.OwnedBytes,
        deadline: std.Io.Clock.Timestamp,
        done: std.atomic.Value(bool) = .init(false),
        established: ?handshake.EstablishedConnection = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.established = handshake.acceptFromInitialSourceWithDeadline(
                self.endpoint,
                self.inbox.datagramSource(),
                self.initial,
                .{
                    .local_connection_id = server_cid,
                    .random = [_]u8{0xb0} ** 32,
                    .x25519_secret_key = [_]u8{0xb1} ** 32,
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                },
                self.deadline,
            ) catch |err| {
                self.err = err;
                self.done.store(true, .release);
                return;
            };
            self.done.store(true, .release);
        }
    };
    const Client = struct {
        endpoint: *quic.runtime.Endpoint,
        inbox: *quic.handshake_inbox.Inbox,
        server: std.Io.net.IpAddress,
        deadline: std.Io.Clock.Timestamp,
        done: std.atomic.Value(bool) = .init(false),
        established: ?handshake.EstablishedConnection = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.established = handshake.connectFromWithDeadline(
                self.endpoint,
                self.inbox.datagramSource(),
                self.server,
                .{
                    .original_destination_connection_id = original_dcid,
                    .local_connection_id = client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xb2} ** 32,
                    .x25519_secret_key = [_]u8{0xb3} ** 32,
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                },
                self.deadline,
            ) catch |err| {
                self.err = err;
                self.done.store(true, .release);
                return;
            };
            self.done.store(true, .release);
        }
    };
    const ClientOwner = struct {
        endpoint: *quic.runtime.Endpoint,
        inbox: *quic.handshake_inbox.Inbox,
        done: *std.atomic.Value(bool),
        deadline: std.Io.Clock.Timestamp,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            while (!self.done.load(.acquire)) {
                const remaining = self.deadline.durationFromNow(
                    self.endpoint.io,
                ).raw.nanoseconds;
                if (remaining <= 0) {
                    if (self.done.load(.acquire)) return;
                    self.err = error.Timeout;
                    self.inbox.close();
                    return;
                }
                var datagram = self.endpoint.receiveBytesTimeout(.{
                    .duration = .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(@min(
                            remaining,
                            20 * std.time.ns_per_ms,
                        )),
                    },
                }) catch |err| switch (err) {
                    error.Timeout => {
                        if (self.done.load(.acquire)) return;
                        continue;
                    },
                    else => {
                        if (self.done.load(.acquire)) return;
                        self.err = err;
                        self.inbox.close();
                        return;
                    },
                };
                self.inbox.push(datagram) catch |err| {
                    datagram.deinit(self.endpoint.allocator);
                    self.err = err;
                    self.inbox.close();
                    return;
                };
            }
        }
    };

    var client = Client{
        .endpoint = &client_endpoint,
        .inbox = &client_inbox,
        .server = server_endpoint.address(),
        .deadline = deadline,
    };
    const client_thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    var client_owner = ClientOwner{
        .endpoint = &client_endpoint,
        .inbox = &client_inbox,
        .done = &client.done,
        .deadline = deadline,
    };
    const client_owner_thread = try std.Thread.spawn(
        .{},
        ClientOwner.run,
        .{&client_owner},
    );

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var admission = try dispatcher.receiveWithDeadline(
        &versions,
        deadline,
    );
    defer admission.deinit(allocator);
    try std.testing.expect(admission == .new_initial);
    const initial = admission.takeNewInitial() orelse
        return error.TestUnexpectedResult;
    try dispatcher.registerPendingHandshake(81, &server_inbox);
    var server = Server{
        .endpoint = &server_endpoint,
        .inbox = &server_inbox,
        .initial = initial,
        .deadline = deadline,
    };
    const server_thread = try std.Thread.spawn(.{}, Server.run, .{&server});

    var server_owner_err: ?anyerror = null;
    while (!server.done.load(.acquire)) {
        const remaining = deadline.durationFromNow(io).raw.nanoseconds;
        if (remaining <= 0) {
            if (server.done.load(.acquire)) break;
            server_owner_err = error.Timeout;
            break;
        }
        var event = dispatcher.receiveTimeout(
            &versions,
            .{ .duration = .{
                .clock = .awake,
                .raw = .fromNanoseconds(@min(
                    remaining,
                    20 * std.time.ns_per_ms,
                )),
            } },
        ) catch |err| switch (err) {
            error.Timeout => {
                if (server.done.load(.acquire)) break;
                continue;
            },
            else => {
                if (server.done.load(.acquire)) break;
                server_owner_err = err;
                break;
            },
        };
        if (event != .pending_handshake or
            event.pending_handshake != 81)
        {
            event.deinit(allocator);
            server_owner_err = error.TestUnexpectedResult;
            break;
        }
        event.deinit(allocator);
    }

    if (!server.done.load(.acquire)) server_inbox.close();
    if (!client.done.load(.acquire)) client_inbox.close();
    client_thread.join();
    client_owner_thread.join();
    server_thread.join();
    defer if (client.established) |*established| established.deinit();
    defer if (server.established) |*established| established.deinit();
    if (client.err) |err| return err;
    if (server.err) |err| return err;
    if (client.established == null) {
        if (client_owner.err) |err| return err;
    }
    if (server.established == null) {
        if (server_owner_err) |err| return err;
    }
    var client_established = client.established orelse
        return error.TestUnexpectedResult;
    client.established = null;
    defer client_established.deinit();
    var server_established = server.established orelse
        return error.TestUnexpectedResult;
    server.established = null;
    defer server_established.deinit();
    try std.testing.expectEqualStrings("h3", client_established.alpn);
    try std.testing.expectEqualStrings("h3", server_established.alpn);
}

test "QUIC server handshake consumes an invalid injected Initial" {
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

    const bytes = try allocator.alloc(
        u8,
        quic.initial_exchange.min_initial_udp_datagram_size,
    );
    @memset(bytes, 0);
    try std.testing.expectError(
        error.HandshakeTimeout,
        handshake.acceptFromInitialWithTimeout(
            &endpoint,
            .{
                .from = .{ .ip4 = .loopback(4444) },
                .bytes = bytes,
            },
            .{ .local_connection_id = "server" },
            .fromMilliseconds(10),
        ),
    );
}

test "QUIC integrated handshake recovers dropped client and server flights" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size },
    );
    defer client_endpoint.deinit();

    const RecoveryConfig =
        @import("../handshake/retransmit.zig").Config;
    const dropFirst = struct {
        fn drop(attempt: u8) bool {
            return attempt == 0;
        }
    }.drop;
    const recovery = RecoveryConfig{
        .initial_pto_ms = 5,
        .max_pto_ms = 10,
        .max_retries = 3,
        .should_drop = dropFirst,
    };
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        recovery: RecoveryConfig,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
                .handshake_recovery = shared.recovery,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            var packet = established.connection.receivePacket() catch |err| {
                shared.err = err;
                return;
            };
            defer packet.deinit(shared.endpoint.allocator);
            if (packet.frames.len != 1 or packet.frames[0] != .ping) {
                shared.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .recovery = recovery,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "losspto1",
            .local_connection_id = "client",
            .random = [_]u8{0xe3} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
            .handshake_recovery = recovery,
        },
    );
    defer established.deinit();
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
}

test "QUIC integrated AES-256 SHA-384 handshake exchanges 1-RTT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,
        suite: ?quic.tls_client_hello.CipherSuite = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xa2} ** 32,
                .x25519_secret_key = [_]u8{0xa3} ** 32,
                .cipher_suites = &.{.aes_256_gcm_sha384},
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            shared.suite = established.connection.config.send_keys.suite;
            var packet = established.connection.receivePacket() catch |err| {
                shared.err = err;
                return;
            };
            defer packet.deinit(shared.endpoint.allocator);
            if (packet.frames.len != 1 or packet.frames[0] != .ping) {
                shared.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "aes25601",
            .local_connection_id = "client",
            .random = [_]u8{0xa4} ** 32,
            .x25519_secret_key = [_]u8{0xa5} ** 32,
            .cipher_suites = &.{.aes_256_gcm_sha384},
        },
    );
    defer established.deinit();
    try std.testing.expectEqual(
        quic.tls_client_hello.CipherSuite.aes_256_gcm_sha384,
        established.connection.config.send_keys.suite,
    );
    try std.testing.expectEqual(
        quic.tls.secret.Hash.sha384,
        established.connection.config.send_keys.traffic_secret.hash,
    );
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        quic.tls_client_hello.CipherSuite.aes_256_gcm_sha384,
        shared.suite.?,
    );
}

test "QUIC integrated secp256r1-only handshake exchanges 1-RTT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xb2} ** 32,
                .p256_secret_key = [_]u8{0} ** 31 ++ [_]u8{2},
                .key_exchange_groups = &.{.secp256r1},
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            var packet = established.connection.receivePacket() catch |err| {
                shared.err = err;
                return;
            };
            defer packet.deinit(shared.endpoint.allocator);
            if (packet.frames.len != 1 or packet.frames[0] != .ping) {
                shared.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "p2560001",
            .local_connection_id = "client",
            .random = [_]u8{0xb3} ** 32,
            .p256_secret_key = [_]u8{0} ** 31 ++ [_]u8{1},
            .key_exchange_groups = &.{.secp256r1},
        },
    );
    defer established.deinit();
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
}

test "QUIC integrated handshake emits matching NSS key logs on both roles" {
    try runMatchingKeylog(.aes_128_gcm_sha256, 32);
}

test "QUIC AES-256 SHA-384 key logs preserve 48-byte traffic secrets" {
    try runMatchingKeylog(.aes_256_gcm_sha384, 48);
}

fn runMatchingKeylog(
    cipher_suite: quic.tls_client_hello.CipherSuite,
    secret_len: usize,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_cid = [_]u8{ 9, 10, 11, 12 };
    const server_cid = [_]u8{ 13, 14, 15, 16 };
    const client_random = [_]u8{0xa5} ** 32;
    var client_output: std.Io.Writer.Allocating = .init(allocator);
    defer client_output.deinit();
    var client_log = quic.keylog.Log.init(&client_output.writer);
    var server_output: std.Io.Writer.Allocating = .init(allocator);
    defer server_output.deinit();
    var server_log = quic.keylog.Log.init(&server_output.writer);

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        keylog: *quic.keylog.Log,
        cipher_suite: quic.tls_client_hello.CipherSuite,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = shared.cid,
                .random = [_]u8{0xb6} ** 32,
                .x25519_secret_key = [_]u8{0xc7} ** 32,
                .keylog = shared.keylog,
                .cipher_suites = &.{shared.cipher_suite},
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .cid = &server_cid,
        .keylog = &server_log,
        .cipher_suite = cipher_suite,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = client_random,
            .x25519_secret_key = [_]u8{0xd8} ** 32,
            .keylog = &client_log,
            .cipher_suites = &.{cipher_suite},
        },
    );
    established.deinit();
    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqualSlices(
        u8,
        client_output.written(),
        server_output.written(),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        std.mem.count(u8, client_output.written(), "\n"),
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET " ++ ("a5" ** 32),
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "SERVER_TRAFFIC_SECRET_0 " ++ ("a5" ** 32),
    ) != null);
    var line_iterator = std.mem.splitScalar(
        u8,
        client_output.written(),
        '\n',
    );
    while (line_iterator.next()) |line| {
        if (line.len == 0) continue;
        const secret_separator = std.mem.lastIndexOfScalar(
            u8,
            line,
            ' ',
        ) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            secret_len * 2,
            line.len - secret_separator - 1,
        );
    }
}

test {
    _ = @import("../resumption/handshake_tests.zig");
}

test "QUIC integrated handshake propagates keylog sink failures" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x31} ** 32,
                .x25519_secret_key = [_]u8{0x32} ** 32,
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var failing: std.Io.Writer = .failing;
    var keylog = quic.keylog.Log.init(&failing);
    try std.testing.expectError(
        error.WriteFailed,
        handshake.connect(&client_endpoint, server_endpoint.address(), .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
            .random = [_]u8{0x30} ** 32,
            .x25519_secret_key = [_]u8{0x33} ** 32,
            .keylog = &keylog,
        }),
    );
    // The client deliberately aborts once it derives handshake secrets. Wake
    // the server's pending Handshake receive with a malformed datagram so this
    // error-path test remains deterministic without closing shared I/O state.
    try client_endpoint.sendBytes(server_endpoint.address(), "invalid");
    thread.join();
    try std.testing.expect(shared.err != null);
}

test "QUIC integrated client restarts after Version Negotiation" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.endpoint, shared.cid) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(endpoint: *quic.runtime.Endpoint, cid: []const u8) !void {
            var first_initial = try endpoint.receiveBytes();
            defer first_initial.deinit(endpoint.allocator);
            const first_header = try quic.LongHeader.parse(first_initial.bytes);
            try std.testing.expectEqual(quic.PacketType.initial, first_header.packet_type);
            try std.testing.expectEqual(quic.Version.version_1.wireValue(), first_header.version);

            const supported_versions = [_]u32{quic.Version.version_2.wireValue()};
            var vn: std.ArrayList(u8) = .empty;
            defer vn.deinit(endpoint.allocator);
            try quic.writeVersionNegotiationPacket(&vn, endpoint.allocator, .{
                .destination_connection_id = first_header.source_connection_id,
                .source_connection_id = first_header.destination_connection_id,
                .versions = &supported_versions,
            });
            try endpoint.sendBytes(first_initial.from, vn.items);

            var established = try handshake.accept(endpoint, .{
                .version = .version_2,
                .available_versions = &.{.version_2},
                .local_connection_id = cid,
                .random = [_]u8{0x82} ** 32,
                .x25519_secret_key = [_]u8{0x84} ** 32,
                .key_exchange_groups = &.{.x25519},
            });
            defer established.deinit();
            try std.testing.expectEqualStrings("h3", established.alpn);

            var request = try established.connection.receivePacket();
            defer request.deinit(endpoint.allocator);
            try std.testing.expectEqualStrings("GET /vn", request.frames[0].stream.data);

            const response = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "VN OK", .fin = true } }};
            try established.connection.send(&response);
        }
    };

    var shared = Shared{ .endpoint = &server_endpoint, .cid = &server_cid };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(&client_endpoint, server_endpoint.address(), .{
        .version = .version_1,
        .available_versions = &.{ .version_2, .version_1 },
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .random = [_]u8{0x81} ** 32,
        .x25519_secret_key = [_]u8{0x83} ** 32,
        .key_exchange_groups = &.{.x25519},
    });
    defer established.deinit();
    try std.testing.expectEqualStrings("h3", established.alpn);

    const request = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "GET /vn", .fin = true } }};
    try established.connection.send(&request);
    var response = try established.connection.receivePacket();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqualStrings("VN OK", response.frames[0].stream.data);
}

test "QUIC integrated server automatically handles Version Negotiation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .version = .version_2,
                .available_versions = &.{.version_2},
                .local_connection_id = "server",
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
                .key_exchange_groups = &.{.x25519},
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            var ping = established.connection.receivePacket() catch |err| {
                shared.err = err;
                return;
            };
            ping.deinit(shared.endpoint.allocator);
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .version = .version_1,
            .available_versions = &.{ .version_2, .version_1 },
            .original_destination_connection_id = "autovn01",
            .local_connection_id = "client",
            .random = [_]u8{0x93} ** 32,
            .x25519_secret_key = [_]u8{0x94} ** 32,
            .key_exchange_groups = &.{.x25519},
        },
    );
    defer established.deinit();
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
}

test "QUIC integrated client rejects mismatched Version Information after VN" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const client_random = [_]u8{0xc1} ** 32;
    const client_secret_key = [_]u8{0xc3} ** 32;
    const server_random = [_]u8{0xc2} ** 32;
    const server_secret_key = clampSecret([_]u8{0xc4} ** 32);

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        server_random: [32]u8,
        server_secret_key: [32]u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var first_initial = try shared.endpoint.receiveBytes();
            defer first_initial.deinit(shared.endpoint.allocator);
            const first_header = try quic.LongHeader.parse(first_initial.bytes);

            const supported_versions = [_]u32{quic.Version.version_2.wireValue()};
            var vn: std.ArrayList(u8) = .empty;
            defer vn.deinit(shared.endpoint.allocator);
            try quic.writeVersionNegotiationPacket(&vn, shared.endpoint.allocator, .{
                .destination_connection_id = first_header.source_connection_id,
                .source_connection_id = first_header.destination_connection_id,
                .versions = &supported_versions,
            });
            try shared.endpoint.sendBytes(first_initial.from, vn.items);

            var client_initial = try receiveClientInitialForTest(shared.endpoint, 0, 4096, &.{}, .version_2);
            defer client_initial.deinit(shared.endpoint.allocator);
            var parsed_client = try quic.tls_client_hello.parseClientHello(client_initial.crypto_data);
            defer parsed_client.deinit(shared.endpoint.allocator);

            const server_public = try quic.tls_client_hello.x25519PublicKey(shared.server_secret_key);
            const shared_secret = try quic.tls_client_hello.x25519SharedSecret(shared.server_secret_key, parsed_client.x25519_public_key);

            var server_hello: std.ArrayList(u8) = .empty;
            defer server_hello.deinit(shared.endpoint.allocator);
            try quic.tls_client_hello.writeServerHello(&server_hello, shared.endpoint.allocator, .{
                .random = shared.server_random,
                .x25519_public_key = server_public,
            });
            const hs_hash = quic.tls.transcript.hash(&.{ client_initial.crypto_data, server_hello.items });
            const handshake_secrets = try quic.tls_client_hello.deriveHandshakeSecretsForVersion(quic.Version.version_2.wireValue(), shared_secret, hs_hash);

            var wrong_tp = quic.practical_transport_parameters;
            wrong_tp.original_destination_connection_id = client_initial.packet.destination_connection_id;
            wrong_tp.initial_source_connection_id = shared.cid;
            wrong_tp.version_information = .{
                .chosen_version = .version_1,
                .available_versions_wire = &[_]u8{ 0x00, 0x00, 0x00, 0x01 },
            };
            var encoded_tp: std.ArrayList(u8) = .empty;
            defer encoded_tp.deinit(shared.endpoint.allocator);
            try quic.encodeTransportParametersForSource(&encoded_tp, shared.endpoint.allocator, wrong_tp, .server);

            var encrypted_extensions: std.ArrayList(u8) = .empty;
            defer encrypted_extensions.deinit(shared.endpoint.allocator);
            try quic.tls_client_hello.writeEncryptedExtensions(&encrypted_extensions, shared.endpoint.allocator, "h3", encoded_tp.items);
            const server_finished_hash = quic.tls.transcript.hash(&.{ client_initial.crypto_data, server_hello.items, encrypted_extensions.items });
            const server_verify = quic.tls_client_hello.computeFinishedVerifyData(handshake_secrets.server_handshake_traffic_secret, server_finished_hash);
            var server_finished: std.ArrayList(u8) = .empty;
            defer server_finished.deinit(shared.endpoint.allocator);
            try quic.tls_client_hello.writeFinished(&server_finished, shared.endpoint.allocator, server_verify);

            var server_flight: std.ArrayList(u8) = .empty;
            defer server_flight.deinit(shared.endpoint.allocator);
            try server_flight.appendSlice(shared.endpoint.allocator, encrypted_extensions.items);
            try server_flight.appendSlice(shared.endpoint.allocator, server_finished.items);

            try quic.initial_exchange.sendCoalescedInitialHandshakeCrypto(
                shared.endpoint,
                client_initial.from,
                client_initial.initial_secrets.server,
                .{
                    .version = quic.Version.version_2.wireValue(),
                    .destination_connection_id = client_initial.packet.source_connection_id,
                    .source_connection_id = shared.cid,
                    .packet_number = 0,
                    .crypto_data = server_hello.items,
                    .max_crypto_frame_data_len = 1024,
                    .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
                },
                handshake_secrets.server_quic,
                .{
                    .version = quic.Version.version_2.wireValue(),
                    .destination_connection_id = client_initial.packet.source_connection_id,
                    .source_connection_id = shared.cid,
                    .packet_number = 0,
                    .crypto_data = server_flight.items,
                    .max_crypto_frame_data_len = 1024,
                },
            );
        }
    };

    var shared = Shared{
        .endpoint = &server_endpoint,
        .cid = &server_cid,
        .server_random = server_random,
        .server_secret_key = server_secret_key,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidTransportParameter, handshake.connect(&client_endpoint, server_endpoint.address(), .{
        .version = .version_1,
        .available_versions = &.{ .version_2, .version_1 },
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .random = client_random,
        .x25519_secret_key = client_secret_key,
        .key_exchange_groups = &.{.x25519},
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "QUIC client Initial carries address validation token" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    const client_cid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const secret: quic.address_validation_token.Secret = [_]u8{0x4a} ** quic.address_validation_token.secret_len;
    const token = try quic.address_validation_token.encode(allocator, secret, .{
        .kind = .new_token,
        .issued_ns = 1_000,
        .lifetime_ns = 5_000,
        .peer_address = "client-path",
        .nonce = [_]u8{0x5b} ** quic.address_validation_token.nonce_len,
    });
    defer allocator.free(token);

    const secrets = quic.protection.deriveInitialSecrets(&original_dcid);
    const random = [_]u8{0x21} ** 32;
    const secret_key = [_]u8{0x22} ** 32;
    const public_key = try quic.tls_client_hello.x25519PublicKey(clampSecret(secret_key));
    var params = quic.practical_transport_parameters;
    params.initial_source_connection_id = &client_cid;
    var encoded_tp: std.ArrayList(u8) = .empty;
    defer encoded_tp.deinit(allocator);
    try quic.encodeTransportParametersForSource(&encoded_tp, allocator, params, .client);

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try quic.tls_client_hello.writeClientHello(&client_hello, allocator, .{
        .random = random,
        .x25519_public_key = public_key,
        .server_name = "localhost",
        .alpn_protocols = &.{"h3"},
        .transport_parameters = encoded_tp.items,
    });

    try quic.initial_exchange.sendInitialCrypto(&client_endpoint, server_endpoint.address(), secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_cid,
        .token = token,
        .packet_number = 0,
        .crypto_data = client_hello.items,
        .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
    });

    var raw = try server_endpoint.receiveBytes();
    defer raw.deinit(allocator);
    var opened = try quic.initial_exchange.openInitialCrypto(&server_endpoint, raw.from, raw.bytes, secrets.client, 0, 4096);
    defer opened.deinit(allocator);
    try std.testing.expectEqualSlices(u8, token, opened.packet.token);
    const validated = try quic.address_validation_token.validateAnySecret(
        &[_]quic.address_validation_token.Secret{secret},
        .new_token,
        .version_1,
        1_100,
        "client-path",
        opened.packet.token,
    );
    try std.testing.expectEqual(quic.address_validation_token.Kind.new_token, validated.kind);
}

test "QUIC server address validation replay gate marks only valid NEW_TOKEN" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();

    const old_secret: quic.address_validation_token.Secret =
        [_]u8{0x5c} ** quic.address_validation_token.secret_len;
    const current_secret: quic.address_validation_token.Secret =
        [_]u8{0x5d} ** quic.address_validation_token.secret_len;
    const token = try quic.address_validation_token.encode(allocator, old_secret, .{
        .kind = .new_token,
        .issued_ns = 1_000,
        .lifetime_ns = 5_000,
        .peer_address = "client-path",
        .nonce = [_]u8{0x5e} ** quic.address_validation_token.nonce_len,
    });
    defer allocator.free(token);

    var replay_filter = try quic.address_validation_token.SharedReplayFilter.init(
        allocator,
        threaded.io(),
        8,
    );
    defer replay_filter.deinit();
    const secrets = [_]quic.address_validation_token.Secret{
        current_secret,
        old_secret,
    };
    const options = handshake.ServerOptions{
        .local_connection_id = "server",
        .address_validation_secrets = &secrets,
        .address_validation_peer = "client-path",
        .address_validation_now_ns = 1_100,
        .address_validation_replay_filter = &replay_filter,
    };

    var invalid = token[0..quic.address_validation_token.token_len].*;
    invalid[invalid.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidPacket,
        handshake.testing.validateAddressTokenForInitialForTest(
            allocator,
            &invalid,
            "initial-dcid",
            options,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), replay_filter.entryCount());

    const expired = try quic.address_validation_token.encode(allocator, old_secret, .{
        .kind = .new_token,
        .issued_ns = 1_000,
        .lifetime_ns = 50,
        .peer_address = "client-path",
        .nonce = [_]u8{0x5f} ** quic.address_validation_token.nonce_len,
    });
    defer allocator.free(expired);
    try std.testing.expectError(
        error.InvalidPacket,
        handshake.testing.validateAddressTokenForInitialForTest(
            allocator,
            expired,
            "initial-dcid",
            options,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), replay_filter.entryCount());

    var missing_auth = options;
    missing_auth.address_validation_secrets = &.{};
    try std.testing.expectError(
        error.InvalidPacket,
        handshake.testing.validateAddressTokenForInitialForTest(
            allocator,
            token,
            "initial-dcid",
            missing_auth,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), replay_filter.entryCount());

    // The previous (rotated) secret remains eligible, but only the first
    // successful use passes the atomic replay gate.
    try handshake.testing.validateAddressTokenForInitialForTest(
        allocator,
        token,
        "initial-dcid",
        options,
    );
    try std.testing.expectEqual(@as(usize, 1), replay_filter.entryCount());
    try std.testing.expectError(
        error.InvalidPacket,
        handshake.testing.validateAddressTokenForInitialForTest(
            allocator,
            token,
            "initial-dcid",
            options,
        ),
    );
}

test "QUIC server Retry replay gate preserves exact CID binding" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();

    const secret: quic.address_validation_token.Secret =
        [_]u8{0x6a} ** quic.address_validation_token.secret_len;
    const odcid = "original";
    const rscid = "retry";
    const token = try quic.address_validation_token.encodeRetry(allocator, secret, .{
        .kind = .retry,
        .issued_ns = 2_000,
        .lifetime_ns = 5_000,
        .peer_address = "client-path",
        .nonce = [_]u8{0x6b} ** quic.address_validation_token.nonce_len,
    }, odcid, rscid);
    defer allocator.free(token);

    var replay_filter = try quic.address_validation_token.SharedReplayFilter.init(
        allocator,
        threaded.io(),
        8,
    );
    defer replay_filter.deinit();
    const options = handshake.ServerOptions{
        .local_connection_id = "server",
        .address_validation_secrets = &.{secret},
        .address_validation_peer = "client-path",
        .address_validation_now_ns = 2_100,
        .address_validation_replay_filter = &replay_filter,
        .retry_original_destination_connection_id = odcid,
        .retry_source_connection_id = rscid,
    };

    try std.testing.expectError(
        error.InvalidPacket,
        handshake.testing.validateAddressTokenForInitialForTest(
            allocator,
            token,
            "wrong-original",
            options,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), replay_filter.entryCount());
    try handshake.testing.validateAddressTokenForInitialForTest(
        allocator,
        token,
        odcid,
        options,
    );
    try std.testing.expectEqual(@as(usize, 1), replay_filter.entryCount());
    try std.testing.expectError(
        error.InvalidPacket,
        handshake.testing.validateAddressTokenForInitialForTest(
            allocator,
            token,
            odcid,
            options,
        ),
    );

    // Omitting the optional borrowed filter retains the previous stateless
    // acceptance behavior for deployments that do not opt into replay state.
    var no_filter = options;
    no_filter.address_validation_replay_filter = null;
    try handshake.testing.validateAddressTokenForInitialForTest(
        allocator,
        token,
        odcid,
        no_filter,
    );
    try handshake.testing.validateAddressTokenForInitialForTest(
        allocator,
        token,
        odcid,
        no_filter,
    );
}

test "QUIC integrated handshake succeeds after validated Retry" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const retry_scid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const server_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const token_secret: quic.address_validation_token.Secret = [_]u8{0x71} ** quic.address_validation_token.secret_len;
    const retry_nonce: quic.address_validation_token.Nonce = [_]u8{0x72} ** quic.address_validation_token.nonce_len;
    const client_random = [_]u8{0x73} ** 32;
    const client_secret_key = [_]u8{0x74} ** 32;
    const server_random = [_]u8{0x75} ** 32;
    const server_secret_key = [_]u8{0x76} ** 32;

    const first_initial_secrets = quic.protection.deriveInitialSecrets(&original_dcid);
    const client_public = try quic.tls_client_hello.x25519PublicKey(clampSecret(client_secret_key));
    var params = quic.practical_transport_parameters;
    params.initial_source_connection_id = &client_cid;
    var encoded_tp: std.ArrayList(u8) = .empty;
    defer encoded_tp.deinit(allocator);
    try quic.encodeTransportParametersForSource(&encoded_tp, allocator, params, .client);

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try quic.tls_client_hello.writeClientHello(&client_hello, allocator, .{
        .random = client_random,
        .x25519_public_key = client_public,
        .server_name = "localhost",
        .alpn_protocols = &.{"h3"},
        .transport_parameters = encoded_tp.items,
    });

    try quic.initial_exchange.sendInitialCrypto(&client_endpoint, server_endpoint.address(), first_initial_secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_cid,
        .packet_number = 0,
        .crypto_data = client_hello.items,
        .max_crypto_frame_data_len = 1024,
        .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
    });

    var first_initial = try receiveClientInitialForTest(&server_endpoint, 0, 4096, &.{}, .version_1);
    defer first_initial.deinit(allocator);
    const retry_datagram = try quic.retry_flow.issue(allocator, .{
        .original_destination_connection_id = first_initial.packet.destination_connection_id,
        .client_source_connection_id = first_initial.packet.source_connection_id,
        .retry_source_connection_id = &retry_scid,
        .peer_address = "client-path",
        .issued_ns = 1_000,
        .lifetime_ns = 5_000,
        .nonce = retry_nonce,
        .secret = token_secret,
    });
    defer allocator.free(retry_datagram);
    try server_endpoint.sendBytes(first_initial.from, retry_datagram);

    var retry_bytes = try client_endpoint.receiveBytes();
    defer retry_bytes.deinit(allocator);
    var retry_state = try quic.retry_flow.ClientState.init(allocator, .version_1, &original_dcid, &client_cid);
    defer retry_state.deinit();
    var processed_retry = try retry_state.process(retry_bytes.bytes, .{
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .random = client_random,
        .x25519_secret_key = client_secret_key,
    });
    defer processed_retry.deinit(allocator);

    const secrets = [_]quic.address_validation_token.Secret{token_secret};
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        secrets: []const quic.address_validation_token.Secret,
        odcid: []const u8,
        rscid: []const u8,
        random: [32]u8,
        secret_key: [32]u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var established = try handshake.accept(shared.endpoint, .{
                .local_connection_id = shared.cid,
                .address_validation_secrets = shared.secrets,
                .address_validation_peer = "client-path",
                .address_validation_now_ns = 1_100,
                .retry_original_destination_connection_id = shared.odcid,
                .retry_source_connection_id = shared.rscid,
                .random = shared.random,
                .x25519_secret_key = shared.secret_key,
            });
            defer established.deinit();

            var request = try established.connection.receivePacket();
            defer request.deinit(shared.endpoint.allocator);
            try std.testing.expectEqualStrings("GET /retry", request.frames[0].stream.data);

            const response = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "RETRIED", .fin = true } }};
            try established.connection.send(&response);
        }
    };

    var shared = Shared{
        .endpoint = &server_endpoint,
        .cid = &server_cid,
        .secrets = &secrets,
        .odcid = &original_dcid,
        .rscid = &retry_scid,
        .random = server_random,
        .secret_key = server_secret_key,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(&client_endpoint, server_endpoint.address(), processed_retry.retry_client_options);
    defer established.deinit();
    try std.testing.expectEqualStrings("h3", established.alpn);

    const request = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "GET /retry", .fin = true } }};
    try established.connection.send(&request);
    var response = try established.connection.receivePacket();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqualStrings("RETRIED", response.frames[0].stream.data);
}

test "QUIC integrated client automatically processes one valid Retry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = "autoretry";
    const client_cid = "client";
    const retry_scid = "retry";
    const server_cid = "server";
    const secret: quic.address_validation_token.Secret =
        [_]u8{0xa1} ** quic.address_validation_token.secret_len;

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var first = try receiveClientInitialForTest(
                shared.endpoint,
                0,
                4096,
                &.{},
                .version_1,
            );
            defer first.deinit(shared.endpoint.allocator);
            const retry = try quic.retry_flow.issue(
                shared.endpoint.allocator,
                .{
                    .original_destination_connection_id = first.packet.destination_connection_id,
                    .client_source_connection_id = first.packet.source_connection_id,
                    .retry_source_connection_id = retry_scid,
                    .peer_address = "client-path",
                    .issued_ns = 1_000,
                    .lifetime_ns = 5_000,
                    .nonce = [_]u8{0xa2} **
                        quic.address_validation_token.nonce_len,
                    .secret = secret,
                },
            );
            defer shared.endpoint.allocator.free(retry);
            try shared.endpoint.sendBytes(first.from, retry);

            // accept() now consumes the client's automatically retransmitted
            // Initial and validates its Retry token/DCID bindings.
            var established = try handshake.accept(shared.endpoint, .{
                .local_connection_id = server_cid,
                .address_validation_secrets = &.{secret},
                .address_validation_peer = "client-path",
                .address_validation_now_ns = 1_100,
                .retry_original_destination_connection_id = original_dcid,
                .retry_source_connection_id = retry_scid,
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
            });
            defer established.deinit();
            try std.testing.expect(established.retry_processed);
            var request = try established.connection.receivePacket();
            defer request.deinit(shared.endpoint.allocator);
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = original_dcid,
            .local_connection_id = client_cid,
            .random = [_]u8{0xa5} ** 32,
            .x25519_secret_key = [_]u8{0xa6} ** 32,
        },
    );
    defer established.deinit();
    try std.testing.expect(established.retry_processed);
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
}

test "QUIC automatic Retry suppresses replayed 0-RTT but resumes PSK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = "retry0rt";
    const client_cid = "client";
    const retry_scid = "retry";
    const ticket = "retry-ticket";
    const psk = [_]u8{0xc1} ** 32;
    const secret: quic.address_validation_token.Secret =
        [_]u8{0xc2} ** quic.address_validation_token.secret_len;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1_000,
        .lifetime_seconds = 3_600,
        .age_add = 0,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1_100,
    )).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        replay_filter: *quic.zero_rtt.ReplayFilter,
        err: ?anyerror = null,
        resumed: bool = false,
        status: quic.zero_rtt.handshake.Status = .not_offered,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var first = try receiveClientInitialForTest(
                shared.endpoint,
                0,
                4096,
                &.{},
                .version_1,
            );
            defer first.deinit(shared.endpoint.allocator);
            // Initial and 0-RTT are separate datagrams. Consume the original
            // 0-RTT packet before Retry; the client must suppress a second one.
            var original_zero_rtt = try shared.endpoint.receiveBytes();
            defer original_zero_rtt.deinit(shared.endpoint.allocator);
            const zero_rtt_info =
                try quic.protection.peekProtectedLongPacketInfo(
                    original_zero_rtt.bytes,
                );
            try std.testing.expectEqual(
                quic.protection.ProtectedLongPacketType.zero_rtt,
                zero_rtt_info.packet_type,
            );
            const retry = try quic.retry_flow.issue(
                shared.endpoint.allocator,
                .{
                    .original_destination_connection_id = first.packet.destination_connection_id,
                    .client_source_connection_id = first.packet.source_connection_id,
                    .retry_source_connection_id = retry_scid,
                    .peer_address = "client-path",
                    .issued_ns = 1_000,
                    .lifetime_ns = 5_000,
                    .nonce = [_]u8{0xc3} **
                        quic.address_validation_token.nonce_len,
                    .secret = secret,
                },
            );
            defer shared.endpoint.allocator.free(retry);
            try shared.endpoint.sendBytes(first.from, retry);

            var established = try handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .address_validation_secrets = &.{secret},
                .address_validation_peer = "client-path",
                .address_validation_now_ns = 1_100,
                .retry_original_destination_connection_id = original_dcid,
                .retry_source_connection_id = retry_scid,
                .psk = .{
                    .identity = ticket,
                    .secret = psk,
                    .age_add = 0,
                    .issued_at_ms = 1_000,
                    .lifetime_seconds = 3_600,
                    .now_ms = 1_100,
                },
                .early_data = .{
                    .accept = true,
                    .replay_filter = shared.replay_filter,
                    .replay_key = "retry-request",
                },
                .random = [_]u8{0xc4} ** 32,
                .x25519_secret_key = [_]u8{0xc5} ** 32,
            });
            defer established.deinit();
            shared.resumed = established.resumed;
            shared.status = established.early_data_status;
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .replay_filter = &replay_filter,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const early_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "must-not-replay",
    } }};
    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = original_dcid,
            .local_connection_id = client_cid,
            .random = [_]u8{0xc6} ** 32,
            .x25519_secret_key = [_]u8{0xc7} ** 32,
            .resumption_now_ms = 1_100,
            .resumption_server_id = "localhost:443",
            .early_data = .{
                .cache = &cache,
                .lease = &lease,
                .frames = &early_frames,
            },
        },
    );
    defer established.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(established.resumed);
    try std.testing.expect(shared.resumed);
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        established.early_data_status,
    );
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        shared.status,
    );
    try std.testing.expectEqual(.consumed, lease.state);
}

test "QUIC integrated server automatically issues Retry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = "srvretry";
    const client_cid = "client";
    const server_cid = "server";
    const secret: quic.address_validation_token.Secret =
        [_]u8{0xd1} ** quic.address_validation_token.secret_len;
    var address_validation_replay_filter =
        try quic.address_validation_token.SharedReplayFilter.init(
            allocator,
            io,
            8,
        );
    defer address_validation_replay_filter.deinit();
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        address_validation_replay_filter: *quic.address_validation_token.SharedReplayFilter,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = server_cid,
                .retry = .{
                    .secret = secret,
                    .peer_address = "client-path",
                    .issued_ns = 1_000,
                    .lifetime_ns = 5_000,
                    .nonce = [_]u8{0xd2} **
                        quic.address_validation_token.nonce_len,
                },
                .address_validation_replay_filter = shared.address_validation_replay_filter,
                .random = [_]u8{0xd3} ** 32,
                .x25519_secret_key = [_]u8{0xd4} ** 32,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            std.testing.expect(established.retry_processed) catch |err| {
                shared.err = err;
                return;
            };
            var ping = established.connection.receivePacket() catch |err| {
                shared.err = err;
                return;
            };
            ping.deinit(shared.endpoint.allocator);
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .address_validation_replay_filter = &address_validation_replay_filter,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = original_dcid,
            .local_connection_id = client_cid,
            .random = [_]u8{0xd5} ** 32,
            .x25519_secret_key = [_]u8{0xd6} ** 32,
        },
    );
    defer established.deinit();
    try std.testing.expect(established.retry_processed);
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 1),
        address_validation_replay_filter.entryCount(),
    );
}

test "QUIC automatic server Retry discards queued pre-Retry 0-RTT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = "srv0rtry";
    const client_cid = "client";
    const ticket = "server-retry-ticket";
    const psk = [_]u8{0xe1} ** 32;
    const secret: quic.address_validation_token.Secret =
        [_]u8{0xe2} ** quic.address_validation_token.secret_len;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1_000,
        .lifetime_seconds = 3_600,
        .age_add = 0,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1_100,
    )).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        replay_filter: *quic.zero_rtt.ReplayFilter,
        err: ?anyerror = null,
        resumed: bool = false,
        status: quic.zero_rtt.handshake.Status = .not_offered,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .retry = .{
                    .secret = secret,
                    .peer_address = "client-path",
                    .issued_ns = 1_000,
                    .lifetime_ns = 5_000,
                    .nonce = [_]u8{0xe3} **
                        quic.address_validation_token.nonce_len,
                },
                .psk = .{
                    .identity = ticket,
                    .secret = psk,
                    .age_add = 0,
                    .issued_at_ms = 1_000,
                    .lifetime_seconds = 3_600,
                    .now_ms = 1_100,
                },
                .early_data = .{
                    .accept = true,
                    .replay_filter = shared.replay_filter,
                    .replay_key = "server-retry-request",
                },
                .random = [_]u8{0xe4} ** 32,
                .x25519_secret_key = [_]u8{0xe5} ** 32,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            shared.resumed = established.resumed;
            shared.status = established.early_data_status;
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .replay_filter = &replay_filter,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const early_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "discard-after-retry",
    } }};
    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = original_dcid,
            .local_connection_id = client_cid,
            .random = [_]u8{0xe6} ** 32,
            .x25519_secret_key = [_]u8{0xe7} ** 32,
            .resumption_now_ms = 1_100,
            .resumption_server_id = "localhost:443",
            .early_data = .{
                .cache = &cache,
                .lease = &lease,
                .frames = &early_frames,
            },
        },
    );
    defer established.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(established.resumed);
    try std.testing.expect(shared.resumed);
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        established.early_data_status,
    );
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        shared.status,
    );
    try std.testing.expect(established.connection.next_packet_number >= 1);
    try std.testing.expectEqual(
        @as(usize, 0),
        established.connection.stats().sent_packet_stats.tracked_packets,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        established.connection.pendingRecoveryCount(),
    );
    try std.testing.expect(established.connection.sendStreamStats(0) == null);
}

test "QUIC integrated client ignores an invalid Retry before a valid Retry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = "badretry1";
    const client_cid = "client";
    const retry_scid = "retry";
    const secret: quic.address_validation_token.Secret =
        [_]u8{0xb1} ** quic.address_validation_token.secret_len;

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var first = try receiveClientInitialForTest(
                shared.endpoint,
                0,
                4096,
                &.{},
                .version_1,
            );
            defer first.deinit(shared.endpoint.allocator);
            const valid = try quic.retry_flow.issue(
                shared.endpoint.allocator,
                .{
                    .original_destination_connection_id = first.packet.destination_connection_id,
                    .client_source_connection_id = first.packet.source_connection_id,
                    .retry_source_connection_id = retry_scid,
                    .peer_address = "client-path",
                    .issued_ns = 1_000,
                    .lifetime_ns = 5_000,
                    .nonce = [_]u8{0xb2} **
                        quic.address_validation_token.nonce_len,
                    .secret = secret,
                },
            );
            defer shared.endpoint.allocator.free(valid);
            const invalid = try shared.endpoint.allocator.dupe(u8, valid);
            defer shared.endpoint.allocator.free(invalid);
            invalid[invalid.len - 1] ^= 1;
            try shared.endpoint.sendBytes(first.from, invalid);
            try shared.endpoint.sendBytes(first.from, valid);

            var established = try handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .address_validation_secrets = &.{secret},
                .address_validation_peer = "client-path",
                .address_validation_now_ns = 1_100,
                .retry_original_destination_connection_id = original_dcid,
                .retry_source_connection_id = retry_scid,
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            });
            defer established.deinit();
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = original_dcid,
            .local_connection_id = client_cid,
            .random = [_]u8{0xb5} ** 32,
            .x25519_secret_key = [_]u8{0xb6} ** 32,
        },
    );
    established.deinit();
    thread.join();
    if (shared.err) |err| return err;
}

test "QUIC integrated server rejects invalid first client Initial datagrams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var short_server = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer short_server.deinit();
    var short_client = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer short_client.deinit();

    const valid_dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const client_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const short_keys = quic.protection.deriveInitialSecrets(&valid_dcid).client;
    try quic.initial_exchange.sendInitialCrypto(&short_client, short_server.address(), short_keys, .{
        .destination_connection_id = &valid_dcid,
        .source_connection_id = &client_cid,
        .packet_number = 0,
        .crypto_data = "too small",
    });
    try std.testing.expectError(
        error.HandshakeTimeout,
        handshake.acceptWithTimeout(
            &short_server,
            .{
                .local_connection_id = "srv1",
                .random = [_]u8{0x52} ** 32,
                .x25519_secret_key = [_]u8{0x53} ** 32,
            },
            .fromMilliseconds(10),
        ),
    );

    var dcid_server = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer dcid_server.deinit();
    var dcid_client = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer dcid_client.deinit();

    const short_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const short_dcid_keys = quic.protection.deriveInitialSecrets(&short_dcid).client;
    try quic.initial_exchange.sendInitialCrypto(&dcid_client, dcid_server.address(), short_dcid_keys, .{
        .destination_connection_id = &short_dcid,
        .source_connection_id = &client_cid,
        .packet_number = 0,
        .crypto_data = "bad dcid",
        .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
    });
    try std.testing.expectError(
        error.HandshakeTimeout,
        handshake.acceptWithTimeout(
            &dcid_server,
            .{
                .local_connection_id = "srv2",
                .random = [_]u8{0x54} ** 32,
                .x25519_secret_key = [_]u8{0x55} ** 32,
            },
            .fromMilliseconds(10),
        ),
    );
}

test "QUIC integrated server ignores unauthenticated Initial before client" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const CorruptFirstInitial = struct {
        count: usize = 0,

        fn corrupt(context: *anyopaque, bytes: []u8) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.count != 0 or bytes.len == 0 or
                (bytes[0] & 0x80) == 0) return false;
            self.count += 1;
            bytes[bytes.len - 1] ^= 0x80;
            return true;
        }
    };
    var corrupt_first = CorruptFirstInitial{};
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .send_interceptor = .{
                .context = &corrupt_first,
                .corrupt = CorruptFirstInitial.corrupt,
            },
        },
    );
    defer client_endpoint.deinit();

    const original_dcid = "noisecli";
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.acceptWithTimeout(
                shared.endpoint,
                .{
                    .local_connection_id = "server",
                    .random = [_]u8{0xc1} ** 32,
                    .x25519_secret_key = [_]u8{0xc2} ** 32,
                },
                .fromSeconds(2),
            ) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = original_dcid,
            .local_connection_id = "client",
            .random = [_]u8{0xc3} ** 32,
            .x25519_secret_key = [_]u8{0xc4} ** 32,
        },
    );
    established.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), corrupt_first.count);
}

test "QUIC integrated client ignores unauthenticated server Initial" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const CorruptFirstInitial = struct {
        count: usize = 0,

        fn corrupt(context: *anyopaque, bytes: []u8) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.count != 0 or bytes.len == 0 or
                (bytes[0] & 0x80) == 0) return false;
            self.count += 1;
            bytes[bytes.len - 1] ^= 0x80;
            return true;
        }
    };
    var corrupt_first = CorruptFirstInitial{};
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .send_interceptor = .{
                .context = &corrupt_first,
                .corrupt = CorruptFirstInitial.corrupt,
            },
        },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const recovery = @import("../handshake/retransmit.zig").Config{
        .initial_pto_ms = 10,
        .max_pto_ms = 20,
        .max_retries = 3,
    };
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        recovery: @import("../handshake/retransmit.zig").Config,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xd1} ** 32,
                .x25519_secret_key = [_]u8{0xd2} ** 32,
                .handshake_recovery = shared.recovery,
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .recovery = recovery,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "noisesrv",
            .local_connection_id = "client",
            .random = [_]u8{0xd3} ** 32,
            .x25519_secret_key = [_]u8{0xd4} ** 32,
            .handshake_recovery = recovery,
        },
    );
    established.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), corrupt_first.count);
}

test "QUIC integrated handshake applies negotiated transport parameters over QUIC v2" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3 };
    const server_cid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3 };

    var client_tp = quic.practical_transport_parameters;
    client_tp.max_idle_timeout = 70;
    client_tp.ack_delay_exponent = 5;
    client_tp.max_ack_delay = 35;
    client_tp.initial_max_data = 30;
    client_tp.initial_max_stream_data_bidi_local = 11;
    client_tp.initial_max_stream_data_bidi_remote = 12;
    client_tp.initial_max_stream_data_uni = 13;
    client_tp.max_datagram_frame_size = 777;
    client_tp.grease_quic_bit = true;
    client_tp.min_ack_delay = 1_000;

    var server_tp = quic.practical_transport_parameters;
    const server_reset_token = [_]u8{0x9a} **
        quic.stateless_reset.token_len;
    server_tp.stateless_reset_token = server_reset_token;
    server_tp.max_idle_timeout = 40;
    server_tp.ack_delay_exponent = 7;
    server_tp.max_ack_delay = 45;
    server_tp.disable_active_migration = true;
    server_tp.initial_max_data = 40;
    server_tp.initial_max_stream_data_bidi_local = 21;
    server_tp.initial_max_stream_data_bidi_remote = 22;
    server_tp.initial_max_stream_data_uni = 23;
    server_tp.max_udp_payload_size = 1400;
    server_tp.max_datagram_frame_size = 888;
    server_tp.grease_quic_bit = true;
    server_tp.min_ack_delay = 2_000;

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        params: quic.TransportParameters,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.endpoint, shared.cid, shared.params) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(endpoint: *quic.runtime.Endpoint, cid: []const u8, params: quic.TransportParameters) !void {
            var established = try handshake.accept(endpoint, .{
                .local_connection_id = cid,
                .local_transport_parameters = params,
                .version = .version_2,
                .initial_one_rtt_config = .{ .enable_pacing = false },
                .random = [_]u8{0x72} ** 32,
                .x25519_secret_key = [_]u8{0x74} ** 32,
            });
            defer established.deinit();

            try std.testing.expectEqual(quic.one_rtt.ConnectionConfig.EndpointRole.server, established.connection.config.local_endpoint);
            try std.testing.expectEqual(@as(u64, 30), established.connection.send_flow.limit);
            try std.testing.expectEqual(@as(u64, 40), established.connection.recv_flow.limit);
            try std.testing.expectEqual(@as(?u64, 11), established.connection.config.initial_send_max_stream_data_bidi_local);
            try std.testing.expectEqual(@as(?u64, 21), established.connection.config.initial_receive_max_stream_data_bidi_local);
            try std.testing.expectEqual(@as(?u64, 600), established.connection.effectiveIdleTimeoutMillis());
            try std.testing.expectEqual(@as(u64, 7), established.connection.config.local_ack_delay_exponent);
            try std.testing.expectEqual(@as(u64, 5), established.connection.config.peer_ack_delay_exponent);
            try std.testing.expectEqual(@as(u64, 35), established.connection.config.peer_max_ack_delay_ms);
            try std.testing.expect(established.connection.localActiveMigrationDisabled());
            try std.testing.expect(!established.connection.peerActiveMigrationDisabled());
            try std.testing.expectEqual(@as(?usize, 888), established.connection.config.local_max_datagram_frame_size);
            try std.testing.expectEqual(@as(?usize, 777), established.connection.config.peer_max_datagram_frame_size);
            try std.testing.expect(established.connection.config.accept_zero_fixed_bit);
            try std.testing.expect(established.connection.config.grease_fixed_bit);
            try std.testing.expect(established.connection.config.enable_ack_frequency);
            try std.testing.expectEqual(@as(?u64, 2_000), established.connection.config.local_min_ack_delay);
            try std.testing.expectEqual(@as(?u64, 1_000), established.connection.config.peer_min_ack_delay);
            try std.testing.expectEqual(
                @as(?[quic.stateless_reset.token_len]u8, null),
                established.connection.config.peer_stateless_reset_token,
            );
            try std.testing.expectEqual(quic.congestion.Algorithm.cubic, established.connection.congestionAlgorithm());
            try std.testing.expect(established.connection.hystartEnabled());
            try std.testing.expect(!established.connection.pacingEnabled());
        }
    };

    var shared = Shared{ .endpoint = &server_endpoint, .cid = &server_cid, .params = server_tp };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(&client_endpoint, server_endpoint.address(), .{
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .local_transport_parameters = client_tp,
        .version = .version_2,
        .initial_one_rtt_config = .{ .enable_pacing = false },
        .random = [_]u8{0x71} ** 32,
        .x25519_secret_key = [_]u8{0x73} ** 32,
    });
    defer established.deinit();

    try std.testing.expectEqual(quic.one_rtt.ConnectionConfig.EndpointRole.client, established.connection.config.local_endpoint);
    try std.testing.expectEqual(@as(u64, 40), established.connection.send_flow.limit);
    try std.testing.expectEqual(@as(u64, 30), established.connection.recv_flow.limit);
    try std.testing.expectEqual(@as(?u64, 22), established.connection.config.initial_send_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(?u64, 11), established.connection.config.initial_receive_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(?u64, 600), established.connection.effectiveIdleTimeoutMillis());
    try std.testing.expectEqual(@as(u64, 5), established.connection.config.local_ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 7), established.connection.config.peer_ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 45), established.connection.config.peer_max_ack_delay_ms);
    try std.testing.expect(!established.connection.localActiveMigrationDisabled());
    try std.testing.expect(established.connection.peerActiveMigrationDisabled());
    try std.testing.expectEqual(@as(?usize, 777), established.connection.config.local_max_datagram_frame_size);
    try std.testing.expectEqual(@as(?usize, 888), established.connection.config.peer_max_datagram_frame_size);
    try std.testing.expect(established.connection.config.accept_zero_fixed_bit);
    try std.testing.expect(established.connection.config.grease_fixed_bit);
    try std.testing.expect(established.connection.config.enable_ack_frequency);
    try std.testing.expectEqual(@as(?u64, 1_000), established.connection.config.local_min_ack_delay);
    try std.testing.expectEqual(@as(?u64, 2_000), established.connection.config.peer_min_ack_delay);
    try std.testing.expectEqual(
        @as(?[quic.stateless_reset.token_len]u8, server_reset_token),
        established.connection.config.peer_stateless_reset_token,
    );
    var reset_datagram = [_]u8{0x40} **
        quic.stateless_reset.min_datagram_len;
    @memcpy(
        reset_datagram[reset_datagram.len - server_reset_token.len ..],
        &server_reset_token,
    );
    try std.testing.expectEqual(
        @as(?u64, 0),
        established.connection.detectStatelessReset(&reset_datagram),
    );
    try std.testing.expectEqual(@as(usize, 1200), established.connection.congestion.max_datagram_size);
    try std.testing.expectEqual(quic.congestion.Algorithm.cubic, established.connection.congestionAlgorithm());
    try std.testing.expect(established.connection.hystartEnabled());
    try std.testing.expect(!established.connection.pacingEnabled());
    try std.testing.expectError(error.FlowControlBlocked, established.connection.send(&[_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "this exceeds server's stream credit",
        .fin = false,
    } }}));

    thread.join();
    if (shared.err) |err| return err;
}

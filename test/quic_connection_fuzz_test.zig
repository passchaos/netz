//! Bounded stateful QUIC 1-RTT connection fuzzing.
//!
//! Each input creates two real loopback UDP endpoints and two production
//! `Connection` values. Sends use the normal packet-protection and recovery
//! path, while a bounded scheduler captures datagrams and chooses delivery,
//! loss, reordering, duplication, corruption, ACKs, PTO, and key updates.

const std = @import("std");
const netz = @import("netz");

const quic = netz.quic;
const one_rtt = quic.one_rtt;
const max_operations = 48;
const max_sequence_bytes = max_operations + 2;
const receive_timeout = std.Io.Duration.fromMilliseconds(100);
const time_step_ns = std.time.ns_per_ms;

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const loss_recovery_seed = smithSliceSeed(&.{
    0, 0, // AES-128, QUIC v1.
    0, 10, 18, 6, 17, 7, 22, // Drop STREAM, deliver PTO, ACK, drain.
    2, 6, 17, 7, 22, // FIN and acknowledgement.
});
const reorder_seed = smithSliceSeed(&.{
    1, 1, // AES-256, QUIC v2.
    0, 0, 8, 6, 17, 7, 22, // Deliver packet 1 before packet 0.
    1, 1, 9, 7, 16, 6, 22, // Exercise the reverse direction too.
});
const key_update_seed = smithSliceSeed(&.{
    2, 0, // ChaCha20-Poly1305, QUIC v1.
    20, 4, 6, 17, 7, // Client update and its ACK gate.
    21, 5, 7,  16, 6, // Server update and its ACK gate.
    0,  6, 17, 7,  22,
});
const hostile_delivery_seed = smithSliceSeed(&.{
    3, 1, // SM4-GCM, QUIC v2.
    4, 12, // Corrupt an authenticated client packet.
    5,  15, // Deliver then duplicate a server packet.
    0,  0,
    8,  6,
    17, 7,
    22,
});
const client_reset_seed = smithSliceSeed(&.{
    0, 0, // AES-128, QUIC v1.
    0, 6, 0xfe, 6, 22, 17, 7, // Client STREAM then RESET_STREAM.
});
const server_reset_seed = smithSliceSeed(&.{
    0, 0, // AES-128, QUIC v1.
    1, 7, 0xff, 7, 22, 16, 6, // Server STREAM then RESET_STREAM.
});
const overlapping_key_update_seed = smithSliceSeed(&.{
    49,  208, // AES-256, QUIC v1.
    107, 95,
    89,  171,
    15,  216,
    43,  130,
    52,  165,
    173, 95,
    131, 201,
    146, 160,
    26,  128,
    0,   125,
    24,  62,
    58,  124,
    117, 78,
    2,   73,
    4,   10,
    169, 19,
    31,  110,
    171, 115,
    249, 48,
    74,  180,
    66,  158,
    42,  27,
});

const corpus = &.{
    &loss_recovery_seed,
    &reorder_seed,
    &key_update_seed,
    &hostile_delivery_seed,
    &client_reset_seed,
    &server_reset_seed,
    &overlapping_key_update_seed,
};

test "structured stateful QUIC connection sequences reach target states" {
    const loss = try runSequence(loss_recovery_seed[4..]);
    try std.testing.expect(loss.dropped != 0);
    try std.testing.expect(loss.pto_packets != 0);
    try std.testing.expect(loss.application_bytes != 0);

    const reordered = try runSequence(reorder_seed[4..]);
    try std.testing.expect(reordered.reordered != 0);
    try std.testing.expect(reordered.application_bytes >= 2);

    const updated = try runSequence(key_update_seed[4..]);
    try std.testing.expect(updated.key_updates >= 2);

    const hostile = try runSequence(hostile_delivery_seed[4..]);
    try std.testing.expect(hostile.corrupted != 0);
    try std.testing.expect(hostile.duplicates != 0);

    const client_reset = try runSequence(client_reset_seed[4..]);
    try std.testing.expectEqual(@as(usize, 1), client_reset.client_resets);
    const server_reset = try runSequence(server_reset_seed[4..]);
    try std.testing.expectEqual(@as(usize, 1), server_reset.server_resets);

    const overlapping = try runSequence(overlapping_key_update_seed[4..]);
    try std.testing.expect(overlapping.key_updates >= 4);
    try std.testing.expect(overlapping.delivered != 0);
}

test "fuzz bounded stateful QUIC connections" {
    try std.testing.fuzz({}, fuzzConnections, .{ .corpus = corpus });
}

test "bounded deterministic stateful QUIC connection mutation smoke" {
    var mutated: [max_sequence_bytes]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (0..seed.len + 1) |length| _ = try runSequence(seed[0..length]);
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try runSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [max_sequence_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x717569635f737461);
    const random = prng.random();
    for (0..8) |_| {
        const length = random.uintLessThan(usize, max_sequence_bytes + 1);
        random.bytes(random_bytes[0..length]);
        _ = try runSequence(random_bytes[0..length]);
    }
}

fn fuzzConnections(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_sequence_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try runSequence(bytes);
}

const Summary = struct {
    delivered: usize = 0,
    dropped: usize = 0,
    reordered: usize = 0,
    corrupted: usize = 0,
    duplicates: usize = 0,
    pto_packets: usize = 0,
    key_updates: usize = 0,
    application_bytes: usize = 0,
    client_resets: usize = 0,
    server_resets: usize = 0,
};

const StreamModel = struct {
    sent: [max_operations]u8 = undefined,
    sent_len: usize = 0,
    received_len: usize = 0,
    fin_sent: bool = false,
    fin_received: bool = false,
    reset_sent: bool = false,
    reset_received: bool = false,
    reset_error_code: u64 = 0,

    fn append(self: *StreamModel, byte: u8) void {
        std.debug.assert(self.sent_len < self.sent.len);
        self.sent[self.sent_len] = byte;
        self.sent_len += 1;
    }
};

const Direction = enum { client_to_server, server_to_client };

const Harness = struct {
    allocator: std.mem.Allocator,
    client_endpoint: *quic.runtime.Endpoint,
    server_endpoint: *quic.runtime.Endpoint,
    client: *one_rtt.Connection,
    server: *one_rtt.Connection,
    client_to_server: std.ArrayList(quic.runtime.OwnedBytes) = .empty,
    server_to_client: std.ArrayList(quic.runtime.OwnedBytes) = .empty,
    client_stream: StreamModel = .{},
    server_stream: StreamModel = .{},
    client_ack_eliciting_received: usize = 0,
    server_ack_eliciting_received: usize = 0,
    now_ns: u64 = time_step_ns,
    summary: Summary = .{},

    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        version: quic.Version,
        suite: quic.protection.CipherSuite,
    ) !Harness {
        const client_endpoint = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(client_endpoint);
        client_endpoint.* = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        errdefer client_endpoint.deinit();
        const server_endpoint = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(server_endpoint);
        server_endpoint.* = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        errdefer server_endpoint.deinit();

        const client_keys = try deriveKeys(version, suite, 0x51);
        const server_keys = try deriveKeys(version, suite, 0xa7);
        const client_cid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
        const server_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
        const client = try allocator.create(one_rtt.Connection);
        errdefer allocator.destroy(client);
        client.* = try one_rtt.Connection.init(client_endpoint, .{
            .version = version,
            .peer = server_endpoint.address(),
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .initial_send_max_data = max_operations,
            .initial_receive_max_data = max_operations,
            .initial_send_max_stream_data = max_operations,
            .initial_receive_max_stream_data = max_operations,
            .initial_send_max_streams_bidi = 1,
            .initial_receive_max_streams_bidi = 1,
            .enable_pacing = false,
            .automatic_ecn_policy = .disabled,
        });
        errdefer client.deinit();
        const server = try allocator.create(one_rtt.Connection);
        errdefer allocator.destroy(server);
        server.* = try one_rtt.Connection.init(server_endpoint, .{
            .version = version,
            .peer = client_endpoint.address(),
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_endpoint = .server,
            .initial_send_max_data = max_operations,
            .initial_receive_max_data = max_operations,
            .initial_send_max_stream_data = max_operations,
            .initial_receive_max_stream_data = max_operations,
            .initial_send_max_streams_bidi = 1,
            .initial_receive_max_streams_bidi = 1,
            .enable_pacing = false,
            .automatic_ecn_policy = .disabled,
        });
        errdefer server.deinit();

        return .{
            .allocator = allocator,
            .client_endpoint = client_endpoint,
            .server_endpoint = server_endpoint,
            .client = client,
            .server = server,
        };
    }

    fn deinit(self: *Harness) void {
        self.deinitQueue(&self.client_to_server);
        self.deinitQueue(&self.server_to_client);
        self.client.deinit();
        self.allocator.destroy(self.client);
        self.server.deinit();
        self.allocator.destroy(self.server);
        self.client_endpoint.deinit();
        self.allocator.destroy(self.client_endpoint);
        self.server_endpoint.deinit();
        self.allocator.destroy(self.server_endpoint);
        self.* = undefined;
    }

    fn deinitQueue(
        self: *Harness,
        datagrams: *std.ArrayList(quic.runtime.OwnedBytes),
    ) void {
        for (datagrams.items) |*datagram| datagram.deinit(self.allocator);
        datagrams.deinit(self.allocator);
    }

    fn advanceTime(self: *Harness) void {
        self.now_ns +|= time_step_ns;
    }

    fn sendStreamByte(self: *Harness, direction: Direction, byte: u8) !void {
        const connection, const model, const stream_id = switch (direction) {
            .client_to_server => .{ self.client, &self.client_stream, @as(u64, 0) },
            .server_to_client => .{ self.server, &self.server_stream, @as(u64, 1) },
        };
        if (model.fin_sent or model.reset_sent or
            model.sent_len == model.sent.len) return;
        var payload = [_]u8{byte};
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = model.sent_len,
            .data = &payload,
        } }};
        if (!try self.sendAndCapture(direction, connection, &frames)) return;
        model.append(byte);
    }

    fn sendFin(self: *Harness, direction: Direction) !void {
        const connection, const model, const stream_id = switch (direction) {
            .client_to_server => .{ self.client, &self.client_stream, @as(u64, 0) },
            .server_to_client => .{ self.server, &self.server_stream, @as(u64, 1) },
        };
        if (model.fin_sent or model.reset_sent) return;
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = model.sent_len,
            .data = &.{},
            .fin = true,
        } }};
        if (!try self.sendAndCapture(direction, connection, &frames)) return;
        model.fin_sent = true;
    }

    fn sendReset(
        self: *Harness,
        direction: Direction,
        error_code: u64,
    ) !void {
        const connection, const model, const stream_id = switch (direction) {
            .client_to_server => .{ self.client, &self.client_stream, @as(u64, 0) },
            .server_to_client => .{ self.server, &self.server_stream, @as(u64, 1) },
        };
        if (model.fin_sent or model.reset_sent) return;
        connection.resetStream(stream_id, error_code) catch |err| switch (err) {
            error.CongestionLimited => return,
            else => |other| return other,
        };
        try self.capture(direction);
        model.reset_sent = true;
        model.reset_error_code = error_code;
    }

    fn sendPing(self: *Harness, direction: Direction) !void {
        const connection = switch (direction) {
            .client_to_server => self.client,
            .server_to_client => self.server,
        };
        _ = try self.sendAndCapture(
            direction,
            connection,
            &.{.{ .ping = {} }},
        );
    }

    fn sendAck(self: *Harness, direction: Direction) !void {
        const connection, const pending = switch (direction) {
            .client_to_server => .{ self.client, &self.client_ack_eliciting_received },
            .server_to_client => .{ self.server, &self.server_ack_eliciting_received },
        };
        if (pending.* == 0) return;
        connection.sendAck(0) catch |err| switch (err) {
            error.CongestionLimited => return,
            else => |other| return other,
        };
        try self.capture(direction);
        pending.* = 0;
    }

    fn retransmitPto(self: *Harness, direction: Direction) !void {
        const connection = switch (direction) {
            .client_to_server => self.client,
            .server_to_client => self.server,
        };
        const sent = connection.retransmitPtoAt(self.now_ns) catch |err| switch (err) {
            error.CongestionLimited => return,
            else => |other| return other,
        };
        if (!sent) return;
        try self.capture(direction);
        self.summary.pto_packets += 1;
    }

    fn initiateKeyUpdate(self: *Harness, direction: Direction) !void {
        const connection = switch (direction) {
            .client_to_server => self.client,
            .server_to_client => self.server,
        };
        if (connection.pendingOneRttKeyUpdateAckThreshold() != null) return;
        try connection.initiateKeyUpdate();
    }

    fn sendAndCapture(
        self: *Harness,
        direction: Direction,
        connection: *one_rtt.Connection,
        frames: []const quic.Frame,
    ) !bool {
        connection.sendAt(frames, self.now_ns) catch |err| switch (err) {
            error.CongestionLimited, error.FlowControlBlocked => return false,
            else => |other| return other,
        };
        try self.capture(direction);
        return true;
    }

    fn capture(self: *Harness, direction: Direction) !void {
        const endpoint, const datagrams = switch (direction) {
            .client_to_server => .{
                self.server_endpoint,
                &self.client_to_server,
            },
            .server_to_client => .{
                self.client_endpoint,
                &self.server_to_client,
            },
        };
        var datagram = try endpoint.receiveBytesWithTimeout(receive_timeout);
        errdefer datagram.deinit(self.allocator);
        try datagrams.append(self.allocator, datagram);
    }

    fn drop(self: *Harness, direction: Direction) void {
        const datagrams = self.queueForDirection(direction);
        if (datagrams.items.len == 0) return;
        var datagram = datagrams.orderedRemove(0);
        datagram.deinit(self.allocator);
        self.summary.dropped += 1;
    }

    fn deliver(self: *Harness, direction: Direction, newest: bool) !void {
        const datagrams = self.queueForDirection(direction);
        if (datagrams.items.len == 0) return;
        const index = if (newest) datagrams.items.len - 1 else 0;
        if (newest and index != 0) self.summary.reordered += 1;
        var datagram = datagrams.orderedRemove(index);
        defer datagram.deinit(self.allocator);
        _ = try self.processValid(direction, &datagram);
    }

    fn corrupt(self: *Harness, direction: Direction) !void {
        const datagrams = self.queueForDirection(direction);
        if (datagrams.items.len == 0) return;
        var datagram = datagrams.orderedRemove(0);
        defer datagram.deinit(self.allocator);
        datagram.bytes[datagram.bytes.len - 1] ^= 1;
        const connection = self.receiver(direction);
        if (one_rtt.testing.processReceivedBytesAt(
            connection,
            datagram.from,
            datagram.bytes,
            datagram.ecn,
            self.now_ns,
        )) |packet_value| {
            var packet = packet_value;
            packet.deinit(self.allocator);
            return error.MutatedPacketAccepted;
        } else |err| try std.testing.expectEqual(
            error.AuthenticationFailed,
            err,
        );
        self.summary.corrupted += 1;
    }

    fn duplicate(self: *Harness, direction: Direction) !void {
        const datagrams = self.queueForDirection(direction);
        if (datagrams.items.len == 0) return;
        var datagram = datagrams.orderedRemove(0);
        defer datagram.deinit(self.allocator);
        if (!try self.processValid(direction, &datagram)) return;
        try std.testing.expectError(
            error.DuplicatePacket,
            one_rtt.testing.processReceivedBytesAt(
                self.receiver(direction),
                datagram.from,
                datagram.bytes,
                datagram.ecn,
                self.now_ns,
            ),
        );
        self.summary.duplicates += 1;
    }

    fn processValid(
        self: *Harness,
        direction: Direction,
        datagram: *quic.runtime.OwnedBytes,
    ) !bool {
        var packet = one_rtt.testing.processReceivedBytesAt(
            self.receiver(direction),
            datagram.from,
            datagram.bytes,
            datagram.ecn,
            self.now_ns,
        ) catch |err| switch (err) {
            // A packet delayed across more than one key generation is no
            // longer decryptable after the bounded previous-key retention.
            error.AuthenticationFailed,
            // Packet-number reconstruction can identify an extremely delayed
            // wire packet as one already accepted. Duplicate delivery is an
            // ordinary network condition and must not abort the fuzz run.
            error.DuplicatePacket,
            => return false,
            else => |other| return other,
        };
        defer packet.deinit(self.allocator);
        if (packetAckEliciting(packet.frames)) {
            switch (direction) {
                .client_to_server => self.server_ack_eliciting_received += 1,
                .server_to_client => self.client_ack_eliciting_received += 1,
            }
        }
        self.summary.delivered += 1;
        return true;
    }

    fn drainStreams(self: *Harness) !void {
        try self.drainStream(
            self.server,
            0,
            &self.client_stream,
            .client_to_server,
        );
        try self.drainStream(
            self.client,
            1,
            &self.server_stream,
            .server_to_client,
        );
    }

    fn drainStream(
        self: *Harness,
        connection: *one_rtt.Connection,
        stream_id: u62,
        model: *StreamModel,
        direction: Direction,
    ) !void {
        var storage: [8]u8 = undefined;
        while (try connection.pollStreamId(stream_id, &storage)) |event| {
            switch (event) {
                .data => |data| {
                    try std.testing.expectEqual(stream_id, data.stream_id);
                    const end = model.received_len + data.bytes;
                    try std.testing.expect(end <= model.sent_len);
                    try std.testing.expectEqualSlices(
                        u8,
                        model.sent[model.received_len..end],
                        storage[0..data.bytes],
                    );
                    model.received_len = end;
                    self.summary.application_bytes += data.bytes;
                    if (data.fin) {
                        try std.testing.expect(model.fin_sent);
                        try std.testing.expectEqual(model.sent_len, end);
                        try std.testing.expect(!model.fin_received);
                        model.fin_received = true;
                    }
                },
                .reset => |reset| {
                    try std.testing.expectEqual(stream_id, reset.stream_id);
                    try std.testing.expect(model.reset_sent);
                    try std.testing.expect(!model.reset_received);
                    try std.testing.expectEqual(
                        model.reset_error_code,
                        reset.application_error_code,
                    );
                    try std.testing.expectEqual(
                        @as(u64, @intCast(model.sent_len)),
                        reset.final_size,
                    );
                    model.reset_received = true;
                    switch (direction) {
                        .client_to_server => self.summary.client_resets += 1,
                        .server_to_client => self.summary.server_resets += 1,
                    }
                },
            }
        }
    }

    fn validate(self: *Harness) !void {
        try self.drainStreams();
        const client_stats = self.client.stats();
        const server_stats = self.server.stats();
        self.summary.key_updates =
            @intCast(client_stats.local_key_update_count +
                server_stats.local_key_update_count);
        try std.testing.expect(
            server_stats.packets_received <= client_stats.packets_sent,
        );
        try std.testing.expect(
            client_stats.packets_received <= server_stats.packets_sent,
        );
        try std.testing.expect(client_stats.active_send_streams <= 1);
        try std.testing.expect(client_stats.active_receive_streams <= 1);
        try std.testing.expect(server_stats.active_send_streams <= 1);
        try std.testing.expect(server_stats.active_receive_streams <= 1);
        try std.testing.expect(
            one_rtt.testing.expectedPacketNumber(self.server) <=
                one_rtt.testing.nextPacketNumber(self.client),
        );
        try std.testing.expect(
            one_rtt.testing.expectedPacketNumber(self.client) <=
                one_rtt.testing.nextPacketNumber(self.server),
        );
        try std.testing.expect(
            server_stats.peer_key_update_count <=
                client_stats.local_key_update_count,
        );
        try std.testing.expect(
            client_stats.peer_key_update_count <=
                server_stats.local_key_update_count,
        );
    }

    fn queueForDirection(
        self: *Harness,
        direction: Direction,
    ) *std.ArrayList(quic.runtime.OwnedBytes) {
        return switch (direction) {
            .client_to_server => &self.client_to_server,
            .server_to_client => &self.server_to_client,
        };
    }

    fn receiver(
        self: *Harness,
        direction: Direction,
    ) *one_rtt.Connection {
        return switch (direction) {
            .client_to_server => self.server,
            .server_to_client => self.client,
        };
    }
};

fn runSequence(bytes: []const u8) !Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const version: quic.Version = if ((byteAt(bytes, 1) & 1) == 0)
        .version_1
    else
        .version_2;
    const suite = selectedSuite(byteAt(bytes, 0));
    var harness = try Harness.init(allocator, threaded.io(), version, suite);
    defer harness.deinit();

    const operations = bytes[@min(bytes.len, 2)..@min(bytes.len, max_sequence_bytes)];
    for (operations) |byte| {
        harness.advanceTime();
        if (byte == 0xfe) {
            try harness.sendReset(.client_to_server, 0x101);
            try harness.validate();
            continue;
        }
        if (byte == 0xff) {
            try harness.sendReset(.server_to_client, 0x102);
            try harness.validate();
            continue;
        }
        switch (byte % 24) {
            0 => try harness.sendStreamByte(.client_to_server, byte),
            1 => try harness.sendStreamByte(.server_to_client, byte),
            2 => try harness.sendFin(.client_to_server),
            3 => try harness.sendFin(.server_to_client),
            4 => try harness.sendPing(.client_to_server),
            5 => try harness.sendPing(.server_to_client),
            6 => try harness.deliver(.client_to_server, false),
            7 => try harness.deliver(.server_to_client, false),
            8 => try harness.deliver(.client_to_server, true),
            9 => try harness.deliver(.server_to_client, true),
            10 => harness.drop(.client_to_server),
            11 => harness.drop(.server_to_client),
            12 => try harness.corrupt(.client_to_server),
            13 => try harness.corrupt(.server_to_client),
            14 => try harness.duplicate(.client_to_server),
            15 => try harness.duplicate(.server_to_client),
            16 => try harness.sendAck(.client_to_server),
            17 => try harness.sendAck(.server_to_client),
            18 => try harness.retransmitPto(.client_to_server),
            19 => try harness.retransmitPto(.server_to_client),
            20 => try harness.initiateKeyUpdate(.client_to_server),
            21 => try harness.initiateKeyUpdate(.server_to_client),
            22 => try harness.drainStreams(),
            23 => try harness.validate(),
            else => unreachable,
        }
        try harness.validate();
    }
    try harness.validate();
    return harness.summary;
}

fn selectedSuite(byte: u8) quic.protection.CipherSuite {
    return switch (byte & 0x03) {
        0 => .aes_128_gcm_sha256,
        1 => .aes_256_gcm_sha384,
        2 => .chacha20_poly1305_sha256,
        3 => .sm4_gcm_sm3,
        else => unreachable,
    };
}

fn packetAckEliciting(frames: []const quic.Frame) bool {
    for (frames) |frame| switch (frame) {
        .padding, .ack, .connection_close, .application_close => {},
        else => return true,
    };
    return false;
}

fn deriveKeys(
    version: quic.Version,
    suite: quic.protection.CipherSuite,
    fill: u8,
) !quic.protection.PacketProtectionKeys {
    const secret = switch (suite.hash()) {
        .sha256 => quic.tls.secret.Secret.fromSha256([_]u8{fill} ** 32),
        .sha384 => quic.tls.secret.Secret.fromSha384([_]u8{fill} ** 48),
        .sm3 => quic.tls.secret.Secret.fromSm3([_]u8{fill} ** 32),
    };
    return quic.protection.deriveKeysForSecretForVersion(
        version.wireValue(),
        suite,
        secret,
    );
}

fn byteAt(bytes: []const u8, index: usize) u8 {
    return if (bytes.len == 0) 0 else bytes[index % bytes.len];
}

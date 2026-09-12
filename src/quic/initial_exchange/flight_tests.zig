const std = @import("std");
const quic = @import("../mod.zig");
const target = @import("flight.zig");

const net = std.Io.net;

const AcceptFirstFlightDatagram = struct {
    delegate: std.Io,
    partial_once: bool = true,

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (!self.partial_once or messages.len < 2) {
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
        self.partial_once = false;
        const send_error, const sent_count = self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages[0..1],
            flags,
        );
        if (send_error != null or sent_count != 1) {
            return .{ send_error orelse error.Unexpected, sent_count };
        }
        return .{ error.NetworkDown, 1 };
    }
};

test "Initial CRYPTO flight stays within MTU and reassembles" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = target.min_initial_udp_datagram_size },
    );
    defer server.deinit();
    var client = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = target.min_initial_udp_datagram_size },
    );
    defer client.deinit();

    const dcid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const scid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const keys = quic.protection.deriveInitialSecrets(&dcid).client;
    var handshake_message: [2604]u8 = undefined;
    handshake_message[0] = 1;
    handshake_message[1] = 0;
    handshake_message[2] = 0x0a;
    handshake_message[3] = 0x28;
    for (handshake_message[4..], 0..) |*byte, index| {
        byte.* = @truncate(index);
    }

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        err: ?anyerror = null,
        packet_count: usize = 0,
        received: [2604]u8 = undefined,

        fn run(shared: *@This()) void {
            var flight = target.receive(
                shared.endpoint,
                shared.keys,
                .{
                    .expected_packet_number = 9,
                    .max_crypto_buffer = shared.received.len,
                    .min_datagram_size = target.min_initial_udp_datagram_size,
                },
            ) catch |err| {
                shared.err = err;
                return;
            };
            defer flight.deinit(shared.endpoint.allocator);
            shared.packet_count = flight.packet_count;
            if (flight.crypto_data.len != shared.received.len) {
                shared.err = error.TestUnexpectedResult;
                return;
            }
            @memcpy(&shared.received, flight.crypto_data);
        }
    };
    var shared = Shared{ .endpoint = &server, .keys = keys };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const sent = try target.send(
        &client,
        server.address(),
        keys,
        .{
            .initial = .{
                .destination_connection_id = &dcid,
                .source_connection_id = &scid,
                .packet_number = 9,
                .crypto_data = &handshake_message,
                .min_datagram_size = target.min_initial_udp_datagram_size,
            },
            .max_datagram_size = target.min_initial_udp_datagram_size,
        },
    );
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(sent.packet_count >= 3);
    try std.testing.expectEqual(sent.packet_count, shared.packet_count);
    try std.testing.expectEqualSlices(
        u8,
        &handshake_message,
        &shared.received,
    );
}

test "Initial CRYPTO flight wire length matches emitted datagrams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();

    const Counter = struct {
        bytes: usize = 0,
        datagrams: usize = 0,

        fn drop(context: *anyopaque, bytes: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.bytes += bytes.len;
            self.datagrams += 1;
            return true;
        }
    };
    var counter = Counter{};
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = target.min_initial_udp_datagram_size,
            .send_interceptor = .{
                .context = &counter,
                .should_drop = Counter.drop,
            },
        },
    );
    defer endpoint.deinit();

    const options = target.SendOptions{
        .initial = .{
            .destination_connection_id = "wire-len",
            .source_connection_id = "peer",
            .packet_number = 61,
            .crypto_data = &([_]u8{0x5a} ** 2604),
            .min_datagram_size = target.min_initial_udp_datagram_size,
        },
        .max_datagram_size = target.min_initial_udp_datagram_size,
    };
    const expected = try target.wireLen(options);
    const sent = try target.send(
        &endpoint,
        .{ .ip4 = .loopback(4433) },
        quic.protection.deriveInitialSecrets("wire-len").client,
        options,
    );

    try std.testing.expectEqual(expected, counter.bytes);
    try std.testing.expectEqual(sent.packet_count, counter.datagrams);
}

test "Initial CRYPTO flight reports protected suffix after partial socket send" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200, .enable_gso_send = false },
    );
    defer sender.deinit();

    var partial = AcceptFirstFlightDatagram{ .delegate = sender.io };
    var partial_vtable = sender.io.vtable.*;
    partial_vtable.netSend = AcceptFirstFlightDatagram.netSend;
    sender.io = .{ .userdata = &partial, .vtable = &partial_vtable };
    defer sender.io = partial.delegate;

    const options = target.SendOptions{
        .initial = .{
            .destination_connection_id = "partial1",
            .source_connection_id = "peer",
            .packet_number = 70,
            .crypto_data = "0123456789abcdef",
            .max_crypto_frame_data_len = 8,
        },
        .max_datagram_size = 1200,
        .max_datagrams = 4,
    };
    const progress = try target.sendProgress(
        &sender,
        receiver.address(),
        quic.protection.deriveInitialSecrets("partial1").client,
        options,
    );
    try std.testing.expectEqual(@as(usize, 1), progress.sent_count);
    try std.testing.expectEqual(@as(usize, 2), progress.protected_count);
    try std.testing.expectEqual(@as(u64, 71), progress.last_packet_number);
    try std.testing.expectEqual(error.NetworkDown, progress.send_error.?);
    try std.testing.expect(progress.sent_bytes < progress.protected_bytes);
    try std.testing.expectEqual(
        try target.wireLen(options),
        progress.protected_bytes,
    );

    var received = try receiver.receiveBytes();
    defer received.deinit(allocator);
    var opened = try quic.protection.openInitialPacket(
        allocator,
        quic.protection.deriveInitialSecrets("partial1").client,
        received.bytes,
        70,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 70), opened.packet_number);
}

test "Initial CRYPTO flight rejects impossible budgets before send" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        std.testing.allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveInitialSecrets("12345678").client;
    try std.testing.expectError(
        error.InvalidCryptoRange,
        target.send(
            &endpoint,
            endpoint.address(),
            keys,
            .{
                .initial = .{
                    .destination_connection_id = "12345678",
                    .source_connection_id = "abcd",
                    .packet_number = 0,
                    .crypto_data = "hello",
                    .min_datagram_size = 1200,
                },
                .max_datagram_size = 1199,
            },
        ),
    );
}

test "Initial CRYPTO flight validates endpoint MTU before protection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        std.testing.allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1000 },
    );
    defer endpoint.deinit();
    try std.testing.expectError(
        error.DatagramTooLarge,
        target.sendProgress(
            &endpoint,
            endpoint.address(),
            quic.protection.deriveInitialSecrets("small-mt1").client,
            .{
                .initial = .{
                    .destination_connection_id = "small-mt1",
                    .source_connection_id = "peer",
                    .packet_number = 0,
                    .crypto_data = "hello",
                    .min_datagram_size = 1200,
                },
                .max_datagram_size = 1200,
            },
        ),
    );
}

test "Initial CRYPTO flight validates complete packet-number range before protection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        std.testing.allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer endpoint.deinit();
    try std.testing.expectError(
        error.InvalidPacketNumber,
        target.sendProgress(
            &endpoint,
            endpoint.address(),
            quic.protection.deriveInitialSecrets("pn-edge1").client,
            .{
                .initial = .{
                    .destination_connection_id = "pn-edge1",
                    .source_connection_id = "peer",
                    .packet_number = quic.protection.max_packet_number,
                    .crypto_data = "two-packets",
                    .max_crypto_frame_data_len = 4,
                },
                .max_datagram_size = 1200,
                .max_datagrams = 4,
            },
        ),
    );
}

test "Initial CRYPTO flight rejects excessive packetization" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        std.testing.allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveInitialSecrets("12345678").client;
    try std.testing.expectError(
        error.CryptoBufferTooLarge,
        target.send(
            &endpoint,
            endpoint.address(),
            keys,
            .{
                .initial = .{
                    .destination_connection_id = "12345678",
                    .source_connection_id = "abcd",
                    .packet_number = 0,
                    .crypto_data = "message requires two packets",
                    .max_crypto_frame_data_len = 8,
                },
                .max_datagram_size = 1200,
                .max_datagrams = 1,
            },
        ),
    );
}

test "Initial CRYPTO flight heap metadata fallback exceeds stack capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();

    const Counter = struct {
        datagrams: usize = 0,

        fn drop(context: *anyopaque, _: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.datagrams += 1;
            return true;
        }
    };
    var counter = Counter{};
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 1200,
            .send_interceptor = .{
                .context = &counter,
                .should_drop = Counter.drop,
            },
        },
    );
    defer endpoint.deinit();

    const payload = [_]u8{0x6a} ** 65;
    const progress = try target.sendProgress(
        &endpoint,
        endpoint.address(),
        quic.protection.deriveInitialSecrets("stack-fb").client,
        .{
            .initial = .{
                .destination_connection_id = "stack-fb",
                .source_connection_id = "peer",
                .packet_number = 100,
                .crypto_data = &payload,
                .max_crypto_frame_data_len = 1,
            },
            .max_datagram_size = 1200,
            .max_datagrams = 65,
        },
    );
    try std.testing.expectEqual(@as(usize, 65), progress.protected_count);
    try std.testing.expectEqual(@as(usize, 65), progress.sent_count);
    try std.testing.expectEqual(@as(usize, 65), counter.datagrams);
    try std.testing.expectEqual(@as(u64, 164), progress.last_packet_number);
}

test "Initial CRYPTO packet sizing matches the MTU without speculative seals" {
    const allocator = std.testing.allocator;
    const keys = quic.protection.deriveInitialSecrets("12345678").client;
    var message: [2400]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index);

    var options = target.SendOptions{
        .initial = .{
            .destination_connection_id = "12345678",
            .source_connection_id = "abcd",
            .packet_number = 7,
            .crypto_offset = 61,
            .crypto_data = &message,
            .max_crypto_frame_data_len = message.len,
        },
        .max_datagram_size = 1200,
    };
    const first_len = try target.largestChunk(options, 0);
    try std.testing.expect(first_len != 0 and first_len < message.len);

    var packet_options = options.initial;
    packet_options.crypto_data = message[0..first_len];
    packet_options.max_crypto_frame_data_len = first_len;
    const packet = try target.sealPacket(allocator, keys, packet_options);
    defer allocator.free(packet);
    try std.testing.expectEqual(options.max_datagram_size, packet.len);

    packet_options.crypto_data = message[0 .. first_len + 1];
    packet_options.max_crypto_frame_data_len = first_len + 1;
    const oversized = try target.sealPacket(allocator, keys, packet_options);
    defer allocator.free(oversized);
    try std.testing.expect(oversized.len > options.max_datagram_size);

    // Crossing a CRYPTO length-varint boundary changes the frame overhead.
    options.max_datagram_size = 90;
    options.initial.crypto_offset = 63;
    const boundary_len = try target.largestChunk(options, 0);
    packet_options = options.initial;
    packet_options.crypto_data = message[0..boundary_len];
    packet_options.max_crypto_frame_data_len = boundary_len;
    const boundary_packet = try target.sealPacket(
        allocator,
        keys,
        packet_options,
    );
    defer allocator.free(boundary_packet);
    try std.testing.expect(boundary_packet.len <= options.max_datagram_size);

    try std.testing.expectError(
        error.InvalidCryptoRange,
        target.largestChunk(options, message.len + 1),
    );
    options.initial.crypto_offset = quic.varint.max_value;
    try std.testing.expectError(
        error.InvalidCryptoRange,
        target.largestChunk(options, 0),
    );
}

test "Initial CRYPTO flight reassembles reordered packets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer sender.deinit();

    const dcid = "reorder1";
    const scid = "peer";
    const keys = quic.protection.deriveInitialSecrets(dcid).client;
    var message: [1500]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index);
    const split = 700;
    const first = try target.sealPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .packet_number = 20,
        .crypto_offset = 0,
        .crypto_data = message[0..split],
    });
    defer allocator.free(first);
    const second = try target.sealPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .packet_number = 21,
        .crypto_offset = split,
        .crypto_data = message[split..],
    });
    defer allocator.free(second);
    var first_datagram: [target.min_initial_udp_datagram_size]u8 = undefined;
    @memcpy(first_datagram[0..first.len], first);
    @memset(first_datagram[first.len..], 0);
    var second_datagram: [target.min_initial_udp_datagram_size]u8 = undefined;
    @memcpy(second_datagram[0..second.len], second);
    @memset(second_datagram[second.len..], 0);

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        err: ?anyerror = null,
        received: [1500]u8 = undefined,

        fn run(shared: *@This()) void {
            var received = target.receive(
                shared.endpoint,
                shared.keys,
                .{
                    .expected_packet_number = 20,
                    .expected_crypto_len = shared.received.len,
                    .max_crypto_buffer = shared.received.len,
                    .min_datagram_size = 1200,
                },
            ) catch |err| {
                shared.err = err;
                return;
            };
            defer received.deinit(shared.endpoint.allocator);
            @memcpy(&shared.received, received.crypto_data);
        }
    };
    var shared = Shared{ .endpoint = &receiver, .keys = keys };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    // Match tquic's valid datagram shape: each Initial packet's Length field
    // ends before an all-zero suffix that expands the UDP payload to 1200.
    try sender.sendBytes(receiver.address(), &second_datagram);
    try sender.sendBytes(receiver.address(), &first_datagram);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(u8, &message, &shared.received);
}

test "Initial CRYPTO flight discards unauthenticated continuation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const dcid = "noise001";
    const scid = "peer";
    const keys = quic.protection.deriveInitialSecrets(dcid).client;
    const message = [_]u8{ 1, 0, 0, 8 } ++ "complete".*;
    const split = 6;
    const first = try target.sealPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .packet_number = 10,
        .crypto_offset = 0,
        .crypto_data = message[0..split],
        .min_datagram_size = 1200,
    });
    defer allocator.free(first);
    const bad = try target.sealPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .packet_number = 11,
        .crypto_offset = split,
        .crypto_data = message[split..],
        .min_datagram_size = 1200,
    });
    defer allocator.free(bad);
    bad[bad.len - 1] ^= 0x80;
    const second = try target.sealPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .packet_number = 12,
        .crypto_offset = split,
        .crypto_data = message[split..],
        .min_datagram_size = 1200,
    });
    defer allocator.free(second);

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        from: std.Io.net.IpAddress,
        first: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var received = target.open(
                shared.endpoint,
                shared.from,
                shared.first,
                shared.keys,
                .{
                    .expected_packet_number = 10,
                    .expected_crypto_len = shared.expected.len,
                    .max_crypto_buffer = shared.expected.len,
                    .min_datagram_size = 1200,
                },
            ) catch |err| {
                shared.err = err;
                return;
            };
            defer received.deinit(shared.endpoint.allocator);
            if (!std.mem.eql(u8, shared.expected, received.crypto_data) or
                received.packet_count != 2 or
                received.next_expected_packet_number != 13)
            {
                shared.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{
        .endpoint = &receiver,
        .keys = keys,
        .from = sender.address(),
        .first = first,
        .expected = &message,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try sender.sendBytes(receiver.address(), bad);
    try sender.sendBytes(receiver.address(), second);
    thread.join();
    if (shared.err) |err| return err;
}

test "Initial CRYPTO handshake discard mode preserves authenticated errors" {
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

    const dcid = "autherr1";
    const keys = quic.protection.deriveInitialSecrets(dcid).client;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 0,
        .data = "forbidden",
    } }).write(&payload, allocator);
    const packet = try quic.protection.sealInitialPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = "peer",
        .packet_number = 0,
        .payload = payload.items,
    });
    defer allocator.free(packet);

    try std.testing.expectError(
        error.InvalidFrame,
        target.open(
            &endpoint,
            endpoint.address(),
            packet,
            keys,
            .{
                .expected_packet_number = 0,
                .max_crypto_buffer = 64,
                .discard_invalid_first = true,
            },
        ),
    );
}

test "Initial CRYPTO one-shot opener preserves authentication errors" {
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

    const dcid = "oneshot1";
    const keys = quic.protection.deriveInitialSecrets(dcid).client;
    const packet = try target.sealPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = "peer",
        .packet_number = 0,
        .crypto_data = &.{ 1, 0, 0, 0 },
        .min_datagram_size = 1200,
    });
    defer allocator.free(packet);
    packet[packet.len - 1] ^= 0x80;

    try std.testing.expectError(
        error.AuthenticationFailed,
        target.open(
            &endpoint,
            endpoint.address(),
            packet,
            keys,
            .{
                .expected_packet_number = 0,
                .max_crypto_buffer = 64,
                .min_datagram_size = 1200,
            },
        ),
    );
    try std.testing.expectError(
        error.DiscardedInitialPacket,
        target.open(
            &endpoint,
            endpoint.address(),
            packet,
            keys,
            .{
                .expected_packet_number = 0,
                .max_crypto_buffer = 64,
                .min_datagram_size = 1200,
                .discard_invalid_first = true,
            },
        ),
    );
}

test "Initial CRYPTO opener accepts a packet slice from validated padded datagram" {
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

    const dcid = "padded01";
    const keys = quic.protection.deriveInitialSecrets(dcid).client;
    const handshake_message = [_]u8{ 1, 0, 0, 0 };
    const packet = try target.sealPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = "peer",
        .packet_number = 0,
        .crypto_data = &handshake_message,
    });
    defer allocator.free(packet);
    try std.testing.expect(packet.len < target.min_initial_udp_datagram_size);
    const datagram = try allocator.alloc(u8, target.min_initial_udp_datagram_size);
    defer allocator.free(datagram);
    @memcpy(datagram[0..packet.len], packet);
    @memset(datagram[packet.len..], 0);

    try std.testing.expectError(
        error.InvalidInitialPacket,
        target.open(
            &endpoint,
            endpoint.address(),
            packet,
            keys,
            .{
                .expected_packet_number = 0,
                .max_crypto_buffer = 64,
                .min_datagram_size = target.min_initial_udp_datagram_size,
            },
        ),
    );

    var from_datagram = try target.open(
        &endpoint,
        endpoint.address(),
        datagram,
        keys,
        .{
            .expected_packet_number = 0,
            .max_crypto_buffer = 64,
            .min_datagram_size = target.min_initial_udp_datagram_size,
        },
    );
    defer from_datagram.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &handshake_message,
        from_datagram.crypto_data,
    );
    datagram[datagram.len - 1] = 1;
    try std.testing.expectError(
        error.InvalidInitialPacket,
        target.open(
            &endpoint,
            endpoint.address(),
            datagram,
            keys,
            .{
                .expected_packet_number = 0,
                .max_crypto_buffer = 64,
                .min_datagram_size = target.min_initial_udp_datagram_size,
            },
        ),
    );

    var received = try target.open(
        &endpoint,
        endpoint.address(),
        packet,
        keys,
        .{
            .expected_packet_number = 0,
            .max_crypto_buffer = 64,
            .min_datagram_size = target.min_initial_udp_datagram_size,
            .first_datagram_size_validated = true,
        },
    );
    defer received.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &handshake_message,
        received.crypto_data,
    );
}

test "Initial CRYPTO payload extraction skips ACK without allocation" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);

    try (quic.Frame{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }).write(&payload, allocator);
    try quic.crypto_stream.writeCryptoFrames(
        &payload,
        allocator,
        0,
        "hello",
        16,
    );

    var reassembler = quic.crypto_stream.Reassembler.init(allocator, 32);
    defer reassembler.deinit();
    try target.insertCryptoPayload(
        allocator,
        &reassembler,
        payload.items,
        .initial,
    );
    try std.testing.expectEqualStrings("hello", reassembler.available());
}

test "Initial CRYPTO payload extraction rejects forbidden frames" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .stream = .{ .stream_id = 0, .data = "bad" } }).write(
        &payload,
        allocator,
    );

    var reassembler = quic.crypto_stream.Reassembler.init(allocator, 32);
    defer reassembler.deinit();
    try std.testing.expectError(
        error.InvalidFrame,
        target.insertCryptoPayload(
            allocator,
            &reassembler,
            payload.items,
            .initial,
        ),
    );
}

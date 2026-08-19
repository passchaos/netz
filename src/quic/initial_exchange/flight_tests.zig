const std = @import("std");
const quic = @import("../mod.zig");
const target = @import("flight.zig");

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
        .min_datagram_size = 1200,
    });
    defer allocator.free(first);
    const second = try target.sealPacket(allocator, keys, .{
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .packet_number = 21,
        .crypto_offset = split,
        .crypto_data = message[split..],
        .min_datagram_size = 1200,
    });
    defer allocator.free(second);

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
    try sender.sendBytes(receiver.address(), second);
    try sender.sendBytes(receiver.address(), first);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(u8, &message, &shared.received);
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

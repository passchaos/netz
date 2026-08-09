const std = @import("std");
const quic = @import("../mod.zig");
const zero_rtt = @import("mod.zig");

test "QUIC 0-RTT long-header frame exchange enforces packet context" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server.deinit();
    var client = try quic.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .max_datagram_size = 4096 },
    );
    defer client.deinit();

    const dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    const scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8a} ** quic.protection.secret_len,
    );

    try zero_rtt.sendFrames(
        &client.endpoint,
        server.address(),
        keys,
        .{
            .destination_connection_id = &dcid,
            .source_connection_id = &scid,
            .packet_number = 0,
            .frames = &.{.{ .stream = .{
                .stream_id = 0,
                .data = "early",
            } }},
        },
    );

    var received = try zero_rtt.receive(&server.endpoint, keys, 0, 8);
    defer received.deinit(allocator);
    try std.testing.expect(received.from.eql(&client.address()));
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
    try std.testing.expectEqualSlices(
        u8,
        &dcid,
        received.packet.destination_connection_id,
    );
    try std.testing.expectEqualSlices(
        u8,
        &scid,
        received.packet.source_connection_id,
    );
    try std.testing.expectEqualStrings("early", received.frames[0].stream.data);

    try std.testing.expectError(
        error.InvalidFrame,
        zero_rtt.sendFrames(
            &client.endpoint,
            server.address(),
            keys,
            .{
                .destination_connection_id = &dcid,
                .source_connection_id = &scid,
                .packet_number = 1,
                .frames = &.{.{ .ack = .{
                    .largest_acknowledged = 0,
                    .ack_delay = 0,
                    .first_ack_range = 0,
                } }},
            },
        ),
    );

    const invalid_payload = try zero_rtt.encodeFrames(
        allocator,
        &.{.{ .crypto = .{
            .offset = 0,
            .data = "forbidden",
        } }},
    );
    defer allocator.free(invalid_payload);
    const invalid_packet = try quic.protection.sealZeroRttPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &dcid,
            .source_connection_id = &scid,
            .packet_number = 1,
            .payload = invalid_payload,
        },
    );
    defer allocator.free(invalid_packet);
    try std.testing.expectError(
        error.InvalidFrame,
        zero_rtt.openBytes(
            &server.endpoint,
            client.address(),
            invalid_packet,
            keys,
            1,
            8,
        ),
    );
}

test "QUIC early-data sender consumes lease after first successful packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server.deinit();
    var client = try quic.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .max_datagram_size = 4096 },
    );
    defer client.deinit();

    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket());
    var lease = (try cache.beginEarlyData("server", "h3", 1001)).?;
    defer lease.deinit();
    var sender = zero_rtt.EarlyDataSender{
        .cache = &cache,
        .lease = &lease,
    };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x77} ** quic.protection.secret_len,
    );
    const stream = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "early",
    } }};
    try sender.send(
        &client.endpoint,
        server.address(),
        keys,
        .{
            .destination_connection_id = "server-cid",
            .source_connection_id = "client-cid",
            .frames = &stream,
        },
    );
    try std.testing.expect(sender.offered);
    try std.testing.expectEqual(@as(u64, 1), sender.packet_number);
    try std.testing.expectEqual(.consumed, lease.state);
    try std.testing.expect(
        (try cache.beginEarlyData("server", "h3", 1002)) == null,
    );

    var first = try server.endpoint.receiveBytes();
    defer first.deinit(allocator);
    var opened_first = try zero_rtt.openBytes(
        &server.endpoint,
        first.from,
        first.bytes,
        keys,
        0,
        8,
    );
    defer opened_first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), opened_first.packet.packet_number);

    // The same attempt may send more packets with increasing packet numbers.
    try sender.send(
        &client.endpoint,
        server.address(),
        keys,
        .{
            .destination_connection_id = "server-cid",
            .source_connection_id = "client-cid",
            .frames = &stream,
        },
    );
    var second = try server.endpoint.receiveBytes();
    defer second.deinit(allocator);
    var opened_second = try zero_rtt.openBytes(
        &server.endpoint,
        second.from,
        second.bytes,
        keys,
        1,
        8,
    );
    defer opened_second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), opened_second.packet.packet_number);
}

test "QUIC early-data sender preserves lease when send validation fails" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket());
    var lease = (try cache.beginEarlyData("server", "h3", 1001)).?;
    defer lease.deinit();
    var sender = zero_rtt.EarlyDataSender{
        .cache = &cache,
        .lease = &lease,
    };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x88} ** quic.protection.secret_len,
    );
    try std.testing.expectError(
        error.InvalidFrame,
        sender.send(
            &endpoint,
            endpoint.address(),
            keys,
            .{
                .destination_connection_id = "server-cid",
                .source_connection_id = "client-cid",
                .frames = &.{.{ .ack = .{
                    .largest_acknowledged = 0,
                    .ack_delay = 0,
                    .first_ack_range = 0,
                } }},
            },
        ),
    );
    try std.testing.expect(!sender.offered);
    try std.testing.expectEqual(.active, lease.state);
    try std.testing.expect(cache.ownsActiveLease(lease));
}

fn earlyTicket() quic.resumption.Ticket {
    return .{
        .server_id = "server",
        .alpn = "h3",
        .ticket = "ticket",
        .psk = [_]u8{0xaa} ** 32,
        .issued_at_ms = 1000,
        .lifetime_seconds = 100,
        .age_add = 0,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    };
}

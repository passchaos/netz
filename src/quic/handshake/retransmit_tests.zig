const std = @import("std");
const quic = @import("../mod.zig");
const target = @import("retransmit.zig");

test "handshake PTO retries with fresh packet numbers" {
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

    const keys = quic.protection.deriveInitialSecrets("retrypto").client;
    const Context = struct {
        endpoint: *quic.runtime.Endpoint,
        peer: std.Io.net.IpAddress,
        keys: quic.protection.PacketProtectionKeys,
        calls: usize = 0,

        fn send(context: *anyopaque, retransmission: u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (retransmission == 0) return; // deterministically drop first
            try quic.initial_exchange.sendInitialCrypto(
                self.endpoint,
                self.peer,
                self.keys,
                .{
                    .destination_connection_id = "retrypto",
                    .source_connection_id = "peer",
                    .packet_number = 40 + retransmission,
                    .crypto_data = "response",
                },
            );
        }
    };
    var context = Context{
        .endpoint = &sender,
        .peer = receiver.address(),
        .keys = keys,
    };
    var datagram = try target.sendAndReceive(
        &receiver,
        .{ .initial_pto_ms = 1, .max_pto_ms = 2, .max_retries = 2 },
        &context,
        Context.send,
    );
    defer datagram.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), context.calls);
    var opened = try quic.initial_exchange.openInitialCrypto(
        &receiver,
        datagram.from,
        datagram.bytes,
        keys,
        41,
        128,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 41), opened.packet.packet_number);
    try std.testing.expectEqualStrings("response", opened.crypto_data);
}

test "handshake PTO exhausts a bounded retry budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        std.testing.allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer endpoint.deinit();
    const Context = struct {
        calls: usize = 0,
        fn send(context: *anyopaque, _: u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
        }
    };
    var context = Context{};
    try std.testing.expectError(
        error.HandshakeTimeout,
        target.sendAndReceive(
            &endpoint,
            .{ .initial_pto_ms = 1, .max_pto_ms = 2, .max_retries = 2 },
            &context,
            Context.send,
        ),
    );
    try std.testing.expectEqual(@as(usize, 3), context.calls);
}

test "handshake max duration can extend past retry count" {
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

    const keys = quic.protection.deriveInitialSecrets("duration").client;
    const Context = struct {
        endpoint: *quic.runtime.Endpoint,
        peer: std.Io.net.IpAddress,
        keys: quic.protection.PacketProtectionKeys,
        calls: usize = 0,

        fn send(context: *anyopaque, retransmission: u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (retransmission < 2) return;
            try quic.initial_exchange.sendInitialCrypto(
                self.endpoint,
                self.peer,
                self.keys,
                .{
                    .destination_connection_id = "duration",
                    .source_connection_id = "peer",
                    .packet_number = 80 + retransmission,
                    .crypto_data = "response",
                },
            );
        }
    };
    var context = Context{
        .endpoint = &sender,
        .peer = receiver.address(),
        .keys = keys,
    };
    var datagram = try target.sendAndReceive(
        &receiver,
        .{
            .initial_pto_ms = 1,
            .max_pto_ms = 1,
            .max_retries = 0,
            .max_duration_ms = 50,
        },
        &context,
        Context.send,
    );
    defer datagram.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), context.calls);
    var opened = try quic.initial_exchange.openInitialCrypto(
        &receiver,
        datagram.from,
        datagram.bytes,
        keys,
        82,
        128,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqualStrings("response", opened.crypto_data);
}

test "passive handshake wait uses the full bounded PTO budget" {
    const config = target.Config{
        .initial_pto_ms = 10,
        .max_pto_ms = 25,
        .max_retries = 4,
    };

    try std.testing.expectEqual(@as(u64, 10), config.timeoutMillis(0));
    try std.testing.expectEqual(@as(u64, 20), config.timeoutMillis(1));
    try std.testing.expectEqual(@as(u64, 25), config.timeoutMillis(2));
    try std.testing.expectEqual(@as(u64, 25), config.timeoutMillis(3));
    try std.testing.expectEqual(@as(u64, 25), config.timeoutMillis(4));

    const passive = config.passiveTimeout();
    switch (passive) {
        .duration => |duration| {
            try std.testing.expectEqual(std.Io.Clock.awake, duration.clock);
            try std.testing.expectEqual(
                @as(i64, 105),
                duration.raw.toMilliseconds(),
            );
        },
        else => return error.InvalidHandshakeRecovery,
    }
}

test "passive handshake wait can use explicit max duration" {
    const config = target.Config{
        .initial_pto_ms = 10,
        .max_pto_ms = 25,
        .max_retries = 4,
        .max_duration_ms = 300,
    };

    try std.testing.expectEqual(@as(u64, 300), config.budgetMillis());
    const passive = config.passiveTimeout();
    switch (passive) {
        .duration => |duration| {
            try std.testing.expectEqual(std.Io.Clock.awake, duration.clock);
            try std.testing.expectEqual(
                @as(i64, 300),
                duration.raw.toMilliseconds(),
            );
        },
        else => return error.InvalidHandshakeRecovery,
    }
}

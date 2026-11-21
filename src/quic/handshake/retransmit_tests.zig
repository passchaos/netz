const std = @import("std");
const quic = @import("../mod.zig");
const target = @import("retransmit.zig");

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

const RejectFirstSingleAfterBatch = struct {
    delegate: std.Io,
    saw_batch: bool = false,
    rejected_single: bool = false,

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (messages.len > 1) self.saw_batch = true;
        if (self.saw_batch and !self.rejected_single and messages.len == 1) {
            self.rejected_single = true;
            return .{ error.NetworkDown, 0 };
        }
        return self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
    }
};

const RejectFirstFlightBatch = struct {
    delegate: std.Io,
    rejected_once: bool = false,

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (!self.rejected_once and messages.len > 1) {
            self.rejected_once = true;
            return .{ error.NetworkDown, 0 };
        }
        return self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
    }
};

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

test "server handshake flight records an unused close packet number" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();

    const initial_keys = quic.protection.deriveInitialSecrets("close-pn").server;
    const handshake_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf2} ** quic.protection.secret_len,
    );
    var context = target.InitialHandshakeFlight{
        .endpoint = &sender,
        .peer = receiver.address(),
        .initial_keys = initial_keys,
        .initial_options = .{
            .initial = .{
                .destination_connection_id = "close-pn",
                .source_connection_id = "server",
                .packet_number = 10,
                .crypto_data = "initial",
            },
            .max_datagram_size = 1200,
        },
        .handshake_keys = handshake_keys,
        .handshake_options = .{
            .destination_connection_id = "close-pn",
            .source_connection_id = "server",
            .packet_number = 20,
            .crypto_data = "handshake",
        },
    };
    try target.InitialHandshakeFlight.send(&context, 2);
    try std.testing.expectEqual(@as(?u64, 23), context.next_handshake_packet_number);
}

test "server handshake flight has no close packet number past QUIC maximum" {
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

    var context = target.InitialHandshakeFlight{
        .endpoint = &sender,
        .peer = receiver.address(),
        .initial_keys = quic.protection
            .deriveInitialSecrets("max-hspn").server,
        .initial_options = .{
            .initial = .{
                .destination_connection_id = "max-hspn",
                .source_connection_id = "server",
                .packet_number = 0,
                .crypto_data = "initial",
            },
            .max_datagram_size = 1200,
        },
        .handshake_keys = quic.protection.deriveAes128Keys(
            [_]u8{0xc8} ** quic.protection.secret_len,
        ),
        .handshake_options = .{
            .destination_connection_id = "max-hspn",
            .source_connection_id = "server",
            .packet_number = quic.protection.max_packet_number,
            .crypto_data = "handshake",
        },
    };
    try target.InitialHandshakeFlight.send(&context, 0);
    try std.testing.expectEqual(@as(?u64, null), context.next_handshake_packet_number);
}

test "handshake Initial flight retires a partial batch packet-number range" {
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

    const keys = quic.protection.deriveInitialSecrets("retry-pn").client;
    var context = target.InitialFlight{
        .endpoint = &sender,
        .peer = receiver.address(),
        .keys = keys,
        .options = .{
            .initial = .{
                .destination_connection_id = "retry-pn",
                .source_connection_id = "peer",
                .packet_number = 10,
                .crypto_data = "0123456789abcdef",
                .max_crypto_frame_data_len = 8,
            },
            .max_datagram_size = 1200,
            .max_datagrams = 4,
        },
    };
    try target.InitialFlight.send(&context, 0);
    try target.InitialFlight.send(&context, 1);

    var first = try receiver.receiveBytes();
    defer first.deinit(allocator);
    var first_packet = try quic.protection.openInitialPacket(
        allocator,
        keys,
        first.bytes,
        10,
    );
    defer first_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 10), first_packet.packet_number);

    var retry = try receiver.receiveBytes();
    defer retry.deinit(allocator);
    var retry_packet = try quic.protection.openInitialPacket(
        allocator,
        keys,
        retry.bytes,
        14,
    );
    defer retry_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 14), retry_packet.packet_number);
}

test "handshake Initial flight retires sealed range after zero socket progress" {
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

    var reject = RejectFirstFlightBatch{ .delegate = sender.io };
    var rejecting_vtable = sender.io.vtable.*;
    rejecting_vtable.netSend = RejectFirstFlightBatch.netSend;
    sender.io = .{ .userdata = &reject, .vtable = &rejecting_vtable };
    defer sender.io = reject.delegate;

    const keys = quic.protection.deriveInitialSecrets("zero-pn1").client;
    var context = target.InitialFlight{
        .endpoint = &sender,
        .peer = receiver.address(),
        .keys = keys,
        .options = .{
            .initial = .{
                .destination_connection_id = "zero-pn1",
                .source_connection_id = "peer",
                .packet_number = 70,
                .crypto_data = "0123456789abcdef",
                .max_crypto_frame_data_len = 8,
            },
            .max_datagram_size = 1200,
            .max_datagrams = 4,
        },
    };
    // A protected but socket-rejected flight is treated as loss so the next
    // PTO attempt advances past its complete reserved PN stride.
    try target.InitialFlight.send(&context, 0);
    try target.InitialFlight.send(&context, 1);

    var datagram = try receiver.receiveBytes();
    defer datagram.deinit(allocator);
    var packet = try quic.protection.openInitialPacket(
        allocator,
        keys,
        datagram.bytes,
        74,
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 74), packet.packet_number);
}

test "server partial Initial flight defers Handshake and accounts sent prefix" {
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

    const initial_keys = quic.protection
        .deriveInitialSecrets("srv-part").server;
    const handshake_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa8} ** quic.protection.secret_len,
    );
    var context = target.InitialHandshakeFlight{
        .endpoint = &sender,
        .peer = receiver.address(),
        .initial_keys = initial_keys,
        .initial_options = .{
            .initial = .{
                .destination_connection_id = "srv-part",
                .source_connection_id = "server",
                .packet_number = 20,
                .crypto_data = "0123456789abcdef",
                .max_crypto_frame_data_len = 8,
            },
            .max_datagram_size = 1200,
            .max_datagrams = 4,
        },
        .handshake_keys = handshake_keys,
        .handshake_options = .{
            .destination_connection_id = "srv-part",
            .source_connection_id = "server",
            .packet_number = 30,
            .crypto_data = "handshake",
        },
        .anti_amplification = .{
            .bytes_received = 10_000,
        },
    };

    try target.InitialHandshakeFlight.send(&context, 0);
    try std.testing.expectEqual(@as(?u64, 31), context.next_handshake_packet_number);
    try std.testing.expect(context.anti_amplification.bytes_sent > 0);
    try std.testing.expect(
        context.anti_amplification.bytes_sent <
            try quic.initial_exchange.initialThenHandshakeCryptoWireLen(
                context.initial_options,
                .{
                    .initial = context.handshake_options,
                    .max_datagram_size = quic.initial_exchange
                        .handshakeDatagramSize(
                        context.endpoint.limits.max_datagram_size,
                    ),
                },
            ),
    );

    try target.InitialHandshakeFlight.send(&context, 1);
    try std.testing.expectEqual(@as(?u64, 32), context.next_handshake_packet_number);

    var first = try receiver.receiveBytes();
    defer first.deinit(allocator);
    var first_packet = try quic.protection.openInitialPacket(
        allocator,
        initial_keys,
        first.bytes,
        20,
    );
    defer first_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 20), first_packet.packet_number);

    var retry_first = try receiver.receiveBytes();
    defer retry_first.deinit(allocator);
    var retry_first_packet = try quic.protection.openInitialPacket(
        allocator,
        initial_keys,
        retry_first.bytes,
        24,
    );
    defer retry_first_packet.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 24),
        retry_first_packet.packet_number,
    );

    var retry_second = try receiver.receiveBytes();
    defer retry_second.deinit(allocator);
    var retry_second_packet = try quic.protection.openInitialPacket(
        allocator,
        initial_keys,
        retry_second.bytes,
        25,
    );
    defer retry_second_packet.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 25),
        retry_second_packet.packet_number,
    );

    var handshake = try receiver.receiveBytes();
    defer handshake.deinit(allocator);
    var handshake_packet = try quic.protection.openHandshakePacket(
        allocator,
        handshake_keys,
        handshake.bytes,
        31,
    );
    defer handshake_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 31), handshake_packet.packet_number);
}

test "server Handshake socket failure retries after visible Initial flight" {
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

    var reject = RejectFirstSingleAfterBatch{ .delegate = sender.io };
    var rejecting_vtable = sender.io.vtable.*;
    rejecting_vtable.netSend = RejectFirstSingleAfterBatch.netSend;
    sender.io = .{ .userdata = &reject, .vtable = &rejecting_vtable };
    defer sender.io = reject.delegate;

    const initial_keys = quic.protection
        .deriveInitialSecrets("hs-fail1").server;
    const handshake_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb8} ** quic.protection.secret_len,
    );
    var context = target.InitialHandshakeFlight{
        .endpoint = &sender,
        .peer = receiver.address(),
        .initial_keys = initial_keys,
        .initial_options = .{
            .initial = .{
                .destination_connection_id = "hs-fail1",
                .source_connection_id = "server",
                .packet_number = 40,
                .crypto_data = "0123456789abcdef",
                .max_crypto_frame_data_len = 8,
            },
            .max_datagram_size = 1200,
            .max_datagrams = 4,
        },
        .handshake_keys = handshake_keys,
        .handshake_options = .{
            .destination_connection_id = "hs-fail1",
            .source_connection_id = "server",
            .packet_number = 50,
            .crypto_data = "handshake",
        },
    };

    try target.InitialHandshakeFlight.send(&context, 0);
    try std.testing.expectEqual(@as(?u64, 51), context.next_handshake_packet_number);
    try target.InitialHandshakeFlight.send(&context, 1);
    try std.testing.expectEqual(@as(?u64, 52), context.next_handshake_packet_number);

    for ([_]u64{ 40, 41, 44, 45 }) |expected_packet_number| {
        var datagram = try receiver.receiveBytes();
        defer datagram.deinit(allocator);
        var packet = try quic.protection.openInitialPacket(
            allocator,
            initial_keys,
            datagram.bytes,
            expected_packet_number,
        );
        defer packet.deinit(allocator);
        try std.testing.expectEqual(
            expected_packet_number,
            packet.packet_number,
        );
    }
    var handshake = try receiver.receiveBytes();
    defer handshake.deinit(allocator);
    var handshake_packet = try quic.protection.openHandshakePacket(
        allocator,
        handshake_keys,
        handshake.bytes,
        51,
    );
    defer handshake_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 51), handshake_packet.packet_number);
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

test "handshake caller deadline bounds active retransmission budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        std.testing.allocator,
        io,
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
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        target.sendAndReceive(
            &endpoint,
            .{
                .initial_pto_ms = 1_000,
                .max_pto_ms = 4_000,
                .max_retries = 3,
                .deadline = .fromNow(io, .{
                    .raw = .fromMilliseconds(10),
                    .clock = .awake,
                }),
            },
            &context,
            Context.send,
        ),
    );
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds < 500 * std.time.ns_per_ms);
    try std.testing.expect(context.calls >= 1);
}

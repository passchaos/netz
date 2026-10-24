const std = @import("std");
const quic = @import("../mod.zig");
const versions = [_]u32{quic.Version.version_1.wireValue()};

test "QUIC closing handshake keeps a retransmitted Initial out of admission" {
    try retransmission(false, false);
}

test "HTTP/3 closing handshake keeps a retransmitted Initial out of admission" {
    try retransmission(true, false);
}

test "QUIC closing handshake retries a socket-rejected fatal close" {
    try retransmission(false, true);
}

fn retransmission(comptime http3: bool, fail_send: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var template: @import("../../http3/runtime.zig").HandshakeServer = undefined;
    if (http3) template = try @import("../../http3/runtime.zig").HandshakeServer.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{}, .{ .handshake = .{ .local_connection_id = "closing-template", .key_exchange_groups = &.{.x25519} } });
    defer if (http3) template.deinit();
    var server = if (http3) try @import("../../http3/runtime.zig").EndpointServer.init(&template, .{}) else try quic.endpoint_server.Server.init(std.testing.allocator, &endpoint, .{ .local_connection_id = "closing-template", .key_exchange_groups = &.{.x25519} }, .{});
    defer server.deinit();
    const dispatcher = server.dispatcher;
    const address = if (http3) template.address() else server.address();
    var client = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer client.deinit();
    const keys = quic.protection.deriveInitialSecrets("closing-origin");
    var parameters: std.ArrayList(u8) = .empty;
    defer parameters.deinit(std.testing.allocator);
    var local = quic.practical_transport_parameters;
    local.initial_source_connection_id = "closing-client";
    try quic.encodeTransportParametersForSource(&parameters, std.testing.allocator, local, .client);
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(std.testing.allocator);
    try quic.tls_client_hello.writeClientHello(&hello, std.testing.allocator, .{
        .random = [_]u8{0x79} ** 32,
        .x25519_public_key = try @import("../tls/key_exchange.zig").x25519PublicKey([_]u8{0x7a} ** 32),
        .alpn_protocols = &.{"unsupported"},
        .transport_parameters = parameters.items,
    });
    var options: quic.initial_exchange.SendInitialFlightOptions = .{ .initial = .{ .destination_connection_id = "closing-origin", .source_connection_id = "closing-client", .packet_number = 0, .crypto_data = hello.items, .min_datagram_size = 1200 }, .max_datagram_size = 1280 };
    _ = try quic.initial_exchange.sendInitialCryptoFlight(&client, address, keys.client, options);
    const original = endpoint.io;
    const FailedSend = struct {
        fn send(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []std.Io.net.OutgoingMessage, _: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            return .{ error.SystemResources, 0 };
        }
    };
    var failed_vtable = original.vtable.*;
    failed_vtable.netSend = FailedSend.send;
    if (fail_send) endpoint.io = .{ .userdata = original.userdata, .vtable = &failed_vtable };
    defer endpoint.io = original;
    var failure = if (http3) try server.receiveTransportWithTimeout(&versions, .fromSeconds(2)) else try server.receiveWithTimeout(&versions, .fromSeconds(2));
    defer failure.deinit(std.testing.allocator);
    try std.testing.expect(failure == .handshake_failed and failure.handshake_failed.err == error.MissingAlpn);
    endpoint.io = original;
    var close: ?quic.runtime.OwnedBytes = null;
    defer if (close) |*value| value.deinit(std.testing.allocator);
    if (!fail_send) close = try client.receiveBytesWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.closingHandshakeCount());
    options.initial.packet_number = 1;
    _ = try quic.initial_exchange.sendInitialCryptoFlight(&client, address, keys.client, options);
    if (http3) try std.testing.expectError(error.Timeout, server.receiveTransportWithTimeout(&versions, .fromMilliseconds(50))) else try std.testing.expectError(error.Timeout, server.receiveWithTimeout(&versions, .fromMilliseconds(50)));
    var retry = try client.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer retry.deinit(std.testing.allocator);
    if (close) |value| try std.testing.expectEqualSlices(u8, value.bytes, retry.bytes);
    var opened = try quic.protection.openInitialPacket(std.testing.allocator, keys.server, retry.bytes, 0);
    defer opened.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 0x178), (try quic.parseFrame(opened.payload)).frame.connection_close.error_code);
    const deadline = dispatcher.nextTimerDeadline().?.timer.deadline_ns;
    _ = try dispatcher.serviceNextTimerAt(deadline);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.closingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pending_router.count());
}

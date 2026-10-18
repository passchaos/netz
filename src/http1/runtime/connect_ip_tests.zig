const std = @import("std");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/1 CONNECT-IP rejects an unencrypted transport" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    const template = try http3.connect_ip.UriTemplate.compile(
        "https://localhost/.well-known/masque/ip/{target}/{ipproto}/",
    );
    var storage: [128]u8 = undefined;
    try std.testing.expectError(
        error.EncryptionRequired,
        client.openConnectIp(template, .{}, &.{}, &storage),
    );
}

test "HTTP/1 TLS CONNECT-IP exchanges configuration and IP packets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();

    const client_packet = [_]u8{ 0x45, 0, 0, 20 } ++ [_]u8{0x11} ** 16;
    const server_packet = [_]u8{ 0x60, 0, 0, 0 } ++ [_]u8{0x22} ** 36;
    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readConnectIpRequestWithTimeout(
                .fromSeconds(5),
            );
            defer request.deinit(self.server.allocator);
            var target_storage: [128]u8 = undefined;
            var accepted = try connection.acceptConnectIpDefault(
                request.request,
                &target_storage,
            );
            var configuration = http3.connect_ip.ConfigurationState.init(
                self.server.allocator,
                .{},
            );
            defer configuration.deinit();
            try accepted.session.bindConfigurationState(&configuration);
            defer accepted.session.deinit();
            try std.testing.expectEqualStrings(
                "192.0.2.0/24",
                accepted.scope.target,
            );
            try std.testing.expectEqual(@as(?u8, 6), accepted.scope.ip_protocol);

            var first = try accepted.session.receiveEventWithTimeout(
                .fromSeconds(2),
            );
            defer first.deinit(self.server.allocator);
            try std.testing.expect(first == .capsule);
            const address_request = first.capsule;
            try std.testing.expectEqual(
                http3.connect_ip.capsules.address_request_type,
                address_request.capsule_type,
            );
            var requests = try http3.connect_ip.capsules.parseAddressRequest(
                address_request.value,
            );
            try std.testing.expectEqual(
                @as(u62, 9),
                (try requests.next()).?.request_id,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                configuration.peerRequestCount(),
            );

            var second = try accepted.session.receiveEventWithTimeout(
                .fromSeconds(2),
            );
            defer second.deinit(self.server.allocator);
            try std.testing.expect(second == .payload);
            try std.testing.expectEqualSlices(
                u8,
                &client_packet,
                second.payload.payload,
            );

            const assigned = [_]http3.connect_ip.capsules.AddressPrefix{.{
                .request_id = 9,
                .address = .{ .ipv4 = .{ 192, 0, 2, 11 } },
                .prefix_length = 32,
            }};
            var encoded: [64]u8 = undefined;
            const assignment = try http3.connect_ip.capsules
                .writeAddressAssignInto(&encoded, &assigned);
            try accepted.session.sendCapsuleWithTimeout(
                assignment,
                .fromSeconds(2),
            );
            try accepted.session.sendWithTimeout(&server_packet, .fromSeconds(2));
            try accepted.session.closeWrite();
            try std.testing.expectError(
                error.ConnectionClosed,
                accepted.session.receiveCapsuleWithTimeout(.fromSeconds(2)),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .verify_host = false },
    );
    defer client.close();
    const template = try http3.connect_ip.UriTemplate.compile(
        "https://localhost/.well-known/masque/ip/{target}/{ipproto}/",
    );
    var uri_storage: [256]u8 = undefined;
    var session = try client.openConnectIpWithTimeout(
        template,
        .{ .target = "192.0.2.0/24", .ip_protocol = 6 },
        &.{},
        &uri_storage,
        .fromSeconds(5),
    );
    var configuration = http3.connect_ip.ConfigurationState.init(
        allocator,
        .{},
    );
    defer configuration.deinit();
    try session.bindConfigurationState(&configuration);
    defer session.deinit();

    const requested = [_]http3.connect_ip.capsules.AddressPrefix{.{
        .request_id = 9,
        .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        .prefix_length = 32,
    }};
    var encoded: [64]u8 = undefined;
    const address_request = try http3.connect_ip.capsules
        .writeAddressRequestInto(&encoded, &requested);
    try session.sendCapsuleWithTimeout(
        address_request,
        .fromSeconds(2),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        configuration.localRequestCount(),
    );
    try session.sendWithTimeout(&client_packet, .fromSeconds(2));

    var first = try session.receiveEventWithTimeout(.fromSeconds(2));
    defer first.deinit(allocator);
    try std.testing.expect(first == .capsule);
    const assignment = first.capsule;
    var assigned = try http3.connect_ip.capsules.parseAddressAssign(
        assignment.value,
    );
    try std.testing.expectEqual(
        @as(u62, 9),
        (try assigned.next()).?.request_id,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        configuration.assignedPrefixes().len,
    );
    var second = try session.receiveEventWithTimeout(.fromSeconds(2));
    defer second.deinit(allocator);
    try std.testing.expect(second == .payload);
    try std.testing.expectEqualSlices(
        u8,
        &server_packet,
        second.payload.payload,
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        session.receiveCapsuleWithTimeout(.fromSeconds(2)),
    );
    try session.closeWrite();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

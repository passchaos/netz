const std = @import("std");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/2 CONNECT-IP rejects an unencrypted transport" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: runtime.Limits = .{ .enable_connect_protocol = true };
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        done: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            self.done.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    var done: std.Io.Event = .unset;
    var shared = Shared{ .server = &server, .done = &done };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        done.set(io);
        thread.join();
    };
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
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
    done.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 TLS CONNECT-IP exchanges configuration and IP packets" {
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
    const public_key = key_pair.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{
        .enable_connect_protocol = true,
        .max_frame_payload = 4096,
        .max_body_bytes = 128 * 1024,
    };
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .limits = limits,
        },
    );
    defer server.deinit();

    const client_packet = [_]u8{ 0x45, 0, 0, 20 } ++ [_]u8{0x31} ** 16;
    const server_packet = [_]u8{ 0x60, 0, 0, 0 } ++ [_]u8{0x42} ** 36;
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
                request,
                &target_storage,
            );
            defer accepted.session.deinit();
            try std.testing.expectEqualStrings("*", accepted.scope.target);

            var first = try accepted.session.receiveEventWithTimeout(
                .fromSeconds(2),
            );
            defer first.deinit(self.server.allocator);
            try std.testing.expect(first == .capsule);
            const address_request = first.capsule;
            var requests = try http3.connect_ip.capsules.parseAddressRequest(
                address_request.value,
            );
            try std.testing.expectEqual(
                @as(u62, 11),
                (try requests.next()).?.request_id,
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

            const routes = [_]http3.connect_ip.capsules.Route{.{
                .ipv4 = .{
                    .start = .{ 0, 0, 0, 0 },
                    .end = .{ 255, 255, 255, 255 },
                },
            }};
            var encoded: [64]u8 = undefined;
            const route = try http3.connect_ip.capsules
                .writeRouteAdvertisementInto(&encoded, &routes);
            try accepted.session.sendCapsuleWithTimeout(
                route,
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
        limits,
        .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    );
    defer client.close();
    const template = try http3.connect_ip.UriTemplate.compile(
        "https://localhost/.well-known/masque/ip/{target}/{ipproto}/",
    );
    var path_storage: [256]u8 = undefined;
    var session = try client.openConnectIpWithTimeout(
        template,
        .{},
        &.{},
        &path_storage,
        .fromSeconds(5),
    );
    defer session.deinit();

    const requested = [_]http3.connect_ip.capsules.AddressPrefix{.{
        .request_id = 11,
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
    try session.sendWithTimeout(&client_packet, .fromSeconds(2));

    var first = try session.receiveEventWithTimeout(.fromSeconds(2));
    defer first.deinit(allocator);
    try std.testing.expect(first == .capsule);
    const route = first.capsule;
    var routes = try http3.connect_ip.capsules.parseRouteAdvertisement(
        route.value,
    );
    try std.testing.expectEqual(
        @as(u8, 4),
        (try routes.next()).?.version(),
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

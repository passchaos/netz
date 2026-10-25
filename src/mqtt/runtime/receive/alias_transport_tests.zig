const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const mqtt_tls = @import("../../tls_runtime.zig");
const mqtt_ws = @import("../../websocket_runtime.zig");
const tls = @import("../../../tls/testing.zig");
const allocator = std.testing.allocator;
const Transport = enum { tcp, tls12, tls13, websocket, wss };
const properties = [_]mqtt.Property{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }};

test "MQTT alias-only publications keep topic ownership across real transport close" {
    inline for (std.enums.values(Transport)) |transport| try exercise(transport);
}

fn exercise(comptime transport: Transport) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.certificate_base64);
    const key = try tls.serverKeyPair();
    const identity: mqtt_tls.ServerIdentity = .{
        .certificate_chain = &.{&certificate},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
    };
    const Server = switch (transport) {
        .tcp => runtime.Server,
        .tls12, .tls13 => mqtt_tls.Server,
        .websocket => mqtt_ws.Server,
        .wss => mqtt_ws.TlsServer,
    };
    var server = switch (transport) {
        .tcp => try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}),
        .tls12, .tls13 => try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .identity = identity,
            .protocol_policy = if (transport == .tls12) .tls12_only else .tls13_only,
        }),
        .websocket => try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}),
        .wss => try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .identity = identity, .protocol_policy = .tls13_only }),
    };
    defer server.deinit();
    const Peer = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(allocator);
            const connection = &accepted.connection;
            connection.peer_topic_alias_maximum = 16;
            _ = try connection.writePublish("first/topic", "seed", .{ .properties = &properties });
            _ = try connection.writePublish("", "retained", .{ .properties = &properties });
            // The retained message reached the caller before its alias changes.
            try connection.readPingReq();
            _ = try connection.writePublish("other/topic", "replacement", .{ .properties = &properties });
            try connection.writePingResp();
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    const options = runtime.ConnectOptions{ .protocol = .v5, .client_id = "owned-alias", .topic_alias_maximum = 16 };
    var client = switch (transport) {
        .tcp => try runtime.Client.connect(allocator, io, server.address(), options),
        .tls12, .tls13 => try mqtt_tls.Client.connectAddress(allocator, io, server.address(), "localhost", .{
            .mqtt = options,
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .protocol_policy = if (transport == .tls12) .tls12_only else .tls13_only,
        }),
        .websocket => try mqtt_ws.Client.connect(allocator, io, server.address(), .{ .mqtt = options, .host = "localhost" }),
        .wss => blk: {
            const uri = try std.fmt.allocPrint(allocator, "wss://localhost:{d}/mqtt", .{server.address().ip4.port});
            defer allocator.free(uri);
            break :blk try mqtt_ws.Client.connectUri(allocator, io, uri, .{
                .mqtt = options,
                .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
                .protocol_policy = .tls13_only,
            });
        },
    };
    var open = true;
    defer if (open) client.close();
    var seed = try client.readPublish();
    seed.deinit(allocator);
    var retained = try client.readPublish();
    defer retained.deinit(allocator);
    try client.pingWithTimeout(.fromSeconds(2));
    // AckReader queued the replacement while waiting for PINGRESP.
    var replacement = try client.readPublish();
    defer replacement.deinit(allocator);
    try std.testing.expectEqualStrings("first/topic", retained.publish.topic);
    client.close();
    open = false;
    try std.testing.expectEqualStrings("first/topic", retained.publish.topic);
    try std.testing.expectEqualStrings("retained", retained.publish.payload);
    try std.testing.expectEqualStrings("other/topic", replacement.publish.topic);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

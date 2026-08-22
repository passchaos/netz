const std = @import("std");
const mqtt = @import("mod.zig");
const mqtt_ws = @import("websocket_runtime.zig");
const websocket_runtime = @import("../websocket/mod.zig").runtime;
const tls_testing = @import("../tls/testing.zig");

const max_packet_size: usize = 4096;

test "MQTT WebSocket server enforces Keep Alive despite control traffic" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        timed_out: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(shared.server.allocator);
            _ = accepted.connection.readBrokerEventWithKeepAlive() catch |err| {
                if (err != error.Timeout) return err;
                shared.timed_out = true;
                return;
            };
            return error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ws = try websocket_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "127.0.0.1",
            .protocols = &.{"mqtt"},
            .limits = .{
                .max_head_bytes = max_packet_size,
                .max_frame_bytes = max_packet_size,
                .max_message_bytes = max_packet_size,
            },
        },
    );
    defer ws.close();
    var connect: std.ArrayList(u8) = .empty;
    defer connect.deinit(allocator);
    try mqtt.writeConnect(
        &connect,
        allocator,
        .v5,
        "mqtt-ws-keep-alive",
        true,
        1,
    );
    try ws.sendBinary(connect.items);
    var connack = try ws.receiveMessage();
    defer connack.deinit(allocator);
    try std.testing.expectEqual(websocket_runtime.Role.client, ws.role);
    try std.testing.expectEqual(mqtt.PacketType.connack, (try mqtt.FixedHeader.parse(connack.payload)).packet_type);

    const started = std.Io.Clock.awake.now(io);
    // Neither a WebSocket message boundary nor transport control traffic is a
    // completed MQTT packet. A one-byte partial PINGREQ followed by repeated
    // WebSocket Ping frames must therefore share, rather than reset, the
    // original 1.5-second packet deadline.
    try std.Io.sleep(io, .fromMilliseconds(300), .awake);
    try ws.sendBinary(&.{0xc0});
    for (0..3) |index| {
        try std.Io.sleep(io, .fromMilliseconds(300), .awake);
        try ws.sendPing(&.{@intCast(index)});
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.timed_out);
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(
        elapsed.nanoseconds >= 1400 * std.time.ns_per_ms,
    );
    try std.testing.expect(elapsed.nanoseconds < 4 * std.time.ns_per_s);
}

test "MQTT WebSocket Keep Alive renews for a progressing large packet" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(shared.server.allocator);
            var event = try accepted.connection
                .readBrokerEventWithKeepAlive();
            defer event.deinit(shared.server.allocator);
            const publish = switch (event) {
                .publish => |value| value.publish,
                else => return error.UnexpectedPacket,
            };
            try std.testing.expectEqualStrings(
                "ws/large-progress",
                publish.topic,
            );
            try std.testing.expectEqual(@as(usize, 2500), publish.payload.len);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ws = try websocket_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "127.0.0.1",
            .protocols = &.{"mqtt"},
            .limits = .{
                .max_head_bytes = max_packet_size,
                .max_frame_bytes = max_packet_size,
                .max_message_bytes = max_packet_size,
            },
        },
    );
    defer ws.close();
    var connect: std.ArrayList(u8) = .empty;
    defer connect.deinit(allocator);
    try mqtt.writeConnect(
        &connect,
        allocator,
        .v5,
        "mqtt-ws-large-progress",
        true,
        1,
    );
    try ws.sendBinary(connect.items);
    var connack = try ws.receiveMessage();
    defer connack.deinit(allocator);

    var payload: [2500]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var publish: std.ArrayList(u8) = .empty;
    defer publish.deinit(allocator);
    try mqtt.writePublish(
        &publish,
        allocator,
        .v5,
        "ws/large-progress",
        &payload,
        .{},
    );
    try std.testing.expect(publish.items.len > 2000);

    // Each useful chunk arrives within the current deadline, but the complete
    // MQTT packet takes longer than one Keep Alive budget. Remaining payload
    // above 1,000 bytes renews the deadline just as on TCP/TLS.
    const started = std.Io.Clock.awake.now(io);
    try std.Io.sleep(io, .fromMilliseconds(700), .awake);
    try ws.sendBinary(publish.items[0..4]);
    try std.Io.sleep(io, .fromMilliseconds(700), .awake);
    try ws.sendBinary(publish.items[4..704]);
    try std.Io.sleep(io, .fromMilliseconds(700), .awake);
    try ws.sendBinary(publish.items[704..]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds > 2 * std.time.ns_per_s);
}

test "MQTT WSS server enforces Keep Alive inactivity" {
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
    var server = try mqtt_ws.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{ .max_packet_size = max_packet_size },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        timed_out: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(shared.server.allocator);
            _ = accepted.connection.readBrokerEventWithKeepAlive() catch |err| {
                if (err != error.Timeout) return err;
                shared.timed_out = true;
                return;
            };
            return error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try mqtt_ws.Client.connectUri(allocator, io, uri, .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = "mqtt-wss-keep-alive",
            .keep_alive_seconds = 1,
        },
        .tls = .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    });
    defer client.close();

    const started = std.Io.Clock.awake.now(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.timed_out);
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(
        elapsed.nanoseconds >= 1400 * std.time.ns_per_ms,
    );
    try std.testing.expect(elapsed.nanoseconds < 4 * std.time.ns_per_s);
}

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { std.crypto.Certificate.Bundle, std.Io.RwLock } {
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: std.crypto.Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}

const std = @import("std");
const context = @import("../broker_tests.zig");
const tls_testing = @import("../../tls/testing.zig");

const mqtt = context.TestContext.mqtt_mod;
const Broker = context.TestContext.BrokerType;
const runtime = context.TestContext.runtime_mod;
const disconnectAll = context.TestContext.disconnectAllFn;

const ListenerServeState = struct {
    broker: *Broker,
    listeners: []const mqtt.broker.Listener,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListeners(self.listeners) catch |err| {
            self.err = err;
        };
    }
};

test "broker shares mounted WSS and global TCP listener namespaces" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var global_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer global_server.deinit();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var mounted_server = try mqtt.websocket_runtime.TlsServer.listen(
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
            .limits = .{ .max_packet_size = 4096 },
            .max_head_bytes = 4096,
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer mounted_server.deinit();

    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = global_server.pendingSource(),
            .connection_count = 1,
        },
        .{
            .source = mounted_server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                "secure/",
            ),
            .connection_count = 2,
        },
    };
    var shared = ListenerServeState{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&shared},
    );
    var joined = false;
    defer if (!joined) thread.join();

    var global = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{ .protocol = .v5, .client_id = "global-tcp" },
    );
    defer global.close();

    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mqtt",
        .{mounted_server.address().ip4.port},
    );
    defer allocator.free(uri);
    const wss_options: mqtt.websocket_runtime.ConnectOptions = .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = "mounted-wss-subscriber",
            .limits = .{ .max_packet_size = 4096 },
        },
        // Pinning keeps this test hermetic while still exercising the real
        // TLS 1.3 and HTTP Upgrade path used by a production WSS listener.
        .use_vail_tls = true,
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .max_head_bytes = 4096,
    };
    var mounted = try mqtt.websocket_runtime.Client.connectUri(
        allocator,
        io,
        uri,
        wss_options,
    );
    defer mounted.close();
    var publisher_options = wss_options;
    publisher_options.mqtt.client_id = "mounted-wss-publisher";
    var publisher = try mqtt.websocket_runtime.Client.connectUri(
        allocator,
        io,
        uri,
        publisher_options,
    );
    defer publisher.close();

    var global_suback = try global.subscribe(
        &.{.{ .topic_filter = "secure/#" }},
        .{},
    );
    defer global_suback.deinit(allocator);
    var mounted_suback = try mounted.subscribe(
        &.{.{ .topic_filter = "#" }},
        .{},
    );
    defer mounted_suback.deinit(allocator);
    try publisher.publish("room/value", "over-wss", .{});

    var global_delivery = try global.readPublish();
    defer global_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "secure/room/value",
        global_delivery.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "over-wss",
        global_delivery.publish.payload,
    );
    var mounted_delivery = try mounted.readPublish();
    defer mounted_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "room/value",
        mounted_delivery.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "over-wss",
        mounted_delivery.publish.payload,
    );

    try disconnectAll(&.{ &global, &mounted, &publisher });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

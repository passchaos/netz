const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const context = @import("../broker_tests.zig");

const mqtt = context.TestContext.mqtt_mod;
const Broker = context.TestContext.BrokerType;
const runtime = context.TestContext.runtime_mod;
const disconnectAll = context.TestContext.disconnectAllFn;

test "broker shares TCP raw Unix and Unix WebSocket listeners" {
    if (comptime @import("builtin").os.tag == .windows) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var directory_storage: [std.fs.max_path_bytes]u8 = undefined;
    const directory_len = try tmp.dir.realPath(io, &directory_storage);
    const directory = directory_storage[0..directory_len];
    const raw_path = try std.fmt.allocPrint(
        allocator,
        "{s}/mqtt.sock",
        .{directory},
    );
    defer allocator.free(raw_path);
    const ws_path = try std.fmt.allocPrint(
        allocator,
        "{s}/mqtt-ws.sock",
        .{directory},
    );
    defer allocator.free(ws_path);
    const raw_address = try std.Io.net.UnixAddress.init(raw_path);
    const ws_address = try std.Io.net.UnixAddress.init(ws_path);

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
    var raw_server = try runtime.UnixServer.listen(
        allocator,
        io,
        raw_address,
        .{ .max_packet_size = 4096 },
    );
    defer {
        raw_server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, raw_path) catch {};
    }
    var ws_server = try mqtt.websocket_runtime.UnixServer.listen(
        allocator,
        io,
        ws_address,
        .{
            .limits = .{ .max_packet_size = 4096 },
            .max_head_bytes = 4096,
        },
    );
    defer {
        ws_server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, ws_path) catch {};
    }

    const namespace = try mqtt.listener_namespace.Namespace.init(
        "local/",
    );
    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = global_server.pendingSource(),
            .connection_count = 1,
        },
        .{
            .source = raw_server.pendingSource(),
            .namespace = namespace,
            .connection_count = 1,
        },
        .{
            .source = ws_server.pendingSource(),
            .namespace = namespace,
            .connection_count = 1,
        },
    };
    const Shared = struct {
        broker: *Broker,
        listeners: []const mqtt.broker.Listener,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serveListeners(self.listeners) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .broker = &broker, .listeners = &listeners };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var global = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{ .protocol = .v5, .client_id = "global-tcp" },
    );
    defer global.close();
    var ws_subscriber = try mqtt.websocket_runtime.Client.connectUnix(
        allocator,
        io,
        ws_address,
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "local-ws-subscriber",
            },
            .host = "localhost",
            .target = "/mqtt",
            .max_head_bytes = 4096,
        },
    );
    defer ws_subscriber.close();
    var raw_publisher = try runtime.Client.connectUnix(
        allocator,
        io,
        raw_address,
        .{ .protocol = .v5, .client_id = "local-raw-publisher" },
    );
    defer raw_publisher.close();

    var global_suback = try global.subscribe(
        &.{.{ .topic_filter = "local/#" }},
        .{},
    );
    defer global_suback.deinit(allocator);
    var ws_suback = try ws_subscriber.subscribe(
        &.{.{ .topic_filter = "#" }},
        .{},
    );
    defer ws_suback.deinit(allocator);
    try raw_publisher.publish("sensor/value", "unix-mixed", .{});

    var global_delivery = try global.readPublish();
    defer global_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "local/sensor/value",
        global_delivery.publish.topic,
    );
    var local_delivery = try ws_subscriber.readPublish();
    defer local_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "sensor/value",
        local_delivery.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "unix-mixed",
        local_delivery.publish.payload,
    );

    try disconnectAll(&.{ &global, &ws_subscriber, &raw_publisher });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

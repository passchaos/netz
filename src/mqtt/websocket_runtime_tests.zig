const std = @import("std");
const mqtt = @import("mod.zig");
const runtime = @import("runtime.zig");
const mqtt_ws = @import("websocket_runtime.zig");
const websocket_runtime = @import("../websocket/mod.zig").runtime;

const max_packet_size: usize = 4096;

test "MQTT 5 WebSocket runtime negotiates mqtt and completes QoS 1 and 2" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{ .max_packet_size = max_packet_size },
            .max_head_bytes = max_packet_size,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_ws.Server) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
            });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "mqtt-ws-v5",
                accepted.connect.connect.client_id,
            );

            var qos1 = try accepted.connection.readPublish();
            defer qos1.deinit(server_ptr.allocator);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, qos1.publish.qos);
            try std.testing.expectEqualStrings("ws/qos1", qos1.publish.topic);
            try std.testing.expectEqualStrings("one", qos1.publish.payload);
            try accepted.connection.writePubAck(qos1.publish.packet_id.?, 0);

            var qos2 = try accepted.connection.readPublish();
            defer qos2.deinit(server_ptr.allocator);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, qos2.publish.qos);
            try std.testing.expectEqualStrings("ws/qos2", qos2.publish.topic);
            try std.testing.expectEqualStrings("two", qos2.publish.payload);
            try accepted.connection.writePubRec(qos2.publish.packet_id.?, 0);

            var pubrel = try accepted.connection.readPubRel();
            defer pubrel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                qos2.publish.packet_id.?,
                pubrel.ack.packet_id,
            );
            try accepted.connection.writePubComp(pubrel.ack.packet_id, 0);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try mqtt_ws.Client.connect(allocator, io, server.address(), .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = "mqtt-ws-v5",
            .limits = .{ .max_packet_size = max_packet_size },
            .max_outgoing_inflight = 2,
        },
        .host = "127.0.0.1",
        .target = "/mqtt",
        .max_head_bytes = max_packet_size,
    });
    defer client.close();
    try client.publish("ws/qos1", "one", .{ .qos = .at_least_once });
    try client.publish("ws/qos2", "two", .{ .qos = .exactly_once });
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT 3.1.1 WebSocket runtime uses shared session state" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
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
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_ws.Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v3_1_1 });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                mqtt.ProtocolVersion.v3_1_1,
                accepted.connection.protocol,
            );
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("ws/v3", publish.publish.topic);
            try std.testing.expectEqualStrings("payload", publish.publish.payload);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try mqtt_ws.Client.connect(allocator, io, server.address(), .{
        .mqtt = .{
            .protocol = .v3_1_1,
            .client_id = "mqtt-ws-v3",
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .host = "127.0.0.1",
    });
    defer client.close();
    try client.publish("ws/v3", "payload", .{});

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket client connects through ws URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
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
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_ws.Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(
                server_ptr.allocator,
            );
            try std.testing.expectEqualStrings(
                "mqtt-ws-uri",
                accepted.connect.connect.client_id,
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(
                server_ptr.allocator,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try mqtt_ws.Client.connectUri(allocator, io, uri, .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = "mqtt-ws-uri",
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .max_head_bytes = max_packet_size,
    });
    defer client.close();
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket reader preserves MQTT byte stream across messages" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = max_packet_size,
            .max_frame_bytes = max_packet_size,
            .max_message_bytes = max_packet_size,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *websocket_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *websocket_runtime.Server) !void {
            var ws = try server_ptr.accept(.{
                .protocols = &.{"mqtt"},
                .require_subprotocol = true,
            });
            defer ws.close();

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.http.allocator);
            try mqtt.writePing(&encoded, server_ptr.http.allocator, false);
            try mqtt.writePing(&encoded, server_ptr.http.allocator, false);
            // First MQTT packet spans two WebSocket messages; the second packet
            // shares the latter message. This is the byte-stream behavior used
            // by rumqtt's WsStream and must not depend on message boundaries.
            try ws.sendBinary(encoded.items[0..1]);
            try ws.sendBinary(encoded.items[1..]);

            var first = try ws.receiveMessage();
            defer first.deinit(server_ptr.http.allocator);
            var second = try ws.receiveMessage();
            defer second.deinit(server_ptr.http.allocator);
            try mqtt.validatePing(first.payload, true);
            try mqtt.validatePing(second.payload, true);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ws = try websocket_runtime.Client.connect(
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
    var connection = runtime.Connection.initWebSocket(
        allocator,
        ws,
        .v5,
        .{ .max_packet_size = max_packet_size },
        16,
        16,
    );
    defer connection.close();
    try connection.readPingReq();
    try connection.writePingResp();
    try connection.readPingReq();
    try connection.writePingResp();

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket server requires mqtt subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
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
            std.testing.expectError(
                error.InvalidSubprotocol,
                shared.server.accept(.{}),
            ) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.testing.expectError(
        error.ConnectionClosed,
        websocket_runtime.Client.connect(
            allocator,
            io,
            server.address(),
            .{
                .host = "127.0.0.1",
                .protocols = &.{"chat"},
                .limits = .{
                    .max_head_bytes = max_packet_size,
                    .max_frame_bytes = max_packet_size,
                    .max_message_bytes = max_packet_size,
                },
            },
        ),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket adapter rejects text messages" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = max_packet_size,
            .max_frame_bytes = max_packet_size,
            .max_message_bytes = max_packet_size,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *websocket_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *websocket_runtime.Server) !void {
            var ws = try server_ptr.accept(.{
                .protocols = &.{"mqtt"},
                .require_subprotocol = true,
            });
            defer ws.close();
            try ws.sendText("not-mqtt");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ws = try websocket_runtime.Client.connect(
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
    var connection = runtime.Connection.initWebSocket(
        allocator,
        ws,
        .v5,
        .{ .max_packet_size = max_packet_size },
        16,
        16,
    );
    defer connection.close();
    try std.testing.expectError(
        error.InvalidWebSocketMessage,
        connection.readPingReq(),
    );

    thread.join();
    if (shared.err) |err| return err;
}

const std = @import("std");
const mqtt_ws = @import("../websocket_runtime.zig");
const mqtt_reconnect = @import("../reconnect.zig");
const websocket_runtime = @import("../../websocket/runtime.zig");

const max_packet_size: usize = 4096;

fn wsUri(
    allocator: std.mem.Allocator,
    port: u16,
    path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}{s}",
        .{ port, path },
    );
}

fn connectOptions(client_id: []const u8) mqtt_ws.ConnectOptions {
    return .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = client_id,
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .max_head_bytes = max_packet_size,
    };
}

test "MQTT WebSocket client follows HTTP redirect before CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var redirector = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = max_packet_size },
    );
    defer redirector.deinit();
    var destination = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer destination.deinit();
    const destination_uri = try wsUri(
        allocator,
        destination.address().getPort(),
        "/mqtt",
    );
    defer allocator.free(destination_uri);

    const Shared = struct {
        redirector: *websocket_runtime.Server,
        destination: *mqtt_ws.Server,
        destination_uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.redirector.receiveUpgradeRequest(.{});
            try std.testing.expectEqualStrings("/start", pending.target());
            try pending.reject(
                302,
                "Found",
                &.{.{ .name = "Location", .value = self.destination_uri }},
                &.{},
            );
            var accepted = try self.destination.accept(.{ .protocol = .v5 });
            defer accepted.deinit(allocator);
            try std.testing.expectEqualStrings(
                "mqtt-http-redirect",
                accepted.connect.connect.client_id,
            );
            var disconnect = try accepted.connection.readDisconnect();
            disconnect.deinit(allocator);
        }
    };
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .destination_uri = destination_uri,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try wsUri(
        allocator,
        redirector.address().getPort(),
        "/start",
    );
    defer allocator.free(initial_uri);
    var connection = try mqtt_ws.Client
        .connectUriFollowingHttpRedirectsWithTimeout(
        allocator,
        io,
        initial_uri,
        connectOptions("mqtt-http-redirect"),
        .{},
        .fromSeconds(3),
    );
    defer connection.close();
    try connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WebSocket client composes HTTP and Server Reference redirects" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var first_http = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = max_packet_size },
    );
    defer first_http.deinit();
    var mqtt_redirector = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer mqtt_redirector.deinit();
    var second_http = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = max_packet_size },
    );
    defer second_http.deinit();
    var destination = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer destination.deinit();

    const mqtt_redirector_uri = try wsUri(
        allocator,
        mqtt_redirector.address().getPort(),
        "/mqtt",
    );
    defer allocator.free(mqtt_redirector_uri);
    const second_http_uri = try wsUri(
        allocator,
        second_http.address().getPort(),
        "/again",
    );
    defer allocator.free(second_http_uri);
    const destination_uri = try wsUri(
        allocator,
        destination.address().getPort(),
        "/mqtt",
    );
    defer allocator.free(destination_uri);

    const Shared = struct {
        first_http: *websocket_runtime.Server,
        mqtt_redirector: *mqtt_ws.Server,
        second_http: *websocket_runtime.Server,
        destination: *mqtt_ws.Server,
        mqtt_redirector_uri: []const u8,
        second_http_uri: []const u8,
        destination_uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.first_http.receiveUpgradeRequest(.{});
            try first.reject(
                307,
                "Temporary Redirect",
                &.{.{
                    .name = "Location",
                    .value = self.mqtt_redirector_uri,
                }},
                &.{},
            );

            var mqtt_hop = try self.mqtt_redirector.accept(.{
                .protocol = .v5,
                .reason_code = 0x9d,
                .server_reference = self.second_http_uri,
            });
            mqtt_hop.deinit(allocator);

            var second = try self.second_http.receiveUpgradeRequest(.{});
            try second.reject(
                308,
                "Permanent Redirect",
                &.{.{ .name = "Location", .value = self.destination_uri }},
                &.{},
            );

            var accepted = try self.destination.accept(.{ .protocol = .v5 });
            defer accepted.deinit(allocator);
            try std.testing.expectEqualStrings(
                "mqtt-all-redirects",
                accepted.connect.connect.client_id,
            );
            var disconnect = try accepted.connection.readDisconnect();
            disconnect.deinit(allocator);
        }
    };
    var shared = Shared{
        .first_http = &first_http,
        .mqtt_redirector = &mqtt_redirector,
        .second_http = &second_http,
        .destination = &destination,
        .mqtt_redirector_uri = mqtt_redirector_uri,
        .second_http_uri = second_http_uri,
        .destination_uri = destination_uri,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try wsUri(
        allocator,
        first_http.address().getPort(),
        "/start",
    );
    defer allocator.free(initial_uri);
    const Authorization = struct {
        expected_from: []const u8,
        expected_to: []const u8,
        called: bool = false,

        fn call(
            context: ?*anyopaque,
            from_uri: []const u8,
            to_uri: []const u8,
            _: u8,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.called = true;
            return std.mem.eql(u8, from_uri, self.expected_from) and
                std.mem.eql(u8, to_uri, self.expected_to);
        }
    };
    var authorization = Authorization{
        .expected_from = mqtt_redirector_uri,
        .expected_to = second_http_uri,
    };
    var result = try mqtt_ws.Client.connectUriFollowingAllRedirectsWithTimeout(
        allocator,
        io,
        initial_uri,
        connectOptions("mqtt-all-redirects"),
        .{},
        .{
            .max_redirects = 1,
            .context = &authorization,
            .authorize = Authorization.call,
        },
        .fromSeconds(5),
    );
    defer result.deinit(allocator);
    try std.testing.expect(authorization.called);
    try result.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT HTTP redirect reconnect connector restarts chain" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var redirector = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = max_packet_size },
    );
    defer redirector.deinit();
    var destination = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer destination.deinit();
    const destination_uri = try wsUri(
        allocator,
        destination.address().getPort(),
        "/mqtt",
    );
    defer allocator.free(destination_uri);

    const Shared = struct {
        redirector: *websocket_runtime.Server,
        destination: *mqtt_ws.Server,
        destination_uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                var pending = try self.redirector.receiveUpgradeRequest(.{});
                try pending.reject(
                    302,
                    "Found",
                    &.{.{
                        .name = "Location",
                        .value = self.destination_uri,
                    }},
                    &.{},
                );
                var accepted = try self.destination.accept(.{
                    .protocol = .v5,
                    .session_present = index != 0,
                });
                try std.testing.expectEqualStrings(
                    "mqtt-http-redirect-reconnect",
                    accepted.connect.connect.client_id,
                );
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(allocator);
                accepted.deinit(allocator);
            }
        }
    };
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .destination_uri = destination_uri,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try wsUri(
        allocator,
        redirector.address().getPort(),
        "/start",
    );
    defer allocator.free(initial_uri);
    var connector = mqtt_ws.HttpRedirectReconnectConnector{
        .uri = initial_uri,
        .options = connectOptions("placeholder"),
    };
    var shutdown: std.Io.Event = .unset;
    var client = try mqtt_reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "mqtt-http-redirect-reconnect",
            .clean_start = false,
        },
        .{},
        &shutdown,
    );
    defer client.deinit();
    const first = try client.connectWithTimeout(.fromSeconds(3));
    try std.testing.expect(!first.session_present);
    try client.disconnect(0);
    const second = try client.connectWithTimeout(.fromSeconds(3));
    try std.testing.expect(second.session_present);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT HTTP and nested redirect timeouts reject before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        mqtt_ws.Client.connectUriFollowingHttpRedirectsWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "ws://127.0.0.1:1/mqtt",
            connectOptions("mqtt-http-redirect-timeout"),
            .{},
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        mqtt_ws.Client.connectUriFollowingAllRedirectsWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "ws://127.0.0.1:1/mqtt",
            connectOptions("mqtt-all-redirect-timeout"),
            .{},
            .{},
            .zero,
        ),
    );
}

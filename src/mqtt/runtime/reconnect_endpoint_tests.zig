const std = @import("std");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

test "MQTT reconnect client owns hostname and URI targets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for ([_][]const u8{
                "owned-host",
                "owned-host",
                "owned-uri",
                "owned-uri",
            }) |client_id| {
                var accepted = try self.server.accept(.{ .protocol = .v5 });
                try std.testing.expectEqualStrings(
                    client_id,
                    accepted.connect.connect.client_id,
                );
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
                accepted.deinit(self.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const hostname = try allocator.dupe(u8, "localhost");
    defer allocator.free(hostname);
    var host_shutdown: std.Io.Event = .unset;
    var host_client = try reconnect.Client.initHost(
        allocator,
        io,
        hostname,
        server.address().ip4.port,
        .{
            .protocol = .v5,
            .client_id = "owned-host",
            .network_connect_timeout = .fromSeconds(1),
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
        },
        &host_shutdown,
    );
    defer host_client.deinit();
    @memset(hostname, 'x');
    try connectAndDisconnectTwice(&host_client);

    const uri = try std.fmt.allocPrint(
        allocator,
        "mqtt://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var uri_shutdown: std.Io.Event = .unset;
    var uri_client = try reconnect.Client.initUri(
        allocator,
        io,
        uri,
        .{
            .protocol = .v5,
            .client_id = "owned-uri",
            .network_connect_timeout = .fromSeconds(1),
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
        },
        &uri_shutdown,
    );
    defer uri_client.deinit();
    @memset(uri, 'x');
    try connectAndDisconnectTwice(&uri_client);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn connectAndDisconnectTwice(client: *reconnect.Client) !void {
    for (0..2) |_| {
        const event = try client.connect();
        try std.testing.expectEqual(@as(usize, 0), event.failed_attempts);
        try client.disconnect(0);
    }
}

test "MQTT reconnect URI validates before retaining target" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    try std.testing.expectError(
        error.UnsupportedRedirectScheme,
        reconnect.Client.initUri(
            std.testing.allocator,
            threaded.io(),
            "mqtts://localhost",
            .{ .client_id = "invalid-reconnect-uri" },
            .{},
            &shutdown,
        ),
    );
    try std.testing.expectError(
        error.InvalidServerReference,
        reconnect.Client.initUri(
            std.testing.allocator,
            threaded.io(),
            "mqtt://localhost/path",
            .{ .client_id = "invalid-reconnect-path" },
            .{},
            &shutdown,
        ),
    );
}

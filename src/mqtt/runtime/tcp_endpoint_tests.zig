const std = @import("std");
const runtime = @import("../runtime.zig");

test "MQTT raw client connects by hostname and URI" {
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
            for ([_][]const u8{ "hostname-client", "uri-client" }) |client_id| {
                var accepted = try self.server.accept(.{ .protocol = .v5 });
                defer accepted.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    client_id,
                    accepted.connect.connect.client_id,
                );
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var host_result = try runtime.Client.connectHostWithConnAck(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .protocol = .v5,
            .client_id = "hostname-client",
            .network_connect_timeout = .fromSeconds(1),
        },
    );
    defer host_result.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0),
        host_result.connack.connack.reason_code,
    );
    try host_result.connection.disconnect(0);

    const uri = try std.fmt.allocPrint(
        allocator,
        "mqtt://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var uri_result = try runtime.Client.connectUriWithConnAck(
        allocator,
        io,
        uri,
        .{
            .protocol = .v5,
            .client_id = "uri-client",
            .network_connect_timeout = .fromSeconds(1),
        },
    );
    defer uri_result.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0),
        uri_result.connack.connack.reason_code,
    );
    try uri_result.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT raw URI client rejects invalid targets and zero network budget" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const options: runtime.ConnectOptions = .{
        .client_id = "invalid-uri-client",
    };

    try std.testing.expectError(
        error.UnsupportedRedirectScheme,
        runtime.Client.connectUriAttempt(
            allocator,
            io,
            "mqtts://localhost",
            options,
        ),
    );
    try std.testing.expectError(
        error.InvalidServerReference,
        runtime.Client.connectUriAttempt(
            allocator,
            io,
            "mqtt://localhost/not-allowed",
            options,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectUriAttempt(
            allocator,
            io,
            "mqtt://localhost:1883",
            .{
                .client_id = "zero-budget-client",
                .network_connect_timeout = .zero,
            },
        ),
    );
}

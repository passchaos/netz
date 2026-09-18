const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

test "MQTT reconnect publish one attempt returns with durable inflight" {
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
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{ .protocol = .v5 }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            self.release.waitUncancelable(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var shared = Shared{ .server = &server, .release = &release };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer {
        release.set(io);
        if (!joined) thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "publish-one-attempt",
            .clean_start = false,
            .properties = &properties,
        },
        .{},
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    try client.connection().?.shutdown();

    const attempt = try client.publishOneAttempt(
        "one/attempt",
        "durable",
        .{ .qos = .at_least_once },
    );
    try std.testing.expect(attempt.transport_interrupted);
    try std.testing.expect(attempt.packet_id != null);
    try std.testing.expect(client.connection() == null);
    const stats = try client.outgoingStats();
    try std.testing.expectEqual(@as(usize, 1), stats.inflight_count);

    release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

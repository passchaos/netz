const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Pair = @import("../acknowledgement/test_connection.zig").Pair;
const allocator = std.testing.allocator;
const method = [_]mqtt.Property{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }};

test "MQTT CONNECT pre-wire timeout rolls back authentication and permits a fresh attempt" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Clock = struct {
        base: std.Io.Timestamp,
        calls: usize = 0,
        var active: ?*@This() = null;
        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self = active.?;
            defer self.calls += 1;
            return if (self.calls == 0) self.base else self.base.addDuration(.fromSeconds(2));
        }
    };
    var clock = Clock{ .base = std.Io.Clock.awake.now(io) };
    Clock.active = &clock;
    defer Clock.active = null;
    var vtable = io.vtable.*;
    vtable.now = Clock.now;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    const pair = try Pair.init(io, .v5);
    var connection = pair.client;
    var open = true;
    defer if (open) connection.close();
    var peer = pair.peer;
    defer peer.close();
    connection.transport.tcp.io = observed_io;
    const options = runtime.ConnectOptions{ .protocol = .v5, .client_id = "pre-wire-auth-retry", .properties = &method };
    try std.testing.expectError(error.Timeout, connection.establishClientWithDeadline(options, clock.base.addDuration(.fromNanoseconds(1)).withClock(.awake)));
    connection.transport.tcp.io = io;
    try std.testing.expect(connection.isUsable());
    try std.testing.expectEqual(.inactive, connection.authentication.phase);
    try std.testing.expect(connection.authentication.method() == null);
    try std.testing.expectError(error.Timeout, peer.readConnectWithTimeout(.fromMilliseconds(10)));
    const Peer = struct {
        connection: *runtime.Connection,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connect = try self.connection.readConnectWithDeadline(self.connection.transport.deadlineFromNow(.fromSeconds(2)));
            defer connect.deinit(allocator);
            try std.testing.expectEqualStrings("mirror", mqtt.authenticationMethod(connect.connect.properties).?);
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(allocator);
            try mqtt.ConnAck.write(&bytes, allocator, .v5, false, 0, &method);
            try self.connection.transport.writePacket(bytes.items);
        }
    };
    var shared = Peer{ .connection = &peer };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var attempt = try connection.establishClientWithDeadline(options, .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }));
    open = false;
    defer attempt.deinit(allocator);
    try std.testing.expect(attempt.accepted());
    try std.testing.expect(attempt.connection.?.isUsable());
    try std.testing.expectEqual(.active, attempt.connection.?.authentication.phase);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

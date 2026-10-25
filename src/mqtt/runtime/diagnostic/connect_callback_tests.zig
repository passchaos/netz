const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Pair = @import("../acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;
const method = [_]mqtt.Property{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }};
const other = [_]mqtt.Property{.{ .utf8 = .{ .id = .authentication_method, .value = "other" } }};

test "MQTT direct CONNECT callback failures retire authentication without a peer diagnostic" {
    for ([_]bool{ false, true }) |callback_error| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var blocked = BlockedWrite{ .delegate = io, .packet_type = .disconnect };
        BlockedWrite.active = &blocked;
        defer BlockedWrite.active = null;
        var vtable = io.vtable.*;
        vtable.netWrite = BlockedWrite.netWrite;
        const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
        var pair = try Pair.init(observed_io, .v5);
        defer pair.deinit();
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
                try self.connection.writeAuth(0x18, &method);
            }
        };
        var peer = Peer{ .connection = &pair.peer };
        const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
        var joined = false;
        defer if (!joined) thread.join();
        const Handler = struct {
            fail: bool,
            fn respond(context: *anyopaque, _: mqtt.Auth) runtime.Error![]const mqtt.Property {
                const self: *@This() = @ptrCast(@alignCast(context));
                if (self.fail) return error.Unexpected;
                return &other;
            }
        };
        var handler = Handler{ .fail = callback_error };
        blocked.armed.store(true, .release);
        const expected: runtime.Error = if (callback_error) error.Unexpected else error.AuthenticationMethodMismatch;
        try std.testing.expectError(expected, pair.client.establishClientWithDeadline(.{
            .protocol = .v5,
            .client_id = "direct-callback-error",
            .properties = &method,
            .authentication = .{ .context = &handler, .respond = Handler.respond },
        }, pair.client.transport.deadlineFromNow(.fromSeconds(1))));
        try std.testing.expect(!blocked.entered.load(.acquire));
        try std.testing.expect(!pair.client.isUsable());
        thread.join();
        joined = true;
        if (peer.err) |err| return err;
    }
}

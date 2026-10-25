const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const BlockedWrite = @import("../acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;
const Mode = enum { peer_auth, peer_connack, local_response };
const method = [_]mqtt.Property{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }};
const other = [_]mqtt.Property{.{ .utf8 = .{ .id = .authentication_method, .value = "other" } }};

test "MQTT initial authentication diagnostics use CONNECT budgets and distinguish local response errors" {
    for (std.enums.values(Mode)) |mode| {
        for ([_]bool{ false, true }) |absolute| try connectFailure(mode, absolute);
    }
}

fn connectFailure(mode: Mode, absolute: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var blocked = BlockedWrite{ .delegate = io, .packet_type = .disconnect };
    BlockedWrite.active = &blocked;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        mode: Mode,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var pending = try self.server.acceptPendingWithTimeout(.{ .protocol = .v5 }, .fromSeconds(2));
            defer pending.deinit(allocator);
            if (self.mode == .peer_connack) {
                // Deliberately violate the negotiated method while retaining
                // valid CONNACK syntax, without weakening server validation.
                var bytes: std.ArrayList(u8) = .empty;
                defer bytes.deinit(allocator);
                try mqtt.ConnAck.write(&bytes, allocator, .v5, false, 0, &other);
                try pending.connection.transport.writePacket(bytes.items);
            } else {
                try pending.connection.writeAuth(0x18, if (self.mode == .peer_auth) &other else &method);
            }
            var event = pending.connection.readBrokerEventWithTimeout(.fromSeconds(2)) catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => return,
                else => return err,
            };
            defer event.deinit(allocator);
            return error.UnexpectedAuthenticationResponse;
        }
    };
    var peer = Peer{ .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    const Handler = struct {
        calls: usize = 0,
        fn respond(context: *anyopaque, _: mqtt.Auth) runtime.Error![]const mqtt.Property {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return &other;
        }
    };
    var handler: Handler = .{};
    blocked.armed.store(true, .release);
    const options = runtime.ConnectOptions{
        .protocol = .v5,
        .client_id = "connect-diagnostic-budget",
        .properties = &method,
        .authentication = .{ .context = &handler, .respond = Handler.respond },
    };
    const timeout = std.Io.Duration.fromMilliseconds(100);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = timeout, .clock = .awake });
    try std.testing.expectError(error.AuthenticationMethodMismatch, if (absolute)
        runtime.Client.connectWithDeadline(allocator, observed_io, server.address(), options, deadline)
    else
        runtime.Client.connectWithTimeout(allocator, observed_io, server.address(), options, timeout));
    try std.testing.expectEqual(mode != .local_response, blocked.entered.load(.acquire));
    try std.testing.expectEqual(mode != .local_response, blocked.canceled.load(.acquire));
    try std.testing.expectEqual(@as(usize, if (mode == .local_response) 1 else 0), handler.calls);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

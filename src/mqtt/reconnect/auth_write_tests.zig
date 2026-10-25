const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const reconnect = @import("../reconnect.zig");
const Pair = @import("../runtime/acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;
const properties = [_]mqtt.Property{
    .{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } },
    .{ .binary = .{ .id = .authentication_data, .value = "step" } },
    .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "kept" } },
};

const Clock = struct {
    delegate: std.Io,
    expired: std.atomic.Value(bool) = .init(false),
    var active: ?*Clock = null;
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = active.?;
        const real = self.delegate.vtable.now(userdata, clock);
        return if (clock == .awake and self.expired.load(.acquire)) real.addDuration(.fromSeconds(2)) else real;
    }
};

test "MQTT reconnect automatic AUTH response shares the original poll deadline" {
    for ([_]bool{ false, true }) |absolute| {
        for ([_]bool{ false, true }) |expire_after_callback| try authenticationReply(absolute, expire_after_callback, false);
        try authenticationReply(absolute, false, true);
    }
}

fn authenticationReply(absolute: bool, expire_after_callback: bool, handler_timeout: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var clock = Clock{ .delegate = io };
    Clock.active = &clock;
    defer Clock.active = null;
    var blocked = BlockedWrite{ .delegate = io, .packet_type = .auth };
    BlockedWrite.active = &blocked;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    vtable.now = Clock.now;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    const Handler = struct {
        calls: usize = 0,
        expire: ?*Clock = null,
        fail: bool = false,
        fn respond(context: *anyopaque, challenge: mqtt.Auth) runtime.Error![]const mqtt.Property {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (!std.mem.eql(u8, mqtt.authenticationData(challenge.properties).?, "step")) return error.InvalidAuthenticationState;
            if (self.fail) return error.Timeout;
            if (self.expire) |value| value.expired.store(true, .release);
            return &properties;
        }
    };
    var handler = Handler{ .expire = if (expire_after_callback) &clock else null, .fail = handler_timeout };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, observed_io, .{ .ip4 = .loopback(1) }, .{
        .protocol = .v5,
        .client_id = "auth-reply-budget",
        .properties = &properties,
        .authentication = .{ .context = &handler, .respond = Handler.respond },
    }, .{}, &shutdown);
    defer client.deinit();
    const pair = try Pair.init(observed_io, .v5);
    client.connection_state = pair.client;
    var peer = pair.peer;
    defer peer.close();
    try client.connection().?.authentication.beginConnect(allocator, &properties);
    client.connection().?.authentication.phase = .active;
    try peer.authentication.beginConnect(allocator, &properties);
    peer.authentication.phase = .active;
    try client.beginReauthentication(&properties);
    var initial = try peer.acceptReauthentication();
    initial.deinit(allocator);
    try peer.continueReauthenticationWithProperties(0x18, &properties);
    blocked.armed.store(true, .release);
    const outcome = if (absolute)
        client.pollWithDeadline(std.Io.Clock.awake.now(io).addDuration(.fromMilliseconds(50)), .{ .reconnect_after_transport_error = false })
    else
        client.pollWithOptions(.{ .timeout = .fromMilliseconds(50), .reconnect_after_transport_error = false });
    if (handler_timeout) {
        try std.testing.expectError(error.Timeout, outcome);
    } else {
        if (try outcome) |value| {
            var event = value;
            event.deinit(allocator);
            return error.AuthenticationReplyEscapedDeadline;
        }
    }
    try std.testing.expectEqual(!expire_after_callback and !handler_timeout, blocked.entered.load(.acquire));
    try std.testing.expectEqual(!expire_after_callback and !handler_timeout, blocked.canceled.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expect(client.connection() == null);
}

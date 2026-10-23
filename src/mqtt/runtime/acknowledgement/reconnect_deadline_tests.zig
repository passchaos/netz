const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const reconnect = @import("../../reconnect.zig");

const Stage = enum { subscribe, unsubscribe, replay, success };

test "MQTT reconnect deadlines bound subscription updates and fresh-session replay" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for ([_]Stage{ .subscribe, .unsubscribe, .replay }) |stage| {
            for ([_]bool{ false, true }) |absolute| try exercise(protocol, stage, absolute);
        }
    }
}

test "MQTT reconnect bounded exchanges commit only acknowledged subscription changes" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for ([_]bool{ false, true }) |absolute| try exercise(protocol, .success, absolute);
    }
}

fn operation(client: *reconnect.Client, stage: Stage, absolute: bool) !void {
    const timeout = if (stage == .success) std.Io.Duration.fromSeconds(2) else std.Io.Duration.fromMilliseconds(50);
    const deadline = std.Io.Clock.Timestamp.fromNow(client.io, .{ .raw = timeout, .clock = .awake });
    switch (stage) {
        .success => {
            var suback = if (absolute)
                try client.subscribeWithDeadline(&.{.{ .topic_filter = "new/#" }}, .{}, deadline)
            else
                try client.subscribeWithTimeout(&.{.{ .topic_filter = "new/#" }}, .{}, timeout);
            defer suback.deinit(client.allocator);
            try std.testing.expect(client.hasSubscription("new/#"));
            try std.testing.expect(client.hasSubscription("old/#"));
            const unsub_deadline = std.Io.Clock.Timestamp.fromNow(client.io, .{ .raw = .fromSeconds(2), .clock = .awake });
            var unsuback = if (absolute)
                try client.unsubscribeWithDeadline(&.{"old/#"}, .{}, unsub_deadline)
            else
                try client.unsubscribeWithTimeout(&.{"old/#"}, .{}, .fromSeconds(2));
            defer unsuback.deinit(client.allocator);
        },
        .replay => {
            _ = if (absolute) try client.connectWithDeadline(deadline) else try client.connectWithTimeout(timeout);
        },
        .subscribe => {
            var acknowledgement = if (absolute)
                try client.subscribeWithDeadline(&.{.{ .topic_filter = "new/#" }}, .{}, deadline)
            else
                try client.subscribeWithTimeout(&.{.{ .topic_filter = "new/#" }}, .{}, timeout);
            defer acknowledgement.deinit(client.allocator);
        },
        .unsubscribe => {
            var acknowledgement = if (absolute)
                try client.unsubscribeWithDeadline(&.{"old/#"}, .{}, deadline)
            else
                try client.unsubscribeWithTimeout(&.{"old/#"}, .{}, timeout);
            defer acknowledgement.deinit(client.allocator);
        },
    }
}

fn exercise(protocol: mqtt.ProtocolVersion, stage: Stage, absolute: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        stage: Stage,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = self.protocol, .session_present = false });
            defer accepted.deinit(self.server.allocator);
            var initial = try accepted.connection.readSubscribe();
            defer initial.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("old/#", initial.subscribe.subscriptions[0].topic_filter);
            if (self.stage != .replay) {
                try accepted.connection.writeSubAck(initial.subscribe.packet_id, &.{0}, &.{});
                switch (self.stage) {
                    .success => {
                        var subscribe = try accepted.connection.readSubscribe();
                        defer subscribe.deinit(self.server.allocator);
                        try std.testing.expectEqualStrings("new/#", subscribe.subscribe.subscriptions[0].topic_filter);
                        try accepted.connection.writeSubAck(subscribe.subscribe.packet_id, &.{0}, &.{});
                        var unsubscribe = try accepted.connection.readUnsubscribe();
                        defer unsubscribe.deinit(self.server.allocator);
                        try std.testing.expectEqualStrings("old/#", unsubscribe.unsubscribe.topic_filters[0]);
                        try accepted.connection.writeUnsubAck(unsubscribe.unsubscribe.packet_id, if (self.protocol == .v5) &.{0} else &.{}, &.{});
                        return;
                    },
                    .subscribe => {
                        var request = try accepted.connection.readSubscribe();
                        defer request.deinit(self.server.allocator);
                        try std.testing.expectEqualStrings("new/#", request.subscribe.subscriptions[0].topic_filter);
                    },
                    .unsubscribe => {
                        var request = try accepted.connection.readUnsubscribe();
                        defer request.deinit(self.server.allocator);
                        try std.testing.expectEqualStrings("old/#", request.unsubscribe.topic_filters[0]);
                    },
                    .replay => unreachable,
                }
            }
            try std.Io.sleep(self.server.io, .fromMilliseconds(150), .awake);
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .stage = stage };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const expiry = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};
    var client = try reconnect.Client.init(allocator, io, server.address(), .{
        .protocol = protocol,
        .client_id = "deadline-cache",
        .clean_start = false,
        .properties = if (protocol == .v5) &expiry else &.{},
    }, .{}, &shutdown);
    defer client.deinit();
    try client.seedSubscription(.{ .topic_filter = "old/#" }, &.{});
    if (stage != .replay) _ = try client.connect();
    const result = operation(&client, stage, absolute);
    if (stage == .success) {
        try result;
        try std.testing.expect(client.connection() != null);
    } else {
        try std.testing.expectError(error.Timeout, result);
        try std.testing.expect(client.connection() == null);
    }
    try std.testing.expectEqual(@as(usize, 1), client.subscriptionCount());
    try std.testing.expectEqual(stage != .success, client.hasSubscription("old/#"));
    try std.testing.expectEqual(stage == .success, client.hasSubscription("new/#"));
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const BlockedWrite = @import("deadline_tests.zig").BlockedWrite;

const Operation = enum { subscribe, unsubscribe };
const Delivery = enum { complete, stalled, split_budget, blocked_write };

test "MQTT subscription deadlines preserve early PUBLISH and exact acknowledgements" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Operation)) |operation| {
            for ([_]bool{ false, true }) |absolute| try exercise(protocol, operation, absolute, .complete);
        }
    }
}

test "MQTT subscription deadlines bound missing responses while preserving early PUBLISH" {
    for (std.enums.values(Operation)) |operation| {
        for ([_]bool{ false, true }) |absolute| try exercise(.v5, operation, absolute, .stalled);
    }
}

test "MQTT subscription deadlines span request writing and response waiting" {
    for (std.enums.values(Operation)) |operation| {
        for ([_]bool{ false, true }) |absolute| try exercise(.v5, operation, absolute, .split_budget);
    }
}

test "MQTT subscription deadlines cancel blocked request writes" {
    for (std.enums.values(Operation)) |operation| {
        for ([_]bool{ false, true }) |absolute| try exercise(.v5, operation, absolute, .blocked_write);
    }
}

fn call(client: *runtime.Connection, operation: Operation, absolute: bool, timeout: std.Io.Duration) !void {
    const deadline = client.transport.deadlineFromNow(timeout);
    switch (operation) {
        .subscribe => {
            var acknowledgement = if (absolute)
                try client.subscribeWithDeadline(&.{.{ .topic_filter = "deadline/#" }}, .{}, deadline)
            else
                try client.subscribeWithTimeout(&.{.{ .topic_filter = "deadline/#" }}, .{}, timeout);
            defer acknowledgement.deinit(client.allocator);
            try std.testing.expectEqual(@as(u16, 1), acknowledgement.suback.packet_id);
            try std.testing.expectEqualSlices(u8, &.{0}, acknowledgement.suback.reason_codes);
        },
        .unsubscribe => {
            var acknowledgement = if (absolute)
                try client.unsubscribeWithDeadline(&.{"deadline/#"}, .{}, deadline)
            else
                try client.unsubscribeWithTimeout(&.{"deadline/#"}, .{}, timeout);
            defer acknowledgement.deinit(client.allocator);
            try std.testing.expectEqual(@as(u16, 1), acknowledgement.unsuback.packet_id);
            if (client.protocol == .v5) try std.testing.expectEqualSlices(u8, &.{0}, acknowledgement.unsuback.reason_codes);
        },
    }
}

fn exercise(protocol: mqtt.ProtocolVersion, operation: Operation, absolute: bool, delivery: Delivery) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = BlockedWrite{ .delegate = io, .delay = if (delivery == .split_budget) .fromMilliseconds(60) else .fromMilliseconds(300) };
    BlockedWrite.active = &observer;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        operation: Operation,
        delivery: Delivery,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = self.protocol });
            defer accepted.deinit(self.server.allocator);
            const packet_id = self.readRequest(&accepted.connection) catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => if (self.delivery == .blocked_write) return else return err,
                else => return err,
            };
            try accepted.connection.publish("deadline/early", "preserved", .{});
            if (self.delivery == .stalled) {
                try std.Io.sleep(self.server.io, .fromMilliseconds(150), .awake);
                return;
            }
            if (self.delivery == .split_budget) try std.Io.sleep(self.server.io, .fromMilliseconds(60), .awake);
            switch (self.operation) {
                .subscribe => try accepted.connection.writeSubAck(packet_id, &.{0}, &.{}),
                .unsubscribe => try accepted.connection.writeUnsubAck(packet_id, if (self.protocol == .v5) &.{0} else &.{}, &.{}),
            }
        }

        fn readRequest(self: *@This(), connection: *runtime.Connection) !u16 {
            return switch (self.operation) {
                .subscribe => blk: {
                    var request = try connection.readSubscribe();
                    defer request.deinit(self.server.allocator);
                    break :blk request.subscribe.packet_id;
                },
                .unsubscribe => blk: {
                    var request = try connection.readUnsubscribe();
                    defer request.deinit(self.server.allocator);
                    break :blk request.unsubscribe.packet_id;
                },
            };
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .operation = operation, .delivery = delivery };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, observed_io, server.address(), .{ .protocol = protocol, .client_id = "subscription-deadline" });
    var open = true;
    defer if (open) client.close();
    observer.armed.store(delivery == .split_budget or delivery == .blocked_write, .release);
    const timeout: std.Io.Duration = if (delivery == .complete) .fromSeconds(2) else if (delivery == .split_budget) .fromMilliseconds(100) else .fromMilliseconds(50);
    const result = call(&client, operation, absolute, timeout);
    if (delivery == .complete) try result else try std.testing.expectError(error.Timeout, result);
    if (delivery == .blocked_write) {
        try std.testing.expect(observer.entered.load(.acquire));
        try std.testing.expect(observer.canceled.load(.acquire));
        try std.testing.expect(!client.isUsable());
        client.close();
        open = false;
    } else {
        var publish = try client.readPublish();
        defer publish.deinit(allocator);
        try std.testing.expectEqualStrings("deadline/early", publish.publish.topic);
        try std.testing.expectEqualStrings("preserved", publish.publish.payload);
        if (delivery == .split_budget) try std.testing.expect(!observer.canceled.load(.acquire));
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "MQTT subscription timeouts reject zero budgets before I/O" {
    var client = runtime.Connection{ .allocator = std.testing.allocator, .transport = undefined };
    try std.testing.expectError(error.Timeout, client.subscribeWithTimeout(&.{.{ .topic_filter = "valid/#" }}, .{}, .zero));
    try std.testing.expectError(error.Timeout, client.unsubscribeWithTimeout(&.{"valid/#"}, .{}, .zero));
    try std.testing.expect(client.pending_packets == null);
    try std.testing.expectEqual(@as(u16, 1), client.next_packet_id);
}

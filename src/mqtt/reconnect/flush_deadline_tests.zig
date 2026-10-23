const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const reconnect = @import("../reconnect.zig");
const BlockedWrite = @import("../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;

test "MQTT reconnect bounded flush preserves QoS state after timeout" {
    for ([_]bool{ false, true }) |absolute| {
        for ([_]bool{ false, true }) |blocked| try exercise(absolute, blocked);
    }
}

fn exercise(absolute: bool, blocked: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = BlockedWrite{ .delegate = io, .packet_type = .publish };
    BlockedWrite.active = &observer;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        blocked: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var publish = accepted.connection.readPublish() catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => if (self.blocked) {
                    var recovered = try self.server.acceptWithTimeout(.{ .protocol = .v5, .session_present = true }, .fromSeconds(3));
                    defer recovered.deinit(self.server.allocator);
                    var retry = try recovered.connection.readPublish();
                    defer retry.deinit(self.server.allocator);
                    try std.testing.expect(retry.publish.dup);
                    try std.testing.expectEqual(@as(?u16, 1), retry.publish.packet_id);
                    try std.testing.expectEqualStrings("flush/deadline", retry.publish.topic);
                    try std.testing.expectEqualStrings("payload", retry.publish.payload);
                    try recovered.connection.writePubAck(1, 0);
                    return;
                } else return err,
                else => return err,
            };
            defer publish.deinit(self.server.allocator);
            if (self.blocked) return error.TestUnexpectedResult;
            try std.testing.expectEqual(@as(?u16, 1), publish.publish.packet_id);
            try accepted.connection.writePubAck(1, 0);
        }
    };
    var peer = Peer{ .server = &server, .blocked = blocked };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};
    var client = try reconnect.Client.init(allocator, observed_io, server.address(), .{
        .protocol = .v5,
        .client_id = "flush-deadline",
        .clean_start = false,
        .properties = &properties,
    }, .{}, &shutdown);
    defer client.deinit();
    _ = try client.connect();
    const id = try client.stagePublish("flush/deadline", "payload", .{ .qos = .at_least_once });
    const staged = try client.outgoing.stats(client.outgoing_handle);
    try std.testing.expectError(error.Timeout, client.flushPendingWithTimeout(.zero));
    try std.testing.expectError(error.Timeout, client.flushPendingWithDeadline(.{ .raw = .zero, .clock = .awake }));
    const pending = try client.outgoing.stats(client.outgoing_handle);
    try std.testing.expectEqualDeep(staged, pending);
    try std.testing.expectEqual(@as(usize, 1), pending.queued_count + pending.inflight_count);
    observer.armed.store(blocked, .release);
    const timeout = if (blocked) std.Io.Duration.fromMilliseconds(50) else std.Io.Duration.fromSeconds(2);
    const result = if (absolute)
        client.flushPendingWithDeadline(.fromNow(observed_io, .{ .raw = timeout, .clock = .awake }))
    else
        client.flushPendingWithTimeout(timeout);
    if (blocked) {
        try std.testing.expectError(error.Timeout, result);
        try std.testing.expect(observer.canceled.load(.acquire));
        try std.testing.expect(client.connection() == null);
        observer.armed.store(false, .release);
        _ = try client.connectWithTimeout(.fromSeconds(2));
    } else try result;
    try std.testing.expectEqual(id, try client.completeNextPublish());
    const completed = try client.outgoing.stats(client.outgoing_handle);
    try std.testing.expectEqual(@as(usize, 0), completed.queued_count + completed.inflight_count);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

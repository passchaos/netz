const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const reconnect = @import("../../reconnect.zig");
const BlockedWrite = @import("../../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT automatic reply recovery keeps serve alive and delivers before reconnect" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| try recoverPublication(protocol);
}

fn recoverPublication(protocol: mqtt.ProtocolVersion) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fault = BlockedWrite{ .delegate = io, .packet_type = .pubrec, .failure = error.ConnectionResetByPeer, .once = true };
    BlockedWrite.active = &fault;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var first = try self.server.acceptWithTimeout(.{ .protocol = self.protocol }, .fromSeconds(2));
            defer first.deinit(allocator);
            const aliases = [_]mqtt.Property{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }};
            if (self.protocol == .v5) {
                _ = try first.connection.writePublish("recovered/message", "alias seed", .{ .properties = &aliases });
            }
            const id = (try first.connection.writePublish(if (self.protocol == .v5) "" else "recovered/message", "owned delivery", .{ .qos = .exactly_once, .properties = if (self.protocol == .v5) &aliases else &.{} })).?;
            var ack = first.connection.readPubRec() catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => null,
                else => return err,
            };
            if (ack) |*value| {
                value.deinit(allocator);
                return error.FirstReplyUnexpectedlyReachedPeer;
            }
            var second = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, .fromSeconds(2));
            defer second.deinit(allocator);
            second.connection.next_packet_id = id;
            _ = try second.connection.writePublish("recovered/message", "owned delivery", .{ .qos = .exactly_once, .dup = true });
            var received = try second.connection.readPubRec();
            defer received.deinit(allocator);
            try std.testing.expectEqual(id, received.ack.packet_id);
            try second.connection.writePubRel(id, 0);
            var complete = try second.connection.readPubComp();
            defer complete.deinit(allocator);
            try std.testing.expectEqual(id, complete.ack.packet_id);
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, observed_io, server.address(), .{
        .protocol = protocol,
        .client_id = "auto-ack-recovery",
        .clean_start = false,
        .topic_alias_maximum = if (protocol == .v5) 16 else 0,
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} else &.{},
    }, .{}, &shutdown);
    defer client.deinit();
    const Handler = struct {
        connections: usize = 0,
        publications: usize = 0,
        releases: usize = 0,
        fn event(self: *@This(), active: *reconnect.Client, value: *reconnect.ClientEvent) !void {
            switch (value.*) {
                .connected => {
                    self.connections += 1;
                    if (self.connections == 2) try std.testing.expectEqual(@as(usize, 1), self.publications);
                },
                .publish => |message| {
                    if (message.publish.qos == .at_most_once) return;
                    try std.testing.expectEqual(@as(usize, 1), self.connections);
                    try std.testing.expect(active.connection() == null);
                    try std.testing.expectEqualStrings("recovered/message", message.publish.topic);
                    try std.testing.expectEqualStrings("owned delivery", message.publish.payload);
                    self.publications += 1;
                },
                .pubrel => {
                    self.releases += 1;
                    active.shutdown.set(active.io);
                },
                else => return error.UnexpectedRecoveryEvent,
            }
        }
    };
    var handler: Handler = .{};
    fault.armed.store(true, .release);
    try client.serveUntil(Handler, &handler, Handler.event, .{ .timeout = .fromSeconds(1) });
    try std.testing.expect(fault.entered.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), handler.connections);
    try std.testing.expectEqual(@as(usize, 1), handler.publications);
    try std.testing.expectEqual(@as(usize, 1), handler.releases);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

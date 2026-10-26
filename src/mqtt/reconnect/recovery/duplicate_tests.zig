const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const reconnect = @import("../../reconnect.zig");
const BlockedWrite = @import("../../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT suppressed duplicate reply failure reconnects within the poll budget" {
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
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var first = try self.server.acceptWithTimeout(.{ .protocol = .v5, .session_present = true }, .fromSeconds(2));
            defer first.deinit(allocator);
            first.connection.next_packet_id = 77;
            _ = try first.connection.writePublish("already/delivered", "accepted earlier", .{ .qos = .exactly_once, .dup = true });
            var ack: ?runtime.OwnedAck = first.connection.readPubRec() catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => null,
                else => return err,
            };
            if (ack) |*value| {
                value.deinit(allocator);
                return error.FailedReplyReachedPeer;
            }
            var second = try self.server.acceptWithTimeout(.{ .protocol = .v5, .session_present = true }, .fromSeconds(2));
            defer second.deinit(allocator);
            try second.connection.writePubRel(77, 0);
            var complete = try second.connection.readPubComp();
            defer complete.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 77), complete.ack.packet_id);
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initWithOptions(allocator, observed_io, server.address(), .{
        .protocol = .v5,
        .client_id = "duplicate-recovery",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    }, .{}, &shutdown, .{ .manual_acknowledgements = true });
    defer client.deinit();
    _ = try client.outgoing.recordIncomingQoS2(client.outgoing_handle, 77);
    var initial = (try client.pollWithTimeout(.fromSeconds(1))).?;
    initial.deinit(allocator);
    try std.testing.expect(client.sessionResumed());
    fault.armed.store(true, .release);
    var resumed = (try client.pollWithDeadline(std.Io.Clock.awake.now(io).addDuration(.fromSeconds(1)), .{})).?;
    defer resumed.deinit(allocator);
    try std.testing.expect(resumed == .connected);
    try std.testing.expect(resumed.connected.session_resumed);
    try std.testing.expect(client.pending_event == null);
    var release = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer release.deinit(allocator);
    try std.testing.expect(release == .pubrel);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

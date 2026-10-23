const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");

const Operation = enum { ping, unsubscribe };

test "MQTT correlated waits enforce byte quota for PING and UNSUBSCRIBE" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Operation)) |operation| try exercise(protocol, operation);
    }
}

fn exercise(protocol: mqtt.ProtocolVersion, operation: Operation) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        operation: Operation,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = self.protocol });
            defer accepted.deinit(self.server.allocator);
            var packet_id: u16 = 0;
            switch (self.operation) {
                .ping => try accepted.connection.readPingReq(),
                .unsubscribe => {
                    var request = try accepted.connection.readUnsubscribe();
                    defer request.deinit(self.server.allocator);
                    packet_id = request.unsubscribe.packet_id;
                },
            }
            try accepted.connection.publish("pending/first", "one", .{});
            try accepted.connection.publish("pending/second", "two", .{});
            switch (self.operation) {
                .ping => try accepted.connection.writePingResp(),
                .unsubscribe => try accepted.connection.writeUnsubAck(packet_id, if (self.protocol == .v5) &.{0} else &.{}, &.{}),
            }
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .operation = operation };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{
        .protocol = protocol,
        .client_id = "byte-limit",
        // The first complete PUBLISH occupies 21 wire bytes in MQTT 5
        // and 20 in MQTT 3.1.1; the payload alone is only three bytes.
        .limits = .{ .max_pending_packet_bytes = if (protocol == .v5) 21 else 20 },
    });
    defer client.close();
    switch (operation) {
        .ping => try std.testing.expectError(error.TooManyPendingPackets, client.pingWithTimeout(.fromSeconds(2))),
        .unsubscribe => try std.testing.expectError(error.TooManyPendingPackets, client.unsubscribe(&.{"pending/#"}, .{})),
    }
    for ([_][]const u8{ "pending/first", "pending/second" }, [_][]const u8{ "one", "two" }) |topic, payload| {
        var publish = try client.readPublish();
        defer publish.deinit(allocator);
        try std.testing.expectEqualStrings(topic, publish.publish.topic);
        try std.testing.expectEqualStrings(payload, publish.publish.payload);
    }
    switch (operation) {
        .ping => {
            var event = try client.readClientPacketEventWithTimeout(.fromSeconds(2));
            defer event.deinit(allocator);
            try std.testing.expect(event == .pingresp);
        },
        .unsubscribe => {
            var acknowledgement = try client.readUnsubAck();
            defer acknowledgement.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 1), acknowledgement.unsuback.packet_id);
        },
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

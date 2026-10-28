const std = @import("std");
const builtin = @import("builtin");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Backend = @import("../../../runtime.zig").Backend;
const native = @import("../../../runtime/timed_socket.zig");
const stream_io = @import("../../../internal/stream_io.zig");
const allocator = std.testing.allocator;
const topic = "native/session";

const Pair = struct {
    io: std.Io,
    server: runtime.Server,
    client: runtime.Connection,
    peer: runtime.AcceptedClient,
    open: bool = true,

    fn init(io: std.Io) !Pair {
        var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 8 * 1024 * 1024 });
        errdefer server.deinit();
        var accepting = try io.concurrent(runtime.Server.accept, .{ &server, runtime.AcceptOptions{ .topic_alias_maximum = 0 } });
        defer _ = accepting.cancel(io) catch {};
        var client = try runtime.Client.connect(allocator, io, server.address(), .{ .client_id = "native-deadline", .limits = .{ .max_packet_size = 8 * 1024 * 1024 } });
        errdefer client.close();
        var peer = try accepting.await(io);
        errdefer peer.deinit(allocator);
        const small: c_int = 4096;
        try std.posix.setsockopt(client.transport.tcp.stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&small));
        return .{ .io = io, .server = server, .client = client, .peer = peer };
    }

    fn deinit(self: *Pair) void {
        if (self.open) self.client.close();
        self.peer.deinit(allocator);
        self.server.deinit();
    }

    fn write(self: *Pair, bytes: []const u8, deadline: std.Io.Clock.Timestamp) !void {
        return self.client.writeClientSessionTransmissionWithDeadline(.{ .publish = .{
            .topic = topic,
            .payload = bytes,
            .qos = .at_least_once,
            .retain = false,
            .dup = false,
            .packet_id = 17,
            .properties = &.{},
            .message_expiry_interval = null,
        } }, deadline);
    }

    fn drain(self: *Pair, payload_len: usize, initial: ?u8) !void {
        self.client.close();
        self.open = false;
        var header: std.ArrayList(u8) = .empty;
        defer header.deinit(allocator);
        const bytes = try allocator.alloc(u8, payload_len);
        defer allocator.free(bytes);
        @memset(bytes, 0xa5);
        const lengths = try mqtt.writePublishPrefix(&header, allocator, .v5, topic, bytes, .{ .qos = .at_least_once, .packet_id = 17 });
        var received: usize = 0;
        if (initial) |byte| {
            try std.testing.expectEqual(header.items[0], byte);
            received = 1;
        }
        const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
        var buffer: [8192]u8 = undefined;
        while (true) {
            const count = try stream_io.readSomeWithDeadline(self.io, self.peer.connection.transport.tcp.stream, &buffer, deadline);
            if (count == 0) break;
            try std.testing.expect(received + count <= lengths.total);
            for (buffer[0..count], received..) |byte, offset| {
                try std.testing.expectEqual(if (offset < header.items.len) header.items[offset] else @as(u8, 0xa5), byte);
            }
            received += count;
        }
        try std.testing.expect(received > header.items.len and received < lengths.total);
    }
};

test "MQTT native Session deadline timeout joins borrowed packet output and retires transport" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    try std.testing.expect(native.available(io));
    var pair = try Pair.init(io);
    defer pair.deinit();
    const payload = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xa5);
    try std.testing.expectError(error.Timeout, pair.write(payload, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(20) })));
    try std.testing.expect(!pair.client.isUsable());
    @memset(payload, 0xee);
    try pair.drain(payload.len, null);
}

test "MQTT native Session deadline cancellation joins a physically committed packet prefix" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var pair = try Pair.init(io);
    defer pair.deinit();
    const payload = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xa5);
    var writing = try io.concurrent(Pair.write, .{ &pair, payload, std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }) });
    defer _ = writing.cancel(io) catch {};
    var first: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try stream_io.readSomeWithDeadline(io, pair.peer.connection.transport.tcp.stream, &first, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    try std.testing.expectError(error.Canceled, writing.cancel(io));
    try std.testing.expect(!pair.client.isUsable());
    @memset(payload, 0xee);
    try pair.drain(payload.len, first[0]);
}

test "MQTT native reconnect deadline retains QoS payload and replays the same packet identifier" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| try replayAfterTimeout(protocol, qos);
    }
}

fn replayAfterTimeout(protocol: mqtt.ProtocolVersion, qos: mqtt.QoS) !void {
    const reconnect = @import("../../reconnect.zig");
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 8 * 1024 * 1024 });
    defer server.deinit();
    var accepting = try io.concurrent(runtime.Server.accept, .{ &server, runtime.AcceptOptions{ .protocol = protocol, .topic_alias_maximum = 0 } });
    defer _ = accepting.cancel(io) catch {};
    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};
    var client = try reconnect.Client.init(allocator, io, server.address(), .{
        .protocol = protocol,
        .client_id = "native-replay",
        .clean_start = false,
        .properties = if (protocol == .v5) &properties else &.{},
        .limits = .{ .max_packet_size = 8 * 1024 * 1024 },
    }, .{}, &shutdown);
    defer client.deinit();
    _ = try client.connectWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    var accepted = try accepting.await(io);
    var accepted_open = true;
    defer if (accepted_open) accepted.deinit(allocator);
    const small: c_int = 4096;
    try std.posix.setsockopt(client.connection().?.transport.tcp.stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&small));
    const payload = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xa5);
    const id = try client.stagePublish(topic, payload, .{ .qos = qos });
    try std.testing.expectError(error.Timeout, client.flushPendingWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(20) })));
    try std.testing.expect(client.connection() == null);
    try std.testing.expect(try client.outgoingQoSState(id) != null);
    const held = try client.outgoingStats();
    try std.testing.expectEqual(@as(usize, 1), held.inflight_count);
    @memset(payload, 0xee);
    accepted.deinit(allocator);
    accepted_open = false;

    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        qos: mqtt.QoS,
        id: u16,
        payload_len: usize,
        fn run(self: *@This()) !void {
            var resumed = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true, .topic_alias_maximum = 0 }, .fromSeconds(2));
            defer resumed.deinit(allocator);
            var publish = try resumed.connection.readPublish();
            defer publish.deinit(allocator);
            try std.testing.expect(publish.publish.dup);
            try std.testing.expectEqual(self.id, publish.publish.packet_id.?);
            try std.testing.expectEqual(self.qos, publish.publish.qos);
            try std.testing.expectEqualStrings(topic, publish.publish.topic);
            try std.testing.expectEqual(self.payload_len, publish.publish.payload.len);
            for (publish.publish.payload) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
            if (self.qos == .at_least_once) {
                try resumed.connection.writePubAck(self.id, 0);
            } else {
                try resumed.connection.writePubRec(self.id, 0);
                var release = try resumed.connection.readPubRel();
                defer release.deinit(allocator);
                try std.testing.expectEqual(self.id, release.ack.packet_id);
                try resumed.connection.writePubComp(self.id, 0);
            }
            var disconnect = try resumed.connection.readDisconnect();
            defer disconnect.deinit(allocator);
            try std.testing.expectEqual(@as(u8, 0), disconnect.disconnect.reason_code);
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .qos = qos, .id = id, .payload_len = payload.len };
    var task = try io.concurrent(Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    const connected = try client.connectWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.expect(connected.session_resumed);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    if (qos == .exactly_once) {
        var receipt = (try client.pollWithDeadline(deadline.raw, .{})) orelse return error.TestUnexpectedResult;
        defer receipt.deinit(allocator);
        try std.testing.expect(receipt == .pubrec);
        try std.testing.expectEqual(id, receipt.pubrec.ack.packet_id);
    }
    var completion = (try client.pollWithDeadline(deadline.raw, .{})) orelse return error.TestUnexpectedResult;
    defer completion.deinit(allocator);
    try std.testing.expect(if (qos == .at_least_once) completion == .puback else completion == .pubcomp);
    try std.testing.expect(try client.outgoingQoSState(id) == null);
    const done = try client.outgoingStats();
    try std.testing.expectEqual(@as(usize, 0), done.inflight_count);
    try std.testing.expectEqual(@as(usize, 0), done.queued_count);
    try client.disconnect(0);
    try task.await(io);
}

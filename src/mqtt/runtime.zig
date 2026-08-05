const std = @import("std");
const mqtt = @import("mod.zig");

const net = std.Io.net;

pub const Error = mqtt.Error || error{
    ConnectionClosed,
    PacketTooLarge,
    UnexpectedPacket,
    ConnectRefused,
    InflightFull,
} || net.IpAddress.ListenError || net.IpAddress.ConnectError || net.Server.AcceptError || net.Stream.Reader.Error || net.Stream.Writer.Error || std.Thread.SpawnError;

pub const Limits = struct {
    max_packet_size: usize = 16 * 1024 * 1024,
};

pub const Server = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    listener: net.Server,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try bind_address.listen(io, .{ .reuse_address = true }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *Server, options: AcceptOptions) Error!AcceptedClient {
        const stream = try self.listener.accept(self.io);
        errdefer stream.close(self.io);

        var connection = Connection{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .protocol = options.protocol,
            .limits = self.limits,
            .max_outgoing_inflight = options.max_outgoing_inflight,
        };
        errdefer connection.close();

        var connect = try connection.readConnect();
        errdefer connect.deinit(self.allocator);
        try connection.writeConnAck(.{ .session_present = false, .reason_code = options.reason_code });

        return .{ .connection = connection, .connect = connect };
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *AcceptedClient) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.allocator.alloc(?anyerror, max_connections);
        errdefer self.allocator.free(results);
        @memset(results, null);

        for (results) |*result| {
            var accepted = try self.accept(options);
            errdefer accepted.deinit(self.allocator);
            const task = ServeTask(HandlerContext){
                .accepted = accepted,
                .context = context,
                .handler = handler,
                .result = result,
                .allocator = self.allocator,
            };
            group.async(self.io, ServeTask(HandlerContext).run, .{task});
        }

        try group.await(self.io);
        return .{ .allocator = self.allocator, .errors = results };
    }
};

pub const AsyncServeError = Error || std.Io.Cancelable;

pub const ConcurrentServeResult = struct {
    allocator: std.mem.Allocator,
    errors: []?anyerror,

    pub fn deinit(self: *ConcurrentServeResult) void {
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: ConcurrentServeResult) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn successCount(self: ConcurrentServeResult) usize {
        var count: usize = 0;
        for (self.errors) |err| {
            if (err == null) count += 1;
        }
        return count;
    }
};

fn ServeTask(comptime HandlerContext: type) type {
    return struct {
        accepted: AcceptedClient,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, *AcceptedClient) Error!void,
        result: *?anyerror,
        allocator: std.mem.Allocator,

        fn run(task: @This()) std.Io.Cancelable!void {
            var accepted = task.accepted;
            defer accepted.deinit(task.allocator);
            task.handler(task.context, &accepted) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const AcceptOptions = struct {
    protocol: mqtt.ProtocolVersion = .v5,
    reason_code: u8 = 0,
    max_outgoing_inflight: u16 = 16,
};

pub const AcceptedClient = struct {
    connection: Connection,
    connect: OwnedConnect,

    pub fn deinit(self: *AcceptedClient, allocator: std.mem.Allocator) void {
        self.connect.deinit(allocator);
        self.connection.close();
        self.* = undefined;
    }
};

pub const Client = struct {
    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, options: ConnectOptions) Error!Connection {
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);

        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .protocol = options.protocol,
            .limits = options.limits,
            .max_outgoing_inflight = options.max_outgoing_inflight,
        };
        errdefer connection.close();

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try mqtt.writeConnectPacket(&encoded, allocator, options.protocol, .{
            .client_id = options.client_id,
            .clean_start = options.clean_start,
            .keep_alive_seconds = options.keep_alive_seconds,
            .properties = options.properties,
            .will = options.will,
            .username = options.username,
            .password = options.password,
        });
        try writeAll(io, stream, encoded.items);

        var connack = try connection.readConnAck();
        defer connack.deinit(allocator);
        if (connack.connack.reason_code != 0) return error.ConnectRefused;

        return connection;
    }
};

pub const ConnectOptions = struct {
    protocol: mqtt.ProtocolVersion = .v5,
    client_id: []const u8,
    clean_start: bool = true,
    keep_alive_seconds: u16 = 30,
    properties: []const mqtt.Property = &.{},
    will: ?mqtt.LastWill = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    limits: Limits = .{},
    max_outgoing_inflight: u16 = 16,
};

pub const ConnAckOptions = struct {
    session_present: bool = false,
    reason_code: u8 = 0,
    properties: []const mqtt.Property = &.{},
    max_outgoing_inflight: u16 = 16,
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    protocol: mqtt.ProtocolVersion = .v5,
    limits: Limits = .{},
    next_packet_id: u16 = 1,
    outgoing_inflight: u16 = 0,
    max_outgoing_inflight: u16 = 16,

    pub fn close(self: *Connection) void {
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn readConnect(self: *Connection) Error!OwnedConnect {
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .connect) return error.UnexpectedPacket;
        var connect = try mqtt.Connect.parse(self.allocator, packet.bytes);
        errdefer connect.deinit(self.allocator);
        self.protocol = connect.protocol;
        return .{ .packet = packet, .connect = connect };
    }

    pub fn writeConnAck(self: *Connection, options: ConnAckOptions) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.ConnAck.write(&encoded, self.allocator, self.protocol, options.session_present, options.reason_code, options.properties);
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn readConnAck(self: *Connection) Error!OwnedConnAck {
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .connack) return error.UnexpectedPacket;
        var connack = try mqtt.ConnAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer connack.deinit(self.allocator);
        return .{ .packet = packet, .connack = connack };
    }

    pub fn publish(self: *Connection, topic: []const u8, payload: []const u8, options: PublishOptions) Error!void {
        const packet_id = if (options.qos == .at_most_once) null else self.nextPacketId();
        if (packet_id != null) {
            if (self.outgoing_inflight >= self.max_outgoing_inflight) return error.InflightFull;
            self.outgoing_inflight += 1;
        }
        defer {
            if (packet_id != null) self.outgoing_inflight -= 1;
        }
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.writePublish(&encoded, self.allocator, self.protocol, topic, payload, .{
            .qos = options.qos,
            .retain = options.retain,
            .dup = options.dup,
            .packet_id = packet_id,
        });
        try writeAll(self.io, self.stream, encoded.items);
        if (packet_id) |id| {
            switch (options.qos) {
                .at_most_once => unreachable,
                .at_least_once => {
                    var ack = try self.readPubAck();
                    defer ack.deinit(self.allocator);
                    if (ack.ack.packet_id != id) return error.UnexpectedPacket;
                },
                .exactly_once => {
                    var pubrec = try self.readPubRec();
                    defer pubrec.deinit(self.allocator);
                    if (pubrec.ack.packet_id != id) return error.UnexpectedPacket;
                    try self.writePubRel(id, 0);
                    var pubcomp = try self.readPubComp();
                    defer pubcomp.deinit(self.allocator);
                    if (pubcomp.ack.packet_id != id) return error.UnexpectedPacket;
                },
            }
        }
    }

    pub fn readPublish(self: *Connection) Error!OwnedPublish {
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .publish) return error.UnexpectedPacket;
        var publish_packet = try mqtt.Publish.parse(self.allocator, self.protocol, packet.bytes);
        errdefer publish_packet.deinit(self.allocator);
        return .{ .packet = packet, .publish = publish_packet };
    }

    pub fn writePubAck(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacket(.puback, packet_id, reason_code);
    }

    pub fn readPubAck(self: *Connection) Error!OwnedAck {
        return self.readAck(.puback);
    }

    pub fn writePubRec(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacket(.pubrec, packet_id, reason_code);
    }

    pub fn readPubRec(self: *Connection) Error!OwnedAck {
        return self.readAck(.pubrec);
    }

    pub fn writePubRel(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacket(.pubrel, packet_id, reason_code);
    }

    pub fn readPubRel(self: *Connection) Error!OwnedAck {
        return self.readAck(.pubrel);
    }

    pub fn writePubComp(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacket(.pubcomp, packet_id, reason_code);
    }

    pub fn readPubComp(self: *Connection) Error!OwnedAck {
        return self.readAck(.pubcomp);
    }

    fn writeAckPacket(self: *Connection, packet_type: mqtt.PacketType, packet_id: u16, reason_code: u8) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.AckPacket.write(&encoded, self.allocator, self.protocol, packet_type, packet_id, reason_code, &.{});
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn subscribe(self: *Connection, subscriptions: []const mqtt.Subscription, options: SubscribeOptions) Error!OwnedSubAck {
        const packet_id = self.nextPacketId();
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.Subscribe.write(&encoded, self.allocator, self.protocol, packet_id, options.properties, subscriptions);
        try writeAll(self.io, self.stream, encoded.items);

        var suback = try self.readSubAck();
        errdefer suback.deinit(self.allocator);
        if (suback.suback.packet_id != packet_id or suback.suback.reason_codes.len != subscriptions.len) {
            return error.UnexpectedPacket;
        }
        return suback;
    }

    pub fn readSubscribe(self: *Connection) Error!OwnedSubscribe {
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .subscribe) return error.UnexpectedPacket;
        var subscribe_packet = try mqtt.Subscribe.parse(self.allocator, self.protocol, packet.bytes);
        errdefer subscribe_packet.deinit(self.allocator);
        return .{ .packet = packet, .subscribe = subscribe_packet };
    }

    pub fn writeSubAck(self: *Connection, packet_id: u16, reason_codes: []const u8, properties: []const mqtt.Property) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.SubAck.write(&encoded, self.allocator, self.protocol, packet_id, properties, reason_codes);
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn readSubAck(self: *Connection) Error!OwnedSubAck {
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .suback) return error.UnexpectedPacket;
        var suback = try mqtt.SubAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer suback.deinit(self.allocator);
        return .{ .packet = packet, .suback = suback };
    }

    pub fn ping(self: *Connection) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.writePing(&encoded, self.allocator, false);
        try writeAll(self.io, self.stream, encoded.items);
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        defer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .pingresp) return error.UnexpectedPacket;
        try mqtt.validatePing(packet.bytes, true);
    }

    pub fn readPingReq(self: *Connection) Error!void {
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        defer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .pingreq) return error.UnexpectedPacket;
        try mqtt.validatePing(packet.bytes, false);
    }

    pub fn writePingResp(self: *Connection) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.writePing(&encoded, self.allocator, true);
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn disconnect(self: *Connection, reason_code: u8) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.Disconnect.write(&encoded, self.allocator, self.protocol, reason_code, &.{});
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn readDisconnect(self: *Connection) Error!OwnedDisconnect {
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .disconnect) return error.UnexpectedPacket;
        var disconnect_packet = try mqtt.Disconnect.parse(self.allocator, self.protocol, packet.bytes);
        errdefer disconnect_packet.deinit(self.allocator);
        return .{ .packet = packet, .disconnect = disconnect_packet };
    }

    fn readAck(self: *Connection, packet_type: mqtt.PacketType) Error!OwnedAck {
        var packet = try readPacket(self.allocator, self.io, self.stream, self.limits);
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != packet_type) return error.UnexpectedPacket;
        var ack = try mqtt.AckPacket.parse(self.allocator, self.protocol, packet.bytes);
        errdefer ack.deinit(self.allocator);
        return .{ .packet = packet, .ack = ack };
    }

    fn nextPacketId(self: *Connection) u16 {
        const id = self.next_packet_id;
        self.next_packet_id +%= 1;
        if (self.next_packet_id == 0) self.next_packet_id = 1;
        return id;
    }
};

pub const PublishOptions = struct {
    qos: mqtt.QoS = .at_most_once,
    retain: bool = false,
    dup: bool = false,
};

pub const SubscribeOptions = struct {
    properties: []const mqtt.Property = &.{},
};

pub const OwnedPacket = struct {
    bytes: []u8,
    fixed: mqtt.FixedHeader,

    pub fn deinit(self: *OwnedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedConnect = struct {
    packet: OwnedPacket,
    connect: mqtt.Connect,

    pub fn deinit(self: *OwnedConnect, allocator: std.mem.Allocator) void {
        self.connect.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedConnAck = struct {
    packet: OwnedPacket,
    connack: mqtt.ConnAck,

    pub fn deinit(self: *OwnedConnAck, allocator: std.mem.Allocator) void {
        self.connack.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedPublish = struct {
    packet: OwnedPacket,
    publish: mqtt.Publish,

    pub fn deinit(self: *OwnedPublish, allocator: std.mem.Allocator) void {
        self.publish.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedAck = struct {
    packet: OwnedPacket,
    ack: mqtt.AckPacket,

    pub fn deinit(self: *OwnedAck, allocator: std.mem.Allocator) void {
        self.ack.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedSubscribe = struct {
    packet: OwnedPacket,
    subscribe: mqtt.Subscribe,

    pub fn deinit(self: *OwnedSubscribe, allocator: std.mem.Allocator) void {
        self.subscribe.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedSubAck = struct {
    packet: OwnedPacket,
    suback: mqtt.SubAck,

    pub fn deinit(self: *OwnedSubAck, allocator: std.mem.Allocator) void {
        self.suback.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedDisconnect = struct {
    packet: OwnedPacket,
    disconnect: mqtt.Disconnect,

    pub fn deinit(self: *OwnedDisconnect, allocator: std.mem.Allocator) void {
        self.disconnect.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

fn readPacket(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error!OwnedPacket {
    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);

    var first: [1]u8 = undefined;
    try readExact(io, stream, &first);
    try encoded.append(allocator, first[0]);

    var remaining_bytes: [4]u8 = undefined;
    var remaining_len_len: usize = 0;
    while (remaining_len_len < remaining_bytes.len) : (remaining_len_len += 1) {
        try readExact(io, stream, remaining_bytes[remaining_len_len .. remaining_len_len + 1]);
        try encoded.append(allocator, remaining_bytes[remaining_len_len]);
        if ((remaining_bytes[remaining_len_len] & 0x80) == 0) break;
    } else {
        return error.MalformedRemainingLength;
    }

    const decoded = try mqtt.decodeRemainingLength(remaining_bytes[0 .. remaining_len_len + 1]);
    if (decoded.value > limits.max_packet_size) return error.PacketTooLarge;
    const payload_start = encoded.items.len;
    try encoded.resize(allocator, payload_start + decoded.value);
    try readExact(io, stream, encoded.items[payload_start..]);

    const bytes = try encoded.toOwnedSlice(allocator);
    errdefer allocator.free(bytes);
    return .{ .bytes = bytes, .fixed = try mqtt.FixedHeader.parse(bytes) };
}

fn readExact(io: std.Io, stream: net.Stream, buffer: []u8) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var bufs = [_][]u8{buffer[offset..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

test "MQTT runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("client-1", accepted.connect.connect.client_id);
            try std.testing.expectEqualStrings("status/client-1", accepted.connect.connect.will.?.topic);
            try std.testing.expectEqualStrings("offline", accepted.connect.connect.will.?.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, accepted.connect.connect.will.?.qos);
            try std.testing.expectEqualStrings("rumq", accepted.connect.connect.username.?);
            try std.testing.expectEqualStrings("mq", accepted.connect.connect.password.?);

            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(usize, 2), subscribe.subscribe.subscriptions.len);
            try std.testing.expectEqualStrings("sensors/+", subscribe.subscribe.subscriptions[0].topic_filter);
            try std.testing.expectEqualStrings("alerts/#", subscribe.subscribe.subscriptions[1].topic_filter);
            const reason_codes = [_]u8{ 0x01, 0x00 };
            try accepted.connection.writeSubAck(subscribe.subscribe.packet_id, &reason_codes, &.{});

            try accepted.connection.publish("alerts/system", "online", .{});

            var exact = try accepted.connection.readPublish();
            defer exact.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("sensors/exact", exact.publish.topic);
            try std.testing.expectEqualStrings("exactly-once", exact.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, exact.publish.qos);
            try accepted.connection.writePubRec(exact.publish.packet_id.?, 0);
            var pubrel = try accepted.connection.readPubRel();
            defer pubrel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(exact.publish.packet_id.?, pubrel.ack.packet_id);
            try accepted.connection.writePubComp(pubrel.ack.packet_id, 0);

            var publish = try accepted.connection.readPublish();
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("sensors/temp", publish.publish.topic);
            try std.testing.expectEqualStrings("21.5", publish.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, publish.publish.qos);
            try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);

            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u8, 0), disconnect.disconnect.reason_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var will_props = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 1 } }};
    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "client-1",
        .will = .{
            .topic = "status/client-1",
            .payload = "offline",
            .qos = .at_least_once,
            .properties = &will_props,
        },
        .username = "rumq",
        .password = "mq",
        .limits = .{ .max_packet_size = 4096 },
    });
    defer client.close();

    const subscriptions = [_]mqtt.Subscription{
        .{ .topic_filter = "sensors/+", .qos = .at_least_once },
        .{ .topic_filter = "alerts/#", .qos = .at_most_once },
    };
    var suback = try client.subscribe(&subscriptions, .{});
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, suback.suback.reason_codes);

    var server_publish = try client.readPublish();
    defer server_publish.deinit(allocator);
    try std.testing.expectEqualStrings("alerts/system", server_publish.publish.topic);
    try std.testing.expectEqualStrings("online", server_publish.publish.payload);

    try client.publish("sensors/exact", "exactly-once", .{ .qos = .exactly_once });
    try client.publish("sensors/temp", "21.5", .{ .qos = .at_least_once });
    try client.ping();
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT connection enforces outgoing inflight limit before writing" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .protocol = .v5,
        .outgoing_inflight = 1,
        .max_outgoing_inflight = 1,
    };

    try std.testing.expectError(error.InflightFull, connection.publish("limited/topic", "blocked", .{ .qos = .at_least_once }));
    try std.testing.expectEqual(@as(u16, 1), connection.outgoing_inflight);
}

test "MQTT async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), accepted: *AcceptedClient) Error!void {
            if (std.mem.eql(u8, accepted.connect.connect.client_id, "mqtt-one")) {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(accepted.connection.allocator);
                if (!std.mem.eql(u8, publish.publish.payload, "one")) return error.UnexpectedPacket;
                try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);
                return;
            }
            if (std.mem.eql(u8, accepted.connect.connect.client_id, "mqtt-two")) {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(accepted.connection.allocator);
                if (!std.mem.eql(u8, publish.publish.payload, "two")) return error.UnexpectedPacket;
                try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);
                return;
            }
            return error.UnexpectedPacket;
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2, .{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        client_id: []const u8,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .protocol = .v5,
                .client_id = task.client_id,
                .limits = .{ .max_packet_size = 4096 },
            });
            defer client.close();
            try client.publish("async/topic", task.payload, .{ .qos = .at_least_once });
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .client_id = "mqtt-one", .payload = "one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .client_id = "mqtt-two", .payload = "two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

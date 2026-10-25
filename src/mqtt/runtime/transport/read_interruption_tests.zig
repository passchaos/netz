//! Real MQTT byte streams retain partial packets across local read faults.
const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Transport = @import("../packet_transport.zig").Transport;
const tls = @import("../../../tls/mod.zig").stream;
const tls_testing = @import("../../../tls/testing.zig");
const http1 = @import("../../../http1/runtime.zig");
const websocket = @import("../../../websocket/runtime.zig");
const support = @import("../../../internal/testing/read_interruption.zig");
const allocator = std.testing.allocator;
const Backend = enum { tcp, tls12, tls13, standard_tls13, websocket };
const body = "packet payload/" ** 20;

const Listener = union(enum) {
    socket: std.Io.net.Server,
    ws: websocket.Server,

    fn address(self: *Listener) std.Io.net.IpAddress {
        return switch (self.*) {
            .socket => |server| server.socket.address,
            .ws => |*server| server.address(),
        };
    }

    fn deinit(self: *Listener, io: std.Io) void {
        switch (self.*) {
            .socket => |*server| server.deinit(io),
            .ws => |*server| server.deinit(),
        }
    }
};

test "MQTT local read interruptions preserve split packets and QoS across TCP TLS and WebSocket" {
    for (std.enums.values(Backend)) |backend| {
        for (std.enums.values(support.Fault)) |fault| {
            for ([_]usize{ 2, 10 }) |cut| {
                for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| try exercise(backend, fault, cut, qos);
            }
        }
    }
}

fn exercise(backend: Backend, fault: support.Fault, cut: usize, qos: mqtt.QoS) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    support.InterruptedIo.delegate = base;
    defer support.InterruptedIo.next = null;
    var vtable = base.vtable.*;
    vtable.batchAwaitConcurrent = support.InterruptedIo.awaitConcurrent;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    try mqtt.writePublish(&wire, allocator, .v5, "resume/topic", body, .{ .qos = qos, .packet_id = 42 });
    var listener: Listener = if (backend == .websocket)
        .{ .ws = try websocket.Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{}) }
    else
        .{ .socket = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{}) };
    defer listener.deinit(base);
    const Peer = struct {
        listener: *Listener,
        io: std.Io,
        backend: Backend,
        qos: mqtt.QoS,
        certificate: []const u8,
        key: @TypeOf(key),
        wire: []const u8,
        cut: usize,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var transport: Transport = if (self.backend == .websocket)
                try .initWebSocket(allocator, try self.listener.ws.accept(.{}))
            else blk: {
                const socket = try self.listener.socket.accept(self.io);
                if (self.backend == .tcp) break :blk .initTcp(self.io, socket);
                var owned = true;
                errdefer if (owned) socket.close(self.io);
                const connection = try tls.ServerConnection.init(allocator, self.io, socket, .{
                    .identity = .{ .certificate_chain = &.{self.certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = self.key } } },
                    .protocol_policy = if (self.backend == .tls12) .tls12_only else .tls13_only,
                });
                owned = false;
                break :blk .initTlsServer(connection);
            };
            defer transport.close(allocator);
            try transport.writePacketParts(self.wire[0..self.cut], "");
            try self.release.waitTimeout(self.io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
            try transport.writePacketParts(self.wire[self.cut..], "");
            try transport.writePacketParts("\xd0\x00", "");
            var ack = try transport.readPacketWithDeadline(allocator, 64, .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
            defer ack.deinit(allocator);
            try std.testing.expectEqual(if (self.qos == .at_least_once) mqtt.PacketType.puback else mqtt.PacketType.pubrec, ack.fixed.packet_type);
            try std.testing.expectEqual(@as(u16, 42), std.mem.readInt(u16, ack.remainingBytes()[0..2], .big));
            if (self.qos == .exactly_once) {
                try transport.writePacketParts("\x62\x02\x00\x2a", "");
                var completed = try transport.readPacketWithDeadline(allocator, 64, .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
                defer completed.deinit(allocator);
                try std.testing.expectEqual(mqtt.PacketType.pubcomp, completed.fixed.packet_type);
                try std.testing.expectEqual(@as(u16, 42), std.mem.readInt(u16, completed.remainingBytes()[0..2], .big));
            }
            var ping = try transport.readPacketWithDeadline(allocator, 64, .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
            defer ping.deinit(allocator);
            try std.testing.expectEqual(mqtt.PacketType.pingreq, ping.fixed.packet_type);
            try transport.writePacketParts("\xd0\x00", "");
        }
    };
    var peer = Peer{ .listener = &listener, .io = base, .backend = backend, .qos = qos, .certificate = &certificate, .key = key, .wire = wire.items, .cut = cut };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.release.set(base);
        thread.join();
    };
    var transport: Transport = if (backend == .websocket)
        try .initWebSocket(allocator, try websocket.Client.connect(allocator, io, listener.address(), .{ .host = "localhost" }))
    else blk: {
        const socket = try listener.address().connect(base, .{ .mode = .stream });
        if (backend == .tcp) break :blk .initTcp(io, socket);
        var owned = true;
        errdefer if (owned) socket.close(base);
        if (backend == .standard_tls13) {
            const connection = try http1.TlsClientConnection.init(allocator, io, socket, "localhost", .{ .verify_host = false });
            owned = false;
            break :blk .initTls(connection);
        }
        const connection = try tls.ClientConnection.init(allocator, io, socket, .{
            .server_name = "localhost",
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .protocol_policy = if (backend == .tls12) .tls12_only else .tls13_only,
        });
        owned = false;
        break :blk .initVailTls(connection);
    };
    var transport_owned = true;
    errdefer if (transport_owned) transport.close(allocator);
    // Decrypt one complete TLS record and consume only its first MQTT byte.
    // The remaining plaintext is already available before fault injection.
    if (backend != .tcp and backend != .websocket) {
        var command: [1]u8 = undefined;
        switch (transport) {
            .tls => |*value| {
                try std.testing.expectEqual(@as(usize, 1), try value.connection.readWithDeadline(&command, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(2) })));
                value.packet_state.header[0] = command[0];
                value.packet_state.header_len = 1;
            },
            .tls_vail => |*value| {
                try std.testing.expectEqual(@as(usize, 1), try value.connection.readWithDeadline(&command, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(2) })));
                value.packet_state.header[0] = command[0];
                value.packet_state.header_len = 1;
            },
            else => unreachable,
        }
    } else {
        try std.testing.expectError(error.Timeout, transport.readPacketWithDeadline(allocator, 1024, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(5) })));
    }
    var client = runtime.Connection{ .allocator = allocator, .transport = transport, .protocol = .v5, .endpoint_role = .client };
    transport_owned = false;
    defer client.close();
    support.InterruptedIo.next = fault;
    const expected = if (fault == .executor) error.ConcurrencyUnavailable else error.Canceled;
    try std.testing.expectError(expected, client.readClientPacketEventWithTimeout(.fromSeconds(2)));
    try std.testing.expect(client.isUsable());
    try std.testing.expect(!client.hasPendingIncomingPublish(42, qos));
    switch (client.transport) {
        inline .tls, .tls_vail => |value| {
            try std.testing.expectEqual(cut, if (cut == 2) value.packet_state.header_len else value.packet_state.packet_read);
        },
        else => {},
    }
    peer.release.set(base);
    var event = try client.readClientPacketEventWithTimeout(.fromSeconds(2));
    defer event.deinit(allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings("resume/topic", event.publish.publish.topic);
    try std.testing.expectEqualStrings(body, event.publish.publish.payload);
    try std.testing.expect(client.hasPendingIncomingPublish(42, qos));
    if (qos == .at_least_once) try client.writePubAck(42, 0) else try client.writePubRec(42, 0);
    var following = try client.readClientPacketEventWithTimeout(.fromSeconds(2));
    defer following.deinit(allocator);
    try std.testing.expect(following == .pingresp);
    if (qos == .exactly_once) {
        var release = try client.readClientPacketEventWithTimeout(.fromSeconds(2));
        defer release.deinit(allocator);
        try std.testing.expect(release == .pubrel);
        try std.testing.expectEqual(@as(u16, 42), release.pubrel.ack.packet_id);
        try client.writePubComp(42, 0);
    }
    try std.testing.expect(!client.hasPendingIncomingPublish(42, qos));
    try client.pingWithTimeout(.fromSeconds(2));
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

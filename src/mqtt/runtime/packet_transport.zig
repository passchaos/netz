const std = @import("std");
const mqtt = @import("../mod.zig");
const websocket_runtime = @import("../../websocket/mod.zig").runtime;
const http1_runtime = @import("../../http1/mod.zig").runtime;
const tls_stream = @import("../../tls/mod.zig").stream;

const net = std.Io.net;

pub const Error = mqtt.Error || websocket_runtime.Error ||
    tls_stream.Error || error{
    ConnectionClosed,
    InvalidWebSocketMessage,
    PacketTooLarge,
} || net.Stream.Reader.Error || net.Stream.Writer.Error;

const WebSocketTransport = struct {
    connection: websocket_runtime.Connection,
    input: std.ArrayList(u8) = .empty,
};

/// MQTT Control Packet transport shared by every runtime session.
///
/// TCP is a byte stream. MQTT-over-WebSocket has the same MQTT byte-stream
/// semantics even though each WebSocket write becomes a binary message:
/// packets may span messages and one message may contain multiple packets.
pub const Transport = union(enum) {
    tcp: struct {
        io: std.Io,
        stream: net.Stream,
    },
    tls: *http1_runtime.TlsClientConnection,
    tls_vail: *tls_stream.ClientConnection,
    tls_server: *tls_stream.ServerConnection,
    websocket: WebSocketTransport,

    pub fn initTcp(io: std.Io, stream: net.Stream) Transport {
        return .{ .tcp = .{ .io = io, .stream = stream } };
    }

    pub fn initWebSocket(
        connection: websocket_runtime.Connection,
    ) Transport {
        return .{ .websocket = .{ .connection = connection } };
    }

    pub fn initTls(
        connection: *http1_runtime.TlsClientConnection,
    ) Transport {
        return .{ .tls = connection };
    }

    pub fn initTlsServer(
        connection: *tls_stream.ServerConnection,
    ) Transport {
        return .{ .tls_server = connection };
    }

    pub fn initVailTls(
        connection: *tls_stream.ClientConnection,
    ) Transport {
        return .{ .tls_vail = connection };
    }

    pub fn peerCertificates(
        self: *const Transport,
    ) ?[]const []const u8 {
        return switch (self.*) {
            .tls_server => |connection| connection.peerCertificates(),
            .websocket => |*ws| ws.connection.peerCertificates(),
            // Client-side TLS peer inspection and non-TLS transports do not
            // expose a client-authenticated identity through this broker API.
            .tcp, .tls, .tls_vail => null,
        };
    }

    pub fn close(
        self: *Transport,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .tcp => |tcp| tcp.stream.close(tcp.io),
            .tls => |connection| connection.deinit(),
            .tls_vail => |connection| connection.deinit(),
            .tls_server => |connection| connection.deinit(),
            .websocket => |*ws| {
                ws.input.deinit(allocator);
                ws.connection.close();
            },
        }
        self.* = undefined;
    }

    pub fn writePacket(
        self: *Transport,
        bytes: []u8,
    ) Error!void {
        switch (self.*) {
            .tcp => |tcp| try writeAll(tcp.io, tcp.stream, bytes),
            .tls => |connection| try connection.writeAll(bytes),
            .tls_vail => |connection| try connection.writeAll(bytes),
            .tls_server => |connection| try connection.writeAll(bytes),
            // One packet per write matches rumqtt's WsStream behavior. The
            // reader intentionally does not depend on that optimization.
            // Client MQTT encoders relinquish their temporary bytes after the
            // send, so mask them in place and avoid a second payload copy.
            .websocket => |*ws| if (ws.connection.role == .client)
                try ws.connection.sendBinaryInPlace(bytes)
            else
                try ws.connection.sendBinary(bytes),
        }
    }

    pub fn readPacket(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |tcp| readTcpPacket(
                allocator,
                tcp.io,
                tcp.stream,
                max_packet_size,
            ),
            .tls => |connection| readStreamPacket(
                allocator,
                connection,
                max_packet_size,
            ),
            .tls_vail => |connection| readStreamPacket(
                allocator,
                connection,
                max_packet_size,
            ),
            .tls_server => |connection| readStreamPacket(
                allocator,
                connection,
                max_packet_size,
            ),
            .websocket => |*ws| readWebSocketPacket(
                allocator,
                ws,
                max_packet_size,
            ),
        };
    }
};

fn readStreamPacket(
    allocator: std.mem.Allocator,
    connection: anytype,
    max_packet_size: usize,
) Error!OwnedPacket {
    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);

    var first: [1]u8 = undefined;
    try readExactTls(connection, &first);
    try encoded.append(allocator, first[0]);

    var remaining_bytes: [4]u8 = undefined;
    var remaining_len_len: usize = 0;
    while (remaining_len_len < remaining_bytes.len) : (remaining_len_len += 1) {
        try readExactTls(
            connection,
            remaining_bytes[remaining_len_len .. remaining_len_len + 1],
        );
        try encoded.append(
            allocator,
            remaining_bytes[remaining_len_len],
        );
        if ((remaining_bytes[remaining_len_len] & 0x80) == 0) {
            break;
        }
    } else {
        return error.MalformedRemainingLength;
    }

    const decoded = try mqtt.decodeRemainingLength(
        remaining_bytes[0 .. remaining_len_len + 1],
    );
    const payload_start = encoded.items.len;
    const packet_len = std.math.add(
        usize,
        payload_start,
        decoded.value,
    ) catch return error.PacketTooLarge;
    if (packet_len > max_packet_size) return error.PacketTooLarge;
    try encoded.resize(allocator, packet_len);
    try readExactTls(connection, encoded.items[payload_start..]);

    const bytes = try encoded.toOwnedSlice(allocator);
    errdefer allocator.free(bytes);
    return .{
        .bytes = bytes,
        .fixed = try mqtt.FixedHeader.parse(bytes),
    };
}

pub const OwnedPacket = struct {
    bytes: []u8,
    fixed: mqtt.FixedHeader,

    pub fn deinit(
        self: *OwnedPacket,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn readTcpPacket(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    max_packet_size: usize,
) Error!OwnedPacket {
    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);

    var first: [1]u8 = undefined;
    try readExact(io, stream, &first);
    try encoded.append(allocator, first[0]);

    var remaining_bytes: [4]u8 = undefined;
    var remaining_len_len: usize = 0;
    while (remaining_len_len < remaining_bytes.len) : (remaining_len_len += 1) {
        try readExact(
            io,
            stream,
            remaining_bytes[remaining_len_len .. remaining_len_len + 1],
        );
        try encoded.append(
            allocator,
            remaining_bytes[remaining_len_len],
        );
        if ((remaining_bytes[remaining_len_len] & 0x80) == 0) {
            break;
        }
    } else {
        return error.MalformedRemainingLength;
    }

    const decoded = try mqtt.decodeRemainingLength(
        remaining_bytes[0 .. remaining_len_len + 1],
    );
    const payload_start = encoded.items.len;
    const packet_len = std.math.add(
        usize,
        payload_start,
        decoded.value,
    ) catch return error.PacketTooLarge;
    // MQTT 5 Maximum Packet Size is defined over the entire Control Packet,
    // not just the Remaining Length payload. Enforce it before allocation.
    if (packet_len > max_packet_size) return error.PacketTooLarge;
    try encoded.resize(allocator, packet_len);
    try readExact(io, stream, encoded.items[payload_start..]);

    const bytes = try encoded.toOwnedSlice(allocator);
    errdefer allocator.free(bytes);
    return .{
        .bytes = bytes,
        .fixed = try mqtt.FixedHeader.parse(bytes),
    };
}

fn readWebSocketPacket(
    allocator: std.mem.Allocator,
    ws: *WebSocketTransport,
    max_packet_size: usize,
) Error!OwnedPacket {
    while (true) {
        if (try completePacketLength(ws.input.items)) |packet_len| {
            if (packet_len > max_packet_size) {
                return error.PacketTooLarge;
            }
            const bytes = try allocator.dupe(
                u8,
                ws.input.items[0..packet_len],
            );
            errdefer allocator.free(bytes);
            const fixed = try mqtt.FixedHeader.parse(bytes);
            discardPacketPrefix(&ws.input, packet_len);
            return .{ .bytes = bytes, .fixed = fixed };
        }
        if (ws.input.items.len >= max_packet_size) {
            return error.PacketTooLarge;
        }

        var message = try ws.connection.receiveMessage();
        defer message.deinit(allocator);
        if (message.opcode != .binary) {
            return error.InvalidWebSocketMessage;
        }
        const next_len = std.math.add(
            usize,
            ws.input.items.len,
            message.payload.len,
        ) catch return error.PacketTooLarge;
        // A message may finish one bounded packet and carry bytes from the
        // next. Each message is itself capped at max_packet_size by the MQTT
        // adapter, so two packet-size windows are the maximum needed here.
        const max_buffered = std.math.mul(
            usize,
            max_packet_size,
            2,
        ) catch std.math.maxInt(usize);
        if (next_len > max_buffered) {
            return error.PacketTooLarge;
        }
        try ws.input.appendSlice(allocator, message.payload);
    }
}

fn completePacketLength(bytes: []const u8) Error!?usize {
    if (bytes.len < 2) return null;
    const max_remaining_length_bytes = @min(bytes.len - 1, 4);
    const decoded = mqtt.decodeRemainingLength(
        bytes[1 .. 1 + max_remaining_length_bytes],
    ) catch |err| switch (err) {
        error.BufferTooShort => return null,
        else => return err,
    };
    return std.math.add(
        usize,
        1 + decoded.len,
        decoded.value,
    ) catch return error.PacketTooLarge;
}

fn discardPacketPrefix(
    input: *std.ArrayList(u8),
    len: usize,
) void {
    const remaining = input.items.len - len;
    if (remaining != 0) {
        std.mem.copyForwards(
            u8,
            input.items[0..remaining],
            input.items[len..],
        );
    }
    input.items.len = remaining;
}

fn readExact(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var bufs = [_][]u8{buffer[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &bufs,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

fn readExactTls(
    connection: anytype,
    buffer: []u8,
) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = try connection.read(buffer[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

fn writeAll(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

test "packet length waits for a complete MQTT remaining length" {
    try std.testing.expectEqual(
        @as(?usize, null),
        try completePacketLength(&.{}),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        try completePacketLength(&.{0x30}),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        try completePacketLength(&.{ 0x30, 0x80 }),
    );
    try std.testing.expectEqual(
        @as(?usize, 2),
        try completePacketLength(&.{ 0xc0, 0x00 }),
    );
    try std.testing.expectEqual(
        @as(?usize, 133),
        try completePacketLength(&.{ 0x30, 0x82, 0x01 }),
    );
}

test "packet prefix discard retains following packet bytes" {
    const allocator = std.testing.allocator;
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    try input.appendSlice(
        allocator,
        &.{ 0xc0, 0x00, 0xd0, 0x00 },
    );

    discardPacketPrefix(&input, 2);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xd0, 0x00 },
        input.items,
    );
    discardPacketPrefix(&input, 2);
    try std.testing.expectEqual(@as(usize, 0), input.items.len);
}

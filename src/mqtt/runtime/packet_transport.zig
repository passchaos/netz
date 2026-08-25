const std = @import("std");
const mqtt = @import("../mod.zig");
const stream_io = @import("../../internal/stream_io.zig");
const websocket_runtime = @import("../../websocket/mod.zig").runtime;
const http1_runtime = @import("../../http1/mod.zig").runtime;
const tls_stream = @import("../../tls/mod.zig").stream;
const keep_alive_reader = @import("keep_alive_reader.zig");

const net = std.Io.net;

pub const Error = mqtt.Error || websocket_runtime.Error ||
    tls_stream.Error || error{
    ConnectionClosed,
    InvalidWebSocketMessage,
    PacketTooLarge,
} || net.Stream.Reader.Error || net.Stream.Writer.Error ||
    keep_alive_reader.Error;

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
            .tls_vail => |connection| connection.peerCertificates(),
            .websocket => |*ws| ws.connection.peerCertificates(),
            // Zig's standard TLS client does not expose its authenticated
            // chain, and cleartext TCP has no certificate identity.
            .tcp, .tls => null,
        };
    }

    pub fn negotiatedAlpn(self: *const Transport) ?[]const u8 {
        return switch (self.*) {
            .tls_vail => |connection| connection.negotiatedAlpn(),
            .tls_server => |connection| connection.negotiatedAlpn(),
            // Zig's standard TLS client does not currently expose ALPN, and
            // MQTT-over-WebSocket negotiates its application protocol through
            // Sec-WebSocket-Protocol rather than the underlying TLS session.
            .tcp, .tls, .websocket => null,
        };
    }

    pub fn remoteAddress(self: *const Transport) net.IpAddress {
        return switch (self.*) {
            .tcp => |tcp| tcp.stream.socket.address,
            .tls => |connection| connection.stream.socket.address,
            .tls_vail => |connection| connection.stream.socket.address,
            .tls_server => |connection| connection.stream.socket.address,
            .websocket => |*ws| ws.connection.stream.socket.address,
        };
    }

    pub fn deadlineFromNow(
        self: Transport,
        duration: std.Io.Duration,
    ) std.Io.Clock.Timestamp {
        const io = switch (self) {
            .tcp => |tcp| tcp.io,
            .tls => |connection| connection.io,
            .tls_vail => |connection| connection.io,
            .tls_server => |connection| connection.io,
            .websocket => |ws| ws.connection.io,
        };
        return .fromNow(
            io,
            .{ .raw = duration, .clock = .awake },
        );
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

    /// Stop both directions of a TCP transport without releasing ownership.
    ///
    /// Tests and broker shutdown paths use this to wake a concurrent reader;
    /// the normal `close` owner still performs the eventual descriptor close.
    pub fn shutdown(self: *Transport) Error!void {
        switch (self.*) {
            .tcp => |tcp| try tcp.stream.shutdown(tcp.io, .both),
            // TLS/WebSocket transports currently expose only owning close
            // operations. Their protocol-specific servers coordinate shutdown
            // outside this raw packet transport.
            .tls, .tls_vail, .tls_server, .websocket => {},
        }
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

    /// Write a packet prefix and borrowed application payload as one logical
    /// transport operation. Stream transports use scatter/gather directly;
    /// WebSocket emits one binary frame and applies one continuous client mask
    /// across both slices without concatenating the MQTT packet.
    pub fn writePacketParts(
        self: *Transport,
        prefix: []const u8,
        payload: []const u8,
    ) Error!void {
        switch (self.*) {
            .tcp => |tcp| try stream_io.writeAllParts(
                tcp.io,
                tcp.stream,
                prefix,
                payload,
            ),
            .tls => |connection| try connection.writeAllParts(
                prefix,
                payload,
            ),
            .tls_vail => |connection| try connection.writeAllParts(
                prefix,
                payload,
            ),
            .tls_server => |connection| try connection.writeAllParts(
                prefix,
                payload,
            ),
            .websocket => |*ws| try ws.connection.sendBinaryParts(
                prefix,
                payload,
            ),
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

    /// Read one packet within the peer's MQTT Keep Alive budget.
    ///
    /// One deadline covers a complete ordinary Control Packet, preventing a
    /// slow peer from retaining broker resources by trickling a small packet.
    /// As in Mosquitto, a progressing large payload renews the budget only
    /// while more than 1,000 bytes remain. TCP, WebSocket, and vail-backed TLS
    /// share this deadline model; WebSocket control frames do not count as
    /// MQTT progress and therefore cannot extend the packet deadline.
    pub fn readPacketWithInactivityTimeout(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
        timeout: std.Io.Clock.Duration,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |tcp| readTcpPacketWithInactivityTimeout(
                allocator,
                tcp.io,
                tcp.stream,
                max_packet_size,
                timeout,
            ),
            .tls => |connection| readStreamPacketWithInactivityTimeout(
                allocator,
                connection,
                max_packet_size,
                timeout,
            ),
            .tls_vail => |connection| readStreamPacketWithInactivityTimeout(
                allocator,
                connection,
                max_packet_size,
                timeout,
            ),
            .tls_server => |connection| readStreamPacketWithInactivityTimeout(
                allocator,
                connection,
                max_packet_size,
                timeout,
            ),
            .websocket => |*ws| readWebSocketPacketWithInactivityTimeout(
                allocator,
                ws,
                max_packet_size,
                timeout,
            ),
        };
    }

    /// Read one MQTT Control Packet under a single absolute deadline. Unlike
    /// Keep Alive reads, this never renews for large-packet progress, making it
    /// suitable for bounding the initial CONNECT/CONNACK exchange.
    pub fn readPacketWithDeadline(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |tcp| readTcpPacketWithDeadline(
                allocator,
                tcp.io,
                tcp.stream,
                max_packet_size,
                deadline,
            ),
            .tls => |connection| readStreamPacketWithDeadline(
                allocator,
                connection,
                max_packet_size,
                deadline,
            ),
            .tls_vail => |connection| readStreamPacketWithDeadline(
                allocator,
                connection,
                max_packet_size,
                deadline,
            ),
            .tls_server => |connection| readStreamPacketWithDeadline(
                allocator,
                connection,
                max_packet_size,
                deadline,
            ),
            .websocket => |*ws| readWebSocketPacketWithDeadline(
                allocator,
                ws,
                max_packet_size,
                deadline,
            ),
        };
    }
};

fn readStreamPacket(
    allocator: std.mem.Allocator,
    connection: anytype,
    max_packet_size: usize,
) Error!OwnedPacket {
    var reader = TlsPacketReader(@TypeOf(connection)).init(
        connection,
        .none,
    );
    return readPacketFromReader(allocator, &reader, max_packet_size);
}

fn readStreamPacketWithInactivityTimeout(
    allocator: std.mem.Allocator,
    connection: anytype,
    max_packet_size: usize,
    timeout: std.Io.Clock.Duration,
) Error!OwnedPacket {
    std.debug.assert(timeout.raw.nanoseconds > 0);
    var reader = TlsPacketReader(@TypeOf(connection)).init(
        connection,
        .{ .inactivity_timeout = timeout },
    );
    return readPacketFromReader(allocator, &reader, max_packet_size);
}

fn readStreamPacketWithDeadline(
    allocator: std.mem.Allocator,
    connection: anytype,
    max_packet_size: usize,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedPacket {
    var reader = TlsPacketReader(@TypeOf(connection)).init(
        connection,
        .{ .absolute_deadline = deadline },
    );
    return readPacketFromReader(allocator, &reader, max_packet_size);
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
    var reader = keep_alive_reader.Reader.init(io, stream, null);
    return readPacketFromReader(allocator, &reader, max_packet_size);
}

fn readTcpPacketWithInactivityTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    max_packet_size: usize,
    timeout: std.Io.Clock.Duration,
) Error!OwnedPacket {
    std.debug.assert(timeout.raw.nanoseconds > 0);
    var reader = keep_alive_reader.Reader.init(io, stream, timeout);
    return readPacketFromReader(allocator, &reader, max_packet_size);
}

fn readTcpPacketWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    max_packet_size: usize,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedPacket {
    var reader = keep_alive_reader.Reader.initDeadline(
        io,
        stream,
        deadline,
    );
    return readPacketFromReader(allocator, &reader, max_packet_size);
}

/// Assemble one owned packet from any reader that implements the shared
/// `readExact(buffer, renew_large_progress)` contract. TCP and TLS therefore
/// cannot drift in fixed-header validation, size preflight, or allocation
/// behavior as their deadline policies evolve.
fn readPacketFromReader(
    allocator: std.mem.Allocator,
    reader: anytype,
    max_packet_size: usize,
) Error!OwnedPacket {
    var header: [5]u8 = undefined;
    try reader.readExact(header[0..1], false);
    var remaining_len_len: usize = 0;
    while (remaining_len_len < 4) : (remaining_len_len += 1) {
        try reader.readExact(
            header[1 + remaining_len_len .. 2 + remaining_len_len],
            false,
        );
        if ((header[1 + remaining_len_len] & 0x80) == 0) {
            break;
        }
    } else {
        return error.MalformedRemainingLength;
    }

    const decoded = try mqtt.decodeRemainingLength(
        header[1 .. 2 + remaining_len_len],
    );
    const payload_start = 1 + decoded.len;
    const packet_len = std.math.add(
        usize,
        payload_start,
        decoded.value,
    ) catch return error.PacketTooLarge;
    // MQTT 5 Maximum Packet Size is defined over the entire Control Packet,
    // not just the Remaining Length payload. Enforce it before allocation.
    if (packet_len > max_packet_size) return error.PacketTooLarge;
    // Preserve the public owned-packet lifetime while avoiding incremental
    // heap growth: all framing bytes are bounded to five stack bytes and the
    // full packet receives one exact allocation after preflight.
    const bytes = try allocator.alloc(u8, packet_len);
    errdefer allocator.free(bytes);
    @memcpy(bytes[0..payload_start], header[0..payload_start]);
    try reader.readExact(bytes[payload_start..], true);
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
    return readWebSocketPacketWithPolicy(
        allocator,
        ws,
        max_packet_size,
        null,
        null,
    );
}

fn readWebSocketPacketWithInactivityTimeout(
    allocator: std.mem.Allocator,
    ws: *WebSocketTransport,
    max_packet_size: usize,
    timeout: std.Io.Clock.Duration,
) Error!OwnedPacket {
    std.debug.assert(timeout.raw.nanoseconds > 0);
    return readWebSocketPacketWithPolicy(
        allocator,
        ws,
        max_packet_size,
        timeout,
        null,
    );
}

fn readWebSocketPacketWithDeadline(
    allocator: std.mem.Allocator,
    ws: *WebSocketTransport,
    max_packet_size: usize,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedPacket {
    return readWebSocketPacketWithPolicy(
        allocator,
        ws,
        max_packet_size,
        null,
        deadline,
    );
}

fn readWebSocketPacketWithPolicy(
    allocator: std.mem.Allocator,
    ws: *WebSocketTransport,
    max_packet_size: usize,
    inactivity_timeout: ?std.Io.Clock.Duration,
    absolute_deadline: ?std.Io.Clock.Timestamp,
) Error!OwnedPacket {
    var deadline: std.Io.Clock.Timestamp = if (inactivity_timeout) |timeout|
        .fromNow(ws.connection.io, timeout)
    else if (absolute_deadline) |value|
        value
    else
        undefined;
    var large_progress_bytes: usize = 0;
    while (true) {
        if (try completePacketLength(ws.input.items)) |packet_len| {
            if (packet_len > max_packet_size) return error.PacketTooLarge;
            // Once Remaining Length is decoded, `packet_len` is the expected
            // size rather than evidence that all bytes have arrived. MQTT
            // packets commonly span several WebSocket messages.
            if (packet_len <= ws.input.items.len) {
                const bytes = try allocator.dupe(
                    u8,
                    ws.input.items[0..packet_len],
                );
                errdefer allocator.free(bytes);
                const fixed = try mqtt.FixedHeader.parse(bytes);
                discardPacketPrefix(&ws.input, packet_len);
                return .{ .bytes = bytes, .fixed = fixed };
            }
        }
        if (ws.input.items.len >= max_packet_size) {
            return error.PacketTooLarge;
        }

        var message = if (inactivity_timeout != null or
            absolute_deadline != null)
            try ws.connection.receiveMessageWithDeadline(deadline)
        else
            try ws.connection.receiveMessage();
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

        // MQTT packets are a byte stream independent of WebSocket message
        // boundaries. Move the one packet deadline only after MQTT bytes have
        // arrived and the decoded Remaining Length proves that more than the
        // bounded progress threshold is still outstanding. Ping/Pong frames
        // are consumed inside receiveMessageWithDeadline and never reach this
        // renewal point.
        if (message.payload.len != 0) {
            if (try completePacketLength(ws.input.items)) |packet_len| {
                if (packet_len > max_packet_size) return error.PacketTooLarge;
                if (inactivity_timeout) |timeout| {
                    if (ws.input.items.len > large_progress_bytes and
                        packet_len > ws.input.items.len and
                        packet_len - ws.input.items.len >
                            keep_alive_reader.progress_threshold)
                    {
                        deadline = .fromNow(ws.connection.io, timeout);
                        large_progress_bytes = ws.input.items.len;
                    }
                }
            }
        }
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

const StreamReadPolicy = union(enum) {
    none,
    inactivity_timeout: std.Io.Clock.Duration,
    absolute_deadline: std.Io.Clock.Timestamp,
};

fn TlsPacketReader(comptime ConnectionType: type) type {
    return struct {
        connection: ConnectionType,
        policy: StreamReadPolicy,
        deadline: ?std.Io.Clock.Timestamp,

        const Self = @This();

        fn init(connection: ConnectionType, policy: StreamReadPolicy) Self {
            const deadline: ?std.Io.Clock.Timestamp = switch (policy) {
                .none => null,
                .inactivity_timeout => |timeout| blk: {
                    std.debug.assert(timeout.raw.nanoseconds > 0);
                    break :blk .fromNow(connection.io, timeout);
                },
                .absolute_deadline => |value| value,
            };
            return .{
                .connection = connection,
                .policy = policy,
                .deadline = deadline,
            };
        }

        fn readExact(
            self: *Self,
            buffer: []u8,
            renew_large_progress: bool,
        ) Error!void {
            if (self.policy == .inactivity_timeout and
                renew_large_progress and
                buffer.len > keep_alive_reader.progress_threshold)
            {
                self.renewInactivityDeadline();
            }
            var offset: usize = 0;
            while (offset < buffer.len) {
                const count = if (self.deadline) |deadline|
                    try self.connection.readWithDeadline(
                        buffer[offset..],
                        deadline,
                    )
                else
                    try self.connection.read(buffer[offset..]);
                if (count == 0) return error.ConnectionClosed;
                offset += count;
                if (self.policy == .inactivity_timeout and
                    renew_large_progress and
                    buffer.len - offset > keep_alive_reader.progress_threshold)
                {
                    self.renewInactivityDeadline();
                }
            }
        }

        fn renewInactivityDeadline(self: *Self) void {
            const timeout = switch (self.policy) {
                .inactivity_timeout => |value| value,
                else => return,
            };
            self.deadline = .fromNow(self.connection.io, timeout);
        }
    };
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

test "TCP packet receive allocates the owned packet exactly once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const receiver = try listener.accept(io);
    defer receiver.close(io);

    var wire_bytes: [133]u8 = @splat(0x5a);
    wire_bytes[0] = 0x30;
    wire_bytes[1] = 0x82;
    wire_bytes[2] = 0x01;
    try writeAll(io, sender, &wire_bytes);

    // Allow exactly the allocation that owns the returned packet. The former
    // incremental ArrayList path needed additional allocation/remap activity
    // while collecting the five-byte fixed header.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1, .resize_fail_index = 0 },
    );
    var transport = Transport.initTcp(io, receiver);
    var packet = try transport.readPacket(
        failing.allocator(),
        wire_bytes.len,
    );
    defer packet.deinit(failing.allocator());
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expectEqual(@as(usize, 0), failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &wire_bytes, packet.bytes);
    try std.testing.expectEqual(@as(usize, 130), packet.fixed.remaining_len);
    try std.testing.expectEqual(@as(usize, 3), packet.fixed.header_len);
}

test "TCP packet receive rejects oversize before allocating" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const receiver = try listener.accept(io);
    defer receiver.close(io);

    // Only the three-byte header is needed to prove that the complete packet
    // exceeds the configured limit; its body deliberately never arrives.
    try writeAll(io, sender, &.{ 0x30, 0x82, 0x01 });
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var transport = Transport.initTcp(io, receiver);
    try std.testing.expectError(
        error.PacketTooLarge,
        transport.readPacket(fail_first.allocator(), 132),
    );
    try std.testing.expect(!fail_first.has_induced_failure);
}

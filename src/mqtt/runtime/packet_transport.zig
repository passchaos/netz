const std = @import("std");
const mqtt = @import("../mod.zig");
const stream_io = @import("../../internal/stream_io.zig");
const websocket_runtime = @import("../../websocket/mod.zig").runtime;
const http1_runtime = @import("../../http1/mod.zig").runtime;
const tls_stream = @import("../../tls/mod.zig").stream;
const keep_alive_reader = @import("keep_alive_reader.zig");

const net = std.Io.net;

fn inactivityDeadline(
    io: std.Io,
    timeout: std.Io.Clock.Duration,
) std.Io.Clock.Timestamp {
    std.debug.assert(timeout.clock == .awake);
    return std.Io.Clock.Timestamp.fromNow(io, timeout);
}

/// Broker-facing packet reads may reserve an aligned prefix for transferring
/// a large packet allocation into a longer-lived object without replacement.
pub const prefixed_packet_alignment = 16;
pub const PrefixedPacketAllocation =
    []align(prefixed_packet_alignment) u8;

pub const Error = mqtt.Error || websocket_runtime.Error ||
    tls_stream.Error || error{
    ConnectionClosed,
    InvalidWebSocketMessage,
    PacketTooLarge,
    ExporterUnavailable,
    TlsKeyUpdateUnavailable,
} || net.Stream.Reader.Error || net.Stream.Writer.Error ||
    keep_alive_reader.Error;

/// Broker-owned inactivity scheduling can renew one external deadline without
/// arming a separate I/O timer for every packet read. The callback must be
/// allocation-free and safe on the connection reader's executor.
pub const InactivityObserver = struct {
    context: *anyopaque,
    renew_fn: *const fn (context: *anyopaque) void,

    pub fn renew(self: InactivityObserver) void {
        self.renew_fn(self.context);
    }
};

const WebSocketTransport = struct {
    connection: websocket_runtime.Connection,
    input: std.ArrayList(u8) = .empty,
    /// Decoded by WebSocket but not yet appended to MQTT's byte stream.
    /// Allocated by connection.allocator; retained only across append OOM.
    pending_payload: ?[]u8 = null,
};

const tcp_read_ahead_capacity = 448;

/// Partial packet state survives a bounded read timeout. TCP reads request
/// into a small connection-local buffer so the fixed header and common small
/// packet body complete in one operation. Bytes from a following coalesced
/// packet remain buffered, while large bodies stream directly into their
/// exact owned allocation.
const TcpTransport = struct {
    io: std.Io,
    stream: net.Stream,
    input: [tcp_read_ahead_capacity]u8 = undefined,
    input_start: usize = 0,
    input_end: usize = 0,
    packet: ?[]u8 = null,
    packet_prefix_len: u16 = 0,
    restored_packet_counted: bool = false,
    packet_read: usize = 0,

    fn buffered(self: *const TcpTransport) []const u8 {
        return self.input[self.input_start..self.input_end];
    }

    fn discardBuffered(self: *TcpTransport, len: usize) void {
        std.debug.assert(len <= self.input_end - self.input_start);
        self.input_start += len;
        if (self.input_start == self.input_end) {
            self.input_start = 0;
            self.input_end = 0;
        }
    }

    fn compactBuffered(self: *TcpTransport) void {
        if (self.input_start == 0) return;
        const remaining = self.input_end - self.input_start;
        std.mem.copyForwards(
            u8,
            self.input[0..remaining],
            self.input[self.input_start..self.input_end],
        );
        self.input_start = 0;
        self.input_end = remaining;
    }

    fn takeRestoredCounted(self: *TcpTransport) bool {
        const counted = self.restored_packet_counted;
        self.restored_packet_counted = false;
        return counted;
    }
};

/// Resumable packet state for stream transports whose own read API does not
/// retain MQTT framing progress. This mirrors `TcpTransport` so timeout and
/// cancellation and executor admission failure retain each accepted prefix.
const StreamPacketState = struct {
    header: [5]u8 = undefined,
    header_len: usize = 0,
    packet: ?[]u8 = null,
    packet_prefix_len: u16 = 0,
    packet_read: usize = 0,

    pub fn deinit(self: *StreamPacketState, allocator: std.mem.Allocator) void {
        if (self.packet) |packet| freePacketBytes(
            allocator,
            packet,
            self.packet_prefix_len,
        );
        self.* = .{};
    }
};

fn StreamTransport(comptime Connection: type) type {
    return struct {
        connection: *Connection,
        packet_state: StreamPacketState = .{},
    };
}

const TlsTransport = StreamTransport(http1_runtime.TlsClientConnection);
const VailTlsTransport = StreamTransport(tls_stream.ClientConnection);
const TlsServerTransport = StreamTransport(tls_stream.ServerConnection);

/// MQTT Control Packet transport shared by every runtime session.
///
/// TCP is a byte stream. MQTT-over-WebSocket has the same MQTT byte-stream
/// semantics even though each WebSocket write becomes a binary message:
/// packets may span messages and one message may contain multiple packets.
pub const Transport = union(enum) {
    tcp: TcpTransport,
    tls: TlsTransport,
    tls_vail: VailTlsTransport,
    tls_server: TlsServerTransport,
    // WebSocket Connection carries HTTP/TLS/compression state that is much
    // larger than the TCP and pointer-backed TLS variants. Keeping it behind
    // one allocation prevents every plain MQTT connection from paying the
    // tagged union's maximum inline size.
    websocket: *WebSocketTransport,

    pub fn initTcp(io: std.Io, stream: net.Stream) Transport {
        return .{ .tcp = .{ .io = io, .stream = stream } };
    }

    pub fn initWebSocket(
        allocator: std.mem.Allocator,
        connection: websocket_runtime.Connection,
    ) std.mem.Allocator.Error!Transport {
        var owned_connection = connection;
        errdefer owned_connection.close();
        const transport = try allocator.create(WebSocketTransport);
        transport.* = .{ .connection = owned_connection };
        return .{ .websocket = transport };
    }

    pub fn initTls(
        connection: *http1_runtime.TlsClientConnection,
    ) Transport {
        return .{ .tls = .{ .connection = connection } };
    }

    pub fn initTlsServer(
        connection: *tls_stream.ServerConnection,
    ) Transport {
        return .{ .tls_server = .{ .connection = connection } };
    }

    pub fn initVailTls(
        connection: *tls_stream.ClientConnection,
    ) Transport {
        return .{ .tls_vail = .{ .connection = connection } };
    }

    pub fn peerCertificates(
        self: *const Transport,
    ) ?[]const []const u8 {
        return switch (self.*) {
            .tls_server => |transport| transport.connection.peerCertificates(),
            .tls_vail => |transport| transport.connection.peerCertificates(),
            .websocket => |ws| ws.connection.peerCertificates(),
            // Zig's standard TLS client does not expose its authenticated
            // chain, and cleartext TCP has no certificate identity.
            .tcp, .tls => null,
        };
    }

    pub fn negotiatedAlpn(self: *const Transport) ?[]const u8 {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.negotiatedAlpn(),
            .tls_server => |transport| transport.connection.negotiatedAlpn(),
            .websocket => |ws| ws.connection.negotiatedAlpn(),
            // Zig's standard TLS client does not currently expose ALPN.
            .tcp, .tls => null,
        };
    }

    pub fn negotiatedTlsProtocol(
        self: *const Transport,
    ) ?tls_stream.Protocol {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.negotiatedProtocol(),
            .tls_server => |transport| transport.connection.negotiatedProtocol(),
            .websocket => |ws| ws.connection.negotiatedTlsProtocol(),
            .tcp, .tls => null,
        };
    }

    pub fn wasTlsSessionResumed(self: *const Transport) ?bool {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.wasResumed(),
            .tls_server => |transport| transport.connection.wasResumed(),
            .websocket => |ws| ws.connection.wasTlsSessionResumed(),
            .tcp, .tls => null,
        };
    }

    pub fn takeTls12SessionTicket(
        self: *Transport,
    ) ?tls_stream.Tls12SessionTicket {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.takeTls12SessionTicket(),
            .websocket => |ws| ws.connection.takeTls12SessionTicket(),
            .tls_server, .tcp, .tls => null,
        };
    }

    pub fn takeTls13SessionTicket(
        self: *Transport,
    ) Error!?tls_stream.Tls13SessionTicket {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.takeTls13SessionTicket(),
            .websocket => |ws| ws.connection.takeTls13SessionTicket(),
            .tls_server, .tcp, .tls => null,
        };
    }

    pub fn negotiatedCipherSuite(
        self: *const Transport,
    ) ?tls_stream.NegotiatedCipherSuite {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.negotiatedCipherSuite(),
            .tls_server => |transport| transport.connection.negotiatedCipherSuite(),
            .websocket => |ws| ws.connection.negotiatedCipherSuite(),
            .tcp, .tls => null,
        };
    }

    pub fn negotiatedTranscriptHash(
        self: *const Transport,
    ) ?tls_stream.TranscriptHash {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.negotiatedTranscriptHash(),
            .tls_server => |transport| transport.connection.negotiatedTranscriptHash(),
            .websocket => |ws| ws.connection.negotiatedTranscriptHash(),
            .tcp, .tls => null,
        };
    }

    pub fn updateTrafficKeys(
        self: *Transport,
        request_peer_update: bool,
    ) Error!void {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.updateTrafficKeys(
                request_peer_update,
            ),
            .tls_server => |transport| transport.connection.updateTrafficKeys(
                request_peer_update,
            ),
            .websocket => |ws| ws.connection.updateTrafficKeys(
                request_peer_update,
            ),
            .tcp, .tls => error.TlsKeyUpdateUnavailable,
        };
    }

    pub fn keyUpdateCounts(
        self: *const Transport,
    ) ?tls_stream.KeyUpdateCounts {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.keyUpdateCounts(),
            .tls_server => |transport| transport.connection.keyUpdateCounts(),
            .websocket => |ws| ws.connection.keyUpdateCounts(),
            .tcp, .tls => null,
        };
    }

    pub fn exportKeyingMaterial(
        self: *const Transport,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        return switch (self.*) {
            .tls_vail => |transport| transport.connection.exportKeyingMaterial(
                label,
                context,
                out,
            ),
            .tls_server => |transport| transport.connection.exportKeyingMaterial(
                label,
                context,
                out,
            ),
            .websocket => |ws| ws.connection.exportKeyingMaterial(
                label,
                context,
                out,
            ),
            .tcp, .tls => error.ExporterUnavailable,
        };
    }

    pub fn remoteAddress(self: *const Transport) net.IpAddress {
        return switch (self.*) {
            .tcp => |tcp| tcp.stream.socket.address,
            .tls => |transport| transport.connection.stream.socket.address,
            .tls_vail => |transport| transport.connection.stream.socket.address,
            .tls_server => |transport| transport.connection.stream.socket.address,
            .websocket => |ws| ws.connection.stream.socket.address,
        };
    }

    pub fn deadlineFromNow(
        self: Transport,
        duration: std.Io.Duration,
    ) std.Io.Clock.Timestamp {
        return .fromNow(
            self.ioHandle(),
            .{ .raw = duration, .clock = .awake },
        );
    }

    pub fn ioHandle(self: Transport) std.Io {
        return switch (self) {
            .tcp => |tcp| tcp.io,
            .tls => |transport| transport.connection.io,
            .tls_vail => |transport| transport.connection.io,
            .tls_server => |transport| transport.connection.io,
            .websocket => |ws| ws.connection.io,
        };
    }

    pub fn close(
        self: *Transport,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .tcp => |*tcp| {
                if (tcp.packet) |packet| freePacketBytes(
                    allocator,
                    packet,
                    tcp.packet_prefix_len,
                );
                tcp.stream.close(tcp.io);
            },
            .tls => |*transport| {
                transport.packet_state.deinit(allocator);
                transport.connection.deinit();
            },
            .tls_vail => |*transport| {
                transport.packet_state.deinit(allocator);
                transport.connection.deinit();
            },
            .tls_server => |*transport| {
                transport.packet_state.deinit(allocator);
                transport.connection.deinit();
            },
            .websocket => |ws| {
                WebSocketPacketReader.discardPending(ws);
                ws.input.deinit(allocator);
                ws.connection.close();
                allocator.destroy(ws);
            },
        }
        self.* = undefined;
    }

    /// Stop both directions of a socket transport without releasing ownership.
    ///
    /// Tests and broker shutdown paths use this to wake a concurrent reader;
    /// the normal `close` owner still performs the eventual descriptor close.
    pub fn shutdown(self: *Transport) Error!void {
        switch (self.*) {
            .tcp => |tcp| try tcp.stream.shutdown(tcp.io, .both),
            .tls => |transport| try transport.connection.stream.shutdown(
                transport.connection.io,
                .both,
            ),
            .tls_vail => |transport| try transport.connection.stream.shutdown(
                transport.connection.io,
                .both,
            ),
            .tls_server => |transport| try transport.connection.stream.shutdown(
                transport.connection.io,
                .both,
            ),
            // WebSocket close is owning and cannot be used only as a wakeup.
            .websocket => {},
        }
    }

    /// Interrupt any blocking transport operation without taking ownership.
    /// Unlike `shutdown`, this also reaches through a WebSocket wrapper to its
    /// underlying stream; the normal owner must still call `close` afterward.
    pub fn interrupt(self: *Transport) Error!void {
        switch (self.*) {
            .websocket => |ws| try ws.connection.stream.shutdown(
                ws.connection.io,
                .both,
            ),
            else => try self.shutdown(),
        }
    }

    pub fn writePacket(
        self: *Transport,
        bytes: []u8,
    ) Error!void {
        switch (self.*) {
            .tcp => |tcp| try writeAll(tcp.io, tcp.stream, bytes),
            .tls => |transport| try transport.connection.writeAll(bytes),
            .tls_vail => |transport| try transport.connection.writeAll(bytes),
            .tls_server => |transport| try transport.connection.writeAll(bytes),
            // One packet per write matches rumqtt's WsStream behavior. The
            // reader intentionally does not depend on that optimization.
            // Client MQTT encoders relinquish their temporary bytes after the
            // send, so mask them in place and avoid a second payload copy.
            .websocket => |ws| if (ws.connection.role == .client)
                try ws.connection.sendBinaryInPlace(bytes)
            else
                try ws.connection.sendBinary(bytes),
        }
    }

    /// Write one complete MQTT packet under a caller-owned deadline. A
    /// timeout may leave transport-specific partial state, so protocol
    /// callers that cannot resume the identical bytes must retire the
    /// connection.
    pub fn writePacketWithDeadline(
        self: *Transport,
        bytes: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        switch (self.*) {
            .tcp => |tcp| {
                var committed: usize = 0;
                try stream_io.writeAllTrackedWithDeadline(
                    tcp.io,
                    tcp.stream,
                    bytes,
                    &committed,
                    deadline,
                );
            },
            .tls => |transport| {
                var committed: usize = 0;
                try transport.connection.writeAllWithDeadline(
                    bytes,
                    &committed,
                    deadline,
                );
            },
            .tls_vail => |transport| {
                var committed: usize = 0;
                try transport.connection.writeAllWithDeadline(
                    bytes,
                    &committed,
                    deadline,
                );
            },
            .tls_server => |transport| {
                var committed: usize = 0;
                try transport.connection.writeAllWithDeadline(
                    bytes,
                    &committed,
                    deadline,
                );
            },
            .websocket => |ws| {
                var progress: websocket_runtime.MessageWriteProgress = .{};
                if (ws.connection.role == .client) {
                    try ws.connection.sendBinaryInPlaceWithDeadline(
                        bytes,
                        &progress,
                        deadline,
                    );
                } else {
                    try ws.connection.sendBinaryWithDeadline(
                        bytes,
                        &progress,
                        deadline,
                    );
                }
            },
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
            .tls => |transport| try transport.connection.writeAllParts(
                prefix,
                payload,
            ),
            .tls_vail => |transport| try transport.connection.writeAllParts(
                prefix,
                payload,
            ),
            .tls_server => |transport| try transport.connection.writeAllParts(
                prefix,
                payload,
            ),
            .websocket => |ws| try ws.connection.sendBinaryParts(
                prefix,
                payload,
            ),
        }
    }

    /// Preserve the ordinary transport's atomic prefix/payload framing while
    /// bounding the complete write. Partial output must retire MQTT ownership.
    pub fn writePacketPartsWithDeadline(self: *Transport, prefix: []const u8, payload: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        const timed_parts = @import("transport/write_parts_deadline.zig");
        if (self.* == .tcp) {
            if (timed_parts.tryTcp(Error, self.tcp.io, self.tcp.stream, prefix, payload, deadline)) |result| return result;
        }
        return timed_parts.write(Error, self.ioHandle(), self, Transport.writePacketPartsForDeadline, prefix, payload, deadline);
    }

    fn writePacketPartsForDeadline(self: *Transport, prefix: []const u8, payload: []const u8) Error!void {
        self.writePacketParts(prefix, payload) catch |err| {
            // The standard TLS writer wraps socket cancellation and other
            // network errors in WriteFailed. Restore that actual cause before
            // the deadline race classifies cancellation versus write failure.
            if (err == error.WriteFailed and self.* == .tls) {
                if (self.tls.connection.net_writer.err) |cause| {
                    self.tls.connection.net_writer.err = null;
                    return cause;
                }
            }
            return err;
        };
    }

    pub fn readPacket(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |*tcp| readTcpPacket(
                allocator,
                tcp,
                max_packet_size,
            ),
            .tls => |*transport| readStreamPacket(
                allocator,
                transport,
                max_packet_size,
            ),
            .tls_vail => |*transport| readStreamPacket(
                allocator,
                transport,
                max_packet_size,
            ),
            .tls_server => |*transport| readStreamPacket(
                allocator,
                transport,
                max_packet_size,
            ),
            .websocket => |ws| readWebSocketPacket(
                allocator,
                ws,
                max_packet_size,
            ),
        };
    }

    /// Read a packet while allowing a complete TCP read-ahead packet to use
    /// caller-owned storage. Other transports, TCP packets not complete in
    /// read-ahead once their length is known, and packets larger than `storage`
    /// retain the ordinary owned-allocation behavior. DISCONNECT always owns
    /// its bytes so event decoding can retain it across local failures.
    pub fn readPacketInto(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
        storage: []u8,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |*tcp| readTcpPacketWithPolicy(
                .none,
                true,
                allocator,
                tcp,
                max_packet_size,
                {},
                storage,
                0,
            ),
            else => self.readPacket(allocator, max_packet_size),
        };
    }

    /// Return a caller-buffer packet to its connection-owned TCP read-ahead
    /// after decode OOM. No transport read or allocation can intervene.
    pub fn restoreBorrowedPacket(self: *Transport, packet: OwnedPacket) void {
        std.debug.assert(!packet.owns_bytes);
        const tcp = &self.tcp;
        std.debug.assert(tcp.packet == null);
        tcp.compactBuffered();
        std.debug.assert(packet.bytes.len + tcp.input_end <= tcp.input.len);
        @memmove(tcp.input[packet.bytes.len..][0..tcp.input_end], tcp.input[0..tcp.input_end]);
        @memcpy(tcp.input[0..packet.bytes.len], packet.bytes);
        tcp.input_end += packet.bytes.len;
        tcp.restored_packet_counted = packet.traffic_recorded;
    }

    /// Broker-oriented variant of `readPacketInto` that reserves an aligned
    /// prefix on an owned TCP fallback. A returned packet exposes that backing
    /// allocation so a longer-lived representation can adopt it. Short TCP
    /// packets other than DISCONNECT still borrow `storage`; other transports
    /// keep their existing ownership behavior.
    pub fn readPacketIntoWithPrefix(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
        storage: []u8,
        prefix_len: usize,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |*tcp| readTcpPacketWithPolicy(
                .none,
                true,
                allocator,
                tcp,
                max_packet_size,
                {},
                storage,
                prefix_len,
            ),
            .tls => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                null,
                null,
                null,
                prefix_len,
            ),
            .tls_vail => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                null,
                null,
                null,
                prefix_len,
            ),
            .tls_server => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                null,
                null,
                null,
                prefix_len,
            ),
            .websocket => |ws| readWebSocketPacketWithPolicy(
                allocator,
                ws,
                max_packet_size,
                null,
                null,
                null,
                prefix_len,
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
            .tcp => |*tcp| readTcpPacketWithInactivityTimeout(
                allocator,
                tcp,
                max_packet_size,
                timeout,
            ),
            .tls => |*transport| readStreamPacketWithInactivityTimeout(
                allocator,
                transport,
                max_packet_size,
                timeout,
            ),
            .tls_vail => |*transport| readStreamPacketWithInactivityTimeout(
                allocator,
                transport,
                max_packet_size,
                timeout,
            ),
            .tls_server => |*transport| readStreamPacketWithInactivityTimeout(
                allocator,
                transport,
                max_packet_size,
                timeout,
            ),
            .websocket => |ws| readWebSocketPacketWithInactivityTimeout(
                allocator,
                ws,
                max_packet_size,
                timeout,
            ),
        };
    }

    /// Keep-Alive-bounded counterpart to `readPacketInto`.
    pub fn readPacketWithInactivityTimeoutInto(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
        timeout: std.Io.Clock.Duration,
        storage: []u8,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |*tcp| readTcpPacketWithPolicy(
                .inactivity_timeout,
                true,
                allocator,
                tcp,
                max_packet_size,
                timeout,
                storage,
                0,
            ),
            else => self.readPacketWithInactivityTimeout(
                allocator,
                max_packet_size,
                timeout,
            ),
        };
    }

    /// Keep-Alive-bounded counterpart to `readPacketIntoWithPrefix`.
    pub fn readPacketWithInactivityTimeoutIntoWithPrefix(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
        timeout: std.Io.Clock.Duration,
        storage: []u8,
        prefix_len: usize,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |*tcp| readTcpPacketWithPolicy(
                .inactivity_timeout,
                true,
                allocator,
                tcp,
                max_packet_size,
                timeout,
                storage,
                prefix_len,
            ),
            .tls => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                timeout,
                null,
                null,
                prefix_len,
            ),
            .tls_vail => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                timeout,
                null,
                null,
                prefix_len,
            ),
            .tls_server => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                timeout,
                null,
                null,
                prefix_len,
            ),
            .websocket => |ws| readWebSocketPacketWithPolicy(
                allocator,
                ws,
                max_packet_size,
                timeout,
                null,
                null,
                prefix_len,
            ),
        };
    }

    /// Read with an externally managed inactivity deadline. Ordinary reads do
    /// not arm a per-operation timer; large-packet progress invokes `observer`
    /// under the same >1000-byte policy as timed Keep Alive reads.
    pub fn readPacketWithInactivityObserverIntoWithPrefix(
        self: *Transport,
        allocator: std.mem.Allocator,
        max_packet_size: usize,
        observer: InactivityObserver,
        storage: []u8,
        prefix_len: usize,
    ) Error!OwnedPacket {
        return switch (self.*) {
            .tcp => |*tcp| readTcpPacketWithPolicy(
                .inactivity_observer,
                true,
                allocator,
                tcp,
                max_packet_size,
                observer,
                storage,
                prefix_len,
            ),
            .tls => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                null,
                null,
                observer,
                prefix_len,
            ),
            .tls_vail => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                null,
                null,
                observer,
                prefix_len,
            ),
            .tls_server => |*transport| readStreamPacketWithPolicy(
                allocator,
                transport,
                max_packet_size,
                null,
                null,
                observer,
                prefix_len,
            ),
            .websocket => |ws| readWebSocketPacketWithPolicy(
                allocator,
                ws,
                max_packet_size,
                null,
                null,
                observer,
                prefix_len,
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
            .tcp => |*tcp| readTcpPacketWithDeadline(
                allocator,
                tcp,
                max_packet_size,
                deadline,
            ),
            .tls => |*transport| readStreamPacketWithDeadline(
                allocator,
                transport,
                max_packet_size,
                deadline,
            ),
            .tls_vail => |*transport| readStreamPacketWithDeadline(
                allocator,
                transport,
                max_packet_size,
                deadline,
            ),
            .tls_server => |*transport| readStreamPacketWithDeadline(
                allocator,
                transport,
                max_packet_size,
                deadline,
            ),
            .websocket => |ws| readWebSocketPacketWithDeadline(
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
    transport: anytype,
    max_packet_size: usize,
) Error!OwnedPacket {
    return readStreamPacketWithPolicy(
        allocator,
        transport,
        max_packet_size,
        null,
        null,
        null,
        0,
    );
}

fn readStreamPacketWithInactivityTimeout(
    allocator: std.mem.Allocator,
    transport: anytype,
    max_packet_size: usize,
    timeout: std.Io.Clock.Duration,
) Error!OwnedPacket {
    std.debug.assert(timeout.raw.nanoseconds > 0);
    return readStreamPacketWithPolicy(
        allocator,
        transport,
        max_packet_size,
        timeout,
        null,
        null,
        0,
    );
}

fn readStreamPacketWithDeadline(
    allocator: std.mem.Allocator,
    transport: anytype,
    max_packet_size: usize,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedPacket {
    return readStreamPacketWithPolicy(
        allocator,
        transport,
        max_packet_size,
        null,
        deadline,
        null,
        0,
    );
}

const StreamPacketReader = @import("transport/stream_receive.zig").Reader(struct {
    pub const ErrorType = Error;
    pub const PacketType = OwnedPacket;
    pub const allocate = allocatePacketBytes;
    pub const free = freePacketBytes;
    pub const fromInactivity = inactivityDeadline;
    pub const InactivityObserverType = InactivityObserver;
});
const readStreamPacketWithPolicy = StreamPacketReader.read;

test "MQTT TLS packet cursor retains every accepted byte across local interruptions" {
    try @import("transport/stream_receive_tests.zig").cursor(StreamPacketReader, StreamPacketState, Error);
}

pub const OwnedPacket = struct {
    bytes: []u8,
    fixed: mqtt.FixedHeader,
    /// False for explicit caller-buffer reads and after ownership transfer.
    owns_bytes: bool = true,
    /// Session receive accounting already consumed this packet. A restored
    /// caller-buffer retry must not count its wire bytes a second time.
    traffic_recorded: bool = false,
    /// Non-zero when an aligned broker allocation reserves a transferable
    /// prefix immediately before the packet bytes.
    prefix_len: u16 = 0,

    /// Bytes covered by the already decoded MQTT Remaining Length.
    pub fn remainingBytes(self: OwnedPacket) []const u8 {
        std.debug.assert(self.fixed.header_len <= self.bytes.len);
        std.debug.assert(
            self.fixed.remaining_len == self.bytes.len - self.fixed.header_len,
        );
        return self.bytes[self.fixed.header_len..];
    }

    pub fn contains(self: OwnedPacket, bytes: []const u8) bool {
        const packet_start = @intFromPtr(self.bytes.ptr);
        const bytes_start = @intFromPtr(bytes.ptr);
        if (bytes_start < packet_start) return false;
        const offset = bytes_start - packet_start;
        return offset <= self.bytes.len and
            bytes.len <= self.bytes.len - offset;
    }

    pub fn prefixedAllocation(
        self: OwnedPacket,
    ) ?PrefixedPacketAllocation {
        if (!self.owns_bytes or self.prefix_len == 0) return null;
        return packetAllocationFromPrefix(self.bytes, self.prefix_len);
    }

    pub fn deinit(
        self: *OwnedPacket,
        allocator: std.mem.Allocator,
    ) void {
        if (self.owns_bytes) freePacketBytes(
            allocator,
            self.bytes,
            self.prefix_len,
        );
        self.* = undefined;
    }
};

fn packetAllocationFromPrefix(
    packet: []u8,
    prefix_len: u16,
) PrefixedPacketAllocation {
    std.debug.assert(prefix_len != 0);
    const allocation_len = packet.len + @as(usize, prefix_len);
    const allocation_ptr: [*]u8 = @ptrFromInt(
        @intFromPtr(packet.ptr) - @as(usize, prefix_len),
    );
    return @alignCast(allocation_ptr[0..allocation_len]);
}

fn freePacketBytes(
    allocator: std.mem.Allocator,
    packet: []u8,
    prefix_len: u16,
) void {
    if (prefix_len == 0) {
        allocator.free(packet);
    } else {
        allocator.free(packetAllocationFromPrefix(packet, prefix_len));
    }
}

const AllocatedPacket = struct {
    bytes: []u8,
    prefix_len: u16,
};

fn allocatePacketBytes(
    allocator: std.mem.Allocator,
    packet_len: usize,
    owned_prefix_len: usize,
) Error!AllocatedPacket {
    const prefix_len = std.math.cast(
        u16,
        owned_prefix_len,
    ) orelse return error.PacketTooLarge;
    if (prefix_len == 0) {
        return .{
            .bytes = try allocator.alloc(u8, packet_len),
            .prefix_len = 0,
        };
    }
    const allocation_len = std.math.add(
        usize,
        prefix_len,
        packet_len,
    ) catch return error.PacketTooLarge;
    const allocation = try allocator.alignedAlloc(
        u8,
        .@"16",
        allocation_len,
    );
    return .{
        .bytes = allocation[prefix_len..],
        .prefix_len = prefix_len,
    };
}

test "MQTT packet transport keeps WebSocket state out of line" {
    try std.testing.expect(
        @sizeOf(Transport) < @sizeOf(WebSocketTransport),
    );
}

test "MQTT WebSocket transport allocation failure closes its stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);
    const server = try listener.accept(io);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        Transport.initWebSocket(
            failing.allocator(),
            websocket_runtime.testing.initDirectConnection(
                allocator,
                io,
                server,
                .server,
                .{},
            ),
        ),
    );
    var byte: [1]u8 = undefined;
    var buffers = [_][]u8{&byte};
    try std.testing.expectEqual(
        @as(usize, 0),
        try io.vtable.netRead(
            io.userdata,
            client.socket.handle,
            &buffers,
        ),
    );
}

fn readTcpPacket(
    allocator: std.mem.Allocator,
    tcp: *TcpTransport,
    max_packet_size: usize,
) Error!OwnedPacket {
    return readTcpPacketWithPolicy(
        .none,
        false,
        allocator,
        tcp,
        max_packet_size,
        {},
        {},
        0,
    );
}

fn readTcpPacketWithInactivityTimeout(
    allocator: std.mem.Allocator,
    tcp: *TcpTransport,
    max_packet_size: usize,
    timeout: std.Io.Clock.Duration,
) Error!OwnedPacket {
    std.debug.assert(timeout.raw.nanoseconds > 0);
    return readTcpPacketWithPolicy(
        .inactivity_timeout,
        false,
        allocator,
        tcp,
        max_packet_size,
        timeout,
        {},
        0,
    );
}

fn readTcpPacketWithDeadline(
    allocator: std.mem.Allocator,
    tcp: *TcpTransport,
    max_packet_size: usize,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedPacket {
    return readTcpPacketWithPolicy(
        .absolute_deadline,
        false,
        allocator,
        tcp,
        max_packet_size,
        deadline,
        {},
        0,
    );
}

const TcpReadPolicy = enum {
    none,
    inactivity_timeout,
    absolute_deadline,
    inactivity_observer,
};

fn TcpReadPolicyValue(comptime policy: TcpReadPolicy) type {
    return switch (policy) {
        .none => void,
        .inactivity_timeout => std.Io.Clock.Duration,
        .absolute_deadline => std.Io.Clock.Timestamp,
        .inactivity_observer => InactivityObserver,
    };
}

fn TcpReadDeadline(comptime policy: TcpReadPolicy) type {
    return switch (policy) {
        .inactivity_timeout, .absolute_deadline => std.Io.Clock.Timestamp,
        .none, .inactivity_observer => void,
    };
}

fn TcpCallerStorage(comptime enabled: bool) type {
    return if (enabled) []u8 else void;
}

noinline fn readTcpPacketWithPolicy(
    comptime policy: TcpReadPolicy,
    comptime has_caller_storage: bool,
    allocator: std.mem.Allocator,
    tcp: *TcpTransport,
    max_packet_size: usize,
    policy_value: TcpReadPolicyValue(policy),
    caller_storage: TcpCallerStorage(has_caller_storage),
    owned_prefix_len: usize,
) Error!OwnedPacket {
    var deadline: TcpReadDeadline(policy) = switch (policy) {
        .inactivity_timeout => inactivityDeadline(tcp.io, policy_value),
        .absolute_deadline => policy_value,
        .none, .inactivity_observer => {},
    };
    var parsed_fixed: ?mqtt.FixedHeader = null;

    while (tcp.packet == null) {
        const buffered = tcp.buffered();
        const frame = (try parsePacketFraming(buffered)) orelse {
            tcp.compactBuffered();
            std.debug.assert(tcp.input_end < tcp.input.len);
            tcp.input_end += try readTcpSome(
                policy == .inactivity_timeout or policy == .absolute_deadline,
                tcp,
                tcp.input[tcp.input_end..],
                deadline,
            );
            continue;
        };
        const packet_len = frame.packet_len;
        if (packet_len > max_packet_size) return error.PacketTooLarge;
        if (has_caller_storage) {
            const storage = caller_storage;
            // Terminal diagnostics can be retained after a decoder's local
            // allocation failure. Own their bytes before consuming read-ahead
            // so they never outlive a caller's temporary storage.
            if (frame.fixed.packet_type != .disconnect and packet_len <= storage.len and
                packet_len <= tcp.input.len)
            {
                if (packet_len > buffered.len) {
                    // Keep a caller-buffer-sized packet in connection-owned
                    // read-ahead until it is complete. A timeout can then
                    // return without retaining a pointer into the caller's
                    // temporary storage or allocating a resumable packet.
                    tcp.compactBuffered();
                    std.debug.assert(tcp.input_end < packet_len);
                    tcp.input_end += try readTcpSome(
                        policy == .inactivity_timeout or policy == .absolute_deadline,
                        tcp,
                        tcp.input[tcp.input_end..packet_len],
                        deadline,
                    );
                    continue;
                }
                const bytes = storage[0..packet_len];
                @memcpy(bytes, buffered[0..packet_len]);
                tcp.discardBuffered(packet_len);
                return .{
                    .bytes = bytes,
                    .fixed = frame.fixed,
                    .owns_bytes = false,
                    .traffic_recorded = tcp.takeRestoredCounted(),
                };
            }
        }
        const allocated = try allocatePacketBytes(
            allocator,
            packet_len,
            owned_prefix_len,
        );
        const packet = allocated.bytes;
        const copy_len = @min(packet_len, buffered.len);
        @memcpy(packet[0..copy_len], buffered[0..copy_len]);
        tcp.discardBuffered(copy_len);
        tcp.packet = packet;
        tcp.packet_prefix_len = allocated.prefix_len;
        tcp.packet_read = copy_len;
        parsed_fixed = frame.fixed;
        if (policy == .inactivity_timeout) {
            if (frame.fixed.remaining_len > keep_alive_reader.progress_threshold and
                copy_len < packet_len)
            {
                // The initial read may already have consumed part of a large
                // body. Preserve the pre-read-ahead policy: once its header
                // establishes a large packet, body progress starts a fresh
                // inactivity window.
                deadline = inactivityDeadline(tcp.io, policy_value);
            }
        } else if (policy == .inactivity_observer) {
            if (frame.fixed.remaining_len > keep_alive_reader.progress_threshold and
                copy_len < packet_len)
            {
                policy_value.renew();
            }
        }
    }

    const packet = tcp.packet.?;
    while (tcp.packet_read < packet.len) {
        if (policy == .inactivity_timeout) {
            if (packet.len - tcp.packet_read >
                keep_alive_reader.progress_threshold)
            {
                deadline = inactivityDeadline(tcp.io, policy_value);
            }
        } else if (policy == .inactivity_observer) {
            if (packet.len - tcp.packet_read >
                keep_alive_reader.progress_threshold)
            {
                policy_value.renew();
            }
        }
        const count = try readTcpSome(
            policy == .inactivity_timeout or policy == .absolute_deadline,
            tcp,
            packet[tcp.packet_read..],
            deadline,
        );
        tcp.packet_read += count;
    }

    tcp.packet = null;
    const packet_prefix_len = tcp.packet_prefix_len;
    tcp.packet_prefix_len = 0;
    tcp.packet_read = 0;
    errdefer freePacketBytes(allocator, packet, packet_prefix_len);
    return .{
        .bytes = packet,
        // A resumed large-packet read reconstructs this from its retained
        // header; the uninterrupted common path reuses the framing parse.
        .fixed = parsed_fixed orelse try mqtt.FixedHeader.parse(packet),
        .prefix_len = packet_prefix_len,
        .traffic_recorded = tcp.takeRestoredCounted(),
    };
}

noinline fn readTcpSome(
    comptime has_deadline: bool,
    tcp: *TcpTransport,
    buffer: []u8,
    deadline: if (has_deadline) std.Io.Clock.Timestamp else void,
) Error!usize {
    const count = if (has_deadline)
        try stream_io.readSomeWithDeadline(
            tcp.io,
            tcp.stream,
            buffer,
            deadline,
        )
    else blk: {
        var bufs = [_][]u8{buffer};
        break :blk try tcp.io.vtable.netRead(
            tcp.io.userdata,
            tcp.stream.socket.handle,
            &bufs,
        );
    };
    if (count == 0) return error.ConnectionClosed;
    return count;
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
    const packet_type = try mqtt.packetTypeFromFirstByte(header[0]);
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
        .fixed = .{
            .packet_type = packet_type,
            .flags = @truncate(header[0] & 0x0f),
            .remaining_len = decoded.value,
            .header_len = payload_start,
        },
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
        null,
        0,
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
        null,
        0,
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
        null,
        0,
    );
}

const WebSocketPacketReader = @import("transport/websocket_receive.zig").Reader(struct {
    pub const ErrorType = Error;
    pub const PacketType = OwnedPacket;
    pub const allocate = allocatePacketBytes;
    pub const free = freePacketBytes;
    pub const parse = parsePacketFraming;
    pub const discard = discardPacketPrefix;
    pub const fromInactivity = inactivityDeadline;
    pub const InactivityObserverType = InactivityObserver;
});
const readWebSocketPacketWithPolicy = WebSocketPacketReader.read;

const PacketFrame = struct {
    fixed: mqtt.FixedHeader,
    packet_len: usize,
};

fn parsePacketFraming(bytes: []const u8) Error!?PacketFrame {
    if (bytes.len == 0) return null;
    const packet_type = try mqtt.packetTypeFromFirstByte(bytes[0]);
    if (bytes.len < 2) return null;
    const max_remaining_length_bytes = @min(bytes.len - 1, 4);
    const decoded = mqtt.decodeRemainingLength(
        bytes[1 .. 1 + max_remaining_length_bytes],
    ) catch |err| switch (err) {
        error.BufferTooShort => return null,
        else => return err,
    };
    const header_len = 1 + decoded.len;
    const packet_len = std.math.add(
        usize,
        header_len,
        decoded.value,
    ) catch return error.PacketTooLarge;
    return .{
        .fixed = .{
            .packet_type = packet_type,
            .flags = @truncate(bytes[0] & 0x0f),
            .remaining_len = decoded.value,
            .header_len = header_len,
        },
        .packet_len = packet_len,
    };
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
                    break :blk inactivityDeadline(connection.io, timeout);
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
        ) Error!usize {
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
            return offset;
        }

        fn renewInactivityDeadline(self: *Self) void {
            const timeout = switch (self.policy) {
                .inactivity_timeout => |value| value,
                else => return,
            };
            self.deadline = inactivityDeadline(self.connection.io, timeout);
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

test "TLS record-boundary EOF is an MQTT connection close" {
    const FakeConnection = struct {
        io: std.Io,
        failure: Error,

        pub fn read(self: *@This(), _: []u8) Error!usize {
            return self.failure;
        }

        pub fn readWithDeadline(
            self: *@This(),
            _: []u8,
            _: std.Io.Clock.Timestamp,
        ) Error!usize {
            return self.failure;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var byte: [1]u8 = undefined;

    var eof = FakeConnection{
        .io = io,
        .failure = error.UnexpectedEof,
    };
    try std.testing.expectError(
        error.ConnectionClosed,
        StreamPacketReader.readSome(&eof, &byte, null),
    );

    var truncated = FakeConnection{
        .io = io,
        .failure = error.TruncatedRecord,
    };
    try std.testing.expectError(
        error.TruncatedRecord,
        StreamPacketReader.readSome(&truncated, &byte, null),
    );
}

test "packet framing waits for a complete MQTT remaining length" {
    try std.testing.expect((try parsePacketFraming(&.{})) == null);
    try std.testing.expect((try parsePacketFraming(&.{0x30})) == null);
    try std.testing.expect((try parsePacketFraming(&.{ 0x30, 0x80 })) == null);

    const ping = (try parsePacketFraming(&.{ 0xc0, 0x00 })).?;
    try std.testing.expectEqual(@as(usize, 2), ping.packet_len);
    try std.testing.expectEqual(mqtt.PacketType.pingreq, ping.fixed.packet_type);
    try std.testing.expectEqual(@as(u4, 0), ping.fixed.flags);
    try std.testing.expectEqual(@as(usize, 0), ping.fixed.remaining_len);
    try std.testing.expectEqual(@as(usize, 2), ping.fixed.header_len);

    const publish = (try parsePacketFraming(&.{ 0x3d, 0x82, 0x01 })).?;
    try std.testing.expectEqual(@as(usize, 133), publish.packet_len);
    try std.testing.expectEqual(mqtt.PacketType.publish, publish.fixed.packet_type);
    try std.testing.expectEqual(@as(u4, 0x0d), publish.fixed.flags);
    try std.testing.expectEqual(@as(usize, 130), publish.fixed.remaining_len);
    try std.testing.expectEqual(@as(usize, 3), publish.fixed.header_len);
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

test "packet length rejects reserved type before malformed length" {
    try std.testing.expectError(
        error.ReservedPacketType,
        parsePacketFraming(&.{ 0x00, 0x80, 0x80, 0x80, 0x80 }),
    );
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

    var wire_bytes: [1027]u8 = @splat(0x5a);
    wire_bytes[0] = 0x30;
    wire_bytes[1] = 0x80;
    wire_bytes[2] = 0x08;
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
    try std.testing.expectEqual(@as(usize, 1024), packet.fixed.remaining_len);
    try std.testing.expectEqual(@as(usize, 3), packet.fixed.header_len);
}

test "TCP packet receive resumes after a split initial header timeout" {
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
    var transport = Transport.initTcp(io, receiver);
    defer transport.close(allocator);

    try writeAll(io, sender, &.{0xc0});
    try std.testing.expectError(
        error.Timeout,
        transport.readPacketWithDeadline(
            allocator,
            mqtt.ping_packet_len,
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), transport.tcp.buffered().len);

    try writeAll(io, sender, &.{0x00});
    var packet = try transport.readPacketWithDeadline(
        allocator,
        mqtt.ping_packet_len,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, packet.bytes);
}

test "TCP externally managed inactivity renews for large packet progress" {
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
    var transport = Transport.initTcp(io, receiver);
    defer transport.close(allocator);

    var encoded: [1500]u8 = @splat(0x5a);
    encoded[0] = 0x30;
    const remaining_len = encoded.len - 3;
    encoded[1] = @as(u8, @truncate(remaining_len)) | 0x80;
    encoded[2] = @intCast(remaining_len >> 7);
    try writeAll(io, sender, &encoded);

    const Counter = struct {
        value: usize = 0,

        fn renew(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.value += 1;
        }
    };
    var counter: Counter = .{};
    var storage: [128]u8 = undefined;
    var packet = try transport
        .readPacketWithInactivityObserverIntoWithPrefix(
        allocator,
        encoded.len,
        .{ .context = &counter, .renew_fn = Counter.renew },
        &storage,
        32,
    );
    defer packet.deinit(allocator);
    try std.testing.expect(counter.value != 0);
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
}

test "TCP packet receive retains a coalesced following packet" {
    const allocator = std.testing.allocator;
    var tcp = TcpTransport{
        .io = undefined,
        .stream = undefined,
    };
    const coalesced = [4]u8{ 0xc0, 0x00, 0xc0, 0x00 };
    @memcpy(tcp.input[0..coalesced.len], &coalesced);
    tcp.input_end = 4;

    var first = try readTcpPacket(
        allocator,
        &tcp,
        mqtt.ping_packet_len,
    );
    defer first.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, first.bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, tcp.buffered());

    var second = try readTcpPacket(
        allocator,
        &tcp,
        mqtt.ping_packet_len,
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, second.bytes);
    try std.testing.expectEqual(@as(usize, 0), tcp.buffered().len);
}

test "TCP packet receive borrows caller storage for complete read-ahead packets" {
    const allocator = std.testing.allocator;
    var transport = Transport{ .tcp = .{
        .io = undefined,
        .stream = undefined,
    } };
    const encoded = [4]u8{ 0x40, 0x02, 0x00, 0x07 };
    @memcpy(transport.tcp.input[0..encoded.len], &encoded);
    transport.tcp.input_end = encoded.len;
    var storage: [4]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    var packet = try transport.readPacketInto(
        failing.allocator(),
        storage.len,
        &storage,
    );
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expectEqual(storage[0..].ptr, packet.bytes.ptr);
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
    try std.testing.expectEqual(@as(usize, 0), transport.tcp.buffered().len);
    packet.deinit(failing.allocator());
    try std.testing.expect(!failing.has_induced_failure);
}

test "TCP packet receive borrows an exact read-ahead-capacity packet" {
    const allocator = std.testing.allocator;
    var transport = Transport{ .tcp = .{
        .io = undefined,
        .stream = undefined,
    } };
    var encoded: [tcp_read_ahead_capacity]u8 = @splat(0x5a);
    encoded[0] = 0x30;
    const remaining_len = encoded.len - 3;
    encoded[1] = @as(u8, @truncate(remaining_len)) | 0x80;
    encoded[2] = @intCast(remaining_len >> 7);
    @memcpy(transport.tcp.input[0..], &encoded);
    transport.tcp.input_end = encoded.len;
    var storage: [tcp_read_ahead_capacity]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    var packet = try transport.readPacketInto(
        failing.allocator(),
        encoded.len,
        &storage,
    );
    defer packet.deinit(failing.allocator());
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
    try std.testing.expectEqual(
        @as(usize, 0),
        transport.tcp.buffered().len,
    );
}

test "TCP packet receive preserves an aligned prefix on owned fallback" {
    const allocator = std.testing.allocator;
    var transport = Transport{ .tcp = .{
        .io = undefined,
        .stream = undefined,
    } };
    var encoded: [131]u8 = @splat(0x5a);
    encoded[0] = 0x30;
    encoded[1] = 0x80;
    encoded[2] = 0x01;
    @memcpy(transport.tcp.input[0..encoded.len], &encoded);
    transport.tcp.input_end = encoded.len;
    var storage: [4]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );
    const prefix_len = 128;

    var packet = try transport.readPacketIntoWithPrefix(
        failing.allocator(),
        encoded.len,
        &storage,
        prefix_len,
    );
    defer packet.deinit(failing.allocator());

    const allocation = packet.prefixedAllocation().?;
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(
        @intFromPtr(allocation.ptr) + prefix_len,
        @intFromPtr(packet.bytes.ptr),
    );
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
    try std.testing.expectEqual(@as(usize, 0), transport.tcp.buffered().len);
}

test "TCP prefixed packet allocation survives timeout and resume" {
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
    var transport = Transport.initTcp(io, receiver);
    defer transport.close(allocator);

    var encoded: [131]u8 = @splat(0x5a);
    encoded[0] = 0x30;
    encoded[1] = 0x80;
    encoded[2] = 0x01;
    var storage: [4]u8 = undefined;
    const prefix_len = 128;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );

    try writeAll(io, sender, encoded[0..7]);
    try std.testing.expectError(
        error.Timeout,
        transport.readPacketWithInactivityTimeoutIntoWithPrefix(
            failing.allocator(),
            encoded.len,
            .{ .raw = .fromMilliseconds(20), .clock = .awake },
            &storage,
            prefix_len,
        ),
    );
    try std.testing.expectEqual(
        @as(u16, prefix_len),
        transport.tcp.packet_prefix_len,
    );
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);

    try writeAll(io, sender, encoded[7..]);
    var packet = try transport
        .readPacketWithInactivityTimeoutIntoWithPrefix(
        failing.allocator(),
        encoded.len,
        .{ .raw = .fromSeconds(1), .clock = .awake },
        &storage,
        prefix_len,
    );
    defer packet.deinit(failing.allocator());

    try std.testing.expect(packet.prefixedAllocation() != null);
    try std.testing.expectEqualSlices(u8, &encoded, packet.bytes);
    try std.testing.expect(!failing.has_induced_failure);
}

test "TCP packet receive resumes a fragmented caller-storage packet without allocation" {
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
    var transport = Transport.initTcp(io, receiver);
    defer transport.close(allocator);
    var storage: [4]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try writeAll(io, sender, &.{ 0x40, 0x02, 0x00 });
    try std.testing.expectError(
        error.Timeout,
        transport.readPacketWithInactivityTimeoutInto(
            failing.allocator(),
            storage.len,
            .{ .raw = .fromMilliseconds(20), .clock = .awake },
            &storage,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x02, 0x00 },
        transport.tcp.buffered(),
    );
    try std.testing.expect(!failing.has_induced_failure);

    try writeAll(io, sender, &.{0x07});
    var packet = try transport.readPacketWithInactivityTimeoutInto(
        failing.allocator(),
        storage.len,
        .{ .raw = .fromSeconds(1), .clock = .awake },
        &storage,
    );
    defer packet.deinit(failing.allocator());
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x02, 0x00, 0x07 },
        packet.bytes,
    );
    try std.testing.expectEqual(@as(usize, 0), transport.tcp.buffered().len);
    try std.testing.expect(!failing.has_induced_failure);
}

test "TCP packet allocation failure retains read-ahead bytes" {
    const allocator = std.testing.allocator;
    var transport = Transport{ .tcp = .{
        .io = undefined,
        .stream = undefined,
    } };
    const encoded = [2]u8{ 0xc0, 0x00 };
    @memcpy(transport.tcp.input[0..encoded.len], &encoded);
    transport.tcp.input_end = 2;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var insufficient_storage: [1]u8 = undefined;

    try std.testing.expectError(
        error.OutOfMemory,
        transport.readPacketInto(
            failing.allocator(),
            mqtt.ping_packet_len,
            &insufficient_storage,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xc0, 0x00 },
        transport.tcp.buffered(),
    );

    var packet = try transport.readPacket(
        allocator,
        mqtt.ping_packet_len,
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, packet.bytes);
    try std.testing.expectEqual(
        @as(usize, 0),
        transport.tcp.buffered().len,
    );
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

test {
    _ = @import("transport/read_interruption_tests.zig");
    _ = @import("transport/websocket_receive_tests.zig");
    _ = @import("transport/websocket_compression_handoff_tests.zig");
}

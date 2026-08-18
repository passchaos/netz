//! Blocking TLS 1.3 server connection for native MQTT listeners.
//!
//! The MQTT runtime consumes this type as an ordinary byte stream. TLS
//! handshake ownership, record framing, traffic-key sequencing, and orderly
//! shutdown stay here so the MQTT CONNECT/QoS state machine remains shared
//! with TCP and WebSocket transports.

const std = @import("std");
const record_stream = @import("record_stream.zig");
const server_handshake = @import("server_handshake.zig");

const net = std.Io.net;

pub const Error = server_handshake.Error ||
    record_stream.Error;

pub const Options = server_handshake.Options;

/// An established TLS 1.3 server-side byte stream.
///
/// `init` borrows the supplied stream on failure and owns it on success.
/// `deinit` sends close_notify when possible, closes the stream, wipes traffic
/// keys, and destroys the heap-stable connection object.
pub const Connection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    records: record_stream.Stream,
    peer_certificate_chain: ?server_handshake.PeerCertificateChain = null,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: Options,
    ) Error!*Connection {
        var keys = try server_handshake.perform(
            allocator,
            io,
            stream,
            options,
        );
        errdefer keys.deinit();

        const connection = try allocator.create(Connection);
        connection.* = .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .records = .init(keys.read, keys.write),
            .peer_certificate_chain = keys.peer_certificate_chain,
        };
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        if (!self.records.closed) {
            self.records.sendCloseNotify(self.io, self.stream) catch {};
        }
        self.records.deinit();
        if (self.peer_certificate_chain) |*chain| chain.deinit();
        self.stream.close(self.io);
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    /// Returns the owned peer chain after a successful authenticated
    /// handshake. Optional client authentication returns null for anonymous
    /// clients. The slices remain valid until `deinit`.
    pub fn peerCertificates(self: *const Connection) ?[]const []const u8 {
        const chain = self.peer_certificate_chain orelse return null;
        return chain.certificates;
    }

    /// Read decrypted application bytes with stream semantics.
    ///
    /// A TLS record may contain several MQTT packets or only part of one. Any
    /// plaintext not consumed by the caller is retained in the connection
    /// rather than forcing the MQTT layer to understand record boundaries.
    pub fn read(self: *Connection, out: []u8) Error!usize {
        return self.records.read(self.io, self.stream, out);
    }

    pub fn writeAll(self: *Connection, bytes: []const u8) Error!void {
        return self.records.writeAll(
            self.io,
            self.stream,
            bytes,
        );
    }
};

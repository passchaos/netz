//! Blocking TLS 1.3 server connection for application protocols.
//!
//! The MQTT runtime consumes this type as an ordinary byte stream. TLS
//! handshake ownership, record framing, traffic-key sequencing, and orderly
//! shutdown stay here so HTTP/WebSocket/MQTT state machines remain transport
//! independent.

const std = @import("std");
const vail = @import("vail");
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
    selected_alpn: ?[]u8 = null,
    cipher_suite: vail.tls.cipher_suite.Suite,
    exporter_master_secret: vail.tls.secret.Secret,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: Options,
    ) Error!*Connection {
        return initBefore(allocator, io, stream, options, null);
    }

    /// Complete the server TLS handshake under the earlier of the caller's
    /// absolute deadline and `options.handshake_timeout`.
    pub fn initWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*Connection {
        return initBefore(allocator, io, stream, options, deadline);
    }

    fn initBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: Options,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!*Connection {
        var keys = if (deadline) |absolute|
            try server_handshake.performWithDeadline(
                allocator,
                io,
                stream,
                options,
                absolute,
            )
        else
            try server_handshake.perform(
                allocator,
                io,
                stream,
                options,
            );
        errdefer keys.deinit();
        const selected_alpn = if (keys.selected_alpn) |protocol|
            try allocator.dupe(u8, protocol)
        else
            null;
        errdefer if (selected_alpn) |protocol| allocator.free(protocol);
        const connection = try allocator.create(Connection);
        connection.* = .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .records = .init(
                keys.read,
                keys.write,
                keys.read_traffic_secret,
                keys.write_traffic_secret,
            ),
            .peer_certificate_chain = keys.peer_certificate_chain,
            .selected_alpn = selected_alpn,
            .cipher_suite = keys.cipher_suite,
            .exporter_master_secret = keys.exporter_master_secret,
        };
        keys.read_traffic_secret = undefined;
        keys.write_traffic_secret = undefined;
        keys.exporter_master_secret = undefined;
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        if (self.records.shouldSendCloseNotify()) {
            self.records.sendCloseNotify(self.io, self.stream) catch {};
        }
        self.records.deinit();
        if (self.peer_certificate_chain) |*chain| chain.deinit();
        self.stream.close(self.io);
        const allocator = self.allocator;
        if (self.selected_alpn) |protocol| allocator.free(protocol);
        self.exporter_master_secret.deinit();
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

    /// Return the ALPN protocol selected during the TLS handshake. The slice
    /// is owned by this connection and remains valid until `deinit`.
    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        return self.selected_alpn;
    }

    /// Return the authenticated TLS 1.3 cipher suite selected for the client.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) vail.tls.cipher_suite.Suite {
        return self.cipher_suite;
    }

    /// Return the transcript/HKDF hash implied by the negotiated suite.
    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) vail.tls.secret.Hash {
        return self.cipher_suite.hash();
    }

    /// Export TLS 1.3 channel-bound keying material (RFC 8446 section 7.5).
    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try vail.tls.key_schedule.exportKeyingMaterialFor(
            self.exporter_master_secret,
            label,
            context,
            out,
        );
    }

    pub fn updateTrafficKeys(
        self: *Connection,
        request_peer_update: bool,
    ) Error!void {
        try self.records.updateTrafficKeys(
            self.io,
            self.stream,
            request_peer_update,
        );
    }

    pub fn keyUpdateCounts(
        self: *const Connection,
    ) record_stream.KeyUpdateCounts {
        return self.records.keyUpdateCounts();
    }

    /// Send an orderly TLS write-half close while retaining the receive side.
    pub fn sendCloseNotify(self: *Connection) Error!void {
        try self.records.sendCloseNotify(self.io, self.stream);
    }

    pub fn receivedCloseNotify(self: *const Connection) bool {
        return self.records.receivedCloseNotify();
    }

    /// Read decrypted application bytes with stream semantics.
    ///
    /// A TLS record may contain several MQTT packets or only part of one. Any
    /// plaintext not consumed by the caller is retained in the connection
    /// rather than forcing the MQTT layer to understand record boundaries.
    pub fn read(self: *Connection, out: []u8) Error!usize {
        return self.records.read(self.io, self.stream, out);
    }

    pub fn readWithDeadline(
        self: *Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return self.records.readWithDeadline(
            self.io,
            self.stream,
            out,
            deadline,
        );
    }

    pub fn writeAll(self: *Connection, bytes: []const u8) Error!void {
        return self.records.writeAll(
            self.io,
            self.stream,
            bytes,
        );
    }

    pub fn writeAllWithDeadline(
        self: *Connection,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return self.records.writeAllWithDeadline(
            self.io,
            self.stream,
            bytes,
            committed,
            deadline,
        );
    }

    pub fn finishPendingWrite(
        self: *Connection,
        committed: *usize,
    ) Error!void {
        return self.records.finishPendingWrite(
            self.io,
            self.stream,
            committed,
        );
    }

    /// Write a protocol header and borrowed payload without concatenating them
    /// in application memory. TLS record framing may still split at 16 KiB,
    /// while callers such as WebSocket preserve their two-slice API.
    pub fn writeAllParts(
        self: *Connection,
        header: []const u8,
        payload: []const u8,
    ) Error!void {
        try self.records.writeAllParts(
            self.io,
            self.stream,
            header,
            payload,
        );
    }

    pub fn writeAllSlices(
        self: *Connection,
        parts: []const []const u8,
    ) Error!void {
        try self.records.writeAllSlices(
            self.io,
            self.stream,
            parts,
        );
    }
};

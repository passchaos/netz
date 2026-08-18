//! Blocking TLS 1.3 server connection for native MQTT listeners.
//!
//! The MQTT runtime consumes this type as an ordinary byte stream. TLS
//! handshake ownership, record framing, traffic-key sequencing, and orderly
//! shutdown stay here so the MQTT CONNECT/QoS state machine remains shared
//! with TCP and WebSocket transports.

const std = @import("std");
const vail = @import("vail");
const record_io = @import("record_io.zig");
const server_handshake = @import("server_handshake.zig");

const net = std.Io.net;
const tls_record = vail.tls.record;

pub const Error = server_handshake.Error ||
    record_io.Error ||
    vail.tls.record.Error ||
    error{
        ConnectionClosed,
        UnexpectedTlsContent,
    };

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
    read_keys: tls_record.Keys,
    write_keys: tls_record.Keys,
    read_sequence: u64 = 0,
    write_sequence: u64 = 0,
    buffered_plaintext: [record_io.max_plaintext_len]u8 = undefined,
    buffered_start: usize = 0,
    buffered_end: usize = 0,
    closed: bool = false,

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
            .read_keys = keys.read,
            .write_keys = keys.write,
        };
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        if (!self.closed) self.sendCloseNotify() catch {};
        self.read_keys.deinit();
        self.write_keys.deinit();
        self.stream.close(self.io);
        const allocator = self.allocator;
        std.crypto.secureZero(u8, &self.buffered_plaintext);
        self.* = undefined;
        allocator.destroy(self);
    }

    /// Read decrypted application bytes with stream semantics.
    ///
    /// A TLS record may contain several MQTT packets or only part of one. Any
    /// plaintext not consumed by the caller is retained in the connection
    /// rather than forcing the MQTT layer to understand record boundaries.
    pub fn read(self: *Connection, out: []u8) Error!usize {
        if (out.len == 0) return 0;
        while (true) {
            if (self.buffered_start != self.buffered_end) {
                const count = @min(
                    out.len,
                    self.buffered_end - self.buffered_start,
                );
                @memcpy(
                    out[0..count],
                    self.buffered_plaintext[self.buffered_start .. self.buffered_start + count],
                );
                self.buffered_start += count;
                if (self.buffered_start == self.buffered_end) {
                    self.buffered_start = 0;
                    self.buffered_end = 0;
                }
                return count;
            }
            if (self.closed) return error.ConnectionClosed;

            var encoded: [record_io.max_record_len]u8 = undefined;
            const record_bytes = try record_io.readRecord(
                self.io,
                self.stream,
                &encoded,
            );
            var opened_storage: [
                record_io.max_plaintext_len + 1
            ]u8 = undefined;
            const opened = try self.read_keys.open(
                self.read_sequence,
                record_bytes,
                &opened_storage,
            );
            self.read_sequence = try record_io.nextSequence(
                self.read_sequence,
            );
            switch (opened.content_type) {
                tls_record.content_type_application_data => {
                    // Empty application records are valid padding/noise and
                    // must not be exposed as byte-stream EOF.
                    if (opened.len == 0) continue;
                    const count = @min(out.len, opened.len);
                    @memcpy(out[0..count], opened_storage[0..count]);
                    if (count != opened.len) {
                        const remaining = opened.len - count;
                        @memcpy(
                            self.buffered_plaintext[0..remaining],
                            opened_storage[count..opened.len],
                        );
                        self.buffered_end = remaining;
                    }
                    return count;
                },
                tls_record.content_type_alert => {
                    self.closed = true;
                    return error.ConnectionClosed;
                },
                // KeyUpdate and other post-handshake messages require a key
                // epoch transition; rejecting them is safer than continuing
                // with stale traffic keys.
                else => return error.UnexpectedTlsContent,
            }
        }
    }

    pub fn writeAll(self: *Connection, bytes: []const u8) Error!void {
        if (self.closed) return error.ConnectionClosed;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const chunk_len = @min(
                record_io.max_plaintext_len,
                bytes.len - offset,
            );
            try self.writeRecord(
                tls_record.content_type_application_data,
                bytes[offset .. offset + chunk_len],
            );
            offset += chunk_len;
        }
    }

    fn writeRecord(
        self: *Connection,
        content_type: u8,
        plaintext: []const u8,
    ) Error!void {
        var encoded: [record_io.max_record_len]u8 = undefined;
        const len = try self.write_keys.seal(
            self.write_sequence,
            content_type,
            plaintext,
            &encoded,
        );
        self.write_sequence = try record_io.nextSequence(
            self.write_sequence,
        );
        try record_io.writeAll(
            self.io,
            self.stream,
            encoded[0..len],
        );
    }

    fn sendCloseNotify(self: *Connection) Error!void {
        try self.writeRecord(
            tls_record.content_type_alert,
            &.{ 1, 0 },
        );
        self.closed = true;
    }
};

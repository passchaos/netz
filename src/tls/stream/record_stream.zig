//! Established TLS 1.3 application-record byte stream.
//!
//! Client and server handshakes produce opposite traffic-key directions, but
//! application record sequencing, byte-stream buffering, fragmentation,
//! alerts, and close_notify are identical. This state deliberately owns only
//! traffic keys and plaintext buffers; socket lifetime remains with the role-
//! specific connection wrapper.

const std = @import("std");
const vail = @import("vail");
const record_io = @import("record_io.zig");

const net = std.Io.net;
const tls_record = vail.tls.record;

pub const Error = record_io.Error || tls_record.Error || error{
    ConnectionClosed,
    UnexpectedTlsContent,
};

pub const Stream = struct {
    read_keys: tls_record.Keys,
    write_keys: tls_record.Keys,
    read_sequence: u64 = 0,
    write_sequence: u64 = 0,
    buffered_plaintext: [record_io.max_plaintext_len]u8 = undefined,
    buffered_start: usize = 0,
    buffered_end: usize = 0,
    closed: bool = false,

    pub fn init(
        read_keys: tls_record.Keys,
        write_keys: tls_record.Keys,
    ) Stream {
        return .{
            .read_keys = read_keys,
            .write_keys = write_keys,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.read_keys.deinit();
        self.write_keys.deinit();
        std.crypto.secureZero(u8, &self.buffered_plaintext);
        self.* = undefined;
    }

    pub fn read(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        out: []u8,
    ) Error!usize {
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
                io,
                stream,
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
                    // Empty records are valid TLS padding/noise and are not
                    // byte-stream EOF.
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
                // KeyUpdate needs a new traffic-secret epoch. Rejecting it is
                // safer than continuing under stale keys.
                else => return error.UnexpectedTlsContent,
            }
        }
    }

    pub fn writeAll(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        bytes: []const u8,
    ) Error!void {
        if (self.closed) return error.ConnectionClosed;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const chunk_len = @min(
                record_io.max_plaintext_len,
                bytes.len - offset,
            );
            try self.writeRecord(
                io,
                stream,
                tls_record.content_type_application_data,
                bytes[offset .. offset + chunk_len],
            );
            offset += chunk_len;
        }
    }

    /// Write two logical slices while filling each TLS record before starting
    /// the next. WebSocket headers therefore share a record/network write with
    /// the first payload bytes instead of paying a tiny standalone record.
    pub fn writeAllParts(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        if (self.closed) return error.ConnectionClosed;
        var first_offset: usize = 0;
        var second_offset: usize = 0;
        var plaintext: [record_io.max_plaintext_len]u8 = undefined;
        while (first_offset < first.len or second_offset < second.len) {
            var len: usize = 0;
            const first_count = @min(
                plaintext.len,
                first.len - first_offset,
            );
            @memcpy(
                plaintext[0..first_count],
                first[first_offset..][0..first_count],
            );
            first_offset += first_count;
            len += first_count;

            const second_count = @min(
                plaintext.len - len,
                second.len - second_offset,
            );
            @memcpy(
                plaintext[len..][0..second_count],
                second[second_offset..][0..second_count],
            );
            second_offset += second_count;
            len += second_count;
            try self.writeRecord(
                io,
                stream,
                tls_record.content_type_application_data,
                plaintext[0..len],
            );
        }
    }

    /// Write an arbitrary sequence of borrowed slices as one TLS plaintext
    /// stream without requiring the protocol layer to concatenate them.
    pub fn writeAllSlices(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        parts: []const []const u8,
    ) Error!void {
        if (self.closed) return error.ConnectionClosed;
        var part_index: usize = 0;
        var part_offset: usize = 0;
        var plaintext: [record_io.max_plaintext_len]u8 = undefined;
        while (true) {
            var len: usize = 0;
            while (part_index < parts.len and len < plaintext.len) {
                const part = parts[part_index];
                if (part_offset == part.len) {
                    part_index += 1;
                    part_offset = 0;
                    continue;
                }
                const count = @min(
                    plaintext.len - len,
                    part.len - part_offset,
                );
                @memcpy(plaintext[len..][0..count], part[part_offset..][0..count]);
                len += count;
                part_offset += count;
                if (part_offset == part.len) {
                    part_index += 1;
                    part_offset = 0;
                }
            }
            if (len == 0) return;
            try self.writeRecord(
                io,
                stream,
                tls_record.content_type_application_data,
                plaintext[0..len],
            );
        }
    }

    pub fn sendCloseNotify(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
    ) Error!void {
        try self.writeRecord(
            io,
            stream,
            tls_record.content_type_alert,
            &.{ 1, 0 },
        );
        self.closed = true;
    }

    fn writeRecord(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
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
        try record_io.writeAll(io, stream, encoded[0..len]);
    }
};

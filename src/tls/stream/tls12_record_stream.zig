//! Compact established TLS 1.2 byte stream.
//!
//! Handshake-only state is discarded before this object is created. The
//! stream retains only directional AEAD state and bounded I/O buffers, so
//! enabling TLS 1.2 does not keep both protocol handshakes resident for the
//! life of a connection.

const std = @import("std");
const vail = @import("vail");
const record_io = @import("record_io.zig");
const io_interruption = @import("../../internal/io_interruption.zig");
const write_retry = @import("write_retry.zig");

const net = std.Io.net;
const tls12 = vail.tls.tls12;

pub const Error = record_io.Error || tls12.Error || vail.tls.alert.Error || error{
    ConnectionClosed,
    PeerTlsAlert,
    UnexpectedTlsContent,
    WriteInProgress,
};

pub const Stream = struct {
    read_traffic: tls12.TrafficState,
    write_traffic: tls12.TrafficState,
    record_reader: record_io.Reader = .{},
    /// Shared ciphertext/plaintext storage. Plaintext is drained before the
    /// next record read, matching the TLS 1.3 stream's single-buffer design.
    buffered_plaintext: [record_io.max_record_len]u8 = undefined,
    buffered_start: usize = 0,
    buffered_end: usize = 0,
    peer_close_notify_received: bool = false,
    peer_eof_without_notify: bool = false,
    close_notify_sent: bool = false,
    failed: bool = false,
    pending_write: [record_io.max_record_len]u8 = undefined,
    pending_write_len: usize = 0,
    pending_write_offset: usize = 0,
    pending_plaintext_len: usize = 0,
    pending_plaintext_fingerprint: write_retry.Fingerprint = .{},
    write_mutex: std.Io.Mutex = .init,

    pub fn init(
        read_traffic: tls12.TrafficState,
        write_traffic: tls12.TrafficState,
    ) Stream {
        return .{
            .read_traffic = read_traffic,
            .write_traffic = write_traffic,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.read_traffic.deinit();
        self.write_traffic.deinit();
        std.crypto.secureZero(u8, &self.buffered_plaintext);
        std.crypto.secureZero(u8, &self.pending_write);
        self.pending_plaintext_fingerprint.clear();
        self.* = undefined;
    }

    pub fn read(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        out: []u8,
    ) Error!usize {
        return self.readInternal(io, stream, out, null);
    }

    /// Local timeout, cancellation and executor admission errors preserve
    /// partial ciphertext. Retry without advancing the record sequence.
    pub fn readWithDeadline(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return self.readInternal(io, stream, out, deadline);
    }

    fn readInternal(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!usize {
        if (out.len == 0) return 0;
        while (true) {
            if (self.buffered_start != self.buffered_end) {
                const count = @min(out.len, self.buffered_end - self.buffered_start);
                @memcpy(
                    out[0..count],
                    self.buffered_plaintext[self.buffered_start..][0..count],
                );
                self.buffered_start += count;
                if (self.buffered_start == self.buffered_end) {
                    self.buffered_start = 0;
                    self.buffered_end = 0;
                }
                return count;
            }
            if (self.peer_close_notify_received) return 0;
            if (self.peer_eof_without_notify) return error.UnexpectedEof;
            if (self.failed) return error.ConnectionClosed;

            const encoded = (if (deadline) |absolute|
                self.record_reader.readWithDeadline(
                    io,
                    stream,
                    &self.buffered_plaintext,
                    absolute,
                )
            else
                self.record_reader.read(io, stream, &self.buffered_plaintext)) catch |err| {
                if (err == error.UnexpectedEof) {
                    self.peer_eof_without_notify = true;
                } else if (!io_interruption.retryable(err)) {
                    self.failed = true;
                }
                return err;
            };
            const old_cancel_protection = io.swapCancelProtection(.blocked);
            defer _ = io.swapCancelProtection(old_cancel_protection);
            var opened_storage: [tls12.max_plaintext_len]u8 = undefined;
            const opened = self.read_traffic.open(encoded, &opened_storage) catch |err| {
                self.failed = true;
                return err;
            };
            const plaintext = opened_storage[0..opened.len];
            switch (opened.content_type) {
                23 => {
                    if (plaintext.len == 0) continue;
                    const count = @min(out.len, plaintext.len);
                    @memcpy(out[0..count], plaintext[0..count]);
                    if (count != plaintext.len) {
                        const remaining = plaintext.len - count;
                        @memcpy(
                            self.buffered_plaintext[0..remaining],
                            plaintext[count..],
                        );
                        self.buffered_end = remaining;
                    }
                    return count;
                },
                21 => {
                    const received = vail.tls.alert.parse(plaintext) catch |err| {
                        self.failed = true;
                        return err;
                    };
                    if (received.isCloseNotify()) {
                        self.peer_close_notify_received = true;
                        return 0;
                    }
                    self.failed = true;
                    return error.PeerTlsAlert;
                },
                // Renegotiation is intentionally unsupported. A new
                // handshake on established keys cannot enter application
                // protocol state.
                else => {
                    self.failed = true;
                    return error.UnexpectedTlsContent;
                },
            }
        }
    }

    pub fn writeAll(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        bytes: []const u8,
    ) Error!void {
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        try self.requireWritable();
        var offset: usize = 0;
        while (offset < bytes.len) {
            const progress = try self.beginPendingWrite(bytes[offset..]);
            record_io.writeAll(
                io,
                stream,
                self.pending_write[0..self.pending_write_len],
            ) catch |err| {
                self.failed = true;
                return err;
            };
            offset += progress;
            self.clearPendingWrite();
        }
    }

    pub fn writeAllParts(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return self.writeAllSlices(io, stream, &.{ first, second });
    }

    pub fn writeAllSlices(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        parts: []const []const u8,
    ) Error!void {
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        try self.requireWritable();
        var part_index: usize = 0;
        var part_offset: usize = 0;
        var plaintext: [tls12.max_plaintext_len]u8 = undefined;
        while (true) {
            var len: usize = 0;
            while (part_index < parts.len and len < plaintext.len) {
                const part = parts[part_index];
                if (part_offset == part.len) {
                    part_index += 1;
                    part_offset = 0;
                    continue;
                }
                const count = @min(plaintext.len - len, part.len - part_offset);
                @memcpy(plaintext[len..][0..count], part[part_offset..][0..count]);
                len += count;
                part_offset += count;
            }
            if (len == 0) return;
            const consumed = try self.beginPendingWrite(plaintext[0..len]);
            if (consumed != len) return error.ConnectionClosed;
            record_io.writeAll(
                io,
                stream,
                self.pending_write[0..self.pending_write_len],
            ) catch |err| {
                self.failed = true;
                return err;
            };
            self.clearPendingWrite();
        }
    }

    /// Count only complete plaintext records and retain partial ciphertext
    /// across timeout, cancellation and executor admission failure. Retry
    /// with the uncommitted suffix of the original bytes.
    /// The pending-record prefix must be identical, but may move to another
    /// address or gain unaccepted tail bytes. A mismatch returns WriteInProgress
    /// without writing or changing the pending record.
    pub fn writeAllWithDeadline(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        committed.* = 0;
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        try self.requireWritableAllowPending();
        if (self.pending_write_len != 0) {
            try self.pending_plaintext_fingerprint.validate(self.pending_plaintext_len, bytes);
            try self.finishPendingWriteWithDeadline(io, stream, committed, deadline);
        }
        while (committed.* < bytes.len) {
            const plaintext = bytes[committed.*..];
            const consumed = try self.beginPendingWrite(plaintext);
            self.finishPendingWriteWithDeadline(io, stream, committed, deadline) catch |err| {
                self.pending_plaintext_fingerprint.capture(plaintext[0..consumed]);
                return err;
            };
        }
    }

    pub fn finishPendingWrite(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        committed: *usize,
    ) Error!void {
        committed.* = 0;
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        if (self.failed or self.close_notify_sent) return error.ConnectionClosed;
        if (self.pending_write_len == 0) return;
        record_io.writeAll(
            io,
            stream,
            self.pending_write[self.pending_write_offset..self.pending_write_len],
        ) catch |err| {
            self.failed = true;
            return err;
        };
        committed.* += self.pending_plaintext_len;
        self.clearPendingWrite();
    }

    fn finishPendingWriteWithDeadline(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        record_io.writeAllWithDeadline(
            io,
            stream,
            self.pending_write[0..self.pending_write_len],
            &self.pending_write_offset,
            deadline,
        ) catch |err| {
            if (!io_interruption.retryable(err)) self.failed = true;
            return err;
        };
        committed.* += self.pending_plaintext_len;
        self.clearPendingWrite();
    }

    fn beginPendingWrite(self: *Stream, plaintext: []const u8) Error!usize {
        const progress = try self.write_traffic.sealFragment(
            23,
            plaintext,
            tls12.max_plaintext_len,
            &self.pending_write,
        );
        self.pending_write_len = progress.output_written;
        self.pending_write_offset = 0;
        self.pending_plaintext_len = progress.plaintext_consumed;
        return progress.plaintext_consumed;
    }

    fn clearPendingWrite(self: *Stream) void {
        self.pending_write_len = 0;
        self.pending_write_offset = 0;
        self.pending_plaintext_len = 0;
        self.pending_plaintext_fingerprint.clear();
    }

    fn requireWritable(self: *const Stream) Error!void {
        try self.requireWritableAllowPending();
        if (self.pending_write_len != 0) return error.WriteInProgress;
    }

    fn requireWritableAllowPending(self: *const Stream) Error!void {
        if (self.failed or self.close_notify_sent) return error.ConnectionClosed;
    }

    pub fn sendCloseNotify(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
    ) Error!void {
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        try self.requireWritable();
        const payload = vail.tls.alert.closeNotify().toBytes();
        const len = try self.write_traffic.seal(21, &payload, &self.pending_write);
        self.close_notify_sent = true;
        record_io.writeAll(io, stream, self.pending_write[0..len]) catch |err| {
            self.failed = true;
            return err;
        };
    }

    pub fn receivedCloseNotify(self: *const Stream) bool {
        return self.peer_close_notify_received;
    }

    pub fn shouldSendCloseNotify(self: *const Stream) bool {
        return !self.close_notify_sent and !self.failed;
    }

    pub fn isReusableBoundary(self: *const Stream) bool {
        return self.buffered_start == self.buffered_end and
            !self.peer_close_notify_received and
            !self.peer_eof_without_notify and
            !self.close_notify_sent and
            !self.failed and
            self.pending_write_len == 0;
    }
};

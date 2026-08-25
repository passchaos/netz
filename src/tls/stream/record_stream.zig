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

pub const Error = record_io.Error || tls_record.Error ||
    vail.tls.secret.Error || error{
    ConnectionClosed,
    InvalidKeyUpdate,
    KeyUpdateLimitExceeded,
    KeyUpdateRequestPending,
    UnexpectedTlsContent,
};

const handshake_type_key_update: u8 = 24;
const key_update_message_len: usize = 5;
/// Bound consecutive post-handshake messages before application progress. A
/// valid peer never needs an unbounded KeyUpdate burst, while each accepted
/// request otherwise forces fresh HKDF and AEAD setup.
pub const max_consecutive_peer_key_updates: usize = 32;

pub const KeyUpdateCounts = struct {
    sent: u64,
    received: u64,
    awaiting_peer_response: bool,
};

pub const Stream = struct {
    read_keys: tls_record.Keys,
    write_keys: tls_record.Keys,
    read_traffic_secret: vail.tls.secret.Secret,
    write_traffic_secret: vail.tls.secret.Secret,
    read_sequence: u64 = 0,
    write_sequence: u64 = 0,
    buffered_plaintext: [record_io.max_plaintext_len]u8 = undefined,
    buffered_start: usize = 0,
    buffered_end: usize = 0,
    post_handshake: [key_update_message_len]u8 = undefined,
    post_handshake_len: usize = 0,
    consecutive_peer_key_updates: usize = 0,
    // These counters can be inspected by an application thread while its sole
    // reader processes a peer update, hence atomic loads/increments.
    key_updates_sent: std.atomic.Value(u64) = .init(0),
    key_updates_received: std.atomic.Value(u64) = .init(0),
    awaiting_peer_key_update: std.atomic.Value(bool) = .init(false),
    // The reader marks a response pending before acquiring the write lock. A
    // concurrent application writer then emits the response first, preserving
    // RFC 8446's ordering without deadlocking on an external protocol mutex.
    peer_update_response_pending: std.atomic.Value(bool) = .init(false),
    write_mutex: std.Io.Mutex = .init,
    closed: bool = false,

    pub fn init(
        read_keys: tls_record.Keys,
        write_keys: tls_record.Keys,
        read_traffic_secret: vail.tls.secret.Secret,
        write_traffic_secret: vail.tls.secret.Secret,
    ) Stream {
        return .{
            .read_keys = read_keys,
            .write_keys = write_keys,
            .read_traffic_secret = read_traffic_secret,
            .write_traffic_secret = write_traffic_secret,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.read_keys.deinit();
        self.write_keys.deinit();
        self.read_traffic_secret.deinit();
        self.write_traffic_secret.deinit();
        std.crypto.secureZero(u8, &self.buffered_plaintext);
        std.crypto.secureZero(u8, &self.post_handshake);
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
            const record_bytes = if (deadline) |value|
                try record_io.readRecordWithDeadline(
                    io,
                    stream,
                    &encoded,
                    value,
                )
            else
                try record_io.readRecord(io, stream, &encoded);
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
                    if (self.post_handshake_len != 0) {
                        return error.InvalidKeyUpdate;
                    }
                    // Empty records are valid TLS padding/noise and are not
                    // byte-stream EOF.
                    if (opened.len == 0) continue;
                    self.consecutive_peer_key_updates = 0;
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
                tls_record.content_type_handshake => {
                    if (opened.len == 0) return error.InvalidKeyUpdate;
                    try self.consumePostHandshake(
                        io,
                        stream,
                        opened_storage[0..opened.len],
                    );
                    continue;
                },
                else => return error.UnexpectedTlsContent,
            }
        }
    }

    fn consumePostHandshake(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        bytes: []const u8,
    ) Error!void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = @min(
                key_update_message_len - self.post_handshake_len,
                bytes.len - offset,
            );
            @memcpy(
                self.post_handshake[self.post_handshake_len..][0..count],
                bytes[offset..][0..count],
            );
            self.post_handshake_len += count;
            offset += count;

            if (self.post_handshake_len >= 4 and
                (self.post_handshake[0] != handshake_type_key_update or
                    !std.mem.eql(
                        u8,
                        self.post_handshake[1..4],
                        &.{ 0, 0, 1 },
                    )))
            {
                return error.InvalidKeyUpdate;
            }
            if (self.post_handshake_len != key_update_message_len) continue;

            const request_peer_update = switch (self.post_handshake[4]) {
                0 => false,
                1 => true,
                else => return error.InvalidKeyUpdate,
            };
            // A sender changes its write epoch immediately after this message,
            // so bytes following it cannot legitimately share the same record.
            if (offset != bytes.len) return error.InvalidKeyUpdate;
            self.post_handshake_len = 0;
            if (self.consecutive_peer_key_updates ==
                max_consecutive_peer_key_updates)
            {
                return error.KeyUpdateLimitExceeded;
            }
            self.consecutive_peer_key_updates += 1;
            try self.rotateReadKeys();
            _ = self.key_updates_received.fetchAdd(1, .monotonic);
            self.awaiting_peer_key_update.store(false, .release);

            if (request_peer_update) {
                self.peer_update_response_pending.store(true, .release);
                self.write_mutex.lockUncancelable(io);
                defer self.write_mutex.unlock(io);
                try self.respondToPeerUpdateUnlocked(io, stream);
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
        if (self.closed) return error.ConnectionClosed;
        try self.respondToPeerUpdateUnlocked(io, stream);
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
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        if (self.closed) return error.ConnectionClosed;
        try self.respondToPeerUpdateUnlocked(io, stream);
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
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        if (self.closed) return error.ConnectionClosed;
        try self.respondToPeerUpdateUnlocked(io, stream);
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
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        try self.respondToPeerUpdateUnlocked(io, stream);
        try self.writeRecord(
            io,
            stream,
            tls_record.content_type_alert,
            &.{ 1, 0 },
        );
        self.closed = true;
    }

    /// Send a TLS 1.3 KeyUpdate under the current write epoch, then rotate the
    /// write secret and reset its record sequence number as required by RFC
    /// 8446 section 7.2. When requested, the peer responds before its next
    /// application record; inbound handling performs that response
    /// automatically without creating a protocol-layer control frame.
    pub fn updateTrafficKeys(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        request_peer_update: bool,
    ) Error!void {
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        if (self.closed) return error.ConnectionClosed;
        if (request_peer_update and
            self.awaiting_peer_key_update.cmpxchgStrong(
                false,
                true,
                .acq_rel,
                .acquire,
            ) != null)
        {
            return error.KeyUpdateRequestPending;
        }
        errdefer if (request_peer_update) {
            self.awaiting_peer_key_update.store(false, .release);
        };
        try self.respondToPeerUpdateUnlocked(io, stream);
        try self.sendKeyUpdateUnlocked(
            io,
            stream,
            request_peer_update,
        );
    }

    fn respondToPeerUpdateUnlocked(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
    ) Error!void {
        if (!self.peer_update_response_pending.load(.acquire)) return;
        try self.sendKeyUpdateUnlocked(io, stream, false);
        self.peer_update_response_pending.store(false, .release);
    }

    pub fn keyUpdateCounts(self: *const Stream) KeyUpdateCounts {
        return .{
            .sent = self.key_updates_sent.load(.monotonic),
            .received = self.key_updates_received.load(.monotonic),
            .awaiting_peer_response = self.awaiting_peer_key_update.load(.acquire),
        };
    }

    fn sendKeyUpdateUnlocked(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        request_peer_update: bool,
    ) Error!void {
        if (self.write_sequence == std.math.maxInt(u64)) {
            return error.SequenceOverflow;
        }
        var next_secret = try vail.tls.key_schedule.nextTrafficSecretFor(
            self.write_traffic_secret,
        );
        errdefer next_secret.deinit();
        var next_keys = try tls_record.Keys.derive(
            self.write_keys.suite,
            next_secret,
        );
        errdefer next_keys.deinit();
        const message = [_]u8{
            handshake_type_key_update,
            0,
            0,
            1,
            @intFromBool(request_peer_update),
        };
        try self.writeRecord(
            io,
            stream,
            tls_record.content_type_handshake,
            &message,
        );
        self.write_keys.deinit();
        self.write_traffic_secret.deinit();
        self.write_keys = next_keys;
        self.write_traffic_secret = next_secret;
        self.write_sequence = 0;
        _ = self.key_updates_sent.fetchAdd(1, .monotonic);
    }

    fn rotateReadKeys(self: *Stream) Error!void {
        var next_secret = try vail.tls.key_schedule.nextTrafficSecretFor(
            self.read_traffic_secret,
        );
        errdefer next_secret.deinit();
        var next_keys = try tls_record.Keys.derive(
            self.read_keys.suite,
            next_secret,
        );
        errdefer next_keys.deinit();
        self.read_keys.deinit();
        self.read_traffic_secret.deinit();
        self.read_keys = next_keys;
        self.read_traffic_secret = next_secret;
        self.read_sequence = 0;
    }

    fn writeRecord(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        content_type: u8,
        plaintext: []const u8,
    ) Error!void {
        const next_sequence = try record_io.nextSequence(
            self.write_sequence,
        );
        var encoded: [record_io.max_record_len]u8 = undefined;
        const len = try self.write_keys.seal(
            self.write_sequence,
            content_type,
            plaintext,
            &encoded,
        );
        // Consume the nonce before attempting socket I/O. A partial write is
        // fatal to framing; retaining the old counter would invite nonce reuse
        // if a caller incorrectly attempted to recover the connection.
        self.write_sequence = next_sequence;
        try record_io.writeAll(io, stream, encoded[0..len]);
    }
};

test "TLS record stream reassembles and bounds peer KeyUpdate messages" {
    const suite = vail.tls.cipher_suite.Suite.aes_256_gcm_sha384;
    var read_secret = try vail.tls.secret.Secret.init(
        suite.hash(),
        &([_]u8{0x41} ** 48),
    );
    defer read_secret.deinit();
    var write_secret = try vail.tls.secret.Secret.init(
        suite.hash(),
        &([_]u8{0x52} ** 48),
    );
    defer write_secret.deinit();
    var records = Stream.init(
        try tls_record.Keys.derive(suite, read_secret),
        try tls_record.Keys.derive(suite, write_secret),
        read_secret,
        write_secret,
    );
    defer records.deinit();

    // Fragmentation may cross arbitrary record boundaries. No socket is used
    // because update_not_requested must not emit a reciprocal record.
    try records.consumePostHandshake(
        undefined,
        undefined,
        &.{ handshake_type_key_update, 0 },
    );
    try std.testing.expectEqual(@as(u64, 0), records.keyUpdateCounts().received);
    try records.consumePostHandshake(undefined, undefined, &.{ 0, 1, 0 });
    try std.testing.expectEqual(@as(u64, 1), records.keyUpdateCounts().received);
    try std.testing.expectEqual(@as(u64, 0), records.read_sequence);
    try std.testing.expectEqual(@as(usize, 0), records.post_handshake_len);

    const update = [_]u8{ handshake_type_key_update, 0, 0, 1, 0 };
    for (1..max_consecutive_peer_key_updates) |_| {
        try records.consumePostHandshake(undefined, undefined, &update);
    }
    try std.testing.expectError(
        error.KeyUpdateLimitExceeded,
        records.consumePostHandshake(undefined, undefined, &update),
    );
}

test "TLS record stream rejects malformed KeyUpdate framing" {
    const suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
    const bytes = [_]u8{0x63} ** 32;
    var traffic_secret = try vail.tls.secret.Secret.init(suite.hash(), &bytes);
    defer traffic_secret.deinit();
    var records = Stream.init(
        try tls_record.Keys.derive(suite, traffic_secret),
        try tls_record.Keys.derive(suite, traffic_secret),
        traffic_secret,
        traffic_secret,
    );
    defer records.deinit();

    try std.testing.expectError(
        error.InvalidKeyUpdate,
        records.consumePostHandshake(
            undefined,
            undefined,
            &.{ handshake_type_key_update, 0, 0, 2, 0 },
        ),
    );
}

//! Established TLS 1.3 application-record byte stream.
//!
//! Client and server handshakes produce opposite traffic-key directions, but
//! application record sequencing, byte-stream buffering, fragmentation,
//! alerts, and close_notify are identical. This state deliberately owns only
//! traffic keys and plaintext buffers; socket lifetime remains with the role-
//! specific connection wrapper.

const std = @import("std");
const key_update_write = @import("key_update/write.zig");
const vail = @import("vail");
const record_io = @import("record_io.zig");
const io_interruption = @import("../../internal/io_interruption.zig");
const write_retry = @import("write_retry.zig");

const net = std.Io.net;
pub const tls_record = vail.tls.record;

pub const Error = std.mem.Allocator.Error || record_io.Error || tls_record.Error ||
    vail.tls.secret.Error || error{
    ConnectionClosed,
    InvalidTlsAlert,
    InvalidKeyUpdate,
    InvalidNewSessionTicket,
    KeyUpdateLimitExceeded,
    KeyUpdateRequestPending,
    PeerTlsAlert,
    UnexpectedTlsContent,
    WriteInProgress,
};

pub const handshake_type_key_update: u8 = 24;
pub const handshake_type_new_session_ticket: u8 = 4;
const key_update_message_len: usize = 5;
const max_new_session_ticket_body_len: usize = 65_548;
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
    record_reader: record_io.Reader = .{},
    /// Shared ciphertext/plaintext storage. Plaintext is always drained before
    /// another encrypted record is read, so one max-record buffer is enough
    /// for both phases and keeps resumable reads from doubling connection size.
    buffered_plaintext: [record_io.max_record_len]u8 = undefined,
    buffered_start: usize = 0,
    buffered_end: usize = 0,
    post_handshake: [key_update_message_len]u8 = undefined,
    post_handshake_len: usize = 0,
    post_handshake_body_remaining: usize = 0,
    accept_new_session_tickets: bool = false,
    session_ticket_allocator: ?std.mem.Allocator = null,
    session_ticket_message: std.ArrayList(u8) = .empty,
    session_ticket_ready: bool = false,
    session_tickets_discarded: u64 = 0,
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
    peer_close_notify_received: bool = false,
    peer_eof_without_notify: bool = false,
    close_notify_sent: bool = false,
    failed: bool = false,
    /// A timed application write may stop after only a ciphertext prefix has
    /// reached the socket. Retain that exact record until a later retry;
    /// regenerating it would reuse the consumed sequence-number nonce.
    pending_write: [record_io.max_record_len]u8 = undefined,
    pending_write_len: usize = 0,
    pending_write_offset: usize = 0,
    pending_plaintext_len: usize = 0,
    pending_plaintext_fingerprint: write_retry.Fingerprint = .{},
    /// A retained KeyUpdate reply contributes no application-write progress.
    pending_write_key_update: bool = false,

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
        if (self.session_ticket_allocator) |allocator| {
            self.session_ticket_message.deinit(allocator);
        }
        std.crypto.secureZero(u8, &self.buffered_plaintext);
        std.crypto.secureZero(u8, &self.post_handshake);
        std.crypto.secureZero(u8, &self.pending_write);
        self.pending_plaintext_fingerprint.clear();
        self.* = undefined;
    }

    /// Permit client-side TLS 1.3 NewSessionTicket messages. The established
    /// stream does not currently expose a resumption cache, so authenticated
    /// tickets are bounded, consumed, and deliberately discarded. Servers do
    /// not enable this and therefore reject client-sent tickets.
    pub fn allowNewSessionTickets(self: *Stream) void {
        self.accept_new_session_tickets = true;
    }

    /// Retain the newest complete authenticated NewSessionTicket for the
    /// owning client connection. A later ticket replaces the unread one.
    pub fn retainNewSessionTickets(
        self: *Stream,
        allocator: std.mem.Allocator,
    ) void {
        self.accept_new_session_tickets = true;
        self.session_ticket_allocator = allocator;
    }

    pub fn takeNewSessionTicketMessage(
        self: *Stream,
    ) ?std.ArrayList(u8) {
        if (!self.session_ticket_ready) return null;
        const message = self.session_ticket_message;
        self.session_ticket_message = .empty;
        self.session_ticket_ready = false;
        return message;
    }

    pub fn discardedSessionTicketCount(self: *const Stream) u64 {
        return self.session_tickets_discarded;
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
            // Respond outside the authenticated-read transition's cancellation
            // protection. A blocked response retains its old-epoch ciphertext
            // and can resume under the next read or application-write budget.
            if (!self.failed and self.peer_update_response_pending.load(.acquire)) {
                if (deadline) |before| {
                    if (!self.write_mutex.tryLock()) return error.WriteInProgress;
                    defer self.write_mutex.unlock(io);
                    try key_update_write.respondUntil(self, io, stream, before, .{
                        .begin = beginPendingWrite,
                        .finish = finishPendingWriteWithDeadline,
                    });
                } else {
                    self.write_mutex.lockUncancelable(io);
                    defer self.write_mutex.unlock(io);
                    if (self.pending_write_key_update) {
                        var committed: usize = 0;
                        try self.finishPendingWriteUnlocked(io, stream, &committed);
                    } else {
                        try self.respondToPeerUpdateUnlocked(io, stream);
                    }
                }
            }
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
            if (self.peer_close_notify_received) return 0;
            if (self.peer_eof_without_notify) return error.UnexpectedEof;
            if (self.failed) return error.ConnectionClosed;

            const record_bytes = if (deadline) |value|
                self.record_reader.readWithDeadline(
                    io,
                    stream,
                    &self.buffered_plaintext,
                    value,
                )
            else
                self.record_reader.read(
                    io,
                    stream,
                    &self.buffered_plaintext,
                );
            const authenticated_record = record_bytes catch |err| {
                if (err == error.UnexpectedEof) {
                    self.peer_eof_without_notify = true;
                } else if (!io_interruption.retryable(err)) {
                    self.failed = true;
                }
                return err;
            };
            // Once a complete record has left the socket, finish its state
            // transition atomically with respect to task cancellation. A
            // deferred cancellation is observed by the next transport read,
            // whose incremental reader can safely preserve partial bytes.
            const old_cancel_protection =
                io.swapCancelProtection(.blocked);
            defer _ = io.swapCancelProtection(old_cancel_protection);
            var opened_storage: [
                record_io.max_plaintext_len + 1
            ]u8 = undefined;
            const opened = self.read_keys.open(
                self.read_sequence,
                authenticated_record,
                &opened_storage,
            ) catch |err| {
                self.failed = true;
                return err;
            };
            self.read_sequence = record_io.nextSequence(
                self.read_sequence,
            ) catch |err| {
                self.failed = true;
                return err;
            };
            switch (opened.content_type) {
                tls_record.content_type_application_data => {
                    if (self.post_handshake_len != 0) {
                        self.failed = true;
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
                    if (self.post_handshake_len != 0) {
                        self.failed = true;
                        return error.InvalidKeyUpdate;
                    }
                    if (try self.consumeAlert(
                        opened_storage[0..opened.len],
                    )) return 0;
                    continue;
                },
                tls_record.content_type_handshake => {
                    if (opened.len == 0) {
                        self.failed = true;
                        return error.InvalidKeyUpdate;
                    }
                    self.consumePostHandshake(
                        io,
                        stream,
                        opened_storage[0..opened.len],
                    ) catch |err| {
                        self.failed = true;
                        return err;
                    };
                    continue;
                },
                else => {
                    self.failed = true;
                    return error.UnexpectedTlsContent;
                },
            }
        }
    }

    /// True only after an authenticated TLS close_notify was received. A raw
    /// transport EOF and a truncated record never set this state.
    pub fn receivedCloseNotify(self: *const Stream) bool {
        return self.peer_close_notify_received;
    }

    /// True only when no decrypted application bytes or terminal/write state
    /// crosses an application boundary. A partial ciphertext or post-handshake
    /// message is not classified as application data until authenticated.
    pub fn isReusableBoundary(self: *const Stream) bool {
        return self.buffered_start == self.buffered_end and
            !self.peer_close_notify_received and
            !self.peer_eof_without_notify and
            !self.close_notify_sent and
            !self.failed and
            self.pending_write_len == 0;
    }

    pub fn shouldSendCloseNotify(self: *const Stream) bool {
        return !self.close_notify_sent and !self.failed;
    }

    fn consumeAlert(self: *Stream, bytes: []const u8) Error!bool {
        // RFC 8446 requires exactly one two-byte Alert message per record.
        if (bytes.len != 2) {
            self.failed = true;
            return error.InvalidTlsAlert;
        }
        const level = bytes[0];
        const description = bytes[1];
        if (level != 1 and level != 2) {
            self.failed = true;
            return error.InvalidTlsAlert;
        }
        // RFC 8446 close_notify is the sole authenticated EOF signal. Keep
        // receive and send directions separate so the application can finish
        // its response and send a reciprocal close_notify.
        if (description == 0) {
            self.peer_close_notify_received = true;
            return true;
        }
        // TLS 1.3 permits warning-level user_canceled before close_notify. It
        // does not terminate the byte stream by itself.
        if (level == 1 and description == 90) return false;
        self.failed = true;
        return if (level == 2)
            error.PeerTlsAlert
        else
            error.InvalidTlsAlert;
    }

    pub fn consumePostHandshake(
        self: *Stream,
        _: std.Io,
        _: net.Stream,
        bytes: []const u8,
    ) Error!void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (self.post_handshake_body_remaining != 0) {
                const count = @min(
                    self.post_handshake_body_remaining,
                    bytes.len - offset,
                );
                if (self.session_ticket_allocator) |allocator| {
                    try self.session_ticket_message.appendSlice(
                        allocator,
                        bytes[offset..][0..count],
                    );
                }
                self.post_handshake_body_remaining -= count;
                offset += count;
                if (self.post_handshake_body_remaining == 0) {
                    self.post_handshake_len = 0;
                    if (self.session_ticket_allocator != null) {
                        self.session_ticket_ready = true;
                    } else {
                        self.session_tickets_discarded +|= 1;
                    }
                }
                continue;
            }

            const header_target: usize = if (self.post_handshake_len < 4)
                4
            else
                key_update_message_len;
            const count = @min(header_target - self.post_handshake_len, bytes.len - offset);
            @memcpy(
                self.post_handshake[self.post_handshake_len..][0..count],
                bytes[offset..][0..count],
            );
            self.post_handshake_len += count;
            offset += count;

            if (self.post_handshake_len < 4) continue;
            const body_len = (@as(usize, self.post_handshake[1]) << 16) |
                (@as(usize, self.post_handshake[2]) << 8) |
                self.post_handshake[3];
            if (self.post_handshake[0] == handshake_type_new_session_ticket) {
                if (!self.accept_new_session_tickets or body_len < 14 or
                    body_len > max_new_session_ticket_body_len)
                {
                    return error.InvalidNewSessionTicket;
                }
                if (self.session_ticket_allocator) |allocator| {
                    if (self.session_ticket_ready) {
                        self.session_tickets_discarded +|= 1;
                    }
                    try self.session_ticket_message.ensureTotalCapacity(
                        allocator,
                        body_len + 4,
                    );
                    self.session_ticket_message.clearRetainingCapacity();
                    self.session_ticket_message.appendSliceAssumeCapacity(
                        self.post_handshake[0..4],
                    );
                    self.session_ticket_ready = false;
                }
                self.post_handshake_body_remaining = body_len;
                continue;
            }
            if (self.post_handshake[0] != handshake_type_key_update or body_len != 1)
                return error.InvalidKeyUpdate;
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
        if (self.close_notify_sent or self.failed) {
            return error.ConnectionClosed;
        }
        if (self.pending_write_len != 0) return error.WriteInProgress;
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
        if (self.close_notify_sent or self.failed) {
            return error.ConnectionClosed;
        }
        if (self.pending_write_len != 0) return error.WriteInProgress;
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
        if (self.close_notify_sent or self.failed) {
            return error.ConnectionClosed;
        }
        if (self.pending_write_len != 0) return error.WriteInProgress;
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

    /// Write application plaintext under an absolute deadline. Progress is a
    /// conservative TLS-record-aligned plaintext prefix: a record contributes
    /// only after all of its ciphertext is accepted by the socket. A partial
    /// ciphertext record remains connection-owned and is resumed before any
    /// new plaintext is encrypted.
    /// Timeout, cancellation and executor admission failure retain that
    /// transaction. Retry with the uncommitted suffix of the original bytes.
    /// That suffix must contain the identical pending-record plaintext prefix;
    /// it may move to a new address or include more unaccepted tail bytes.
    /// A mismatch returns WriteInProgress without writing or changing progress.
    pub fn writeAllWithDeadline(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        committed.* = 0;
        _ = try @import("../../internal/deadline.zig").usableAwake(io, deadline);
        if (!self.write_mutex.tryLock()) return error.WriteInProgress;
        defer self.write_mutex.unlock(io);
        if (self.close_notify_sent or self.failed) {
            return error.ConnectionClosed;
        }
        if (self.pending_write_len != 0 and !self.pending_write_key_update) {
            try self.pending_plaintext_fingerprint.validate(self.pending_plaintext_len, bytes);
            try self.finishPendingWriteWithDeadline(
                io,
                stream,
                committed,
                deadline,
            );
        }
        try key_update_write.respondUntil(self, io, stream, deadline, .{
            .begin = beginPendingWrite,
            .finish = finishPendingWriteWithDeadline,
        });
        while (committed.* < bytes.len) {
            const chunk_len = @min(
                record_io.max_plaintext_len,
                bytes.len - committed.*,
            );
            const plaintext = bytes[committed.*..][0..chunk_len];
            try self.beginPendingWrite(
                tls_record.content_type_application_data,
                plaintext,
            );
            self.finishPendingWriteWithDeadline(
                io,
                stream,
                committed,
                deadline,
            ) catch |err| {
                self.pending_plaintext_fingerprint.capture(plaintext);
                return err;
            };
        }
    }

    /// Finish ciphertext retained by a previous bounded write without
    /// encrypting another plaintext record. The returned count is the
    /// plaintext prefix that becomes committed by completing that record.
    /// A KeyUpdate reply completes its epoch transition and contributes zero.
    pub fn finishPendingWrite(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        committed: *usize,
    ) Error!void {
        committed.* = 0;
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        return self.finishPendingWriteUnlocked(io, stream, committed);
    }

    fn finishPendingWriteUnlocked(self: *Stream, io: std.Io, stream: net.Stream, committed: *usize) Error!void {
        if (self.close_notify_sent or self.failed) {
            return error.ConnectionClosed;
        }
        if (self.pending_write_len == 0) return;
        record_io.writeAll(
            io,
            stream,
            self.pending_write[self.pending_write_offset..self.pending_write_len],
        ) catch |err| {
            self.failed = true;
            return err;
        };
        try self.commitPendingWrite(committed);
    }

    pub fn beginPendingWrite(
        self: *Stream,
        content_type: u8,
        plaintext: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_write_len == 0);
        const next_sequence = try record_io.nextSequence(
            self.write_sequence,
        );
        const len = try self.write_keys.seal(
            self.write_sequence,
            content_type,
            plaintext,
            &self.pending_write,
        );
        self.write_sequence = next_sequence;
        self.pending_write_len = len;
        self.pending_write_offset = 0;
        self.pending_plaintext_len = plaintext.len;
    }

    fn finishPendingWriteWithDeadline(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        std.debug.assert(self.pending_write_len != 0);
        record_io.writeAllWithDeadline(
            io,
            stream,
            self.pending_write[0..self.pending_write_len],
            &self.pending_write_offset,
            deadline,
        ) catch |err| {
            if (!io_interruption.retryable(err)) {
                self.failed = true;
            }
            return err;
        };
        try self.commitPendingWrite(committed);
    }

    fn commitPendingWrite(self: *Stream, committed: *usize) Error!void {
        if (self.pending_write_key_update) {
            key_update_write.rotate(self) catch |err| {
                self.failed = true;
                return err;
            };
            self.peer_update_response_pending.store(false, .release);
        } else {
            committed.* += self.pending_plaintext_len;
        }
        self.pending_write_len = 0;
        self.pending_write_offset = 0;
        self.pending_plaintext_len = 0;
        self.pending_plaintext_fingerprint.clear();
        self.pending_write_key_update = false;
    }

    pub fn sendCloseNotify(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
    ) Error!void {
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        if (self.close_notify_sent) return;
        if (self.failed) return error.ConnectionClosed;
        if (self.pending_write_len != 0) return error.WriteInProgress;
        try self.respondToPeerUpdateUnlocked(io, stream);
        try self.writeRecord(
            io,
            stream,
            tls_record.content_type_alert,
            &.{ 1, 0 },
        );
        self.close_notify_sent = true;
    }

    pub fn sendCloseNotifyWithDeadline(self: *Stream, io: std.Io, stream: net.Stream, deadline: std.Io.Clock.Timestamp) Error!void {
        try @import("../../internal/timed_mutex.zig").lock(&self.write_mutex, io, deadline);
        defer self.write_mutex.unlock(io);
        if (self.close_notify_sent) return;
        if (self.failed) return error.ConnectionClosed;
        if (self.pending_write_len != 0) return error.WriteInProgress;
        errdefer self.failed = true;
        try key_update_write.respondUntil(self, io, stream, deadline, .{ .begin = beginPendingWrite, .finish = finishPendingWriteWithDeadline });
        try self.beginPendingWrite(tls_record.content_type_alert, &.{ 1, 0 });
        var committed: usize = 0;
        try self.finishPendingWriteWithDeadline(io, stream, &committed, deadline);
        self.close_notify_sent = true;
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
        if (self.close_notify_sent or self.failed) {
            return error.ConnectionClosed;
        }
        if (self.pending_write_len != 0) return error.WriteInProgress;
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
        if (self.pending_write_len != 0) return error.WriteInProgress;
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
        var epoch = try key_update_write.prepare(self);
        errdefer epoch.deinit();
        const message = key_update_write.message(request_peer_update);
        try self.writeRecord(
            io,
            stream,
            tls_record.content_type_handshake,
            &message,
        );
        epoch.activate(self);
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

    pub fn writeRecord(
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
        record_io.writeAll(io, stream, encoded[0..len]) catch |err| {
            self.failed = true;
            return err;
        };
    }
};

pub fn testingRecordStream(
    read_fill: u8,
    write_fill: u8,
) !Stream {
    const suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
    var read_secret = try vail.tls.secret.Secret.init(
        suite.hash(),
        &([_]u8{read_fill} ** 32),
    );
    errdefer read_secret.deinit();
    var write_secret = try vail.tls.secret.Secret.init(
        suite.hash(),
        &([_]u8{write_fill} ** 32),
    );
    errdefer write_secret.deinit();
    var read_keys = try tls_record.Keys.derive(suite, read_secret);
    errdefer read_keys.deinit();
    var write_keys = try tls_record.Keys.derive(suite, write_secret);
    errdefer write_keys.deinit();
    return .init(
        read_keys,
        write_keys,
        read_secret,
        write_secret,
    );
}

pub fn testingNetworkStreams(io: std.Io) ![2]net.Stream {
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const first = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    errdefer first.close(io);
    const second = try listener.accept(io);
    return .{ first, second };
}

test {
    _ = @import("record_stream/tests.zig");
}

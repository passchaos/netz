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
const io_interruption = @import("../../internal/io_interruption.zig");

const net = std.Io.net;
const tls_record = vail.tls.record;

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

const handshake_type_key_update: u8 = 24;
const handshake_type_new_session_ticket: u8 = 4;
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

    fn consumePostHandshake(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
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
        if (self.close_notify_sent or self.failed) {
            return error.ConnectionClosed;
        }
        if (self.pending_write_len != 0) {
            try self.finishPendingWriteWithDeadline(
                io,
                stream,
                committed,
                deadline,
            );
        }
        // A response requested while the previous record was partially sent
        // must follow that record and precede any later application bytes.
        // It is tiny and the just-completed record established writability.
        try self.respondToPeerUpdateUnlocked(io, stream);
        while (committed.* < bytes.len) {
            const chunk_len = @min(
                record_io.max_plaintext_len,
                bytes.len - committed.*,
            );
            try self.beginPendingWrite(
                tls_record.content_type_application_data,
                bytes[committed.*..][0..chunk_len],
            );
            try self.finishPendingWriteWithDeadline(
                io,
                stream,
                committed,
                deadline,
            );
        }
    }

    /// Finish ciphertext retained by a previous bounded write without
    /// encrypting another plaintext record. The returned count is the
    /// plaintext prefix that becomes committed by completing that record.
    pub fn finishPendingWrite(
        self: *Stream,
        io: std.Io,
        stream: net.Stream,
        committed: *usize,
    ) Error!void {
        committed.* = 0;
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
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
        committed.* = self.pending_plaintext_len;
        self.pending_write_len = 0;
        self.pending_write_offset = 0;
        self.pending_plaintext_len = 0;
    }

    fn beginPendingWrite(
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
        committed.* += self.pending_plaintext_len;
        self.pending_write_len = 0;
        self.pending_write_offset = 0;
        self.pending_plaintext_len = 0;
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
        record_io.writeAll(io, stream, encoded[0..len]) catch |err| {
            self.failed = true;
            return err;
        };
    }
};

fn testingRecordStream(
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

fn testingNetworkStreams(io: std.Io) ![2]net.Stream {
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

test "TLS record stream exposes authenticated close notify as EOF" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    try sender.writeAll(io, streams[0], "body");
    try sender.sendCloseNotify(io, streams[0]);
    var buffer: [8]u8 = undefined;
    const body_len = try receiver.read(io, streams[1], &buffer);
    try std.testing.expectEqualStrings("body", buffer[0..body_len]);
    try std.testing.expectEqual(
        @as(usize, 0),
        try receiver.read(io, streams[1], &buffer),
    );
    try std.testing.expect(receiver.receivedCloseNotify());
    try std.testing.expectError(
        error.ConnectionClosed,
        sender.writeAll(io, streams[0], "late"),
    );

    // Receiving close_notify closes only the peer's write direction. The
    // receiver may still finish its own application data before replying.
    try receiver.writeAll(io, streams[1], "reply");
    try receiver.sendCloseNotify(io, streams[1]);
    const reply_len = try sender.read(io, streams[0], &buffer);
    try std.testing.expectEqualStrings("reply", buffer[0..reply_len]);
    try std.testing.expectEqual(
        @as(usize, 0),
        try sender.read(io, streams[0], &buffer),
    );
}

test "TLS record stream finishes retained ciphertext without re-encrypting" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();
    sender.beginPendingWrite(
        tls_record.content_type_application_data,
        "retained",
    ) catch |err| return err;
    sender.pending_write_offset = 3;
    try record_io.writeAll(
        io,
        streams[0],
        sender.pending_write[0..sender.pending_write_offset],
    );

    var committed: usize = 99;
    try sender.finishPendingWrite(io, streams[0], &committed);
    try std.testing.expectEqual(@as(usize, "retained".len), committed);
    try std.testing.expectEqual(@as(usize, 0), sender.pending_write_len);
    try std.testing.expectEqual(@as(u64, 1), sender.write_sequence);

    var plaintext: [16]u8 = undefined;
    const count = try receiver.read(io, streams[1], &plaintext);
    try std.testing.expectEqualStrings("retained", plaintext[0..count]);
}

test "TLS record stream reusable boundary distinguishes plaintext from ciphertext" {
    var records = try testingRecordStream(0x22, 0x11);
    defer records.deinit();
    try std.testing.expect(records.isReusableBoundary());

    // Ciphertext and post-handshake fragments have not yet been authenticated
    // as application data and must not be treated as an unsolicited response.
    records.record_reader.encoded_len = 1;
    records.post_handshake_len = 1;
    try std.testing.expect(records.isReusableBoundary());

    records.buffered_end = 1;
    try std.testing.expect(!records.isReusableBoundary());
    records.buffered_end = 0;
    records.failed = true;
    try std.testing.expect(!records.isReusableBoundary());
}

test "TLS record stream rejects fatal and malformed alerts" {
    const cases = [_]struct {
        alert: [2]u8,
        expected: anyerror,
    }{
        .{ .alert = .{ 2, 40 }, .expected = error.PeerTlsAlert },
        .{ .alert = .{ 1, 40 }, .expected = error.InvalidTlsAlert },
    };
    for (cases) |case| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const streams = try testingNetworkStreams(io);
        defer streams[0].close(io);
        defer streams[1].close(io);
        var sender = try testingRecordStream(0x22, 0x11);
        defer sender.deinit();
        var receiver = try testingRecordStream(0x11, 0x22);
        defer receiver.deinit();

        try sender.writeRecord(
            io,
            streams[0],
            tls_record.content_type_alert,
            &case.alert,
        );
        var byte: [1]u8 = undefined;
        try std.testing.expectError(
            case.expected,
            receiver.read(io, streams[1], &byte),
        );
        try std.testing.expect(!receiver.receivedCloseNotify());
        try std.testing.expectError(
            error.ConnectionClosed,
            receiver.read(io, streams[1], &byte),
        );
    }
}

test "TLS record stream accepts user canceled followed by close notify" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);
    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    try sender.writeRecord(
        io,
        streams[0],
        tls_record.content_type_alert,
        &.{ 1, 90 },
    );
    try sender.writeRecord(
        io,
        streams[0],
        tls_record.content_type_alert,
        &.{ 1, 0 },
    );
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        try receiver.read(io, streams[1], &byte),
    );
    try std.testing.expect(receiver.receivedCloseNotify());
}

test "TLS record stream distinguishes socket EOF from record truncation" {
    const cuts = [_]?usize{ null, 1, 4, 5, 10 };
    for (cuts) |cut| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const streams = try testingNetworkStreams(io);
        var sender_open = true;
        defer if (sender_open) streams[0].close(io);
        defer streams[1].close(io);
        var sender = try testingRecordStream(0x22, 0x11);
        defer sender.deinit();
        var receiver = try testingRecordStream(0x11, 0x22);
        defer receiver.deinit();

        if (cut) |count| {
            var encoded: [record_io.max_record_len]u8 = undefined;
            const len = try sender.write_keys.seal(
                sender.write_sequence,
                tls_record.content_type_application_data,
                "truncated",
                &encoded,
            );
            try std.testing.expect(count < len);
            try record_io.writeAll(io, streams[0], encoded[0..count]);
        }
        streams[0].close(io);
        sender_open = false;

        var byte: [1]u8 = undefined;
        try std.testing.expectError(
            if (cut == null) error.UnexpectedEof else error.TruncatedRecord,
            receiver.read(io, streams[1], &byte),
        );
        try std.testing.expect(!receiver.receivedCloseNotify());
        if (cut == null) {
            try std.testing.expect(receiver.shouldSendCloseNotify());
            try std.testing.expectError(
                error.UnexpectedEof,
                receiver.read(io, streams[1], &byte),
            );
        } else {
            try std.testing.expect(!receiver.shouldSendCloseNotify());
            try std.testing.expectError(
                error.ConnectionClosed,
                receiver.read(io, streams[1], &byte),
            );
        }
    }
}

test "TLS record stream delivers authenticated data before later truncation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    var sender_open = true;
    defer if (sender_open) streams[0].close(io);
    defer streams[1].close(io);
    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    try sender.writeAll(io, streams[0], "complete");
    var encoded: [record_io.max_record_len]u8 = undefined;
    const len = try sender.write_keys.seal(
        sender.write_sequence,
        tls_record.content_type_application_data,
        "truncated",
        &encoded,
    );
    try std.testing.expect(len > 8);
    try record_io.writeAll(io, streams[0], encoded[0..8]);
    streams[0].close(io);
    sender_open = false;

    var buffer: [16]u8 = undefined;
    const count = try receiver.read(io, streams[1], &buffer);
    try std.testing.expectEqualStrings("complete", buffer[0..count]);
    try std.testing.expectError(
        error.TruncatedRecord,
        receiver.read(io, streams[1], &buffer),
    );
}

test "TLS record stream resumes a partial record after read timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);
    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    var encoded: [record_io.max_record_len]u8 = undefined;
    const len = try sender.write_keys.seal(
        sender.write_sequence,
        tls_record.content_type_application_data,
        "resumed-record",
        &encoded,
    );
    try record_io.writeAll(io, streams[0], encoded[0..1]);

    var plaintext: [32]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        receiver.readWithDeadline(
            io,
            streams[1],
            &plaintext,
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), receiver.record_reader.encoded_len);

    try record_io.writeAll(io, streams[0], encoded[1..len]);
    const count = try receiver.read(io, streams[1], &plaintext);
    try std.testing.expectEqualStrings(
        "resumed-record",
        plaintext[0..count],
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        receiver.record_reader.encoded_len,
    );
}

test "TLS record stream resumes a partial record after task cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);
    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    var encoded: [record_io.max_record_len]u8 = undefined;
    const len = try sender.write_keys.seal(
        sender.write_sequence,
        tls_record.content_type_application_data,
        "canceled-record",
        &encoded,
    );
    try record_io.writeAll(io, streams[0], encoded[0..1]);

    var plaintext: [32]u8 = undefined;
    var read_future = try io.concurrent(
        Stream.read,
        .{ &receiver, io, streams[1], &plaintext },
    );
    try std.Io.sleep(
        io,
        .fromMilliseconds(20),
        .awake,
    );
    try std.testing.expectError(error.Canceled, read_future.cancel(io));
    try std.testing.expectEqual(
        @as(usize, 1),
        receiver.record_reader.encoded_len,
    );

    try record_io.writeAll(io, streams[0], encoded[1..len]);
    const count = try receiver.read(io, streams[1], &plaintext);
    try std.testing.expectEqualStrings(
        "canceled-record",
        plaintext[0..count],
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        receiver.record_reader.encoded_len,
    );
}

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

test "TLS record stream client discards bounded fragmented NewSessionTicket" {
    const suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
    const bytes = [_]u8{0x64} ** 32;
    var traffic_secret = try vail.tls.secret.Secret.init(suite.hash(), &bytes);
    defer traffic_secret.deinit();
    var records = Stream.init(
        try tls_record.Keys.derive(suite, traffic_secret),
        try tls_record.Keys.derive(suite, traffic_secret),
        traffic_secret,
        traffic_secret,
    );
    defer records.deinit();
    records.allowNewSessionTickets();

    // Minimal structurally sized ticket body split across record boundaries,
    // immediately followed by a KeyUpdate in the same handshake fragment.
    const ticket_and_update = [_]u8{
        handshake_type_new_session_ticket, 0, 0, 14,
        0, 0, 0, 1, // lifetime
        0, 0, 0, 2, // age_add
        0, // nonce length
        0, 1, 0xaa, // one-byte ticket
        0,                         0, // extensions
        handshake_type_key_update, 0,
        0,                         1,
        0,
    };
    try records.consumePostHandshake(undefined, undefined, ticket_and_update[0..9]);
    try std.testing.expectEqual(@as(u64, 0), records.discardedSessionTicketCount());
    try records.consumePostHandshake(undefined, undefined, ticket_and_update[9..]);
    try std.testing.expectEqual(@as(u64, 1), records.discardedSessionTicketCount());
    try std.testing.expectEqual(@as(u64, 1), records.keyUpdateCounts().received);

    var server_records = Stream.init(
        try tls_record.Keys.derive(suite, traffic_secret),
        try tls_record.Keys.derive(suite, traffic_secret),
        traffic_secret,
        traffic_secret,
    );
    defer server_records.deinit();
    try std.testing.expectError(
        error.InvalidNewSessionTicket,
        server_records.consumePostHandshake(undefined, undefined, ticket_and_update[0..18]),
    );
}

test "TLS record stream retains the newest complete NewSessionTicket" {
    const suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
    const bytes = [_]u8{0x65} ** 32;
    var traffic_secret = try vail.tls.secret.Secret.init(suite.hash(), &bytes);
    defer traffic_secret.deinit();
    var records = Stream.init(
        try tls_record.Keys.derive(suite, traffic_secret),
        try tls_record.Keys.derive(suite, traffic_secret),
        traffic_secret,
        traffic_secret,
    );
    defer records.deinit();
    records.retainNewSessionTickets(std.testing.allocator);

    const ticket_and_update = [_]u8{
        handshake_type_new_session_ticket, 0, 0, 14,
        0, 0, 0, 1, // lifetime
        0, 0, 0, 2, // age_add
        0, // nonce length
        0, 1, 0xaa, // one-byte ticket
        0,                         0, // extensions
        handshake_type_key_update, 0,
        0,                         1,
        0,
    };
    try records.consumePostHandshake(
        undefined,
        undefined,
        ticket_and_update[0..9],
    );
    try std.testing.expect(records.takeNewSessionTicketMessage() == null);
    try records.consumePostHandshake(
        undefined,
        undefined,
        ticket_and_update[9..],
    );
    var retained = records.takeNewSessionTicketMessage() orelse
        return error.MissingSessionTicket;
    defer retained.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        ticket_and_update[0..18],
        retained.items,
    );
    try std.testing.expect(records.takeNewSessionTicketMessage() == null);
    try std.testing.expectEqual(@as(u64, 0), records.discardedSessionTicketCount());
    try std.testing.expectEqual(@as(u64, 1), records.keyUpdateCounts().received);
}

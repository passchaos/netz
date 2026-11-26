const std = @import("std");
const http2 = @import("../../mod.zig");
const wire = @import("wire.zig");
const socket_read = @import("../../../internal/stream_io/read.zig");

pub const Error = http2.Error || error{
    ConnectionClosed,
    InvalidFrame,
    MessageTooLarge,
} || std.mem.Allocator.Error || std.Io.net.Stream.Reader.Error;

pub const BorrowedFrame = struct {
    bytes: []const u8,
    frame: http2.Frame,
};

/// Immutable ownership for one read-ahead allocation. The Reader keeps one
/// reference while it may return more frames from the allocation; every owned
/// frame retains another reference to its exact subspan. A subsequent socket
/// read reuses the allocation only when the Reader is its sole owner.
const SharedReadBuffer = struct {
    references: std.atomic.Value(usize) = .init(1),
    allocation: []u8,

    fn retain(self: *SharedReadBuffer) void {
        const previous = self.references.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0 and previous != std.math.maxInt(usize));
    }

    fn isUnique(self: *const SharedReadBuffer) bool {
        return self.references.load(.acquire) == 1;
    }

    fn release(self: *SharedReadBuffer, allocator: std.mem.Allocator) void {
        const previous = self.references.fetchSub(1, .release);
        std.debug.assert(previous != 0);
        if (previous != 1) return;
        // Pair with releases from any other thread only for the final owner;
        // ordinary frame retirement does not need an acquire barrier.
        _ = self.references.load(.acquire);
        allocator.free(self.allocation);
        allocator.destroy(self);
    }
};

pub const OwnedFrame = struct {
    bytes: []u8,
    frame: http2.Frame,

    pub fn deinit(self: *OwnedFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Internal duplex/read-pump ownership. Exact frames can move into the ordinary
/// OwnedFrame queues without allocation; read-ahead-backed frames retain their
/// immutable block and copy only if they cross into an ordinary owning queue.
pub const RetainedFrame = struct {
    bytes: []u8,
    frame: http2.Frame,
    shared_read_buffer: ?*SharedReadBuffer = null,

    pub fn fromOwned(owned: OwnedFrame) RetainedFrame {
        return .{ .bytes = owned.bytes, .frame = owned.frame };
    }

    /// Prepare an ordinary owner without consuming this frame. Shared storage
    /// is copied; exact storage is only aliased until commitPreparedOwned.
    pub fn prepareOwned(self: RetainedFrame, allocator: std.mem.Allocator) std.mem.Allocator.Error!OwnedFrame {
        if (self.shared_read_buffer == null) {
            return .{ .bytes = self.bytes, .frame = self.frame };
        }
        const bytes = try allocator.dupe(u8, self.bytes);
        return .{
            .bytes = bytes,
            .frame = http2.Frame.parse(bytes) catch unreachable,
        };
    }

    /// Complete a successful prepareOwned transfer after all fallible queue or
    /// HPACK work. The caller then owns only the returned OwnedFrame.
    pub fn commitPreparedOwned(self: *RetainedFrame, allocator: std.mem.Allocator) void {
        if (self.shared_read_buffer != null) {
            self.deinit(allocator);
        } else {
            self.* = undefined;
        }
    }

    pub fn deinit(self: *RetainedFrame, allocator: std.mem.Allocator) void {
        if (self.shared_read_buffer) |shared| {
            shared.release(allocator);
        } else {
            allocator.free(self.bytes);
        }
        self.* = undefined;
    }
};

/// Match the measured bulk-read window: it coalesces four default-size HTTP/2
/// frames while remaining bounded independently from negotiated frame limits.
pub const default_read_size: usize = 64 * 1024;

/// Read one owned frame without retaining connection-level read-ahead.
pub fn readOwned(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    inbound_payload_limit: usize,
) Error!OwnedFrame {
    const Source = struct {
        io: std.Io,
        stream: std.Io.net.Stream,

        fn read(source: @This(), buffer: []u8) !usize {
            return socket_read.readSome(source.io, source.stream, buffer);
        }

        fn readWithDeadline(
            source: @This(),
            buffer: []u8,
            _: std.Io.Clock.Timestamp,
        ) !usize {
            return source.read(buffer);
        }
    };
    return readOwnedFrom(
        allocator,
        Source{ .io = io, .stream = stream },
        inbound_payload_limit,
    );
}

pub fn readOwnedTransport(
    allocator: std.mem.Allocator,
    transport: anytype,
    inbound_payload_limit: usize,
) !OwnedFrame {
    return readOwnedFrom(allocator, transport, inbound_payload_limit);
}

pub fn readOwnedTransportWithDeadline(
    allocator: std.mem.Allocator,
    transport: anytype,
    inbound_payload_limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
) !OwnedFrame {
    return readOwnedTransportWithDeadlineClassified(
        allocator,
        transport,
        inbound_payload_limit,
        deadline,
        null,
    );
}

pub fn readOwnedTransportWithDeadlineClassified(
    allocator: std.mem.Allocator,
    transport: anytype,
    inbound_payload_limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
    envelope_violation: ?*?wire.EnvelopeViolation,
) !OwnedFrame {
    if (envelope_violation) |out| out.* = null;
    if (deadline == null) {
        return readOwnedFromClassified(
            allocator,
            transport,
            inbound_payload_limit,
            envelope_violation,
        );
    }

    var header_bytes: [http2.FrameHeader.encoded_len]u8 = undefined;
    try readExactWithDeadline(transport, &header_bytes, deadline.?);
    return finishOwnedRead(
        allocator,
        transport,
        &header_bytes,
        inbound_payload_limit,
        deadline,
        envelope_violation,
    );
}

fn readOwnedFrom(
    allocator: std.mem.Allocator,
    source: anytype,
    inbound_payload_limit: usize,
) !OwnedFrame {
    return readOwnedFromClassified(
        allocator,
        source,
        inbound_payload_limit,
        null,
    );
}

fn readOwnedFromClassified(
    allocator: std.mem.Allocator,
    source: anytype,
    inbound_payload_limit: usize,
    envelope_violation: ?*?wire.EnvelopeViolation,
) !OwnedFrame {
    var header_bytes: [http2.FrameHeader.encoded_len]u8 = undefined;
    try readExact(source, &header_bytes);
    return finishOwnedRead(
        allocator,
        source,
        &header_bytes,
        inbound_payload_limit,
        null,
        envelope_violation,
    );
}

fn finishOwnedRead(
    allocator: std.mem.Allocator,
    source: anytype,
    header_bytes: *const [http2.FrameHeader.encoded_len]u8,
    inbound_payload_limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
    envelope_violation: ?*?wire.EnvelopeViolation,
) !OwnedFrame {
    const header = try http2.FrameHeader.parse(header_bytes);
    const payload_len: usize = header.length;
    if (payload_len > inbound_payload_limit) return error.MessageTooLarge;

    const bytes = try allocator.alloc(
        u8,
        http2.FrameHeader.encoded_len + payload_len,
    );
    errdefer allocator.free(bytes);
    @memcpy(bytes[0..http2.FrameHeader.encoded_len], header_bytes);
    if (deadline) |absolute| {
        try readExactWithDeadline(
            source,
            bytes[http2.FrameHeader.encoded_len..],
            absolute,
        );
    } else {
        try readExact(source, bytes[http2.FrameHeader.encoded_len..]);
    }
    const frame = try http2.Frame.parse(bytes);
    if (wire.classifyEnvelope(frame)) |violation| {
        if (envelope_violation) |out| out.* = violation;
        return error.InvalidFrame;
    }
    return .{ .bytes = bytes, .frame = frame };
}

pub fn writeTransport(
    allocator: std.mem.Allocator,
    transport: anytype,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) !void {
    _ = allocator;
    var header: [http2.FrameHeader.encoded_len]u8 = undefined;
    try wire.encodeHeader(
        &header,
        frame_type,
        flags,
        stream_id,
        payload.len,
    );
    try transport.writeAllParts(&header, payload);
}

/// Encode one complete frame contiguously and write it under an absolute
/// deadline. `committed` reports the exact HTTP/2 wire prefix accepted by a
/// cleartext transport, or complete TLS-record plaintext progress.
pub fn writeTransportWithDeadline(
    allocator: std.mem.Allocator,
    transport: anytype,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
    committed: *usize,
    deadline: std.Io.Clock.Timestamp,
) !void {
    committed.* = 0;
    const total_len = std.math.add(
        usize,
        http2.FrameHeader.encoded_len,
        payload.len,
    ) catch return error.InvalidFrameSize;
    var stack_storage: [256]u8 = undefined;
    const storage = if (total_len <= stack_storage.len)
        stack_storage[0..total_len]
    else
        try allocator.alloc(u8, total_len);
    defer if (storage.ptr != stack_storage[0..].ptr) allocator.free(storage);
    try wire.encodeHeader(
        storage[0..http2.FrameHeader.encoded_len],
        frame_type,
        flags,
        stream_id,
        payload.len,
    );
    @memcpy(storage[http2.FrameHeader.encoded_len..], payload);
    try transport.writeAllWithDeadline(storage, committed, deadline);
}

fn readExact(source: anytype, buffer: []u8) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const count = try source.read(buffer[offset..]);
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}

fn readExactWithDeadline(
    source: anytype,
    buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const count = try source.readWithDeadline(buffer[offset..], deadline);
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}

/// Buffered frame source for one HTTP/2 connection.
///
/// A returned frame borrows `buffer` until the next `read` call. The reader
/// deliberately asks the socket for a 64-KiB tail so one syscall can capture
/// several adjacent frames; a cursor consumes complete frames without
/// memmoving until another socket read is required.
pub const Reader = struct {
    buffer: std.ArrayList(u8) = .empty,
    shared_buffer: ?*SharedReadBuffer = null,
    start: usize = 0,
    last_envelope_violation: ?wire.EnvelopeViolation = null,
    retry_len: usize = 0,
    last_replayed: bool = false,

    /// Copy the latest borrow into independent ownership. Failed allocation
    /// keeps that complete frame ahead of every following buffered frame.
    pub fn copyOwned(self: *Reader, allocator: std.mem.Allocator, borrowed: BorrowedFrame) std.mem.Allocator.Error!OwnedFrame {
        std.debug.assert(self.start >= borrowed.bytes.len);
        std.debug.assert(borrowed.bytes.ptr == self.buffer.items[self.start - borrowed.bytes.len ..].ptr);
        const bytes = allocator.dupe(u8, borrowed.bytes) catch |err| {
            self.retry_len = borrowed.bytes.len;
            return err;
        };
        self.retry_len = 0;
        return .{ .bytes = bytes, .frame = http2.Frame.parse(bytes) catch unreachable };
    }

    /// Retain the latest frame as an immutable subspan of this Reader's
    /// read-ahead block. Failed first-owner allocation preserves retry order.
    pub fn retainOwned(self: *Reader, allocator: std.mem.Allocator, borrowed: BorrowedFrame) std.mem.Allocator.Error!RetainedFrame {
        std.debug.assert(self.start >= borrowed.bytes.len);
        std.debug.assert(borrowed.bytes.ptr == self.buffer.items[self.start - borrowed.bytes.len ..].ptr);
        const shared = self.ensureSharedBuffer(allocator) catch |err| {
            self.retry_len = borrowed.bytes.len;
            return err;
        };
        shared.retain();
        self.retry_len = 0;
        return .{
            .bytes = @constCast(borrowed.bytes),
            .frame = borrowed.frame,
            .shared_read_buffer = shared,
        };
    }

    pub fn deinit(self: *Reader, allocator: std.mem.Allocator) void {
        if (self.shared_buffer) |shared| {
            shared.release(allocator);
        } else {
            self.buffer.deinit(allocator);
        }
        self.* = undefined;
    }

    fn ensureSharedBuffer(self: *Reader, allocator: std.mem.Allocator) std.mem.Allocator.Error!*SharedReadBuffer {
        if (self.shared_buffer) |shared| return shared;
        const shared = try allocator.create(SharedReadBuffer);
        shared.* = .{ .allocation = self.buffer.allocatedSlice() };
        self.shared_buffer = shared;
        return shared;
    }

    /// Make the read-ahead storage writable for a socket read. An outstanding
    /// OwnedFrame makes the current allocation immutable, so move only the
    /// incomplete suffix into a new block. Allocation failure leaves the old
    /// cursor and every retained frame unchanged for retry.
    fn prepareReadStorage(self: *Reader, allocator: std.mem.Allocator, target_read_size: usize) std.mem.Allocator.Error!void {
        const remaining = self.buffer.items[self.start..];
        if (self.shared_buffer) |shared| {
            if (!shared.isUnique()) {
                const next_shared = try allocator.create(SharedReadBuffer);
                errdefer allocator.destroy(next_shared);
                var next: std.ArrayList(u8) = .empty;
                errdefer next.deinit(allocator);
                try next.ensureTotalCapacityPrecise(allocator, target_read_size);
                next.appendSliceAssumeCapacity(remaining);
                next_shared.* = .{ .allocation = next.allocatedSlice() };

                self.buffer = next;
                self.start = 0;
                self.shared_buffer = next_shared;
                shared.release(allocator);
                return;
            }
        }

        if (self.start != 0) {
            if (remaining.len != 0) {
                @memmove(
                    self.buffer.items[0..remaining.len],
                    remaining,
                );
            }
            self.buffer.items.len = remaining.len;
            self.start = 0;
        }
        try self.buffer.ensureTotalCapacityPrecise(allocator, target_read_size);
        if (self.shared_buffer) |shared| {
            std.debug.assert(shared.isUnique());
            shared.allocation = self.buffer.allocatedSlice();
        }
    }

    pub fn read(
        self: *Reader,
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
        inbound_payload_limit: usize,
    ) Error!BorrowedFrame {
        const Source = struct {
            io: std.Io,
            stream: std.Io.net.Stream,

            fn read(source: @This(), buffer: []u8) !usize {
                return socket_read.readSome(source.io, source.stream, buffer);
            }
        };
        return self.readFrom(
            allocator,
            Source{ .io = io, .stream = stream },
            inbound_payload_limit,
        );
    }

    pub fn readTransport(
        self: *Reader,
        allocator: std.mem.Allocator,
        transport: anytype,
        inbound_payload_limit: usize,
    ) !BorrowedFrame {
        return self.readTransportWithDeadline(
            allocator,
            transport,
            inbound_payload_limit,
            null,
        );
    }

    pub fn readTransportWithDeadline(
        self: *Reader,
        allocator: std.mem.Allocator,
        transport: anytype,
        inbound_payload_limit: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) !BorrowedFrame {
        const Source = struct {
            transport: @TypeOf(transport),
            deadline: ?std.Io.Clock.Timestamp,

            fn read(source: @This(), buffer: []u8) !usize {
                if (source.deadline) |absolute| {
                    return source.transport.readWithDeadline(
                        buffer,
                        absolute,
                    );
                }
                return source.transport.read(buffer);
            }
        };
        return self.readFrom(
            allocator,
            Source{ .transport = transport, .deadline = deadline },
            inbound_payload_limit,
        );
    }

    pub fn readFrom(
        self: *Reader,
        allocator: std.mem.Allocator,
        source: anytype,
        inbound_payload_limit: usize,
    ) !BorrowedFrame {
        self.last_envelope_violation = null;
        self.last_replayed = false;
        if (self.retry_len != 0) {
            const bytes = self.buffer.items[self.start - self.retry_len .. self.start];
            self.retry_len = 0;
            self.last_replayed = true;
            return .{ .bytes = bytes, .frame = http2.Frame.parse(bytes) catch unreachable };
        }
        while (true) {
            const available = self.buffer.items[self.start..];
            var target_read_size = default_read_size;
            if (available.len >= http2.FrameHeader.encoded_len) {
                const header = try http2.FrameHeader.parse(available);
                const payload_len: usize = header.length;
                if (payload_len > inbound_payload_limit) {
                    return error.MessageTooLarge;
                }
                const total_len = std.math.add(
                    usize,
                    http2.FrameHeader.encoded_len,
                    payload_len,
                ) catch return error.MessageTooLarge;
                if (available.len >= total_len) {
                    const bytes = available[0..total_len];
                    const frame = try http2.Frame.parse(bytes);
                    self.start += total_len;
                    if (wire.classifyEnvelope(frame)) |violation| {
                        self.last_envelope_violation = violation;
                        return error.InvalidFrame;
                    }
                    return .{ .bytes = bytes, .frame = frame };
                }
                target_read_size = @max(total_len, default_read_size);
            }

            // A plain borrow expires on entry. Owned frames keep their block
            // immutable, so a shared block rolls over before compaction/read.
            try self.prepareReadStorage(allocator, target_read_size);
            const old_len = self.buffer.items.len;
            self.buffer.items.len = target_read_size;
            const destination = self.buffer.items[old_len..];
            const count = source.read(destination) catch |err| {
                self.buffer.items.len -= destination.len;
                return err;
            };
            if (count == 0) {
                self.buffer.items.len -= destination.len;
                return error.ConnectionClosed;
            }
            self.buffer.items.len -= destination.len - count;
        }
    }

    /// Take classification for the immediately preceding InvalidFrame. Other
    /// parse/read failures clear this slot on entry and cannot be mistaken for
    /// peer envelope violations by the connection runtime.
    pub fn takeEnvelopeViolation(self: *Reader) ?wire.EnvelopeViolation {
        const violation = self.last_envelope_violation;
        self.last_envelope_violation = null;
        return violation;
    }
};

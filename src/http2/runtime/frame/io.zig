const std = @import("std");
const http2 = @import("../../mod.zig");
const wire = @import("wire.zig");

pub const Error = http2.Error || error{
    ConnectionClosed,
    InvalidFrame,
    MessageTooLarge,
} || std.mem.Allocator.Error || std.Io.net.Stream.Reader.Error;

pub const BorrowedFrame = struct {
    bytes: []const u8,
    frame: http2.Frame,
};

pub const OwnedFrame = struct {
    bytes: []u8,
    frame: http2.Frame,

    pub fn deinit(self: *OwnedFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
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
            var buffers = [_][]u8{buffer};
            return source.io.vtable.netRead(
                source.io.userdata,
                source.stream.socket.handle,
                &buffers,
            );
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
    start: usize = 0,
    last_envelope_violation: ?wire.EnvelopeViolation = null,

    pub fn deinit(self: *Reader, allocator: std.mem.Allocator) void {
        self.buffer.deinit(allocator);
        self.* = undefined;
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
                var buffers = [_][]u8{buffer};
                return source.io.vtable.netRead(
                    source.io.userdata,
                    source.stream.socket.handle,
                    &buffers,
                );
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

            // The caller's previous borrow expires on entry to this method, so
            // compaction is safe here and retains only an incomplete frame.
            if (self.start != 0) {
                const remaining = self.buffer.items[self.start..];
                if (remaining.len != 0) {
                    @memmove(
                        self.buffer.items[0..remaining.len],
                        remaining,
                    );
                }
                self.buffer.items.len = remaining.len;
                self.start = 0;
            }

            const old_len = self.buffer.items.len;
            try self.buffer.ensureTotalCapacityPrecise(
                allocator,
                target_read_size,
            );
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

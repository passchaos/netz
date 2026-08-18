//! Incremental gRPC message framing for HTTP/2 DATA payloads.
//!
//! A five-byte gRPC prefix and its payload may cross arbitrary DATA frame
//! boundaries, while one DATA payload may contain several complete messages.
//! This parser retains only the current incomplete message and delivers each
//! complete decoded payload immediately.

const std = @import("std");
const compression = @import("../compression.zig");
const wire = @import("../wire.zig");

pub const Error = wire.Error || compression.Error || error{
    CompressionNotNegotiated,
    InvalidStreamState,
};

pub const DecodedMessage = struct {
    /// Borrowed for the duration of the decoder callback.
    payload: []const u8,
    was_compressed: bool,
};

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    max_message_size: usize,
    encoding: compression.Algorithm,
    accepted_encodings: compression.AlgorithmSet,
    prefix: [5]u8 = undefined,
    prefix_len: usize = 0,
    payload: ?[]u8 = null,
    payload_len: usize = 0,
    payload_written: usize = 0,
    finished: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        max_message_size: usize,
        encoding: ?[]const u8,
        accepted_encodings: compression.AlgorithmSet,
    ) Error!Decoder {
        const algorithm = if (encoding) |value|
            compression.Algorithm.parse(value) orelse
                return error.UnsupportedCompression
        else
            .identity;
        return .{
            .allocator = allocator,
            .max_message_size = max_message_size,
            .encoding = algorithm,
            .accepted_encodings = accepted_encodings,
        };
    }

    pub fn deinit(self: *Decoder) void {
        if (self.payload) |payload| self.allocator.free(payload);
        self.* = undefined;
    }

    /// Consume one arbitrary DATA payload and deliver every completed message.
    ///
    /// Uncompressed messages wholly contained in `bytes` are delivered
    /// directly without allocation. Messages crossing calls use one exact-size
    /// allocation; compressed messages additionally use the bounded wrapper
    /// decoder and release both allocations before `feed` returns.
    pub fn feed(
        self: *Decoder,
        bytes: []const u8,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (self.finished) return error.InvalidStreamState;
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (self.prefix_len < self.prefix.len) {
                const count = @min(
                    self.prefix.len - self.prefix_len,
                    bytes.len - offset,
                );
                @memcpy(
                    self.prefix[self.prefix_len..][0..count],
                    bytes[offset..][0..count],
                );
                self.prefix_len += count;
                offset += count;
                if (self.prefix_len != self.prefix.len) return;
                try self.preparePayload();
            }

            if (self.payload_len == 0) {
                try self.deliver(&.{}, context, consume);
                self.resetMessage();
                continue;
            }

            if (self.payload == null and
                bytes.len - offset >= self.payload_len)
            {
                const payload = bytes[offset..][0..self.payload_len];
                offset += self.payload_len;
                try self.deliver(payload, context, consume);
                self.resetMessage();
                continue;
            }

            if (self.payload == null) {
                self.payload = try self.allocator.alloc(
                    u8,
                    self.payload_len,
                );
            }
            const payload = self.payload.?;
            const count = @min(
                payload.len - self.payload_written,
                bytes.len - offset,
            );
            @memcpy(
                payload[self.payload_written..][0..count],
                bytes[offset..][0..count],
            );
            self.payload_written += count;
            offset += count;
            if (self.payload_written != payload.len) return;

            // Remove ownership from parser state before invoking application
            // code so callback failure cannot leave a completed message stuck.
            self.payload = null;
            self.deliver(payload, context, consume) catch |err| {
                self.allocator.free(payload);
                return err;
            };
            self.allocator.free(payload);
            self.resetMessage();
        }
    }

    /// Mark the HTTP body complete and reject a truncated prefix or payload.
    pub fn finish(self: *Decoder) Error!void {
        if (self.finished) return error.InvalidStreamState;
        if (self.prefix_len != 0 or self.payload != null or
            self.payload_len != 0)
        {
            return error.BufferTooShort;
        }
        self.finished = true;
    }

    fn preparePayload(self: *Decoder) Error!void {
        const compressed_flag = self.prefix[0];
        if (compressed_flag > 1) return error.InvalidCompressedFlag;
        self.payload_len = std.mem.readInt(
            u32,
            self.prefix[1..5],
            .big,
        );
        if (self.payload_len > self.max_message_size) {
            return error.GrpcMessageTooLarge;
        }
        if (compressed_flag == 1) {
            if (self.encoding == .identity) {
                return error.CompressionNotNegotiated;
            }
            if (!self.accepted_encodings.contains(self.encoding)) {
                return error.UnsupportedCompression;
            }
        }
    }

    fn deliver(
        self: Decoder,
        payload: []const u8,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        const was_compressed = self.prefix[0] == 1;
        if (!was_compressed) {
            return consume(context, DecodedMessage{
                .payload = payload,
                .was_compressed = false,
            });
        }
        var decoded = try compression.decompressAlloc(
            self.allocator,
            self.encoding,
            payload,
            self.max_message_size,
        );
        defer decoded.deinit(self.allocator);
        try consume(context, DecodedMessage{
            .payload = decoded.bytes,
            .was_compressed = true,
        });
    }

    fn resetMessage(self: *Decoder) void {
        std.debug.assert(self.payload == null);
        self.prefix_len = 0;
        self.payload_len = 0;
        self.payload_written = 0;
    }
};

pub const Encoder = struct {
    allocator: std.mem.Allocator,
    algorithm: compression.Algorithm = .identity,
    compression_level: u4 = 6,
    max_message_size: usize = 16 * 1024 * 1024,

    /// Write one independently compressed and framed message to an HTTP/2
    /// RequestWriter or ResponseWriter without materializing prefix+payload.
    pub fn writeMessage(
        self: Encoder,
        writer: anytype,
        payload: []const u8,
    ) !void {
        if (payload.len > self.max_message_size) {
            return error.GrpcMessageTooLarge;
        }
        var encoded = try compression.compressAlloc(
            self.allocator,
            self.algorithm,
            payload,
            self.compression_level,
        );
        defer encoded.deinit(self.allocator);
        var prefix: [5]u8 = undefined;
        _ = try wire.writeMessageInto(
            &prefix,
            &.{},
            encoded.compressed,
        );
        std.mem.writeInt(
            u32,
            prefix[1..5],
            @intCast(encoded.bytes.len),
            .big,
        );
        try writer.write(&prefix);
        if (encoded.bytes.len != 0) try writer.write(encoded.bytes);
    }

    /// Encode one message as a single temporary slice for tests, batching or
    /// transports that do not expose a stateful DATA writer.
    pub fn appendMessage(
        self: Encoder,
        out: *std.ArrayList(u8),
        payload: []const u8,
    ) !void {
        if (payload.len > self.max_message_size) {
            return error.GrpcMessageTooLarge;
        }
        var encoded = try compression.compressAlloc(
            self.allocator,
            self.algorithm,
            payload,
            self.compression_level,
        );
        defer encoded.deinit(self.allocator);
        try wire.writeMessage(
            out,
            self.allocator,
            encoded.bytes,
            encoded.compressed,
        );
    }
};

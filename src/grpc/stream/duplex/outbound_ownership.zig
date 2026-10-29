//! Prefix-reserved ownership for queued outbound gRPC messages.

const std = @import("std");
const compression = @import("../../compression.zig");
const wire = @import("../../wire.zig");
const codec = @import("../codec.zig");

/// Prefix-reserved storage that can move from a serializer into a duplex
/// transport without another payload allocation or copy.
pub const OwnedMessage = struct {
    allocator: std.mem.Allocator,
    storage: ?[]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        payload_len: usize,
    ) (std.mem.Allocator.Error || error{GrpcMessageTooLarge})!OwnedMessage {
        const encoded_len = wire.encodedMessageLen(payload_len) catch
            return error.GrpcMessageTooLarge;
        return .{
            .allocator = allocator,
            .storage = try allocator.alloc(u8, encoded_len),
        };
    }

    pub fn payload(self: *OwnedMessage) []u8 {
        return self.storage.?[5..];
    }

    pub fn hasValue(self: *const OwnedMessage) bool {
        return self.storage != null;
    }

    pub fn deinit(self: *OwnedMessage) void {
        if (self.storage) |storage| self.allocator.free(storage);
        self.storage = null;
    }

    pub fn storageFor(
        self: *OwnedMessage,
        allocator: std.mem.Allocator,
    ) error{InvalidStreamState}![]u8 {
        if (self.allocator.ptr != allocator.ptr or
            self.allocator.vtable != allocator.vtable)
        {
            return error.InvalidStreamState;
        }
        return self.storage orelse error.InvalidStreamState;
    }

    pub fn takeFor(
        self: *OwnedMessage,
        allocator: std.mem.Allocator,
    ) error{InvalidStreamState}![]u8 {
        const storage = try self.storageFor(allocator);
        self.storage = null;
        return storage;
    }
};

pub const Encoding = struct {
    bytes: []u8,
    input_transferred: bool,
};

/// `storage` reserves the first five bytes for the gRPC message prefix and
/// owns its payload in the remaining bytes. Identity and compression fallback
/// can therefore prepend the prefix without allocating or copying again.
pub fn encode(
    allocator: std.mem.Allocator,
    encoder: codec.Encoder,
    storage: []u8,
    options: codec.MessageOptions,
) (compression.Error || wire.Error)!Encoding {
    if (storage.len < 5) return error.BufferTooShort;
    const payload = storage[5..];
    if (payload.len > encoder.max_message_size) {
        return error.GrpcMessageTooLarge;
    }
    _ = try wire.encodedMessageLen(payload.len);
    const algorithm = if (options.disable_compression)
        compression.Algorithm.identity
    else
        encoder.algorithm;
    var encoded = try compression.compressAlloc(
        allocator,
        algorithm,
        payload,
        encoder.compression_level,
    );
    defer encoded.deinit(allocator);
    if (!encoded.compressed) {
        storage[0] = 0;
        std.mem.writeInt(u32, storage[1..5], @intCast(payload.len), .big);
        return .{ .bytes = storage, .input_transferred = true };
    }
    const framed = try allocator.alloc(
        u8,
        try wire.encodedMessageLen(encoded.bytes.len),
    );
    errdefer allocator.free(framed);
    _ = try wire.writeMessageInto(framed, encoded.bytes, true);
    return .{ .bytes = framed, .input_transferred = false };
}

/// Encode and conditionally transfer an `OwnedMessage`. On successful
/// identity or compression fallback the returned slice is the exact input
/// allocation and `message` becomes empty. Successful compression returns a
/// separate allocation and leaves the input for the caller's deferred cleanup.
pub fn encodeMessage(
    allocator: std.mem.Allocator,
    encoder: codec.Encoder,
    message: *OwnedMessage,
    options: codec.MessageOptions,
) (compression.Error || wire.Error || error{InvalidStreamState})![]u8 {
    const storage = try message.storageFor(allocator);
    const encoded = try encode(allocator, encoder, storage, options);
    if (encoded.input_transferred) {
        const transferred = try message.takeFor(allocator);
        std.debug.assert(transferred.ptr == encoded.bytes.ptr and
            transferred.len == encoded.bytes.len);
    }
    return encoded.bytes;
}

test "gRPC owned message storage prepends identity without allocation" {
    const allocator = std.testing.allocator;
    const payload = "owned-identity";
    const storage = try allocator.alloc(u8, 5 + payload.len);
    @memcpy(storage[5..], payload);
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const encoded = try encode(
        failing.allocator(),
        .{ .allocator = failing.allocator() },
        storage,
        .{},
    );
    try std.testing.expect(encoded.input_transferred);
    try std.testing.expectEqual(storage.ptr, encoded.bytes.ptr);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(u8, 0), encoded.bytes[0]);
    try std.testing.expectEqual(@as(u32, payload.len), std.mem.readInt(
        u32,
        encoded.bytes[1..5],
        .big,
    ));
    try std.testing.expectEqualStrings(payload, encoded.bytes[5..]);
    allocator.free(encoded.bytes);
}

test "gRPC owned message storage retains input on compressed output" {
    const allocator = std.testing.allocator;
    const payload = "compressible-owned-message-" ** 64;
    const storage = try allocator.alloc(u8, 5 + payload.len);
    defer allocator.free(storage);
    @memcpy(storage[5..], payload);
    const encoded = try encode(
        allocator,
        .{
            .allocator = allocator,
            .algorithm = .gzip,
            .compression_level = 1,
            .max_message_size = payload.len,
        },
        storage,
        .{},
    );
    defer allocator.free(encoded.bytes);
    try std.testing.expect(!encoded.input_transferred);
    try std.testing.expect(encoded.bytes.ptr != storage.ptr);
    try std.testing.expectEqual(@as(u8, 1), encoded.bytes[0]);
    var decoded = try compression.decompressAlloc(
        allocator,
        .gzip,
        encoded.bytes[5..],
        payload.len,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings(payload, decoded.bytes);
}

test "gRPC owned compressed-message staging releases every OOM boundary" {
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const payload = "owned-compression-oom-" ** 64;
            const storage = try allocator.alloc(u8, 5 + payload.len);
            var storage_owned = true;
            defer if (storage_owned) allocator.free(storage);
            @memcpy(storage[5..], payload);
            const encoded = try encode(
                allocator,
                .{
                    .allocator = allocator,
                    .algorithm = .gzip,
                    .compression_level = 1,
                    .max_message_size = payload.len,
                },
                storage,
                .{},
            );
            if (encoded.input_transferred) storage_owned = false;
            defer allocator.free(encoded.bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Scenario.run,
        .{},
    );
}

test "gRPC owned duplex message transfers identity without another allocation" {
    const backing = std.testing.allocator;
    const payload = "owned-duplex-response";
    var counting = std.testing.FailingAllocator.init(backing, .{});
    var message = try OwnedMessage.init(
        counting.allocator(),
        payload.len,
    );
    defer message.deinit();
    @memcpy(message.payload(), payload);
    const storage = message.storage.?;
    counting.fail_index = counting.alloc_index;
    const encoded = try encodeMessage(
        counting.allocator(),
        .{ .allocator = counting.allocator() },
        &message,
        .{},
    );
    defer counting.allocator().free(encoded);
    try std.testing.expect(!message.hasValue());
    try std.testing.expectEqual(storage.ptr, encoded.ptr);
    try std.testing.expect(!counting.has_induced_failure);
}

test "gRPC owned duplex response removes caller-payload allocation" {
    const backing = std.testing.allocator;
    const payload = "serialized-server-response";

    var owned_counting = std.testing.FailingAllocator.init(backing, .{});
    var message = try OwnedMessage.init(
        owned_counting.allocator(),
        payload.len,
    );
    @memcpy(message.payload(), payload);
    const owned = try encodeMessage(
        owned_counting.allocator(),
        .{ .allocator = owned_counting.allocator() },
        &message,
        .{},
    );
    defer owned_counting.allocator().free(owned);
    try std.testing.expectEqual(@as(usize, 1), owned_counting.allocations);

    var borrowed_counting = std.testing.FailingAllocator.init(backing, .{});
    const caller_payload = try borrowed_counting.allocator().dupe(u8, payload);
    defer borrowed_counting.allocator().free(caller_payload);
    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(borrowed_counting.allocator());
    const encoder = codec.Encoder{ .allocator = borrowed_counting.allocator() };
    try encoder.appendMessageWithOptions(&framed, caller_payload, .{});
    try std.testing.expectEqual(@as(usize, 2), borrowed_counting.allocations);
    try std.testing.expectEqualStrings(payload, framed.items[5..]);
}

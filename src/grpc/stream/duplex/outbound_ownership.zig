//! Prefix-reserved ownership for queued outbound gRPC messages.

const std = @import("std");
const compression = @import("../../compression.zig");
const wire = @import("../../wire.zig");
const codec = @import("../codec.zig");

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

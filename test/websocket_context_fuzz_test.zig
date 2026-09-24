//! Bounded RFC 7692 context-takeover sequence fuzzing.
//!
//! Two directional codec pairs retain independent compression histories. The
//! operation stream mixes context takeover, no-context resets, fragmented
//! messages, output-limit failures, repeated messages, and hostile wire input.

const std = @import("std");
const netz = @import("netz");

const max_input_bytes = 4 * 1024;
const max_operations = 48;
const max_message_bytes = 256;

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const takeover_seed = smithSliceSeed(&.{
    15, 15,
    0,  63,
    12, 0,
    2,  47,
    12, 0,
    1,  63,
    13, 0,
    3,  47,
    13, 0,
});
const reset_seed = smithSliceSeed(&.{
    8,  9,
    0,  31,
    12, 0,
    6,  0,
    12, 0,
    1,  31,
    13, 0,
    7,  0,
    13, 0,
});
const no_context_seed = smithSliceSeed(&.{
    12, 13,
    4,  63,
    4,  63,
    2,  31,
    5,  63,
    5,  63,
    3,  31,
});
const hostile_seed = smithSliceSeed(&.{
    15, 8,
    8,  0xff,
    9,  0x80,
    0,  47,
    10, 47,
    12, 0,
    1,  47,
    11, 47,
    13, 0,
});

const corpus = &.{
    &takeover_seed,
    &reset_seed,
    &no_context_seed,
    &hostile_seed,
};

test "structured WebSocket context-takeover sequences reach target states" {
    const takeover = try exerciseSequence(takeover_seed[4..]);
    try std.testing.expect(takeover.takeover_messages >= 6);
    try std.testing.expect(takeover.fragmented_messages >= 2);
    try std.testing.expect(takeover.repeated_messages >= 2);

    const reset = try exerciseSequence(reset_seed[4..]);
    try std.testing.expect(reset.resets >= 2);

    const no_context = try exerciseSequence(no_context_seed[4..]);
    try std.testing.expect(no_context.no_context_messages >= 4);

    const hostile = try exerciseSequence(hostile_seed[4..]);
    try std.testing.expect(hostile.hostile_attempts >= 2);
    try std.testing.expect(hostile.transactional_failures >= 2);

    for (8..16) |bits| {
        const window_sequence = [_]u8{
            @intCast(bits), @intCast(bits),
            0,              63,
            2,              63,
            12,             0,
        };
        const window = try exerciseSequence(&window_sequence);
        try std.testing.expect(window.takeover_messages >= 3);
        try std.testing.expectEqual(@as(usize, 1), window.fragmented_messages);
        try std.testing.expectEqual(@as(usize, 1), window.repeated_messages);
    }
}

test "fuzz bounded WebSocket context takeover" {
    try std.testing.fuzz({}, fuzzContextTakeover, .{ .corpus = corpus });
}

test "bounded deterministic WebSocket context-takeover mutation smoke" {
    var storage: [max_input_bytes]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (0..seed.len + 1) |length| {
            _ = try exerciseSequence(seed[0..length]);
        }
        for (seed, 0..) |_, index| {
            @memcpy(storage[0..seed.len], seed);
            storage[index] ^= 0xff;
            _ = try exerciseSequence(storage[0..seed.len]);
        }
    }

    var prng = std.Random.DefaultPrng.init(0x77735f6374785f66);
    const random = prng.random();
    for (0..32) |_| {
        const len = random.uintLessThan(usize, 513);
        random.bytes(storage[0..len]);
        _ = try exerciseSequence(storage[0..len]);
    }
}

fn fuzzContextTakeover(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try exerciseSequence(bytes);
}

const Summary = struct {
    takeover_messages: usize = 0,
    no_context_messages: usize = 0,
    fragmented_messages: usize = 0,
    repeated_messages: usize = 0,
    hostile_attempts: usize = 0,
    transactional_failures: usize = 0,
    resets: usize = 0,
};

const Direction = struct {
    compressor: netz.websocket.CompressionContext,
    decompressor: netz.websocket.DecompressionContext,
    hostile: netz.websocket.DecompressionContext,
    wire: std.ArrayList(u8) = .empty,
    output: std.ArrayList(u8) = .empty,
    hostile_output: std.ArrayList(u8) = .empty,
    last_message: [max_message_bytes]u8 = undefined,
    last_message_len: usize = 0,

    fn init(
        allocator: std.mem.Allocator,
        window_bits: u8,
    ) !Direction {
        var compressor = try netz.websocket.CompressionContext.init(
            allocator,
            window_bits,
        );
        errdefer compressor.deinit();
        var decompressor = try netz.websocket.DecompressionContext.init(
            allocator,
            window_bits,
        );
        errdefer decompressor.deinit();
        const hostile = try netz.websocket.DecompressionContext.init(
            allocator,
            window_bits,
        );
        return .{
            .compressor = compressor,
            .decompressor = decompressor,
            .hostile = hostile,
        };
    }

    fn deinit(self: *Direction, allocator: std.mem.Allocator) void {
        self.compressor.deinit();
        self.decompressor.deinit();
        self.hostile.deinit();
        self.wire.deinit(allocator);
        self.output.deinit(allocator);
        self.hostile_output.deinit(allocator);
        self.* = undefined;
    }

    fn reset(self: *Direction) void {
        self.compressor.resetContext();
        self.decompressor.resetContext();
    }

    fn roundTrip(
        self: *Direction,
        payload: []const u8,
        fragmented: bool,
        no_context_takeover: bool,
    ) !void {
        if (no_context_takeover) self.reset();
        const encoded = if (fragmented) blk: {
            const first = payload.len / 3;
            const second = first + (payload.len - first) / 2;
            const fragments = [_][]const u8{
                payload[0..first],
                payload[first..second],
                payload[second..],
            };
            break :blk try self.compressor.compressFragmentsInto(
                &self.wire,
                &fragments,
            );
        } else try self.compressor.compressInto(&self.wire, payload);
        const decoded = try self.decompressor.decompressInto(
            &self.output,
            encoded,
            payload.len,
        );
        try std.testing.expectEqualSlices(u8, payload, decoded);
        @memmove(self.last_message[0..payload.len], payload);
        self.last_message_len = payload.len;
        if (no_context_takeover) self.reset();
    }

    fn roundTripAfterLimitFailure(
        self: *Direction,
        payload: []const u8,
    ) !void {
        const encoded = try self.compressor.compressInto(
            &self.wire,
            payload,
        );
        try std.testing.expect(payload.len != 0);
        try std.testing.expectError(
            error.PayloadTooLarge,
            self.decompressor.decompressInto(
                &self.output,
                encoded,
                payload.len - 1,
            ),
        );
        try std.testing.expectEqualSlices(
            u8,
            payload,
            try self.decompressor.decompressInto(
                &self.output,
                encoded,
                payload.len,
            ),
        );
        @memmove(self.last_message[0..payload.len], payload);
        self.last_message_len = payload.len;
    }

    fn repeatLast(self: *Direction) !bool {
        if (self.last_message_len == 0) return false;
        try self.roundTrip(
            self.last_message[0..self.last_message_len],
            false,
            false,
        );
        return true;
    }

    fn hostileDecode(self: *Direction, bytes: []const u8) !void {
        if (self.hostile.decompressInto(
            &self.hostile_output,
            bytes,
            max_message_bytes,
        )) |decoded| {
            try std.testing.expect(decoded.len <= max_message_bytes);
        } else |_| {}
    }
};

fn exerciseSequence(bytes: []const u8) !Summary {
    const allocator = std.testing.allocator;
    var client = try Direction.init(allocator, windowBits(byteAt(bytes, 0)));
    defer client.deinit(allocator);
    var server = try Direction.init(allocator, windowBits(byteAt(bytes, 1)));
    defer server.deinit(allocator);
    var summary: Summary = .{};
    var message: [max_message_bytes]u8 = undefined;

    const operations = @min((bytes.len -| 2) / 2, max_operations);
    for (0..operations) |index| {
        const offset = 2 + index * 2;
        const opcode = bytes[offset] & 0x0f;
        const argument = bytes[offset + 1];
        const payload = buildMessage(&message, bytes, index, argument);
        switch (opcode) {
            0 => {
                try client.roundTrip(payload, false, false);
                summary.takeover_messages += 1;
            },
            1 => {
                try server.roundTrip(payload, false, false);
                summary.takeover_messages += 1;
            },
            2 => {
                try client.roundTrip(payload, true, false);
                summary.takeover_messages += 1;
                summary.fragmented_messages += 1;
            },
            3 => {
                try server.roundTrip(payload, true, false);
                summary.takeover_messages += 1;
                summary.fragmented_messages += 1;
            },
            4 => {
                try client.roundTrip(payload, false, true);
                summary.no_context_messages += 1;
            },
            5 => {
                try server.roundTrip(payload, false, true);
                summary.no_context_messages += 1;
            },
            6 => {
                client.reset();
                summary.resets += 1;
            },
            7 => {
                server.reset();
                summary.resets += 1;
            },
            8 => {
                try client.hostileDecode(hostileSlice(bytes, offset));
                summary.hostile_attempts += 1;
            },
            9 => {
                try server.hostileDecode(hostileSlice(bytes, offset));
                summary.hostile_attempts += 1;
            },
            10 => {
                try client.roundTripAfterLimitFailure(payload);
                summary.transactional_failures += 1;
            },
            11 => {
                try server.roundTripAfterLimitFailure(payload);
                summary.transactional_failures += 1;
            },
            12 => if (try client.repeatLast()) {
                summary.takeover_messages += 1;
                summary.repeated_messages += 1;
            },
            13 => if (try server.repeatLast()) {
                summary.takeover_messages += 1;
                summary.repeated_messages += 1;
            },
            14 => {
                client.reset();
                server.reset();
                summary.resets += 2;
            },
            15 => {
                try client.roundTrip(payload, true, true);
                try server.roundTrip(payload, true, true);
                summary.no_context_messages += 2;
                summary.fragmented_messages += 2;
            },
            else => unreachable,
        }
    }
    return summary;
}

fn buildMessage(
    storage: *[max_message_bytes]u8,
    bytes: []const u8,
    operation_index: usize,
    argument: u8,
) []const u8 {
    const len = 1 + @as(usize, argument) % max_message_bytes;
    const phrase = "permessage-deflate context takeover ";
    for (storage[0..len], 0..) |*byte, index| {
        byte.* = switch ((argument >> 6) & 0x03) {
            0 => phrase[index % phrase.len],
            1 => byteAt(bytes, operation_index + index),
            2 => @truncate((index / 8) + operation_index),
            3 => argument,
            else => unreachable,
        };
    }
    return storage[0..len];
}

fn hostileSlice(bytes: []const u8, offset: usize) []const u8 {
    if (bytes.len == 0) return &.{};
    const start = @min(offset, bytes.len);
    return bytes[start..@min(bytes.len, start + max_message_bytes)];
}

fn windowBits(byte: u8) u8 {
    return 8 + byte % 8;
}

fn byteAt(bytes: []const u8, index: usize) u8 {
    return if (bytes.len == 0) 0 else bytes[index % bytes.len];
}

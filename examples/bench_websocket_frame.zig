const std = @import("std");
const netz = @import("netz");

const iterations: usize = 200_000;
const payload_len: usize = 4096;
const compression_iterations: usize = 20_000;
const compression_fragments: usize = 16;
const mask_key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);

    var allocating: std.ArrayList(u8) = .empty;
    defer allocating.deinit(allocator);
    const allocating_started = nowNs(io);
    var allocating_checksum: u64 = 0;
    for (0..iterations) |iteration| {
        const current_payload = payload[0 .. payload.len - (iteration & 3)];
        var current_mask = mask_key;
        current_mask[0] +%= @truncate(iteration);
        allocating.clearAndFree(allocator);
        try netz.websocket.writeFrameExtended(
            &allocating,
            allocator,
            .binary,
            current_payload,
            .{ .mask_key = current_mask },
        );
        allocating_checksum +%= checksum(allocating.items);
    }
    const allocating_ns = nowNs(io) -| allocating_started;

    var encoded_storage: [
        payload_len +
            netz.websocket.max_frame_header_len
    ]u8 align(64) = undefined;
    const caller_buffer_started = nowNs(io);
    var caller_buffer_checksum: u64 = 0;
    for (0..iterations) |iteration| {
        const current_payload = payload[0 .. payload.len - (iteration & 3)];
        var current_mask = mask_key;
        current_mask[0] +%= @truncate(iteration);
        const encoded = try netz.websocket.writeFrameInto(
            &encoded_storage,
            .binary,
            current_payload,
            .{ .mask_key = current_mask },
        );
        caller_buffer_checksum +%= checksum(encoded);
    }
    const caller_buffer_ns = nowNs(io) -| caller_buffer_started;

    var header_storage: [netz.websocket.max_frame_header_len]u8 = undefined;
    const header_started = nowNs(io);
    var header_checksum: u64 = 0;
    for (0..iterations) |iteration| {
        const current_payload = payload[0 .. payload.len - (iteration & 3)];
        var current_mask = mask_key;
        current_mask[0] +%= @truncate(iteration);
        const header = try netz.websocket.writeFrameHeaderInto(
            &header_storage,
            .binary,
            current_payload,
            .{ .mask_key = current_mask },
        );
        header_checksum +%= checksum(header);
    }
    const header_ns = nowNs(io) -| header_started;

    var compressible: [payload_len]u8 = undefined;
    for (&compressible, 0..) |*byte, index| {
        byte.* = "sensor=42;status=nominal;"[
            index % "sensor=42;status=nominal;".len
        ];
    }
    var compression_output: std.ArrayList(u8) = .empty;
    defer compression_output.deinit(allocator);
    const compression_window = try allocator.alloc(
        u8,
        std.compress.flate.max_window_len,
    );
    defer allocator.free(compression_window);
    _ = try netz.websocket.compressMessageInto(
        &compression_output,
        allocator,
        compression_window,
        &compressible,
    );
    const compressed_bytes = compression_output.items.len;
    const compression_started = nowNs(io);
    var compression_checksum: u64 = 0;
    for (0..compression_iterations) |_| {
        const compressed = try netz.websocket.compressMessageInto(
            &compression_output,
            allocator,
            compression_window,
            &compressible,
        );
        compression_checksum +%= checksum(compressed);
    }
    const compression_ns = nowNs(io) -| compression_started;

    var fragment_storage: [compression_fragments][]const u8 = undefined;
    for (&fragment_storage, 0..) |*fragment, index| {
        const start = index * payload_len / compression_fragments;
        const end = (index + 1) * payload_len / compression_fragments;
        fragment.* = compressible[start..end];
    }
    const fragmented_started = nowNs(io);
    var fragmented_checksum: u64 = 0;
    for (0..compression_iterations) |_| {
        const compressed = try netz.websocket
            .compressMessageFragmentsInto(
            &compression_output,
            allocator,
            compression_window,
            &fragment_storage,
        );
        fragmented_checksum +%= checksum(compressed);
    }
    const fragmented_ns = nowNs(io) -| fragmented_started;

    const caller_speedup_x100 = ratioTimes100(
        allocating_ns,
        caller_buffer_ns,
    );
    const header_speedup_x100 = ratioTimes100(
        allocating_ns,
        header_ns,
    );
    std.debug.print(
        \\WebSocket frame encode benchmark
        \\  iterations: {d}, payload bytes: {d}
        \\  allocating masked frame: {d} ns/op
        \\  caller-buffer masked frame: {d} ns/op
        \\  header-only stream preparation: {d:.2} ns/op
        \\  caller-buffer speedup: {d}.{d:0>2}x
        \\  header-only speedup: {d}.{d:0>2}x
        \\  permessage-deflate: {d} ns/message, {d} -> {d} wire bytes
        \\  fragmented deflate ({d} slices): {d} ns/message, no plaintext join
        \\  checksum: {d}
        \\
    , .{
        iterations,
        payload_len,
        allocating_ns / iterations,
        caller_buffer_ns / iterations,
        @as(f64, @floatFromInt(header_ns)) /
            @as(f64, @floatFromInt(iterations)),
        caller_speedup_x100 / 100,
        caller_speedup_x100 % 100,
        header_speedup_x100 / 100,
        header_speedup_x100 % 100,
        compression_ns / compression_iterations,
        compressible.len,
        compressed_bytes,
        compression_fragments,
        fragmented_ns / compression_iterations,
        allocating_checksum +%
            caller_buffer_checksum +%
            header_checksum +%
            compression_checksum +%
            fragmented_checksum,
    });
}

fn checksum(bytes: []const u8) u64 {
    if (bytes.len == 0) return 0;
    return @as(u64, bytes[0]) +%
        @as(u64, bytes[bytes.len / 2]) +%
        @as(u64, bytes[bytes.len - 1]) +%
        bytes.len;
}

fn ratioTimes100(numerator: u64, denominator: u64) u64 {
    if (denominator == 0) return 0;
    return (numerator *| 100) / denominator;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

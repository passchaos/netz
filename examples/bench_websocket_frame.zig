const std = @import("std");
const netz = @import("netz");

const iterations: usize = 200_000;
const payload_len: usize = 4096;
const compression_iterations: usize = 20_000;
const utf8_iterations: usize = 500_000;
const compression_fragments: usize = 16;
const parse_iterations: usize = 2_000_000;
const mask_key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

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
    _ = try netz.websocket.compressMessageVortInto(
        &compression_output,
        allocator,
        &compressible,
    );
    const compressed_bytes = compression_output.items.len;
    const compression_started = nowNs(io);
    var compression_checksum: u64 = 0;
    for (0..compression_iterations) |_| {
        const compressed = try netz.websocket.compressMessageVortInto(
            &compression_output,
            allocator,
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
    _ = try netz.websocket.compressMessageFragmentsVortInto(
        &compression_output,
        allocator,
        &fragment_storage,
    );
    const fragmented_bytes = compression_output.items.len;
    const fragmented_started = nowNs(io);
    var fragmented_checksum: u64 = 0;
    for (0..compression_iterations) |_| {
        const compressed = try netz.websocket
            .compressMessageFragmentsVortInto(
            &compression_output,
            allocator,
            &fragment_storage,
        );
        fragmented_checksum +%= checksum(compressed);
    }
    const fragmented_ns = nowNs(io) -| fragmented_started;

    var ascii_text: [payload_len]u8 = undefined;
    for (&ascii_text, 0..) |*byte, index| {
        byte.* = "sensor=42;status=nominal;"[
            index % "sensor=42;status=nominal;".len
        ];
    }
    const utf8_scalar_started = nowNs(io);
    var utf8_scalar_checksum: u64 = 0;
    for (0..utf8_iterations) |_| {
        var validator: netz.websocket.Utf8Validator = .{};
        for (&ascii_text) |byte| try validator.feedByte(byte);
        try validator.finish();
        utf8_scalar_checksum +%= validator.remaining + ascii_text[0];
    }
    const utf8_scalar_ns = nowNs(io) -| utf8_scalar_started;
    const utf8_started = nowNs(io);
    var utf8_checksum: u64 = 0;
    for (0..utf8_iterations) |_| {
        var validator: netz.websocket.Utf8Validator = .{};
        try validator.feed(&ascii_text);
        try validator.finish();
        utf8_checksum +%= validator.remaining + ascii_text[0];
    }
    const utf8_ns = nowNs(io) -| utf8_started;

    var sparse_unicode = ascii_text;
    const snowman = "\xe2\x98\x83";
    var unicode_offset: usize = 253;
    while (unicode_offset + snowman.len <= sparse_unicode.len) : (unicode_offset += 256) {
        @memcpy(sparse_unicode[unicode_offset..][0..snowman.len], snowman);
    }
    const sparse_scalar_started = nowNs(io);
    var sparse_scalar_checksum: u64 = 0;
    for (0..utf8_iterations) |_| {
        var validator: netz.websocket.Utf8Validator = .{};
        for (&sparse_unicode) |byte| try validator.feedByte(byte);
        try validator.finish();
        sparse_scalar_checksum +%= validator.remaining + sparse_unicode[0];
    }
    const sparse_scalar_ns = nowNs(io) -| sparse_scalar_started;
    const sparse_started = nowNs(io);
    var sparse_checksum: u64 = 0;
    for (0..utf8_iterations) |_| {
        var validator: netz.websocket.Utf8Validator = .{};
        try validator.feed(&sparse_unicode);
        try validator.finish();
        sparse_checksum +%= validator.remaining + sparse_unicode[0];
    }
    const sparse_ns = nowNs(io) -| sparse_started;

    var masked_text = ascii_text;
    const masked_offset: usize = 3;
    netz.websocket.applyMask(&masked_text, mask_key, masked_offset);
    const masked_utf8_scalar_started = nowNs(io);
    var masked_utf8_scalar_checksum: u64 = 0;
    for (0..utf8_iterations) |_| {
        var validator: netz.websocket.Utf8Validator = .{};
        for (&masked_text, 0..) |byte, index| {
            try validator.feedByte(
                byte ^ mask_key[(masked_offset + index) & 3],
            );
        }
        try validator.finish();
        masked_utf8_scalar_checksum +%= validator.remaining + masked_text[0];
    }
    const masked_utf8_scalar_ns = nowNs(io) -| masked_utf8_scalar_started;
    const masked_utf8_started = nowNs(io);
    var masked_utf8_checksum: u64 = 0;
    for (0..utf8_iterations) |_| {
        var validator: netz.websocket.Utf8Validator = .{};
        try validator.feedMasked(&masked_text, mask_key, masked_offset);
        try validator.finish();
        masked_utf8_checksum +%= validator.remaining + masked_text[0];
    }
    const masked_utf8_ns = nowNs(io) -| masked_utf8_started;

    var masked_copy_output: [payload_len]u8 = undefined;
    const masked_copy_two_pass_started = nowNs(io);
    var masked_copy_two_pass_checksum: u64 = 0;
    for (0..utf8_iterations) |_| {
        var validator: netz.websocket.Utf8Validator = .{};
        try netz.websocket.applyMaskCopy(
            &masked_copy_output,
            &masked_text,
            mask_key,
            masked_offset,
        );
        try validator.feed(&masked_copy_output);
        try validator.finish();
        masked_copy_two_pass_checksum +%= checksum(&masked_copy_output);
    }
    const masked_copy_two_pass_ns =
        nowNs(io) -| masked_copy_two_pass_started;
    const masked_copy_fused_started = nowNs(io);
    var masked_copy_fused_checksum: u64 = 0;
    for (0..utf8_iterations) |_| {
        var validator: netz.websocket.Utf8Validator = .{};
        try validator.feedMaskedCopy(
            &masked_copy_output,
            &masked_text,
            mask_key,
            masked_offset,
        );
        try validator.finish();
        masked_copy_fused_checksum +%= checksum(&masked_copy_output);
    }
    const masked_copy_fused_ns = nowNs(io) -| masked_copy_fused_started;

    var parse_storage: [32]u8 = undefined;
    const parse_frame = try netz.websocket.writeFrameInto(
        &parse_storage,
        .binary,
        "payload",
        .{ .mask_key = mask_key },
    );
    const parse_started = nowNs(io);
    var parse_checksum: u64 = 0;
    for (0..parse_iterations) |iteration| {
        parse_frame[parse_frame.len - 1] = @truncate(iteration);
        std.mem.doNotOptimizeAway(parse_frame.ptr);
        const first = try netz.websocket.FrameHeader.parse(parse_frame);
        const second = try netz.websocket.FrameHeader.parse(parse_frame);
        std.mem.doNotOptimizeAway(first);
        std.mem.doNotOptimizeAway(second);
        parse_checksum +%= first.header_len + second.payload_len;
    }
    const parse_ns = nowNs(io) -| parse_started;
    const reused_parse_started = nowNs(io);
    var reused_parse_checksum: u64 = 0;
    for (0..parse_iterations) |iteration| {
        parse_frame[parse_frame.len - 1] = @truncate(iteration);
        std.mem.doNotOptimizeAway(parse_frame.ptr);
        const header = try netz.websocket.FrameHeader.parse(parse_frame);
        std.mem.doNotOptimizeAway(header);
        reused_parse_checksum +%= header.header_len + header.payload_len;
    }
    const reused_parse_ns = nowNs(io) -| reused_parse_started;

    var aggregate_wire_storage: [
        payload_len + netz.websocket.max_frame_header_len
    ]u8 = undefined;
    const aggregate_wire = try netz.websocket.writeFrameInto(
        &aggregate_wire_storage,
        .binary,
        &payload,
        .{},
    );
    const aggregate_header = try netz.websocket.FrameHeader.parse(
        aggregate_wire,
    );
    const owned_parse_started = nowNs(io);
    var owned_parse_checksum: u64 = 0;
    for (0..iterations) |_| {
        var frame = try netz.websocket.parseFrameWithHeader(
            allocator,
            aggregate_wire,
            aggregate_header,
            .{ .expect_mask = .unmasked },
        );
        owned_parse_checksum +%= checksum(frame.payload);
        frame.deinit(allocator);
    }
    const owned_parse_ns = nowNs(io) -| owned_parse_started;
    const in_place_parse_started = nowNs(io);
    var in_place_parse_checksum: u64 = 0;
    for (0..iterations) |_| {
        const frame = try netz.websocket.parseFrameInPlaceWithHeader(
            aggregate_wire,
            aggregate_header,
            .{ .expect_mask = .unmasked },
        );
        in_place_parse_checksum +%= checksum(frame.payload);
    }
    const in_place_parse_ns = nowNs(io) -| in_place_parse_started;

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
        \\  io backend: zio-std-io
        \\  iterations: {d}, payload bytes: {d}
        \\  allocating masked frame: {d} ns/op
        \\  caller-buffer masked frame: {d} ns/op
        \\  header-only stream preparation: {d:.2} ns/op
        \\  caller-buffer speedup: {d}.{d:0>2}x
        \\  header-only speedup: {d}.{d:0>2}x
        \\  permessage-deflate: {d} ns/message, {d} -> {d} wire bytes
        \\  fragmented deflate ({d} slices): {d} ns/message, {d} -> {d} wire bytes, no plaintext join
        \\  incremental UTF-8 scalar reference: {d:.2} ns/message
        \\  incremental UTF-8 ASCII validation: {d:.2} ns/message
        \\  incremental UTF-8 ASCII speedup: {d:.2}x
        \\  incremental UTF-8 sparse scalar: {d:.2} ns/message
        \\  incremental UTF-8 sparse validation: {d:.2} ns/message
        \\  incremental UTF-8 sparse speedup: {d:.2}x
        \\  masked UTF-8 scalar validation: {d:.2} ns/message
        \\  masked UTF-8 vector validation: {d:.2} ns/message
        \\  masked UTF-8 speedup: {d:.2}x
        \\  masked copy + UTF-8 two-pass: {d:.2} ns/message
        \\  masked copy + UTF-8 fused: {d:.2} ns/message
        \\  masked copy + UTF-8 fused speedup: {d:.2}x
        \\  duplicate frame-header parse: {d:.2} ns/frame
        \\  reused frame-header parse: {d:.2} ns/frame
        \\  frame-header reuse speedup: {d:.2}x
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
        compressible.len,
        fragmented_bytes,
        @as(f64, @floatFromInt(utf8_scalar_ns)) /
            @as(f64, @floatFromInt(utf8_iterations)),
        @as(f64, @floatFromInt(utf8_ns)) /
            @as(f64, @floatFromInt(utf8_iterations)),
        @as(f64, @floatFromInt(utf8_scalar_ns)) /
            @as(f64, @floatFromInt(@max(utf8_ns, 1))),
        @as(f64, @floatFromInt(sparse_scalar_ns)) /
            @as(f64, @floatFromInt(utf8_iterations)),
        @as(f64, @floatFromInt(sparse_ns)) /
            @as(f64, @floatFromInt(utf8_iterations)),
        @as(f64, @floatFromInt(sparse_scalar_ns)) /
            @as(f64, @floatFromInt(@max(sparse_ns, 1))),
        @as(f64, @floatFromInt(masked_utf8_scalar_ns)) /
            @as(f64, @floatFromInt(utf8_iterations)),
        @as(f64, @floatFromInt(masked_utf8_ns)) /
            @as(f64, @floatFromInt(utf8_iterations)),
        @as(f64, @floatFromInt(masked_utf8_scalar_ns)) /
            @as(f64, @floatFromInt(@max(masked_utf8_ns, 1))),
        @as(f64, @floatFromInt(masked_copy_two_pass_ns)) /
            @as(f64, @floatFromInt(utf8_iterations)),
        @as(f64, @floatFromInt(masked_copy_fused_ns)) /
            @as(f64, @floatFromInt(utf8_iterations)),
        @as(f64, @floatFromInt(masked_copy_two_pass_ns)) /
            @as(f64, @floatFromInt(@max(masked_copy_fused_ns, 1))),
        @as(f64, @floatFromInt(parse_ns)) /
            @as(f64, @floatFromInt(parse_iterations)),
        @as(f64, @floatFromInt(reused_parse_ns)) /
            @as(f64, @floatFromInt(parse_iterations)),
        @as(f64, @floatFromInt(parse_ns)) /
            @as(f64, @floatFromInt(@max(reused_parse_ns, 1))),
        allocating_checksum +%
            caller_buffer_checksum +%
            header_checksum +%
            compression_checksum +%
            fragmented_checksum +%
            utf8_scalar_checksum +%
            utf8_checksum +%
            sparse_scalar_checksum +%
            sparse_checksum +%
            masked_utf8_scalar_checksum +%
            masked_utf8_checksum +%
            masked_copy_two_pass_checksum +%
            masked_copy_fused_checksum +%
            parse_checksum +%
            reused_parse_checksum +%
            owned_parse_checksum +%
            in_place_parse_checksum,
    });
    std.debug.print(
        \\  owned aggregate-frame parse: {d:.2} ns/frame
        \\  in-place aggregate-frame parse: {d:.2} ns/frame
        \\  in-place aggregate-frame speedup: {d:.2}x
        \\
    , .{
        @as(f64, @floatFromInt(owned_parse_ns)) /
            @as(f64, @floatFromInt(iterations)),
        @as(f64, @floatFromInt(in_place_parse_ns)) /
            @as(f64, @floatFromInt(iterations)),
        @as(f64, @floatFromInt(owned_parse_ns)) /
            @as(f64, @floatFromInt(@max(in_place_parse_ns, 1))),
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

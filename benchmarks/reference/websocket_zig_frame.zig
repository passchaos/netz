//! Direct frame-hot-path driver for `~/Work/websocket.zig`.
//!
//! This file is intentionally not part of `zig build examples`: it depends on
//! a user-owned checkout supplied explicitly as the `proto` module. See
//! `docs/benchmark-baseline.md` for the reproducible build command.
const std = @import("std");
const proto = @import("proto");

const iterations: usize = 200_000;
const payload_len: usize = 4096;
const mask_key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var original: [payload_len]u8 = undefined;
    for (&original, 0..) |*byte, index| byte.* = @truncate(index);
    var payload: [payload_len]u8 align(64) = undefined;
    var header: [14]u8 = undefined;

    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |iteration| {
        const len = payload.len - (iteration & 3);
        // websocket.zig masks its mutable client payload in place. Copy first
        // to benchmark the immutable-input contract exposed by netz.
        @memcpy(payload[0..len], original[0..len]);
        var mask = mask_key;
        mask[0] +%= @truncate(iteration);

        const encoded_header = proto.writeFrameHeader(
            &header,
            .binary,
            len,
            false,
        );
        header[1] |= 0x80;
        @memcpy(header[encoded_header.len..][0..mask.len], &mask);
        proto.mask(&mask, payload[0..len]);
        checksum +%= @as(u64, header[0]) +%
            header[encoded_header.len] +%
            payload[len / 2] +%
            len;
    }
    const elapsed = nowNs(io) -| started;

    std.debug.print(
        "websocket.zig frame header + payload copy/mask: " ++
            "{d} ns/op, checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

const std = @import("std");
const netz = @import("netz");

const chunk_size: usize = 1024;
const chunks: usize = 100_000;
const window_size: usize = 16 * 1024;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var state = netz.quic.stream_state.RecvState.init(
        allocator,
        0,
        window_size,
    );
    defer state.deinit();
    var chunk: [chunk_size]u8 = undefined;
    for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);

    var peak_retained: usize = 0;
    const started = nowNs(io);
    for (0..chunks) |index| {
        try state.insert(.{
            .stream_id = 0,
            .offset = index * chunk_size,
            .data = &chunk,
            .fin = index + 1 == chunks,
        });
        peak_retained = @max(peak_retained, state.buffer.items.len);
        try state.consume(chunk.len);
    }
    const elapsed = nowNs(io) -| started;
    const total_bytes = chunks * chunk_size;
    const legacy_retained = total_bytes;
    const retained_ratio = if (peak_retained == 0)
        0
    else
        legacy_retained / peak_retained;

    std.debug.print(
        \\QUIC receive sliding-window benchmark
        \\  chunks: {d}, bytes/chunk: {d}, total bytes: {d}
        \\  ns/chunk: {d}, ns/byte: {d}
        \\  peak retained bytes: {d}
        \\  legacy absolute-offset retained bytes: {d}
        \\  retained-memory reduction: {d}x
        \\
    , .{
        chunks,
        chunk_size,
        total_bytes,
        elapsed / chunks,
        elapsed / total_bytes,
        peak_retained,
        legacy_retained,
        retained_ratio,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

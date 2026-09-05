const std = @import("std");
const netz = @import("netz");
const buffer = netz.websocket.runtime.ReceiveBuffer;

const frame_size: usize = 8;
const frame_count: usize = 8192;
const iterations: usize = 20;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const input = try allocator.alloc(u8, frame_size * frame_count);
    defer allocator.free(input);
    for (input, 0..) |*byte, index| byte.* = @truncate(index * 17 + 3);

    var eager: std.ArrayList(u8) = .empty;
    defer eager.deinit(allocator);
    var lazy: std.ArrayList(u8) = .empty;
    defer lazy.deinit(allocator);
    try eager.ensureTotalCapacityPrecise(allocator, input.len);
    try lazy.ensureTotalCapacityPrecise(allocator, input.len);

    var checksum: u64 = 0;
    var eager_moved: u128 = 0;
    const eager_started = nowNs(io);
    for (0..iterations) |_| {
        eager.clearRetainingCapacity();
        eager.appendSliceAssumeCapacity(input);
        for (0..frame_count) |_| {
            const remaining = eager.items[frame_size..];
            eager_moved += remaining.len;
            if (remaining.len != 0) {
                @memmove(eager.items[0..remaining.len], remaining);
                checksum +%= eager.items[0];
            }
            eager.shrinkRetainingCapacity(remaining.len);
        }
    }
    const eager_ns = nowNs(io) -| eager_started;

    var lazy_moved: u128 = 0;
    const lazy_started = nowNs(io);
    for (0..iterations) |_| {
        lazy.clearRetainingCapacity();
        lazy.appendSliceAssumeCapacity(input);
        var consumed: usize = 0;
        for (0..frame_count) |_| {
            lazy_moved += buffer.discardPrefix(
                &lazy,
                &consumed,
                frame_size,
            );
            const available = buffer.unread(&lazy, consumed);
            if (available.len != 0) checksum +%= available[0];
        }
    }
    const lazy_ns = nowNs(io) -| lazy_started;

    if (eager.items.len != 0 or lazy.items.len != 0) {
        return error.InvalidBenchmarkResult;
    }
    std.debug.print(
        \\WebSocket coalesced receive-buffer benchmark
        \\  frames/batch: {d}, frame bytes: {d}, iterations: {d}
        \\  eager memmove: {d:.2} ns/frame, moved={d} bytes
        \\  lazy window: {d:.2} ns/frame, moved={d} bytes
        \\  speedup: {d:.2}x, checksum={d}
        \\
    , .{
        frame_count,
        frame_size,
        iterations,
        perFrame(eager_ns),
        eager_moved,
        perFrame(lazy_ns),
        lazy_moved,
        @as(f64, @floatFromInt(eager_ns)) /
            @as(f64, @floatFromInt(@max(lazy_ns, 1))),
        checksum,
    });
}

fn perFrame(elapsed: u64) f64 {
    return @as(f64, @floatFromInt(elapsed)) /
        @as(f64, @floatFromInt(iterations * frame_count));
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

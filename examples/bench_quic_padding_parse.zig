const std = @import("std");
const netz = @import("netz");

const iterations: usize = 1_000_000;
const padding_len: usize = 1200;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var payload: [padding_len + 1]u8 = .{0} ** (padding_len + 1);
    payload[payload.len - 1] = @intFromEnum(netz.quic.FrameType.ping);

    const padding_only_ns, const padding_only_checksum = try measurePaddingOnly(io, payload[0..padding_len]);
    const padding_then_ping_ns, const padding_then_ping_checksum = try measurePaddingThenPing(io, &payload);
    const checksum = padding_only_checksum +% padding_then_ping_checksum;

    std.debug.print(
        \\QUIC PADDING parse benchmark
        \\  iterations: {d}, padding bytes: {d}
        \\  padding-only payload:  {d} ns/op
        \\  padding before PING:   {d} ns/op
        \\  checksum: {d}
        \\
    , .{
        iterations,
        padding_len,
        padding_only_ns / iterations,
        padding_then_ping_ns / iterations,
        checksum,
    });
}

fn measurePaddingOnly(io: std.Io, payload: []const u8) !struct { u64, u64 } {
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        const parsed = try netz.quic.parseFrame(payload);
        checksum +%= parsed.consumed;
        checksum +%= parsed.frame.padding.len;
    }
    return .{ nowNs(io) -| started, checksum };
}

fn measurePaddingThenPing(io: std.Io, payload: []const u8) !struct { u64, u64 } {
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        const parsed = try netz.quic.parseFrame(payload);
        checksum +%= parsed.consumed;
        checksum +%= parsed.frame.padding.len;
        const ping = try netz.quic.parseFrame(payload[parsed.consumed..]);
        checksum +%= @intFromEnum(std.meta.activeTag(ping.frame));
    }
    return .{ nowNs(io) -| started, checksum };
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

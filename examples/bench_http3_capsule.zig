const std = @import("std");
const netz = @import("netz");

const iterations: usize = 1_000_000;
const payload_len: usize = 256;
const capsules_per_buffer: usize = 8;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @truncate(index);
    }

    const encoded_len = try netz.http3.capsule.encodedLen(
        netz.http3.capsule.CapsuleType.datagram,
        payload.len,
    );
    var encoded: [payload_len + 8]u8 = undefined;
    const capsule = try netz.http3.capsule.writeDatagramInto(&encoded, &payload);

    var stream_buf: [capsules_per_buffer * (payload_len + 8)]u8 = undefined;
    var stream_len: usize = 0;
    for (0..capsules_per_buffer) |_| {
        std.mem.copyForwards(u8, stream_buf[stream_len..][0..capsule.len], capsule);
        stream_len += capsule.len;
    }
    const stream = stream_buf[0..stream_len];

    const parse_ns, const parse_checksum = try measureSingleParse(io, capsule);
    const iter_ns, const iter_checksum = try measureIterator(io, stream);
    const write_ns, const write_checksum = try measureWriteInto(io, &payload);

    std.debug.print(
        \\HTTP/3 Capsule Protocol benchmark
        \\  iterations: {d}, payload bytes: {d}, encoded bytes: {d}
        \\  parse single capsule:   {d} ns/op
        \\  iterate {d} capsules:    {d} ns/buffer, {d} ns/capsule
        \\  caller-buffer encode:   {d} ns/op
        \\  checksum: {d}
        \\
    , .{
        iterations,
        payload.len,
        encoded_len,
        parse_ns / iterations,
        capsules_per_buffer,
        iter_ns / iterations,
        iter_ns / (iterations * capsules_per_buffer),
        write_ns / iterations,
        parse_checksum +% iter_checksum +% write_checksum,
    });
}

fn measureSingleParse(io: std.Io, capsule: []const u8) !struct { u64, u64 } {
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(capsule.ptr);
        const parsed = try netz.http3.capsule.parse(capsule);
        std.mem.doNotOptimizeAway(parsed.consumed);
        checksum +%= parsed.consumed;
        checksum +%= parsed.capsule.value[0];
        checksum +%= parsed.capsule.value[parsed.capsule.value.len - 1];
    }
    return .{ nowNs(io) -| started, checksum };
}

fn measureIterator(io: std.Io, stream: []const u8) !struct { u64, u64 } {
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(stream.ptr);
        var iter = netz.http3.capsule.Iterator.init(stream);
        while (try iter.next()) |capsule| {
            std.mem.doNotOptimizeAway(capsule.value.ptr);
            checksum +%= capsule.value.len;
            checksum +%= capsule.value[0];
        }
        checksum +%= iter.remaining();
    }
    return .{ nowNs(io) -| started, checksum };
}

fn measureWriteInto(io: std.Io, payload: []const u8) !struct { u64, u64 } {
    var encoded: [payload_len + 8]u8 = undefined;
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(payload.ptr);
        const written = try netz.http3.capsule.writeDatagramInto(&encoded, payload);
        std.mem.doNotOptimizeAway(&encoded);
        checksum +%= written.len;
        checksum +%= written[0];
    }
    return .{ nowNs(io) -| started, checksum };
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

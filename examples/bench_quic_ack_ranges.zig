const std = @import("std");
const netz = @import("netz");

const iterations: usize = 500_000;
const tracked_ranges: usize = netz.quic.packet_space.ReceivedPacketTracker.stack_ack_range_capacity;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var received = netz.quic.packet_space.ReceivedPacketTracker.init(
        allocator,
        tracked_ranges,
    );
    defer received.deinit();

    // Every second packet number creates a separate ACK range. This models a
    // heavily reordered/lossy path and keeps the number of extra ranges exactly
    // within the stack storage used by the 1-RTT ACK sender.
    for (0..tracked_ranges) |index| {
        const packet_number: u64 = @intCast(index * 2 + 1);
        if (!try received.recordFresh(packet_number)) return error.UnexpectedDuplicate;
    }

    const allocating_ns, const allocating_checksum = try measureAllocating(
        allocator,
        received,
    );
    const stack_ns, const stack_checksum = try measureCallerStorage(
        io,
        received,
    );
    const speedup_x100 = ratioTimes100(allocating_ns, stack_ns);

    std.debug.print(
        \\QUIC ACK range benchmark
        \\  iterations: {d}, tracked ranges: {d}, extra ACK ranges/frame: {d}
        \\  allocating ackFrame:      {d} ns/op
        \\  caller-storage ackFrame:  {d} ns/op
        \\  caller-storage speedup:   {d}.{d:0>2}x
        \\  checksum: {d}
        \\
    , .{
        iterations,
        received.ranges.items.len,
        received.ranges.items.len - 1,
        allocating_ns / iterations,
        stack_ns / iterations,
        speedup_x100 / 100,
        speedup_x100 % 100,
        allocating_checksum +% stack_checksum,
    });
}

fn measureAllocating(
    allocator: std.mem.Allocator,
    received: netz.quic.packet_space.ReceivedPacketTracker,
) !struct { u64, u64 } {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        const ack = try received.ackFrame(allocator, 0);
        defer allocator.free(ack.ranges);
        checksum +%= ack.largest_acknowledged;
        checksum +%= ack.first_ack_range;
        checksum +%= ack.ranges.len;
    }
    return .{ nowNs(io) -| started, checksum };
}

fn measureCallerStorage(
    io: std.Io,
    received: netz.quic.packet_space.ReceivedPacketTracker,
) !struct { u64, u64 } {
    var scratch: [netz.quic.packet_space.ReceivedPacketTracker.stack_ack_range_capacity]netz.quic.AckRange = undefined;
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        const ack = try received.ackFrameInto(&scratch, 0);
        checksum +%= ack.largest_acknowledged;
        checksum +%= ack.first_ack_range;
        checksum +%= ack.ranges.len;
    }
    return .{ nowNs(io) -| started, checksum };
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

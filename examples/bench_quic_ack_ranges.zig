const std = @import("std");
const netz = @import("netz");

const iterations: usize = 500_000;
const tracked_ranges: usize = netz.quic.packet_space.ReceivedPacketTracker.stack_ack_range_capacity;
const packet_number_base: u64 = 10_000;
const sent_packets: usize = 4096;
const recovery_packets: usize = 128;
const recovery_iterations: usize = 5_000;

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
        const packet_number = packet_number_base + @as(u64, @intCast(index * 2 + 1));
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
    const stale_ns, const stale_checksum = try measureStaleReject(io, received);
    const sent_validate_ns, const sent_validate_checksum = try measureSentAckValidation(
        allocator,
        io,
    );
    const recovery_ns, const recovery_checksum = try measureRecoveryAckRanges(
        allocator,
        io,
    );
    const speedup_x100 = ratioTimes100(allocating_ns, stack_ns);

    std.debug.print(
        \\QUIC ACK range benchmark
        \\  iterations: {d}, tracked ranges: {d}, extra ACK ranges/frame: {d}
        \\  allocating ackFrame:      {d} ns/op
        \\  caller-storage ackFrame:  {d} ns/op
        \\  caller-storage speedup:   {d}.{d:0>2}x
        \\  stale wouldRecordFresh:   {d} ns/op
        \\  sent ACK validation ({d} packets): {d} ns/op
        \\  recovery ACK cycle ({d} packets, {d} ranges): {d} ns/cycle
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
        stale_ns / iterations,
        sent_packets,
        sent_validate_ns / iterations,
        recovery_packets,
        recovery_packets / 2,
        recovery_ns / recovery_iterations,
        allocating_checksum +% stack_checksum +% stale_checksum +%
            sent_validate_checksum +% recovery_checksum,
    });
}

fn measureRecoveryAckRanges(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { u64, u64 } {
    var queue = netz.quic.recovery.Queue.init(allocator);
    defer queue.deinit();
    const extra_range_count = recovery_packets / 2 - 1;
    var ranges = [_]netz.quic.AckRange{.{
        .gap = 0,
        .ack_range_length = 0,
    }} ** extra_range_count;
    const even_ack = netz.quic.AckFrame{
        .largest_acknowledged = recovery_packets - 2,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };
    const odd_ack = netz.quic.AckFrame{
        .largest_acknowledged = recovery_packets - 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..recovery_iterations) |iteration| {
        const base = @as(u64, @intCast(iteration * recovery_packets));
        for (0..recovery_packets) |packet_index| {
            _ = try queue.trackSent(base + packet_index, "x");
        }
        var current_even = even_ack;
        current_even.largest_acknowledged += base;
        var current_odd = odd_ack;
        current_odd.largest_acknowledged += base;
        checksum +%= try queue.applyAck(current_even);
        checksum +%= try queue.applyAck(current_odd);
        if (queue.pendingCount() != 0) return error.UnexpectedPendingPacket;
    }
    return .{ nowNs(io) -| started, checksum };
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
        checksum +%= ack.largest_acknowledged;
        checksum +%= ack.first_ack_range;
        checksum +%= ack.ranges.len;
        allocator.free(ack.ranges);
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

fn measureStaleReject(
    io: std.Io,
    received: netz.quic.packet_space.ReceivedPacketTracker,
) !struct { u64, u64 } {
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        checksum +%= @intFromBool(try received.wouldRecordFresh(packet_number_base - 2));
    }
    return .{ nowNs(io) -| started, checksum };
}

fn measureSentAckValidation(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { u64, u64 } {
    var sent = netz.quic.packet_space.SentPacketTracker.init(allocator);
    defer sent.deinit();
    for (0..sent_packets) |packet_number| {
        try sent.sent(@intCast(packet_number), true, 1200);
    }

    const ack = netz.quic.AckFrame{
        .largest_acknowledged = sent_packets - 1,
        .ack_delay = 0,
        .first_ack_range = sent_packets - 1,
    };
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        try sent.validateAckCoversSentPackets(ack);
        checksum +%= ack.largest_acknowledged;
        checksum +%= ack.first_ack_range;
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

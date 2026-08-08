const std = @import("std");
const netz = @import("netz");

const batch_size: usize = 32;
const payload_size: usize = 1024;
const warmup_iterations: usize = 100;
const measured_iterations: usize = 2_000;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer receiver.deinit();
    var sequential_sender = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sequential_sender.deinit();
    var batch_sender = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer batch_sender.deinit();

    const keys = netz.quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** netz.quic.protection.secret_len,
    );
    const destination_connection_id = [_]u8{ 0xba, 0x7c, 0x11, 0x01 };
    var payload: [payload_size]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);

    var frame_storage: [batch_size][1]netz.quic.Frame = undefined;
    var packets: [batch_size][]const netz.quic.Frame = undefined;
    for (&frame_storage, &packets, 0..) |*packet_frames, *packet, index| {
        packet_frames[0] = .{ .stream = .{
            .stream_id = 0,
            .offset = index * payload.len,
            .data = &payload,
        } };
        packet.* = packet_frames;
    }

    var sequential_packet_number: u64 = 0;
    var batch_packet_number: u64 = 0;
    const batch_options: netz.quic.one_rtt.BatchSendOptions = .{
        .destination_connection_id = &destination_connection_id,
        .first_packet_number = 0,
        .packets = &packets,
    };
    const batch_sizes = try netz.quic.one_rtt.batchStorageSizes(batch_options);
    const batch_payload_storage = try allocator.alloc(u8, batch_sizes.payload);
    defer allocator.free(batch_payload_storage);
    const batch_packet_storage = try allocator.alloc(u8, batch_sizes.packet);
    defer allocator.free(batch_packet_storage);
    try runSequential(
        &sequential_sender,
        receiver.address(),
        keys,
        &destination_connection_id,
        &packets,
        warmup_iterations,
        &sequential_packet_number,
    );
    try runBatch(
        &batch_sender,
        receiver.address(),
        keys,
        &destination_connection_id,
        &packets,
        warmup_iterations,
        &batch_packet_number,
        batch_payload_storage,
        batch_packet_storage,
    );

    const sequential_started = nowNs(io);
    try runSequential(
        &sequential_sender,
        receiver.address(),
        keys,
        &destination_connection_id,
        &packets,
        measured_iterations,
        &sequential_packet_number,
    );
    const sequential_ns = nowNs(io) -| sequential_started;

    const batch_started = nowNs(io);
    try runBatch(
        &batch_sender,
        receiver.address(),
        keys,
        &destination_connection_id,
        &packets,
        measured_iterations,
        &batch_packet_number,
        batch_payload_storage,
        batch_packet_storage,
    );
    const batch_ns = nowNs(io) -| batch_started;

    const total_packets = measured_iterations * batch_size;
    const ratio_x100 = ratioTimes100(sequential_ns, batch_ns);
    std.debug.print(
        \\QUIC 1-RTT send benchmark
        \\  iterations: {d}, packets/batch: {d}, payload bytes/packet: {d}
        \\  batch GSO available after run: {}
        \\  sequential: {d} ns/batch, {d} ns/packet
        \\  batched:    {d} ns/batch, {d} ns/packet
        \\  batched relative packet throughput: {d}.{d:0>2}x
        \\  total packets/path: {d}
        \\
    , .{
        measured_iterations,
        batch_size,
        payload_size,
        batch_sender.gsoSendEnabled(),
        sequential_ns / measured_iterations,
        sequential_ns / total_packets,
        batch_ns / measured_iterations,
        batch_ns / total_packets,
        ratio_x100 / 100,
        ratio_x100 % 100,
        total_packets,
    });
}

fn runSequential(
    endpoint: *netz.quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: netz.quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packets: []const []const netz.quic.Frame,
    iterations: usize,
    next_packet_number: *u64,
) !void {
    // The receiver is intentionally not drained: this benchmark isolates
    // protection, allocation, and sender syscall overhead. UDP queue overflow
    // can drop loopback datagrams without changing sender-side work.
    for (0..iterations) |_| {
        for (packets) |frames| {
            try netz.quic.one_rtt.sendFrames(endpoint, to, keys, .{
                .destination_connection_id = destination_connection_id,
                .packet_number = next_packet_number.*,
                .frames = frames,
            });
            next_packet_number.* += 1;
        }
    }
}

fn runBatch(
    endpoint: *netz.quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: netz.quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packets: []const []const netz.quic.Frame,
    iterations: usize,
    next_packet_number: *u64,
    payload_storage: []u8,
    packet_storage: []u8,
) !void {
    for (0..iterations) |_| {
        const options: netz.quic.one_rtt.BatchSendOptions = .{
            .destination_connection_id = destination_connection_id,
            .first_packet_number = next_packet_number.*,
            .packets = packets,
        };
        // Match the runtime path, which sizes each changing frame batch before
        // growing (and then reusing) its connection-scoped scratch buffers.
        const sizes = try netz.quic.one_rtt.batchStorageSizes(options);
        _ = try netz.quic.one_rtt.sendFramesBatchInto(
            endpoint,
            to,
            keys,
            options,
            payload_storage[0..sizes.payload],
            packet_storage[0..sizes.packet],
        );
        next_packet_number.* += packets.len;
    }
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

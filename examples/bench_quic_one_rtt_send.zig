const std = @import("std");
const netz = @import("netz");

const batch_size: usize = 32;
const payload_size: usize = 1024;
const warmup_iterations: usize = 100;
const measured_iterations: usize = 1_000;

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

    var sequential = try netz.quic.one_rtt.Connection.init(
        &sequential_sender,
        .{
            .peer = receiver.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = &destination_connection_id,
            .peer_connection_id = &destination_connection_id,
            .initial_send_max_streams_bidi = std.math.maxInt(u60),
            .enable_pacing = false,
        },
    );
    defer sequential.deinit();
    var batched = try netz.quic.one_rtt.Connection.init(
        &batch_sender,
        .{
            .peer = receiver.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = &destination_connection_id,
            .peer_connection_id = &destination_connection_id,
            .initial_send_max_streams_bidi = std.math.maxInt(u60),
            .enable_pacing = false,
        },
    );
    defer batched.deinit();
    // This sender-only benchmark intentionally does not process ACKs. Remove
    // cwnd as the limiting variable so measurements isolate state bookkeeping,
    // packet protection, and socket batching.
    sequential.congestion.congestion_window = std.math.maxInt(usize);
    batched.congestion.congestion_window = std.math.maxInt(usize);
    try runSequential(
        &sequential,
        &packets,
        warmup_iterations,
    );
    try runBatch(
        &batched,
        &packets,
        warmup_iterations,
    );

    const sequential_started = nowNs(io);
    try runSequential(
        &sequential,
        &packets,
        measured_iterations,
    );
    const sequential_ns = nowNs(io) -| sequential_started;

    const batch_started = nowNs(io);
    try runBatch(
        &batched,
        &packets,
        measured_iterations,
    );
    const batch_ns = nowNs(io) -| batch_started;

    const total_packets = measured_iterations * batch_size;
    const ratio_x100 = ratioTimes100(sequential_ns, batch_ns);
    std.debug.print(
        \\QUIC 1-RTT send benchmark
        \\  iterations: {d}, packets/batch: {d}, payload bytes/packet: {d}
        \\  stateful batch GSO available after run: {}
        \\  stateful sequential: {d} ns/batch, {d} ns/packet
        \\  stateful batched:    {d} ns/batch, {d} ns/packet
        \\  stateful batch relative packet throughput: {d}.{d:0>2}x
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
    connection: *netz.quic.one_rtt.Connection,
    packets: []const []const netz.quic.Frame,
    iterations: usize,
) !void {
    // The receiver is intentionally not drained: this benchmark isolates
    // protection, allocation, and sender syscall overhead. UDP queue overflow
    // can drop loopback datagrams without changing sender-side work.
    for (0..iterations) |_| {
        for (packets) |frames| {
            try connection.send(frames);
        }
    }
}

fn runBatch(
    connection: *netz.quic.one_rtt.Connection,
    packets: []const []const netz.quic.Frame,
    iterations: usize,
) !void {
    for (0..iterations) |_| {
        try connection.sendMany(packets);
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

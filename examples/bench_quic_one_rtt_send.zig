const std = @import("std");
const netz = @import("netz");

const batch_size: usize = 32;
const payload_size: usize = 1024;
// Mirror HTTP/3 DATA packetization, where a framing prefix and borrowed body
// ranges can produce several adjacent STREAM descriptors for the same stream.
const default_stream_fragments_per_packet: usize = 1;
const max_stream_fragments_per_packet: usize = 16;
const default_warmup_iterations: usize = 100;
const default_measured_iterations: usize = 1_000;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(
        init,
        allocator,
    );
    const stream_fragments_per_packet = options.stream_fragments_per_packet;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

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

    var frame_storage: [batch_size][max_stream_fragments_per_packet]netz.quic.Frame =
        undefined;
    var packets: [batch_size][]const netz.quic.Frame = undefined;
    for (&frame_storage, &packets, 0..) |*packet_frames, *packet, index| {
        const fragment_size = payload.len / stream_fragments_per_packet;
        for (packet_frames[0..stream_fragments_per_packet], 0..) |*frame, fragment_index| {
            const start = fragment_index * fragment_size;
            const end = if (fragment_index + 1 == stream_fragments_per_packet)
                payload.len
            else
                start + fragment_size;
            frame.* = .{ .stream = .{
                .stream_id = 0,
                .offset = index * payload.len + start,
                .data = payload[start..end],
            } };
        }
        packet.* = packet_frames[0..stream_fragments_per_packet];
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
        options.warmup_iterations,
    );
    try runBatch(
        &batched,
        &packets,
        options.warmup_iterations,
    );

    const sequential_started = nowNs(io);
    try runSequential(
        &sequential,
        &packets,
        options.measured_iterations,
    );
    const sequential_ns = nowNs(io) -| sequential_started;

    const batch_started = nowNs(io);
    try runBatch(
        &batched,
        &packets,
        options.measured_iterations,
    );
    const batch_ns = nowNs(io) -| batch_started;

    const total_packets = options.measured_iterations * batch_size;
    const ratio_x100 = ratioTimes100(sequential_ns, batch_ns);
    std.debug.print(
        \\QUIC 1-RTT send benchmark
        \\  io backend: zio-std-io
        \\  iterations: {d}, packets/batch: {d}, STREAM descriptors/packet: {d}, payload bytes/packet: {d}
        \\  stateful batch GSO available after run: {}
        \\  stateful sequential: {d} ns/batch, {d} ns/packet
        \\  stateful batched:    {d} ns/batch, {d} ns/packet
        \\  stateful batch relative packet throughput: {d}.{d:0>2}x
        \\  total packets/path: {d}
        \\
    , .{
        options.measured_iterations,
        batch_size,
        stream_fragments_per_packet,
        payload_size,
        batch_sender.gsoSendEnabled(),
        sequential_ns / options.measured_iterations,
        sequential_ns / total_packets,
        batch_ns / options.measured_iterations,
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

const Options = struct {
    stream_fragments_per_packet: usize = default_stream_fragments_per_packet,
    warmup_iterations: usize = default_warmup_iterations,
    measured_iterations: usize = default_measured_iterations,
};

fn parseOptions(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !Options {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--stream-fragments=")) {
            options.stream_fragments_per_packet = try std.fmt.parseInt(
                usize,
                arg["--stream-fragments=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup_iterations = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.measured_iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else return error.InvalidArgument;
    }
    if (options.stream_fragments_per_packet == 0 or
        options.stream_fragments_per_packet > max_stream_fragments_per_packet or
        options.measured_iterations == 0)
    {
        return error.InvalidArgument;
    }
    return options;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

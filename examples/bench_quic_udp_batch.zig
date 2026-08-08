const std = @import("std");
const netz = @import("netz");

// 54 * 1200 stays below Linux's 16-bit UDP super-packet limit while being
// large enough for GRO to amortize its ancillary parsing and batch ownership.
const batch_size: usize = 54;
const datagram_size: usize = 1200;
const send_iterations: usize = 5_000;
const receive_iterations: usize = 5_000;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = datagram_size },
    );
    defer receiver.deinit();
    const destination = receiver.address();

    var gso_sender = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = datagram_size,
            .enable_gso_send = true,
        },
    );
    defer gso_sender.deinit();
    var mmsg_sender = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = datagram_size,
            .enable_gso_send = false,
        },
    );
    defer mmsg_sender.deinit();

    var storage: [batch_size * datagram_size]u8 = undefined;
    for (&storage, 0..) |*byte, index| byte.* = @truncate(index);
    var datagrams: [batch_size][]const u8 = undefined;
    for (&datagrams, 0..) |*datagram, index| {
        const offset = index * datagram_size;
        datagram.* = storage[offset..][0..datagram_size];
    }

    const gso_ns = try measureSend(io, &gso_sender, destination, &datagrams);
    const mmsg_ns = try measureSend(io, &mmsg_sender, destination, &datagrams);
    const total_datagrams = send_iterations * batch_size;
    const gso_ratio_x100 = ratioTimes100(mmsg_ns, gso_ns);

    std.debug.print(
        \\QUIC UDP batch benchmark
        \\  send iterations: {d}, packets/batch: {d}, bytes/packet: {d}
        \\  GSO available after run: {}
        \\  UDP_SEGMENT: {d} ns/batch, {d} ns/packet
        \\  sendmmsg:    {d} ns/batch, {d} ns/packet
        \\  GSO relative packet throughput: {d}.{d:0>2}x
        \\  total datagrams/path: {d}
        \\
    , .{
        send_iterations,
        batch_size,
        datagram_size,
        gso_sender.gsoSendEnabled(),
        gso_ns / send_iterations,
        gso_ns / total_datagrams,
        mmsg_ns / send_iterations,
        mmsg_ns / total_datagrams,
        gso_ratio_x100 / 100,
        gso_ratio_x100 % 100,
        total_datagrams,
    });

    // Use fresh sockets so the sender-only phase cannot leave packets queued
    // for the receive benchmark.
    var gro_receiver = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = datagram_size,
            .enable_gro_receive = true,
        },
    );
    defer gro_receiver.deinit();
    var plain_receiver = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = datagram_size,
            .enable_gro_receive = false,
        },
    );
    defer plain_receiver.deinit();

    const gro_receive_ns = try measureReceive(
        io,
        allocator,
        &gso_sender,
        &gro_receiver,
        &datagrams,
    );
    const plain_receive_ns = try measureReceive(
        io,
        allocator,
        &gso_sender,
        &plain_receiver,
        &datagrams,
    );
    const total_received = receive_iterations * batch_size;
    const gro_receive_ratio_x100 = ratioTimes100(plain_receive_ns, gro_receive_ns);
    std.debug.print(
        \\QUIC UDP receive benchmark
        \\  receive iterations: {d}, packets/batch: {d}, bytes/packet: {d}
        \\  GRO available after run: {}
        \\  UDP_GRO:    {d} ns/batch, {d} ns/packet
        \\  plain recv: {d} ns/batch, {d} ns/packet
        \\  GRO relative packet throughput: {d}.{d:0>2}x
        \\  total datagrams/path: {d}
        \\
    , .{
        receive_iterations,
        batch_size,
        datagram_size,
        gro_receiver.groReceiveEnabled(),
        gro_receive_ns / receive_iterations,
        gro_receive_ns / total_received,
        plain_receive_ns / receive_iterations,
        plain_receive_ns / total_received,
        gro_receive_ratio_x100 / 100,
        gro_receive_ratio_x100 % 100,
        total_received,
    });
}

fn measureSend(
    io: std.Io,
    sender: *netz.quic.runtime.Endpoint,
    destination: std.Io.net.IpAddress,
    datagrams: []const []const u8,
) !u64 {
    // UDP loopback can drop when the receiver queue fills; that is acceptable
    // here because this benchmark isolates sender syscall overhead.
    const started = nowNs(io);
    for (0..send_iterations) |_| try sender.sendManyBytes(destination, datagrams);
    return nowNs(io) -| started;
}

fn measureReceive(
    io: std.Io,
    allocator: std.mem.Allocator,
    sender: *netz.quic.runtime.Endpoint,
    receiver: *netz.quic.runtime.Endpoint,
    datagrams: []const []const u8,
) !u64 {
    var total_ns: u64 = 0;
    for (0..receive_iterations) |_| {
        try sender.sendManyBytes(receiver.address(), datagrams);
        const started = nowNs(io);
        if (receiver.groReceiveEnabled()) {
            var received = try receiver.receiveBytesBatch();
            defer received.deinit(allocator);
            if (received.segment_count != datagrams.len) return error.UnexpectedSegmentCount;
            for (datagrams, 0..) |expected, index| {
                const actual = received.datagramAt(index) orelse return error.UnexpectedSegmentCount;
                if (!std.mem.eql(u8, expected, actual)) return error.UnexpectedPayload;
            }
        } else {
            for (datagrams) |expected| {
                var received = try receiver.receiveBytes();
                defer received.deinit(allocator);
                if (!std.mem.eql(u8, expected, received.bytes)) return error.UnexpectedPayload;
            }
        }
        total_ns +|= nowNs(io) -| started;
    }
    return total_ns;
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

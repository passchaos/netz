const std = @import("std");
const netz = @import("netz");

const batch_size: usize = 10;
const datagram_size: usize = 1200;
const iterations: usize = 20_000;

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

    const gso_ns = try measure(io, &gso_sender, destination, &datagrams);
    const mmsg_ns = try measure(io, &mmsg_sender, destination, &datagrams);
    const total_datagrams = iterations * batch_size;
    const gso_ratio_x100 = ratioTimes100(mmsg_ns, gso_ns);

    std.debug.print(
        \\QUIC UDP batch benchmark
        \\  iterations: {d}, packets/batch: {d}, bytes/packet: {d}
        \\  GSO available after run: {}
        \\  UDP_SEGMENT: {d} ns/batch, {d} ns/packet
        \\  sendmmsg:    {d} ns/batch, {d} ns/packet
        \\  GSO relative packet throughput: {d}.{d:0>2}x
        \\  total datagrams/path: {d}
        \\
    , .{
        iterations,
        batch_size,
        datagram_size,
        gso_sender.gsoSendEnabled(),
        gso_ns / iterations,
        gso_ns / total_datagrams,
        mmsg_ns / iterations,
        mmsg_ns / total_datagrams,
        gso_ratio_x100 / 100,
        gso_ratio_x100 % 100,
        total_datagrams,
    });
}

fn measure(
    io: std.Io,
    sender: *netz.quic.runtime.Endpoint,
    destination: std.Io.net.IpAddress,
    datagrams: []const []const u8,
) !u64 {
    // UDP loopback can drop when the receiver queue fills; that is acceptable
    // here because this benchmark isolates sender syscall overhead.
    const started = nowNs(io);
    for (0..iterations) |_| try sender.sendManyBytes(destination, datagrams);
    return nowNs(io) -| started;
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

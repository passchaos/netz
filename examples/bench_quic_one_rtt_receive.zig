const std = @import("std");
const netz = @import("netz");

const batch_size: usize = 54;
const payload_size: usize = 1152;
const iterations: usize = 1_000;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const keys = netz.quic.protection.deriveAes128Keys([_]u8{0xb7} ** netz.quic.protection.secret_len);
    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };

    const gro_ns = try measure(
        allocator,
        io,
        keys,
        client_cid,
        server_cid,
        true,
    );
    const plain_ns = try measure(
        allocator,
        io,
        keys,
        client_cid,
        server_cid,
        false,
    );
    const total_packets = iterations * batch_size;
    const ratio_x100 = ratioTimes100(plain_ns, gro_ns);
    std.debug.print(
        \\QUIC 1-RTT receive benchmark
        \\  iterations: {d}, packets/batch: {d}, payload bytes/packet: {d}
        \\  GRO batch:    {d} ns/batch, {d} ns/packet
        \\  plain packet: {d} ns/batch, {d} ns/packet
        \\  GRO relative packet throughput: {d}.{d:0>2}x
        \\  total packets/path: {d}
        \\
    , .{
        iterations,
        batch_size,
        payload_size,
        gro_ns / iterations,
        gro_ns / total_packets,
        plain_ns / iterations,
        plain_ns / total_packets,
        ratio_x100 / 100,
        ratio_x100 % 100,
        total_packets,
    });
}

fn measure(
    allocator: std.mem.Allocator,
    io: std.Io,
    keys: netz.quic.protection.PacketProtectionKeys,
    client_cid: [4]u8,
    server_cid: [4]u8,
    enable_gro: bool,
) !u64 {
    var server_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 1400,
            .enable_gro_receive = enable_gro,
        },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer client_endpoint.deinit();
    if (enable_gro and !server_endpoint.groReceiveEnabled()) return error.GroUnavailable;

    var server = try netz.quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const payload = [_]u8{0x01} ++ [_]u8{0x00} ** (payload_size - 1);
    var packet_storage: [batch_size * 1400]u8 = undefined;
    var datagrams: [batch_size][]const u8 = undefined;
    var total_ns: u64 = 0;
    var first_packet_number: u64 = 0;
    for (0..iterations) |_| {
        const written = try sealPacketBatch(
            &packet_storage,
            &datagrams,
            keys,
            &server_cid,
            first_packet_number,
            &payload,
        );
        _ = written;
        try client_endpoint.sendManyBytes(server_endpoint.address(), &datagrams);

        const started = nowNs(io);
        if (enable_gro) {
            if (try server.servicePacketBatchAt(started) != batch_size) {
                return error.UnexpectedPacketCount;
            }
        } else {
            for (0..batch_size) |_| {
                var received = try server.receivePacketAt(started);
                defer received.deinit(allocator);
            }
        }
        total_ns +|= nowNs(io) -| started;
        first_packet_number += batch_size;
    }
    return total_ns;
}

fn sealPacketBatch(
    storage: []u8,
    datagrams: *[batch_size][]const u8,
    keys: netz.quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    first_packet_number: u64,
    payload: []const u8,
) !usize {
    const packet_len = try netz.quic.protection.shortPacketLen(.{
        .destination_connection_id = destination_connection_id,
        .packet_number = first_packet_number,
        .packet_number_len = 4,
        .payload = payload,
    });
    var offset: usize = 0;
    for (datagrams, 0..) |*datagram, index| {
        const packet_number = first_packet_number + index;
        datagram.* = try netz.quic.protection.sealShortPacketInto(
            storage[offset..][0..packet_len],
            keys,
            .{
                .destination_connection_id = destination_connection_id,
                .packet_number = packet_number,
                .packet_number_len = 4,
                .payload = payload,
            },
        );
        offset += packet_len;
    }
    return offset;
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

const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 2_000_000;
const connection_counts = [_]usize{ 1, 16, 128, 1024 };

pub fn main(init: std.process.Init) !void {
    const iterations = try parseIterations(init);
    const allocator = std.heap.smp_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    std.debug.print(
        \\QUIC endpoint pending-packet lookup benchmark
        \\  io backend: zio-std-io
        \\  direct iterations: {d}
        \\  dispatcher ready queue is empty
        \\  times are integer hundredths of a nanosecond per operation
        \\
    , .{iterations});
    std.debug.print(
        \\connections  direct empty  endpoint ready index  index/direct
        \\
    , .{});

    for (connection_counts) |connection_count| {
        var endpoint = try netz.quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        defer endpoint.deinit();
        const connections = try allocator.alloc(
            netz.quic.one_rtt.Connection,
            connection_count,
        );
        defer allocator.free(connections);
        var initialized: usize = 0;
        defer for (connections[0..initialized]) |*connection| {
            connection.deinit();
        };
        var dispatcher = netz.quic.endpoint_dispatcher.Dispatcher.init(
            allocator,
            &endpoint,
        );
        defer dispatcher.deinit();
        const keys = netz.quic.protection.deriveAes128Keys(
            [_]u8{0x70} ** netz.quic.protection.secret_len,
        );
        for (connections, 0..) |*connection, index| {
            var cid: [8]u8 = undefined;
            std.mem.writeInt(u64, &cid, index + 1, .big);
            connection.* = try netz.quic.one_rtt.Connection.init(
                &endpoint,
                .{
                    .peer = endpoint.address(),
                    .receive_keys = keys,
                    .send_keys = keys,
                    .local_connection_id = &cid,
                    .peer_connection_id = "peer",
                    .local_endpoint = .server,
                    .enable_pacing = false,
                },
            );
            initialized += 1;
            try dispatcher.registerConnection(index + 1, connection);
        }

        const direct_started = nowNs(io);
        for (0..iterations) |_| {
            std.mem.doNotOptimizeAway(&dispatcher);
            if ((try dispatcher.pollConnectionPacket(1)) != null) {
                return error.InvalidBenchmarkResult;
            }
        }
        const direct_elapsed = nowNs(io) -| direct_started;

        const scan_started = nowNs(io);
        for (0..iterations) |_| {
            std.mem.doNotOptimizeAway(&dispatcher);
            if ((try dispatcher.pollPendingPacket()) != null) {
                return error.InvalidBenchmarkResult;
            }
        }
        const scan_elapsed = nowNs(io) -| scan_started;
        const direct = hundredthsPerOperation(direct_elapsed, iterations);
        const scan = hundredthsPerOperation(scan_elapsed, iterations);
        const ratio_x100 = if (direct == 0) 0 else scan * 100 / direct;

        std.debug.print(
            "{d: >11}  {d: >7}.{d:0>2} ns  {d: >13}.{d:0>2} ns  {d}.{d:0>2}x\n",
            .{
                connection_count,
                direct / 100,
                direct % 100,
                scan / 100,
                scan % 100,
                ratio_x100 / 100,
                ratio_x100 % 100,
            },
        );
    }
}

fn hundredthsPerOperation(elapsed_ns: u64, iterations: usize) u64 {
    return elapsed_ns * 100 / iterations;
}

fn parseIterations(init: std.process.Init) !usize {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 1) return default_iterations;
    if (args.len != 2 or !std.mem.startsWith(u8, args[1], "--iterations=")) {
        return error.InvalidArgument;
    }
    const value = try std.fmt.parseInt(
        usize,
        args[1]["--iterations=".len..],
        10,
    );
    if (value == 0 or value > 10_000_000) {
        return error.InvalidArgument;
    }
    return value;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

const std = @import("std");
const netz = @import("netz");

const stream_count: usize = netz.quic.one_rtt.max_batch_packets;
const payload_bytes: usize = 1024;
const default_warmup_iterations: usize = 10_000;
const default_iterations: usize = 100_000;

const Options = struct {
    warmup_iterations: usize = default_warmup_iterations,
    iterations: usize = default_iterations,
};

pub fn main(init: std.process.Init) !void {
    const options = try parseOptions(init);
    const allocator = std.heap.smp_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer endpoint.deinit();
    const keys = netz.quic.protection.deriveAes128Keys(
        [_]u8{0x57} ** netz.quic.protection.secret_len,
    );
    var connection = try netz.quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-batch-client",
        .peer_connection_id = "wt-batch-server",
        .initial_send_max_data = std.math.maxInt(u62),
        .initial_send_max_stream_data = std.math.maxInt(u62),
        .initial_send_max_streams_bidi = stream_count,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();
    connection.congestion.congestion_window = std.math.maxInt(usize);

    var registry = try netz.webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = stream_count },
    );
    defer registry.deinit();
    var payload: [payload_bytes]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var writes: [stream_count]netz.webtransport.runtime.StreamWrite = undefined;
    for (&writes, 0..) |*write, index| {
        const stream = try registry.openLocal(.bidirectional);
        stream.prefix_sent = true;
        stream.send_offset = 3 + 17 * index;
        stream.priority = @as(i32, @intCast((index * 29) % stream_count)) -
            @as(i32, @intCast(stream_count / 2));
        write.* = .{ .stream_id = stream.stream_id, .data = &payload };
    }

    var warmup_checksum: u64 = 0;
    for (0..options.warmup_iterations) |_| {
        const staged = try netz.webtransport.runtime.testing.stream_batch
            .stageSteady(&connection, &registry, &writes);
        if (staged.packet_count != stream_count) {
            return error.InvalidPacketCount;
        }
        warmup_checksum +%= staged.checksum;
    }
    std.mem.doNotOptimizeAway(warmup_checksum);

    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..options.iterations) |_| {
        const staged = try netz.webtransport.runtime.testing.stream_batch
            .stageSteady(&connection, &registry, &writes);
        if (staged.packet_count != stream_count) {
            return error.InvalidPacketCount;
        }
        checksum +%= staged.checksum;
    }
    const elapsed = nowNs(io) -| started;
    const expected_per_iteration = expectedChecksum();
    if (checksum != expected_per_iteration *% options.iterations) {
        return error.InvalidChecksum;
    }
    std.debug.print(
        "WebTransport steady stream-batch staging benchmark\n" ++
            "  io backend: zio-std-io\n" ++
            "  warmup iterations: {d}\n" ++
            "  measured iterations: {d}\n" ++
            "  streams/staging: {d}\n" ++
            "  elapsed ns: {d}\n" ++
            "  ns/staging: {d:.3}\n" ++
            "  ns/stream: {d:.3}\n" ++
            "  checksum: {d}\n",
        .{
            options.warmup_iterations,
            options.iterations,
            stream_count,
            elapsed,
            @as(f64, @floatFromInt(elapsed)) /
                @as(f64, @floatFromInt(options.iterations)),
            @as(f64, @floatFromInt(elapsed)) /
                @as(f64, @floatFromInt(options.iterations * stream_count)),
            checksum,
        },
    );
}

fn expectedChecksum() u64 {
    var checksum: u64 = 0;
    for (0..stream_count) |index| {
        checksum +%= 4 + 4 * index;
        checksum +%= 3 + 17 * index;
        checksum +%= payload_bytes;
        checksum +%= index;
        checksum +%= payload_bytes;
    }
    return checksum;
}

fn parseOptions(init: std.process.Init) !Options {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var options: Options = .{};
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup_iterations = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else {
            return error.InvalidArgument;
        }
    }
    if (options.iterations == 0 or options.iterations > 10_000_000) {
        return error.InvalidArgument;
    }
    return options;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

const std = @import("std");
const netz = @import("netz");

const max_datagram_size: usize = 8900;
const dgram_payload_size: usize = 1200;
const transfer_size: usize = 16 * 1024 * 1024;
const burst_datagrams: usize = 64;
const client_cid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
const server_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = max_datagram_size, .max_frames_per_datagram = 64 },
    );
    defer client_endpoint.deinit();
    var server_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = max_datagram_size, .max_frames_per_datagram = 64 },
    );
    defer server_endpoint.deinit();

    const keys = netz.quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** netz.quic.protection.secret_len,
    );

    var client = try netz.quic.one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_max_datagram_frame_size = 65_535,
        .local_max_datagram_frame_size = 65_535,
        .max_datagram_size = max_datagram_size,
        .max_datagram_queue_items = burst_datagrams * 2,
        .congestion_algorithm = .cubic,
        .enable_pacing = false,
        .tls_handshake_complete = true,
    });
    defer client.deinit();
    var server = try netz.quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .peer_max_datagram_frame_size = 65_535,
        .local_max_datagram_frame_size = 65_535,
        .max_datagram_size = max_datagram_size,
        .max_datagram_queue_items = burst_datagrams * 2,
        .congestion_algorithm = .cubic,
        .enable_pacing = false,
        .tls_handshake_complete = true,
    });
    defer server.deinit();

    // This installed-key benchmark intentionally removes cwnd as the limiting
    // variable, matching the transport-only nature of quicz's
    // `quic_bench_datagram.zig` reference while still exercising real packet
    // protection, UDP send/receive, frame parsing, and DATAGRAM queueing.
    client.congestion.congestion_window = std.math.maxInt(usize);
    server.congestion.congestion_window = std.math.maxInt(usize);

    var done = std.atomic.Value(bool).init(false);
    var bytes_received = std.atomic.Value(usize).init(0);
    const ServerCtx = struct {
        server: *netz.quic.one_rtt.Connection,
        done: *std.atomic.Value(bool),
        bytes_received: *std.atomic.Value(usize),
        err: ?anyerror = null,

        fn run(ctx: *@This()) void {
            runFallible(ctx) catch |err| {
                ctx.err = err;
            };
        }

        fn runFallible(ctx: *@This()) !void {
            var datagram_buf: [dgram_payload_size]u8 = undefined;
            while (!ctx.done.load(.acquire)) {
                var packet = ctx.server.receivePacketTimeout(shortPollTimeout()) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => |other| return other,
                };
                defer packet.deinit(ctx.server.endpoint.allocator);
                while (try ctx.server.popDatagram(&datagram_buf)) |payload| {
                    _ = ctx.bytes_received.fetchAdd(payload.len, .monotonic);
                }
            }
        }
    };
    var server_ctx = ServerCtx{
        .server = &server,
        .done = &done,
        .bytes_received = &bytes_received,
    };
    const server_thread = try std.Thread.spawn(.{}, ServerCtx.run, .{&server_ctx});
    var joined = false;
    defer if (!joined) server_thread.join();

    var payload: [dgram_payload_size]u8 = undefined;
    @memset(&payload, 'D');

    var sent: usize = 0;
    var datagrams_sent: usize = 0;
    const start_ns = nowNs(io);
    const deadline_ns = start_ns +| 10 * std.time.ns_per_s;
    while (sent < transfer_size) {
        if (nowNs(io) > deadline_ns) return error.BenchmarkTimeout;
        var burst: usize = 0;
        while (burst < burst_datagrams and sent < transfer_size) : (burst += 1) {
            const count = @min(payload.len, transfer_size - sent);
            try client.sendDatagram(payload[0..count]);
            sent += count;
            datagrams_sent += 1;
        }
        std.Thread.yield() catch {};
    }
    while (bytes_received.load(.monotonic) < transfer_size) {
        if (nowNs(io) > deadline_ns) return error.BenchmarkTimeout;
        std.Thread.yield() catch {};
    }
    const elapsed = nowNs(io) -| start_ns;
    done.store(true, .release);
    server_thread.join();
    joined = true;
    if (server_ctx.err) |err| return err;

    const received = bytes_received.load(.monotonic);
    if (received != transfer_size) return error.InvalidFrame;
    const mib_per_second = mibPerSecond(received, elapsed);
    std.debug.print(
        \\QUIC DATAGRAM throughput benchmark
        \\  transfer bytes: {d}
        \\  payload bytes: {d}
        \\  datagrams sent: {d}
        \\  received bytes: {d}
        \\  ns: {d}
        \\  MiB/s: {d:.2}
        \\
    , .{
        transfer_size,
        dgram_payload_size,
        datagrams_sent,
        received,
        elapsed,
        mib_per_second,
    });
}

fn shortPollTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = .fromMicroseconds(100),
    } };
}

fn mibPerSecond(bytes: usize, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    const mib = @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
    return mib / seconds;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

const std = @import("std");
const netz = @import("netz");

const default_transfer_bytes: usize = 4 * 1024 * 1024;
const default_streams: usize = 1;
const max_streams: usize = 64;
const read_buffer_bytes: usize = 16 * 1024;
const default_stream_window: u64 = 64 * 1024;
const default_one_rtt_datagram_size: usize = 4096;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const io = init.io;
    const config = try parseArgs(init, allocator);
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x42, 0x01, 0x57, 0x54, 0x42, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x42, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x42, 0x04 };

    const payload = try allocator.alloc(u8, config.transfer_bytes);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = payloadByte(index);

    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                .quic = .{
                    .max_datagram_size = config.one_rtt_datagram_size,
                    .max_frames_per_datagram = 8,
                },
            },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = transportParameters(config),
                .initial_one_rtt_config = .{
                    .stream_receive_window = config.stream_window,
                    .max_datagram_size = config.one_rtt_datagram_size,
                    .enable_pacing = config.enable_pacing,
                },
                .random = [_]u8{0xc3} ** 32,
                .x25519_secret_key = [_]u8{0xc4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.webtransport.runtime.HandshakeServer,
        err: ?anyerror = null,
        received: usize = 0,
        events: usize = 0,
        checksum: u64 = 0,
        streams: usize,
        io: std.Io,
        started: std.Io.Event = .unset,
        finished: std.Io.Event = .unset,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
            shared.finished.set(shared.io);
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var buffer: [read_buffer_bytes]u8 = undefined;
            var finished_streams: usize = 0;
            while (finished_streams < shared.streams) {
                shared.started.set(shared.io);
                const event = try session.readStream(&buffer);
                switch (event) {
                    .data => |data| {
                        if (data.direction != .bidirectional or
                            data.locally_initiated)
                        {
                            return error.UnexpectedStream;
                        }
                        for (buffer[0..data.bytes]) |byte| {
                            shared.checksum +%= byte;
                        }
                        shared.received += data.bytes;
                        shared.events += 1;
                        if (data.fin) finished_streams += 1;
                    },
                    else => return error.UnexpectedStreamEvent,
                }
            }
        }
    };

    var shared = Shared{
        .server = &server,
        .streams = config.streams,
        .io = io,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.webtransport.runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-stream-bench",
            .limits = .{
                .http3 = .{
                    .quic = .{
                        .max_datagram_size = config.one_rtt_datagram_size,
                        .max_frames_per_datagram = 8,
                    },
                },
            },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .local_transport_parameters = transportParameters(config),
                    .initial_one_rtt_config = .{
                        .stream_receive_window = config.stream_window,
                        .max_datagram_size = config.one_rtt_datagram_size,
                        .enable_pacing = config.enable_pacing,
                    },
                    .server_name = "localhost",
                    .random = [_]u8{0xc1} ** 32,
                    .x25519_secret_key = [_]u8{0xc2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    shared.started.waitUncancelable(io);
    const stream_ids = try allocator.alloc(u62, config.streams);
    defer allocator.free(stream_ids);
    for (stream_ids) |*stream_id| {
        stream_id.* = try client.openBidirectionalStream();
    }
    const started_ns = nowNs(io);
    var write_calls: usize = 0;
    const offsets = try allocator.alloc(usize, config.streams);
    defer allocator.free(offsets);
    @memset(offsets, 0);
    const writes = try allocator.alloc(
        netz.webtransport.runtime.StreamWrite,
        config.streams,
    );
    defer allocator.free(writes);
    const counts = try allocator.alloc(usize, config.streams);
    defer allocator.free(counts);
    var remaining = config.streams;
    while (remaining != 0) {
        for (writes, stream_ids, offsets) |*item, stream_id, offset| {
            item.* = .{
                .stream_id = stream_id,
                .data = payload[offset..],
            };
        }
        const result = try client.writeStreams(writes, counts);
        if (result.send_error) |err| return err;
        if (result.progressed == 0) return error.IncompleteTransfer;
        write_calls += result.progressed;
        for (offsets, counts) |*offset, count| {
            if (offset.* == payload.len) continue;
            offset.* += count;
            if (offset.* == payload.len) remaining -= 1;
        }
    }
    for (stream_ids) |stream_id| try client.finishStream(stream_id);
    shared.finished.waitUncancelable(io);
    const elapsed_ns = nowNs(io) -| started_ns;
    thread.join();
    if (shared.err) |err| return err;
    const total_bytes = payload.len * config.streams;
    if (shared.received != total_bytes) return error.IncompleteTransfer;

    const mib_per_second = if (elapsed_ns == 0)
        0
    else
        (@as(u64, total_bytes) *| std.time.ns_per_s) /
            (elapsed_ns *| 1024 * 1024);
    std.debug.print(
        \\WebTransport incremental stream benchmark
        \\  streams: {d}
        \\  bytes per stream: {d}
        \\  total transfer bytes: {d}
        \\  receive window: {d}
        \\  caller buffer: {d}
        \\  partial writes: {d}
        \\  read events: {d}
        \\  checksum: {d}
        \\  elapsed ns: {d}
        \\  throughput MiB/s: {d}
        \\
    , .{
        config.streams,
        payload.len,
        total_bytes,
        config.stream_window,
        read_buffer_bytes,
        write_calls,
        shared.events,
        shared.checksum,
        elapsed_ns,
        mib_per_second,
    });
}

const Config = struct {
    transfer_bytes: usize = default_transfer_bytes,
    streams: usize = default_streams,
    stream_window: u64 = default_stream_window,
    one_rtt_datagram_size: usize = default_one_rtt_datagram_size,
    enable_pacing: bool = true,
};

fn parseArgs(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !Config {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var config = Config{};
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--transfer-bytes=")) {
            config.transfer_bytes = try parsePositiveUsize(
                arg["--transfer-bytes=".len..],
            );
        } else if (std.mem.startsWith(u8, arg, "--streams=")) {
            config.streams = try parsePositiveUsize(
                arg["--streams=".len..],
            );
        } else if (std.mem.startsWith(u8, arg, "--stream-window=")) {
            config.stream_window = try parsePositiveU64(
                arg["--stream-window=".len..],
            );
        } else if (std.mem.startsWith(u8, arg, "--one-rtt-datagram-size=")) {
            config.one_rtt_datagram_size = try parsePositiveUsize(
                arg["--one-rtt-datagram-size=".len..],
            );
        } else if (std.mem.eql(u8, arg, "--disable-pacing")) {
            config.enable_pacing = false;
        } else return error.InvalidArgument;
    }
    if (config.streams > max_streams) return error.InvalidArgument;
    return config;
}

fn parsePositiveU64(raw: []const u8) !u64 {
    const value = try std.fmt.parseInt(u64, raw, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

fn parsePositiveUsize(raw: []const u8) !usize {
    const value = try std.fmt.parseInt(usize, raw, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

fn transportParameters(config: Config) netz.quic.TransportParameters {
    var parameters = netz.quic.practical_transport_parameters;
    parameters.initial_max_data = config.stream_window *| config.streams;
    parameters.initial_max_stream_data_bidi_local = config.stream_window;
    parameters.initial_max_stream_data_bidi_remote = config.stream_window;
    parameters.initial_max_stream_data_uni = config.stream_window;
    return parameters;
}

fn payloadByte(index: usize) u8 {
    return @truncate((index *% 131) ^ (index >> 3));
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

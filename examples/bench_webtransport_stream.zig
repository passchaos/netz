const std = @import("std");
const netz = @import("netz");

const default_transfer_bytes: usize = 4 * 1024 * 1024;
const default_streams: usize = 1;
const max_streams: usize = 64;
const read_buffer_bytes: usize = 16 * 1024;
const default_stream_window: u64 = 64 * 1024;
const default_one_rtt_datagram_size: usize = 4096;
const cancellation_code: u32 = 42;

const LossState = struct {
    enabled: std.atomic.Value(bool) = .init(false),
    state: std.atomic.Value(u64) = .init(0x5754_4c4f_5353),
    considered: std.atomic.Value(usize) = .init(0),
    dropped: std.atomic.Value(usize) = .init(0),
    drop_pct: u8,

    fn shouldDrop(context: *anyopaque, _: []const u8) bool {
        const self: *LossState = @ptrCast(@alignCast(context));
        if (!self.enabled.load(.acquire)) return false;
        _ = self.considered.fetchAdd(1, .monotonic);
        var current = self.state.load(.monotonic);
        while (true) {
            var next = current;
            next ^= next << 13;
            next ^= next >> 7;
            next ^= next << 17;
            if (self.state.cmpxchgWeak(
                current,
                next,
                .monotonic,
                .monotonic,
            )) |observed| {
                current = observed;
                continue;
            }
            if (next % 100 >= self.drop_pct) return false;
            _ = self.dropped.fetchAdd(1, .monotonic);
            return true;
        }
    }
};

const ReorderState = struct {
    enabled: std.atomic.Value(bool) = .init(false),
    considered: std.atomic.Value(usize) = .init(0),
    held: std.atomic.Value(usize) = .init(0),
    every: usize,

    fn shouldHold(context: *anyopaque, _: []const u8) bool {
        const self: *ReorderState = @ptrCast(@alignCast(context));
        if (!self.enabled.load(.acquire) or self.every == 0) return false;
        const index = self.considered.fetchAdd(1, .monotonic) + 1;
        if (index % self.every != 0) return false;
        _ = self.held.fetchAdd(1, .monotonic);
        return true;
    }
};

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
    var loss_state = LossState{ .drop_pct = config.loss_pct };
    var reorder_state = ReorderState{ .every = config.reorder_every };
    var server_limits: netz.webtransport.runtime.Limits = .{
        .http3 = .{
            .quic = .{
                .max_datagram_size = config.one_rtt_datagram_size,
                .max_frames_per_datagram = 8,
            },
        },
    };
    if (config.loss_pct != 0 and config.reorder_every != 0) {
        return error.InvalidArgument;
    }
    if (config.loss_pct != 0) {
        server_limits.http3.quic.send_interceptor = .{
            .context = &loss_state,
            .should_drop = LossState.shouldDrop,
        };
    } else if (config.reorder_every != 0 and
        config.fault_direction == .server)
    {
        server_limits.http3.quic.send_interceptor = .{
            .context = &reorder_state,
            .should_hold = ReorderState.shouldHold,
        };
    }

    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_limits,
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
            .session = .{
                .local_settings = webTransportSettings(config),
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
        reset_streams: usize,
        expected_bytes: usize,
        io: std.Io,
        started: std.Io.Event = .unset,
        finished: std.Io.Event = .unset,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
                shared.finished.set(shared.io);
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var buffer: [read_buffer_bytes]u8 = undefined;
            var finished_streams: usize = 0;
            var reset_streams: usize = 0;
            var terminal: [max_streams]bool = .{false} ** max_streams;
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
                        if (data.fin) {
                            const index = streamIndex(data.stream_id) orelse
                                return error.UnexpectedStream;
                            if (index >= shared.streams or terminal[index]) {
                                return error.UnexpectedStreamEvent;
                            }
                            terminal[index] = true;
                            finished_streams += 1;
                        }
                    },
                    .reset => |reset| {
                        if (reset.direction != .bidirectional or
                            reset.locally_initiated or
                            reset.error_info.application_code !=
                                cancellation_code)
                        {
                            return error.UnexpectedStreamEvent;
                        }
                        const index = streamIndex(reset.stream_id) orelse
                            return error.UnexpectedStream;
                        if (index >= shared.streams or terminal[index]) {
                            return error.UnexpectedStreamEvent;
                        }
                        terminal[index] = true;
                        reset_streams += 1;
                        finished_streams += 1;
                    },
                    .stopped => return error.UnexpectedStreamEvent,
                }
            }
            if (shared.received != shared.expected_bytes or
                reset_streams != shared.reset_streams)
            {
                return error.IncompleteTransfer;
            }
            // Application completion precedes session teardown. The client
            // progress future below is canceled only after this point, so all
            // terminal FIN/reset packets have already been validated.
            shared.finished.set(shared.io);
        }
    };

    var shared = Shared{
        .server = &server,
        .streams = config.streams,
        .reset_streams = resetStreamCount(config),
        .expected_bytes = expectedReceivedBytes(config),
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
                        .send_interceptor = if (config.reorder_every != 0 and
                            config.fault_direction == .client) .{
                            .context = &reorder_state,
                            .should_hold = ReorderState.shouldHold,
                        } else null,
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
                .session = .{
                    .local_settings = webTransportSettings(config),
                },
            },
        },
    );
    defer client.deinit();

    shared.started.waitUncancelable(io);
    // Handshake and CONNECT setup stay reliable. Loss starts only for the
    // associated stream phase so repeated runs share one authenticated state
    // and deterministic RESET_STREAM/ACK loss decisions.
    loss_state.enabled.store(true, .release);
    reorder_state.enabled.store(true, .release);
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
    const reset_prefix_bytes = @min(
        config.reset_after_bytes,
        payload.len,
    );
    for (stream_ids, offsets, 0..) |stream_id, *offset, index| {
        if (!streamShouldReset(config, index)) continue;
        if (reset_prefix_bytes != 0) {
            try client.sendStream(
                stream_id,
                payload[0..reset_prefix_bytes],
                false,
            );
        }
        try client.resetStream(stream_id, cancellation_code);
        offset.* = payload.len;
    }
    const writes = try allocator.alloc(
        netz.webtransport.runtime.StreamWrite,
        config.streams,
    );
    defer allocator.free(writes);
    const counts = try allocator.alloc(usize, config.streams);
    defer allocator.free(counts);
    var remaining = config.streams - resetStreamCount(config);
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
    for (stream_ids, 0..) |stream_id, index| {
        if (!streamShouldReset(config, index)) {
            try client.finishStream(stream_id);
        }
    }
    const Progress = struct {
        fn run(session: *netz.webtransport.runtime.HandshakeClientSession) ?anyerror {
            while (true) session.serviceTransport() catch |err| return err;
        }
    };
    var progress = try std.Io.concurrent(io, Progress.run, .{&client});
    shared.finished.waitUncancelable(io);
    const elapsed_ns = nowNs(io) -| started_ns;
    const progress_result = progress.cancel(io);
    if (progress_result) |err| switch (err) {
        error.Canceled => {},
        else => return err,
    };
    thread.join();
    if (shared.err) |err| return err;
    const total_bytes = expectedReceivedBytes(config);
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
        \\  reset every N streams: {d}
        \\  reset streams: {d}
        \\  bytes before reset: {d}
        \\  simulated loss percent: {d}
        \\  datagrams considered: {d}
        \\  datagrams dropped: {d}
        \\  reorder every: {d}
        \\  fault direction: {s}
        \\  reorder datagrams considered: {d}
        \\  datagrams held: {d}
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
        config.reset_every,
        resetStreamCount(config),
        reset_prefix_bytes,
        config.loss_pct,
        loss_state.considered.load(.monotonic),
        loss_state.dropped.load(.monotonic),
        config.reorder_every,
        @tagName(config.fault_direction),
        reorder_state.considered.load(.monotonic),
        reorder_state.held.load(.monotonic),
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
    reset_every: usize = 0,
    reset_after_bytes: usize = 1024,
    loss_pct: u8 = 0,
    reorder_every: usize = 0,
    fault_direction: FaultDirection = .server,
};

const FaultDirection = enum { client, server };

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
        } else if (std.mem.startsWith(u8, arg, "--reset-every=")) {
            config.reset_every = try parsePositiveUsize(
                arg["--reset-every=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--reset-after-bytes=",
        )) {
            config.reset_after_bytes = try std.fmt.parseInt(
                usize,
                arg["--reset-after-bytes=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--loss-pct=")) {
            config.loss_pct = try std.fmt.parseInt(
                u8,
                arg["--loss-pct=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--reorder-every=")) {
            config.reorder_every = try parsePositiveUsize(
                arg["--reorder-every=".len..],
            );
        } else if (std.mem.startsWith(u8, arg, "--fault-direction=")) {
            config.fault_direction = std.meta.stringToEnum(
                FaultDirection,
                arg["--fault-direction=".len..],
            ) orelse return error.InvalidArgument;
        } else return error.InvalidArgument;
    }
    if (config.streams > max_streams or config.loss_pct > 100) {
        return error.InvalidArgument;
    }
    return config;
}

fn streamShouldReset(config: Config, index: usize) bool {
    return config.reset_every != 0 and
        (index + 1) % config.reset_every == 0;
}

fn resetStreamCount(config: Config) usize {
    if (config.reset_every == 0) return 0;
    return config.streams / config.reset_every;
}

fn expectedReceivedBytes(config: Config) usize {
    const resets = resetStreamCount(config);
    return (config.streams - resets) * config.transfer_bytes +
        resets * @min(config.reset_after_bytes, config.transfer_bytes);
}

fn streamIndex(stream_id: u62) ?usize {
    if (stream_id < 4 or (stream_id - 4) % 4 != 0) return null;
    return @intCast((stream_id - 4) / 4);
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
    parameters.initial_max_streams_bidi = @intCast(config.streams + 4);
    parameters.initial_max_streams_uni = @intCast(config.streams + 4);
    return parameters;
}

fn webTransportSettings(config: Config) netz.http3.Settings {
    return .{
        .webtransport_initial_max_streams_bidi = config.streams + 4,
        .webtransport_initial_max_streams_uni = config.streams + 4,
    };
}

fn payloadByte(index: usize) u8 {
    return @truncate((index *% 131) ^ (index >> 3));
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

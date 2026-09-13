const std = @import("std");
const netz = @import("netz");
const transfer = @import("quic_quic_go_bench.zig");

const alpn = "netz-raw-persistent-bench";
const close_code: u64 = 0;
const close_reason = "benchmark complete";
const echo_prelude = "NZQPE1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

const Mode = enum { echo, aggregate };
const ServerTopology = enum { independent, shared };

const Config = struct {
    mode: Mode,
    role_pair: []const u8,
    sender: transfer.Sender = .client,
    run: u32 = 1,
    connections: u16 = 1,
    warmup: u32 = 200,
    iterations: u32 = 5000,
    streams: u16 = 1,
    bytes_per_stream: u64 = 4 * 1024 * 1024,
    payload_bytes: u32 = 1024,
    chunk_bytes: u32 = 16 * 1024,
    stream_window: u64 = 1024 * 1024,
    timeout_ms: u32 = 30_000,
    server_topology: ServerTopology = .independent,
    shared_receive_batch: u8 = 32,

    fn parse(args: []const []const u8) !Config {
        var mode: ?Mode = null;
        var role_pair: ?[]const u8 = null;
        var result = Config{ .mode = undefined, .role_pair = undefined };
        for (args) |arg| {
            if (option(arg, "--mode=")) |value| {
                if (mode != null) return error.InvalidArgument;
                mode = std.meta.stringToEnum(Mode, value) orelse
                    return error.InvalidArgument;
            } else if (option(arg, "--role-pair=")) |value| {
                if (role_pair != null) return error.InvalidArgument;
                role_pair = value;
            } else if (option(arg, "--sender=")) |value| {
                result.sender = std.meta.stringToEnum(transfer.Sender, value) orelse
                    return error.InvalidArgument;
            } else if (option(arg, "--run=")) |value| {
                result.run = try parsePositive(u32, value);
            } else if (option(arg, "--connections=")) |value| {
                result.connections = try parsePositive(u16, value);
            } else if (option(arg, "--warmup=")) |value| {
                result.warmup = try parseNonNegative(u32, value);
            } else if (option(arg, "--iterations=")) |value| {
                result.iterations = try parsePositive(u32, value);
            } else if (option(arg, "--streams=")) |value| {
                result.streams = try parsePositive(u16, value);
            } else if (option(arg, "--bytes-per-stream=")) |value| {
                result.bytes_per_stream = try parsePositive(u64, value);
            } else if (option(arg, "--payload-bytes=")) |value| {
                result.payload_bytes = try parsePositive(u32, value);
            } else if (option(arg, "--chunk-bytes=")) |value| {
                result.chunk_bytes = try parsePositive(u32, value);
            } else if (option(arg, "--stream-window=")) |value| {
                result.stream_window = try parsePositive(u64, value);
            } else if (option(arg, "--timeout-ms=")) |value| {
                result.timeout_ms = try parsePositive(u32, value);
            } else if (option(arg, "--server-topology=")) |value| {
                result.server_topology = std.meta.stringToEnum(
                    ServerTopology,
                    value,
                ) orelse return error.InvalidArgument;
            } else if (option(arg, "--shared-receive-batch=")) |value| {
                result.shared_receive_batch = try parsePositive(u8, value);
            } else {
                return error.InvalidArgument;
            }
        }
        result.mode = mode orelse return error.InvalidArgument;
        result.role_pair = role_pair orelse return error.InvalidArgument;
        try result.validate();
        return result;
    }

    fn validate(self: Config) !void {
        if (!validRolePair(self.role_pair) or self.run == 0 or
            self.connections == 0 or self.connections > 16 or
            self.warmup > 100_000 or self.iterations == 0 or
            self.iterations > 1_000_000 or
            (self.streams != 1 and self.streams != 4) or
            self.bytes_per_stream == 0 or
            self.bytes_per_stream > 1024 * 1024 * 1024 or
            self.payload_bytes == 0 or self.payload_bytes > 4096 or
            self.chunk_bytes == 0 or self.chunk_bytes > self.bytes_per_stream or
            self.stream_window == 0 or
            self.stream_window > 1024 * 1024 * 1024 or
            self.timeout_ms == 0 or self.timeout_ms > 10 * 60 * 1000 or
            self.shared_receive_batch >
                netz.quic.runtime.max_receive_batch_messages or
            (self.mode == .echo and
                (self.connections != 1 or self.streams != 1 or
                    self.sender != .client)) or
            (self.mode == .aggregate and
                (self.warmup != 0 or self.iterations != 1)) or
            (self.server_topology == .shared and
                (self.mode != .aggregate or self.sender != .client or
                    !std.mem.eql(
                        u8,
                        self.role_pair,
                        "netz-client+netz-server",
                    ))))
        {
            return error.InvalidArgument;
        }
        try self.wire().validate();
        _ = try self.totalEchoRounds();
        _ = try self.aggregateBytes();
    }

    fn timeout(self: Config) std.Io.Duration {
        return .fromMilliseconds(self.timeout_ms);
    }

    fn wire(self: Config) transfer.Config {
        return switch (self.mode) {
            .echo => .{
                .warmup = self.warmup,
                .iterations = self.iterations,
                .streams = 1,
                .bytes_per_stream = self.payload_bytes,
                .chunk_bytes = self.payload_bytes,
                .stream_window = self.stream_window,
                .timeout_ms = self.timeout_ms,
            },
            .aggregate => .{
                .warmup = 0,
                .iterations = 1,
                .streams = self.streams,
                .bytes_per_stream = self.bytes_per_stream,
                .chunk_bytes = self.chunk_bytes,
                .stream_window = self.stream_window,
                .timeout_ms = self.timeout_ms,
            },
        };
    }

    fn totalEchoRounds(self: Config) !u32 {
        return std.math.add(u32, self.warmup, self.iterations) catch
            error.InvalidArgument;
    }

    fn aggregateBytes(self: Config) !u64 {
        const per_connection = try self.wire().totalBytes();
        return std.math.mul(u64, per_connection, self.connections) catch
            error.InvalidArgument;
    }
};

const WorkerResult = struct {
    bytes: u64 = 0,
    checksum: u64 = 0,
    finished_ns: u64 = 0,
    err: ?anyerror = null,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) return error.InvalidArgument;
    if (std.mem.eql(u8, args[1], "server")) {
        return runServer(try Config.parse(args[2..]));
    }
    if (std.mem.eql(u8, args[1], "client")) {
        var ports: ?[]const u8 = null;
        var ca_path: ?[]const u8 = null;
        var config_args: std.ArrayList([]const u8) = .empty;
        defer config_args.deinit(std.heap.c_allocator);
        for (args[2..]) |arg| {
            if (option(arg, "--ports=")) |value| {
                ports = value;
            } else if (option(arg, "--ca=")) |value| {
                ca_path = value;
            } else {
                try config_args.append(std.heap.c_allocator, arg);
            }
        }
        const client_config = try Config.parse(config_args.items);
        return runClient(
            client_config,
            ports orelse return error.InvalidArgument,
            ca_path orelse return error.InvalidArgument,
        );
    }
    return error.InvalidArgument;
}

fn runServer(config: Config) !void {
    if (config.server_topology == .shared) {
        return runSharedServer(config);
    }
    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const endpoints = try allocator.alloc(netz.quic.runtime.Endpoint, config.connections);
    defer allocator.free(endpoints);
    var initialized: usize = 0;
    defer for (endpoints[0..initialized]) |*endpoint| endpoint.deinit();
    for (endpoints) |*endpoint| {
        endpoint.* = try netz.quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            endpointLimits(),
        );
        initialized += 1;
    }
    std.debug.print("NETZ_QUIC_PERSISTENT_PORTS=", .{});
    for (endpoints, 0..) |*endpoint, index| {
        if (index != 0) std.debug.print(",", .{});
        std.debug.print("{d}", .{endpoint.address().ip4.port});
    }
    std.debug.print("\n", .{});

    const contexts = try allocator.alloc(ServerWorker, config.connections);
    defer allocator.free(contexts);
    const threads = try allocator.alloc(std.Thread, config.connections);
    defer allocator.free(threads);
    const results = try allocator.alloc(WorkerResult, config.connections);
    defer allocator.free(results);
    @memset(results, .{});
    for (0..config.connections) |index| {
        contexts[index] = .{
            .allocator = allocator,
            .io = io,
            .endpoint = &endpoints[index],
            .config = config,
            .index = @intCast(index),
            .result = &results[index],
        };
        threads[index] = try std.Thread.spawn(.{}, ServerWorker.run, .{&contexts[index]});
    }
    for (threads) |thread| thread.join();
    try printServerCompletion(config, results, null, null);
}

const SharedStage = enum {
    config,
    config_ack,
    start,
    preludes,
    ready,
    payload,
    done,
    done_ack,
    complete,
};

const SharedConnectionState = struct {
    handle: ?netz.quic.endpoint_dispatcher.ConnectionHandle = null,
    connection_index: ?u32 = null,
    stage: SharedStage = .config,
    control: [transfer.record_len]u8 = undefined,
    control_len: usize = 0,
    control_offset: u64 = 0,
    discovered_stream_ids: [4]u64 = @splat(std.math.maxInt(u64)),
    stream_ids: [4]u64 = @splat(std.math.maxInt(u64)),
    preludes: [4][transfer.prelude_len]u8 = undefined,
    prelude_lengths: [4]usize = @splat(0),
    payload_offsets: [4]usize = @splat(0),
    checksums: [4]u64 = @splat(0),
    finished: [4]bool = @splat(false),
    completed_streams: usize = 0,
};

const SharedReceiveStats = struct {
    calls: u64 = 0,
    events: u64 = 0,
    max_events: usize = 0,
    received_datagrams: u64 = 0,
    max_received_datagrams: u64 = 0,
    connected_events: u64 = 0,
    packet_events: u64 = 0,
    timer_events: u64 = 0,
};

fn runSharedServer(config: Config) !void {
    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var socket_traffic: netz.quic.runtime.SocketTrafficCounters = .{};
    var limits = endpointLimits();
    limits.socket_traffic_counters = &socket_traffic;
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer endpoint.deinit();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    var server = try netz.quic.endpoint_server.Server.init(
        allocator,
        &endpoint,
        .{
            .local_connection_id = &.{},
            .version = .version_1,
            .available_versions = &.{.version_1},
            .alpn_protocol = alpn,
            .local_transport_parameters = try config.wire().transportParameters(),
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = try netz.tls.testing.serverKeyPair(),
                } },
            },
            .max_crypto_buffer = 64 * 1024,
            .initial_one_rtt_config = try config.wire().oneRttConfig(),
        },
        .{
            .max_pending_handshakes = config.connections,
            .max_connections = config.connections,
            .inbox_capacity = 32,
            .handshake_timeout_ms = config.timeout_ms,
        },
    );
    defer server.deinit();

    std.debug.print("NETZ_QUIC_PERSISTENT_PORTS=", .{});
    for (0..config.connections) |index| {
        if (index != 0) std.debug.print(",", .{});
        std.debug.print("{d}", .{server.address().ip4.port});
    }
    std.debug.print("\n", .{});

    const states = try allocator.alloc(SharedConnectionState, config.connections);
    defer allocator.free(states);
    @memset(states, .{});
    const results = try allocator.alloc(WorkerResult, config.connections);
    defer allocator.free(results);
    @memset(results, .{});

    const deadline = deadlineFromNow(io, config.timeout());
    const versions = [_]u32{quicVersionOne()};
    var receive_storage: [
        netz.quic.runtime.max_receive_batch_messages * 4096
    ]u8 = undefined;
    var receive_events: [netz.quic.runtime.max_receive_batch_messages]netz.quic.endpoint_server.VisitEvent = undefined;
    var receive_stats: SharedReceiveStats = .{};
    var complete: usize = 0;
    while (complete < config.connections) {
        const traffic_before = socket_traffic.stats();
        const event_count = try server.receiveManyVisitingTimeout(
            &versions,
            receive_storage[0 .. @as(usize, config.shared_receive_batch) * 4096],
            receive_events[0..config.shared_receive_batch],
            .{ .deadline = deadline },
            {},
            discardSharedPacket,
        );
        const received_datagrams = socket_traffic.stats()
            .since(traffic_before).received_datagrams;
        receive_stats.calls += 1;
        receive_stats.events += event_count;
        receive_stats.max_events = @max(
            receive_stats.max_events,
            event_count,
        );
        receive_stats.received_datagrams += received_datagrams;
        receive_stats.max_received_datagrams = @max(
            receive_stats.max_received_datagrams,
            received_datagrams,
        );
        for (receive_events[0..event_count]) |*event| {
            defer event.deinit(allocator);
            switch (event.*) {
                .connected => |handle| {
                    receive_stats.connected_events += 1;
                    if (handle == 0 or handle > states.len) {
                        return error.InvalidBenchmarkResult;
                    }
                    const state = &states[handle - 1];
                    if (state.handle != null) {
                        return error.InvalidBenchmarkResult;
                    }
                    state.handle = handle;
                    const established = server.connection(handle) orelse
                        return error.InvalidBenchmarkResult;
                    try validateHandshake(established.*, false);
                    complete += @intFromBool(try driveSharedUntilBlocked(
                        &server,
                        config,
                        states,
                        state,
                        results,
                    ));
                },
                .packet => |packet| {
                    receive_stats.packet_events += 1;
                    const handle = packet.connection_handle;
                    if (handle == 0 or handle > states.len) {
                        return error.InvalidBenchmarkResult;
                    }
                    complete += @intFromBool(try driveSharedUntilBlocked(
                        &server,
                        config,
                        states,
                        &states[handle - 1],
                        results,
                    ));
                },
                .timer => |timer| {
                    receive_stats.timer_events += 1;
                    const handle = timer.connection_handle;
                    if (handle == 0 or handle > states.len) {
                        return error.InvalidBenchmarkResult;
                    }
                    complete += @intFromBool(try driveSharedUntilBlocked(
                        &server,
                        config,
                        states,
                        &states[handle - 1],
                        results,
                    ));
                },
                .handshake_failed => |failure| return failure.err,
                .unrouted => return error.InvalidBenchmarkResult,
            }
        }
    }
    try printServerCompletion(
        config,
        results,
        receive_stats,
        socket_traffic.stats(),
    );
}

fn discardSharedPacket(
    _: void,
    _: netz.quic.endpoint_dispatcher.RoutedPacketView,
) error{}!void {}

fn driveSharedUntilBlocked(
    server: *netz.quic.endpoint_server.Server,
    config: Config,
    states: []SharedConnectionState,
    state: *SharedConnectionState,
    results: []WorkerResult,
) !bool {
    const was_complete = state.stage == .complete;
    while (!was_complete and state.stage != .complete and
        try driveSharedConnection(server, config, states, state, results))
    {}
    return !was_complete and state.stage == .complete;
}

fn quicVersionOne() u32 {
    return netz.quic.Version.version_1.wireValue();
}

fn driveSharedConnection(
    server: *netz.quic.endpoint_server.Server,
    config: Config,
    states: []SharedConnectionState,
    state: *SharedConnectionState,
    results: []WorkerResult,
) !bool {
    const handle = state.handle.?;
    const wire = config.wire();
    switch (state.stage) {
        .config, .start, .done_ack => {
            const event = (try server.pollStreamId(
                handle,
                0,
                state.control[state.control_len..],
            )) orelse return false;
            const data = switch (event) {
                .reset => return error.InvalidBenchmarkControl,
                .data => |value| value,
            };
            if (data.stream_id != 0 or
                state.control_len + data.bytes > state.control.len)
            {
                return error.InvalidBenchmarkControl;
            }
            state.control_len += data.bytes;
            if (state.control_len != state.control.len) {
                if (data.fin) return error.InvalidBenchmarkControl;
                return true;
            }
            const expected_kind: transfer.Kind = switch (state.stage) {
                .config => .config,
                .start => .start,
                .done_ack => .done_ack,
                else => unreachable,
            };
            if (data.fin != (state.stage == .done_ack)) {
                return error.InvalidBenchmarkControl;
            }
            const record = try transfer.Record.decode(&state.control);
            if (state.stage == .config) {
                if (record.round >= config.connections) {
                    return error.InvalidBenchmarkControl;
                }
                for (states) |other| {
                    if (other.handle != handle and
                        other.connection_index == record.round)
                    {
                        return error.InvalidBenchmarkControl;
                    }
                }
                state.connection_index = record.round;
            }
            const index = state.connection_index orelse
                return error.InvalidBenchmarkControl;
            try transfer.validateRecord(
                record,
                expected_kind,
                .client,
                index,
                wire,
            );
            if (state.stage == .done_ack) {
                const result = results[index];
                if (record.received_bytes != result.bytes or
                    record.checksum != result.checksum)
                {
                    return error.InvalidBenchmarkResult;
                }
                const connection = server.connection(handle) orelse
                    return error.InvalidBenchmarkResult;
                try connection.connection.closeApplication(
                    close_code,
                    close_reason,
                );
                try server.refreshConnectionTimer(handle);
                state.stage = .complete;
                return true;
            }
            state.control_len = 0;
            state.stage = if (state.stage == .config) .config_ack else .preludes;
            return true;
        },
        .config_ack, .ready, .done => {
            const index = state.connection_index orelse
                return error.InvalidBenchmarkControl;
            var record = transfer.Record.init(
                switch (state.stage) {
                    .config_ack => .config_ack,
                    .ready => .ready,
                    .done => .done,
                    else => unreachable,
                },
                .client,
                index,
                wire,
            );
            const fin = state.stage == .done;
            if (fin) {
                const result = results[index];
                record.received_bytes = result.bytes;
                record.checksum = result.checksum;
            }
            if (!try trySendSharedRecord(
                server,
                handle,
                &state.control_offset,
                record,
                fin,
            )) return false;
            state.stage = switch (state.stage) {
                .config_ack => .start,
                .ready => .payload,
                .done => .done_ack,
                else => unreachable,
            };
            return true;
        },
        .preludes => {
            var scratch: [transfer.prelude_len]u8 = undefined;
            const event = (try server.pollStream(
                handle,
                &scratch,
            )) orelse return false;
            const data = switch (event) {
                .reset => return error.InvalidBenchmarkPrelude,
                .data => |value| value,
            };
            if (data.stream_id == 0 or data.fin) {
                return error.InvalidBenchmarkPrelude;
            }
            var slot: ?usize = null;
            for (0..config.streams) |index| {
                if (state.discovered_stream_ids[index] == data.stream_id) {
                    slot = index;
                }
            }
            if (slot == null) {
                for (0..config.streams) |index| {
                    if (state.discovered_stream_ids[index] ==
                        std.math.maxInt(u64))
                    {
                        state.discovered_stream_ids[index] = data.stream_id;
                        slot = index;
                        break;
                    }
                }
            }
            const found = slot orelse return error.InvalidBenchmarkPrelude;
            if (state.prelude_lengths[found] + data.bytes >
                transfer.prelude_len) return error.InvalidBenchmarkPrelude;
            @memcpy(
                state.preludes[found][state.prelude_lengths[found]..][0..data.bytes],
                scratch[0..data.bytes],
            );
            state.prelude_lengths[found] += data.bytes;
            if (state.prelude_lengths[found] == transfer.prelude_len) {
                const index = try transfer.decodePrelude(
                    &state.preludes[found],
                    state.connection_index.?,
                    config.streams,
                );
                if (state.stream_ids[index] != std.math.maxInt(u64)) {
                    return error.InvalidBenchmarkPrelude;
                }
                const expected = @as(u64, 2) + @as(u64, index) * 4;
                if (data.stream_id != expected) {
                    return error.InvalidBenchmarkPrelude;
                }
                state.stream_ids[index] = data.stream_id;
                var complete: usize = 0;
                for (state.stream_ids[0..config.streams]) |stream_id| {
                    complete += @intFromBool(stream_id != std.math.maxInt(u64));
                }
                if (complete == config.streams) state.stage = .ready;
            }
            return true;
        },
        .payload => {
            var buffer: [transfer.mtu]u8 = undefined;
            const event = (try server.pollStream(
                handle,
                buffer[0..wire.effectiveChunk()],
            )) orelse return false;
            const data = switch (event) {
                .reset => return error.InvalidBenchmarkPayload,
                .data => |value| value,
            };
            var stream_index: ?usize = null;
            for (state.stream_ids[0..config.streams], 0..) |stream_id, index| {
                if (stream_id == data.stream_id) stream_index = index;
            }
            const index = stream_index orelse
                return error.InvalidBenchmarkPayload;
            if (state.finished[index] or
                state.payload_offsets[index] + data.bytes >
                    config.bytes_per_stream)
            {
                return error.InvalidBenchmarkPayload;
            }
            state.checksums[index] +%= try transfer.verifyPayload(
                buffer[0..data.bytes],
                state.connection_index.?,
                index,
                state.payload_offsets[index],
            );
            state.payload_offsets[index] += data.bytes;
            if (data.fin) {
                if (state.payload_offsets[index] != config.bytes_per_stream) {
                    return error.InvalidBenchmarkPayload;
                }
                state.finished[index] = true;
                state.completed_streams += 1;
            }
            if (state.completed_streams == config.streams) {
                var checksum: u64 = 0;
                for (state.checksums[0..config.streams]) |value| {
                    checksum +%= value;
                }
                results[state.connection_index.?] = .{
                    .bytes = try wire.totalBytes(),
                    .checksum = checksum,
                };
                state.stage = .done;
            }
            return true;
        },
        .complete => return false,
    }
}

fn trySendSharedRecord(
    server: *netz.quic.endpoint_server.Server,
    handle: netz.quic.endpoint_dispatcher.ConnectionHandle,
    offset: *u64,
    record: transfer.Record,
    fin: bool,
) !bool {
    const bytes = try record.encode();
    server.trySend(handle, &.{.{ .stream = .{
        .stream_id = 0,
        .offset = offset.*,
        .data = &bytes,
        .fin = fin,
    } }}) catch |err| switch (err) {
        error.PacingLimited,
        error.CongestionLimited,
        error.FlowControlBlocked,
        => return false,
        else => return err,
    };
    offset.* += bytes.len;
    return true;
}

fn runClient(config: Config, ports_text: []const u8, ca_path: []const u8) !void {
    if (!std.Io.Dir.path.isAbsolute(ca_path)) return error.InvalidArgument;
    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const ports = try parsePorts(allocator, ports_text, config.connections);
    defer allocator.free(ports);
    const contexts = try allocator.alloc(ClientWorker, config.connections);
    defer allocator.free(contexts);
    const threads = try allocator.alloc(std.Thread, config.connections);
    defer allocator.free(threads);
    const results = try allocator.alloc(WorkerResult, config.connections);
    defer allocator.free(results);
    @memset(results, .{});
    const latency_count = if (config.mode == .echo) config.iterations else 0;
    const latencies = try allocator.alloc(u64, latency_count);
    defer allocator.free(latencies);
    var ready = std.atomic.Value(usize).init(0);
    var failed = std.atomic.Value(bool).init(false);
    var start: std.Io.Event = .unset;
    for (0..config.connections) |index| {
        contexts[index] = .{
            .allocator = allocator,
            .io = io,
            .port = ports[index],
            .ca_path = ca_path,
            .config = config,
            .index = @intCast(index),
            .ready = &ready,
            .failed = &failed,
            .start = &start,
            .latencies = if (config.mode == .echo) latencies else &.{},
            .result = &results[index],
        };
        threads[index] = try std.Thread.spawn(.{}, ClientWorker.run, .{&contexts[index]});
    }
    while (ready.load(.acquire) != config.connections and
        !failed.load(.acquire))
    {
        std.Thread.yield() catch {};
    }
    const started_ns = transfer.nowNs(io);
    start.set(io);
    for (threads) |thread| thread.join();
    for (results) |result| if (result.err) |err| return err;
    var finished_ns = started_ns;
    var bytes: u64 = 0;
    var checksum: u64 = 0;
    for (results) |result| {
        finished_ns = @max(finished_ns, result.finished_ns);
        bytes +|= result.bytes;
        checksum +%= result.checksum;
    }
    try printClientResult(config, latencies, finished_ns -| started_ns, bytes, checksum);
}

const ServerWorker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: *netz.quic.runtime.Endpoint,
    config: Config,
    index: u32,
    result: *WorkerResult,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.result.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
        try std.base64.standard.Decoder.decode(
            &certificate_der,
            netz.tls.testing.certificate_base64,
        );
        var server_cid: [8]u8 = undefined;
        try std.Io.randomSecure(self.io, &server_cid);
        var established = try netz.quic.handshake.acceptWithTimeout(
            self.endpoint,
            .{
                .local_connection_id = &server_cid,
                .version = .version_1,
                .available_versions = &.{.version_1},
                .alpn_protocol = alpn,
                .local_transport_parameters = try self.config.wire().transportParameters(),
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = try netz.tls.testing.serverKeyPair(),
                    } },
                },
                .max_crypto_buffer = 64 * 1024,
                .initial_one_rtt_config = try self.config.wire().oneRttConfig(),
            },
            self.config.timeout(),
        );
        defer established.deinit();
        try validateHandshake(established, false);
        const deadline = deadlineFromNow(self.io, self.config.timeout());
        const request = try transfer.receiveRecord(
            &established.connection,
            0,
            deadline,
            false,
        );
        try transfer.validateRecord(
            request,
            .config,
            self.config.sender,
            self.index,
            self.config.wire(),
        );
        var control_offset: u64 = 0;
        try transfer.sendRecord(
            &established.connection,
            0,
            &control_offset,
            transfer.Record.init(
                .config_ack,
                self.config.sender,
                self.index,
                self.config.wire(),
            ),
            false,
            deadline,
        );
        self.result.* = switch (self.config.mode) {
            .echo => try serverEcho(
                self.allocator,
                &established.connection,
                self.config,
                &control_offset,
                deadline,
            ),
            .aggregate => try serverAggregate(
                self.allocator,
                &established.connection,
                self.config,
                self.index,
                &control_offset,
                deadline,
            ),
        };
        if (self.config.mode == .aggregate and self.config.sender == .client) {
            try established.connection.closeApplication(close_code, close_reason);
        } else if (self.config.mode == .aggregate) {
            try waitForPersistentClose(&established.connection, deadline);
        }
    }
};

const ClientWorker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    ca_path: []const u8,
    config: Config,
    index: u32,
    ready: *std.atomic.Value(usize),
    failed: *std.atomic.Value(bool),
    start: *std.Io.Event,
    latencies: []u64,
    result: *WorkerResult,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.result.err = err;
            self.failed.store(true, .release);
            self.start.set(self.io);
        };
    }

    fn runFallible(self: *@This()) !void {
        const now = std.Io.Clock.real.now(self.io);
        var ca_bundle: std.crypto.Certificate.Bundle = .empty;
        defer ca_bundle.deinit(self.allocator);
        try ca_bundle.addCertsFromFilePathAbsolute(
            self.allocator,
            self.io,
            now,
            self.ca_path,
        );
        var verifier = netz.quic.tls.trust.BundleVerifier{
            .bundle = &ca_bundle,
            .now_seconds = now.toSeconds(),
        };
        var endpoint = try netz.quic.runtime.Endpoint.bind(
            self.allocator,
            self.io,
            .{ .ip4 = .loopback(0) },
            endpointLimits(),
        );
        defer endpoint.deinit();
        var original_dcid: [8]u8 = undefined;
        var client_cid: [8]u8 = undefined;
        try std.Io.randomSecure(self.io, &original_dcid);
        try std.Io.randomSecure(self.io, &client_cid);
        var established = try netz.quic.handshake.connectWithTimeout(
            &endpoint,
            .{ .ip4 = .loopback(self.port) },
            .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .version = .version_1,
                .available_versions = &.{.version_1},
                .server_name = "localhost",
                .alpn_protocols = &.{alpn},
                .server_auth = verifier.clientVerifier(),
                .local_transport_parameters = try self.config.wire().transportParameters(),
                .max_crypto_buffer = 64 * 1024,
                .initial_one_rtt_config = try self.config.wire().oneRttConfig(),
            },
            self.config.timeout(),
        );
        defer established.deinit();
        try validateHandshake(established, true);
        const deadline = deadlineFromNow(self.io, self.config.timeout());
        const control_id = try established.connection.openStreamWithDeadline(deadline);
        if (control_id != 0) return error.UnexpectedStreamId;
        var control_offset: u64 = 0;
        try transfer.sendRecord(
            &established.connection,
            control_id,
            &control_offset,
            transfer.Record.init(
                .config,
                self.config.sender,
                self.index,
                self.config.wire(),
            ),
            false,
            deadline,
        );
        const ack = try transfer.receiveRecord(
            &established.connection,
            0,
            deadline,
            false,
        );
        try transfer.validateRecord(
            ack,
            .config_ack,
            self.config.sender,
            self.index,
            self.config.wire(),
        );
        self.result.* = switch (self.config.mode) {
            .echo => try clientEcho(
                self.allocator,
                self.io,
                &established.connection,
                self.config,
                self.ready,
                self.start,
                self.latencies,
                &control_offset,
                deadline,
            ),
            .aggregate => try clientAggregate(
                self.allocator,
                &established.connection,
                self.config,
                self.index,
                self.ready,
                self.start,
                &control_offset,
                deadline,
            ),
        };
        if (self.config.mode == .aggregate and self.config.sender == .server) {
            try established.connection.closeApplication(close_code, close_reason);
        } else if (self.config.mode == .aggregate) {
            try waitForPersistentClose(&established.connection, deadline);
        }
    }
};

fn clientEcho(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    ready_count: *std.atomic.Value(usize),
    start: *std.Io.Event,
    latencies: []u64,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !WorkerResult {
    const stream_id = try connection.openStreamWithDeadline(deadline);
    if (stream_id != 4) return error.UnexpectedStreamId;
    var stream_offset: u64 = 0;
    try transfer.sendBytes(
        connection,
        stream_id,
        stream_offset,
        echo_prelude,
        false,
        deadline,
    );
    stream_offset += echo_prelude.len;
    const ready = try transfer.receiveRecord(connection, 0, deadline, false);
    try transfer.validateRecord(ready, .ready, .client, 0, config.wire());
    const payload = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(payload);
    const echoed = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(echoed);
    var checksum: u64 = 0;
    for (0..config.warmup) |sequence| {
        checksum +%= fillEchoPayload(payload, @intCast(sequence));
        try echoOnce(
            connection,
            stream_id,
            &stream_offset,
            payload,
            echoed,
            false,
            deadline,
        );
    }
    _ = ready_count.fetchAdd(1, .release);
    start.waitUncancelable(io);
    for (latencies, 0..) |*elapsed, index| {
        const sequence = config.warmup + @as(u32, @intCast(index));
        checksum +%= fillEchoPayload(payload, sequence);
        const started = transfer.nowNs(io);
        try echoOnce(
            connection,
            stream_id,
            &stream_offset,
            payload,
            echoed,
            index + 1 == latencies.len,
            deadline,
        );
        elapsed.* = transfer.nowNs(io) -| started;
    }
    var done = transfer.Record.init(.done, .client, 0, config.wire());
    done.received_bytes = @as(u64, try config.totalEchoRounds()) * config.payload_bytes;
    done.checksum = checksum;
    try transfer.sendRecord(connection, 0, control_offset, done, true, deadline);
    const done_ack = try transfer.receiveRecord(connection, 0, deadline, true);
    try transfer.validateRecord(done_ack, .done_ack, .client, 0, config.wire());
    if (done_ack.received_bytes != done.received_bytes or
        done_ack.checksum != checksum) return error.InvalidBenchmarkResult;
    return .{
        .bytes = done.received_bytes,
        .checksum = checksum,
        .finished_ns = transfer.nowNs(io),
    };
}

fn serverEcho(
    allocator: std.mem.Allocator,
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !WorkerResult {
    var prelude: [echo_prelude.len]u8 = undefined;
    try receiveExact(connection, 4, &prelude, false, deadline);
    if (!std.mem.eql(u8, &prelude, echo_prelude)) return error.InvalidBenchmarkPrelude;
    try transfer.sendRecord(
        connection,
        0,
        control_offset,
        transfer.Record.init(.ready, .client, 0, config.wire()),
        false,
        deadline,
    );
    const payload = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(payload);
    const expected = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(expected);
    var stream_offset: u64 = 0;
    var checksum: u64 = 0;
    const rounds = try config.totalEchoRounds();
    for (0..rounds) |sequence| {
        const fin = sequence + 1 == rounds;
        try receiveExact(connection, 4, payload, fin, deadline);
        checksum +%= fillEchoPayload(expected, @intCast(sequence));
        if (!std.mem.eql(u8, payload, expected)) return error.InvalidBenchmarkPayload;
        try transfer.sendBytes(
            connection,
            4,
            stream_offset,
            payload,
            fin,
            deadline,
        );
        stream_offset += payload.len;
    }
    const done = try transfer.receiveRecord(connection, 0, deadline, true);
    try transfer.validateRecord(done, .done, .client, 0, config.wire());
    const total_bytes = @as(u64, rounds) * config.payload_bytes;
    if (done.received_bytes != total_bytes or done.checksum != checksum)
        return error.InvalidBenchmarkResult;
    var ack = transfer.Record.init(.done_ack, .client, 0, config.wire());
    ack.received_bytes = total_bytes;
    ack.checksum = checksum;
    try transfer.sendRecord(connection, 0, control_offset, ack, true, deadline);
    return .{ .bytes = total_bytes, .checksum = checksum };
}

fn clientAggregate(
    allocator: std.mem.Allocator,
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    connection_index: u32,
    ready_count: *std.atomic.Value(usize),
    start: *std.Io.Event,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !WorkerResult {
    const wire = config.wire();
    _ = ready_count.fetchAdd(1, .release);
    start.waitUncancelable(connection.endpoint.io);
    try transfer.sendRecord(
        connection,
        0,
        control_offset,
        transfer.Record.init(.start, config.sender, connection_index, wire),
        false,
        deadline,
    );
    var payloads: ?transfer.PayloadSet = null;
    defer if (payloads) |*set| set.deinit(allocator);
    var stream_ids: [4]u64 = undefined;
    if (config.sender == .client) {
        payloads = try transfer.PayloadSet.init(allocator, wire, connection_index);
        stream_ids = try transfer.prepareDataStreams(
            connection,
            wire,
            connection_index,
            deadline,
        );
        const ready = try transfer.receiveRecord(connection, 0, deadline, false);
        try transfer.validateRecord(
            ready,
            .ready,
            .client,
            connection_index,
            wire,
        );
    } else {
        stream_ids = try transfer.receiveDataPreludes(
            connection,
            wire,
            connection_index,
            .server,
            deadline,
        );
        try transfer.sendRecord(
            connection,
            0,
            control_offset,
            transfer.Record.init(.ready, .server, connection_index, wire),
            false,
            deadline,
        );
    }
    if (config.sender == .client) {
        try transfer.sendPayloads(connection, wire, &stream_ids, &payloads.?, deadline);
        const done = try transfer.receiveRecord(connection, 0, deadline, true);
        try transfer.validateRecord(done, .done, .client, connection_index, wire);
        if (done.received_bytes != try wire.totalBytes() or
            done.checksum != payloads.?.checksum) return error.InvalidBenchmarkResult;
        var ack = transfer.Record.init(.done_ack, .client, connection_index, wire);
        ack.received_bytes = done.received_bytes;
        ack.checksum = done.checksum;
        try transfer.sendRecord(connection, 0, control_offset, ack, true, deadline);
        return .{
            .bytes = done.received_bytes,
            .checksum = done.checksum,
            .finished_ns = transfer.nowNs(connection.endpoint.io),
        };
    }
    const buffer = try allocator.alloc(u8, wire.effectiveChunk());
    defer allocator.free(buffer);
    const received = try transfer.receivePayloads(
        connection,
        wire,
        connection_index,
        &stream_ids,
        buffer,
        deadline,
    );
    var done = transfer.Record.init(.done, .server, connection_index, wire);
    done.received_bytes = received.bytes;
    done.checksum = received.checksum;
    try transfer.sendRecord(connection, 0, control_offset, done, true, deadline);
    const ack = try transfer.receiveRecord(connection, 0, deadline, true);
    try transfer.validateRecord(ack, .done_ack, .server, connection_index, wire);
    if (ack.received_bytes != received.bytes or ack.checksum != received.checksum)
        return error.InvalidBenchmarkResult;
    return .{
        .bytes = received.bytes,
        .checksum = received.checksum,
        .finished_ns = transfer.nowNs(connection.endpoint.io),
    };
}

fn serverAggregate(
    allocator: std.mem.Allocator,
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    connection_index: u32,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !WorkerResult {
    const wire = config.wire();
    const go = try transfer.receiveRecord(connection, 0, deadline, false);
    try transfer.validateRecord(go, .start, config.sender, connection_index, wire);
    var payloads: ?transfer.PayloadSet = null;
    defer if (payloads) |*set| set.deinit(allocator);
    var stream_ids: [4]u64 = undefined;
    if (config.sender == .server) {
        payloads = try transfer.PayloadSet.init(allocator, wire, connection_index);
        stream_ids = try transfer.prepareDataStreams(
            connection,
            wire,
            connection_index,
            deadline,
        );
        const ready = try transfer.receiveRecord(connection, 0, deadline, false);
        try transfer.validateRecord(
            ready,
            .ready,
            .server,
            connection_index,
            wire,
        );
    } else {
        stream_ids = try transfer.receiveDataPreludes(
            connection,
            wire,
            connection_index,
            .client,
            deadline,
        );
        try transfer.sendRecord(
            connection,
            0,
            control_offset,
            transfer.Record.init(.ready, .client, connection_index, wire),
            false,
            deadline,
        );
    }
    if (config.sender == .server) {
        try transfer.sendPayloads(connection, wire, &stream_ids, &payloads.?, deadline);
        const done = try transfer.receiveRecord(connection, 0, deadline, true);
        try transfer.validateRecord(done, .done, .server, connection_index, wire);
        if (done.received_bytes != try wire.totalBytes() or
            done.checksum != payloads.?.checksum) return error.InvalidBenchmarkResult;
        var ack = transfer.Record.init(.done_ack, .server, connection_index, wire);
        ack.received_bytes = done.received_bytes;
        ack.checksum = done.checksum;
        try transfer.sendRecord(connection, 0, control_offset, ack, true, deadline);
        return .{ .bytes = done.received_bytes, .checksum = done.checksum };
    }
    const buffer = try allocator.alloc(u8, wire.effectiveChunk());
    defer allocator.free(buffer);
    const received = try transfer.receivePayloads(
        connection,
        wire,
        connection_index,
        &stream_ids,
        buffer,
        deadline,
    );
    var done = transfer.Record.init(.done, .client, connection_index, wire);
    done.received_bytes = received.bytes;
    done.checksum = received.checksum;
    try transfer.sendRecord(connection, 0, control_offset, done, true, deadline);
    const ack = try transfer.receiveRecord(connection, 0, deadline, true);
    try transfer.validateRecord(ack, .done_ack, .client, connection_index, wire);
    if (ack.received_bytes != received.bytes or ack.checksum != received.checksum)
        return error.InvalidBenchmarkResult;
    return .{ .bytes = received.bytes, .checksum = received.checksum };
}

fn echoOnce(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    offset: *u64,
    payload: []const u8,
    echoed: []u8,
    fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    try transfer.sendBytes(connection, stream_id, offset.*, payload, fin, deadline);
    try receiveExact(connection, @intCast(stream_id), echoed, fin, deadline);
    if (!std.mem.eql(u8, payload, echoed)) return error.InvalidBenchmarkPayload;
    offset.* += payload.len;
}

fn receiveExact(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u62,
    output: []u8,
    expect_fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var received: usize = 0;
    var fin = false;
    var fin_probe: [1]u8 = undefined;
    while (received < output.len or expect_fin and !fin) {
        const event = try connection.receiveStreamIdWithDeadline(
            stream_id,
            if (received < output.len) output[received..] else &fin_probe,
            deadline,
        );
        const data = switch (event) {
            .reset => return error.InvalidBenchmarkPayload,
            .data => |value| value,
        };
        if (data.stream_id != stream_id or received + data.bytes > output.len)
            return error.InvalidBenchmarkPayload;
        received += data.bytes;
        fin = fin or data.fin;
        if (fin and received != output.len) return error.InvalidBenchmarkPayload;
    }
    if (fin != expect_fin) return error.InvalidBenchmarkPayload;
}

fn fillEchoPayload(payload: []u8, sequence: u32) u64 {
    var checksum: u64 = 0;
    for (payload, 0..) |*byte, index| {
        byte.* = @truncate(@as(u64, sequence) *% 17 +% index *% 131);
        checksum +%= byte.*;
    }
    return checksum;
}

fn waitForPersistentClose(
    connection: *netz.quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) !void {
    while (connection.peerCloseInfo() == null) {
        var packet = connection.receivePacketServicingTimersDeadline(deadline) catch |err|
            switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
        packet.deinit(connection.endpoint.allocator);
    }
    try transfer.validateBenchmarkClose(connection);
}

fn validateHandshake(
    established: netz.quic.handshake.EstablishedConnection,
    require_certificate: bool,
) !void {
    if (!std.mem.eql(u8, established.alpn, alpn) or
        (require_certificate and established.peerCertificates() == null))
    {
        return error.InvalidHandshake;
    }
}

fn endpointLimits() netz.quic.runtime.Limits {
    return .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = transfer.max_frames,
        .enable_gso_send = false,
        .enable_gro_receive = false,
    };
}

fn deadlineFromNow(io: std.Io, timeout: std.Io.Duration) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = timeout });
}

fn endpointTopology(config: Config) []const u8 {
    return if (config.server_topology == .shared)
        "shared-server-udp"
    else
        "one-udp-socket-per-connection";
}

fn connectionScope(config: Config) []const u8 {
    return if (config.server_topology == .shared)
        "parallel-shared-server-endpoint"
    else
        "parallel-independent-endpoints";
}

fn serverReceiveBatch(config: Config) usize {
    return if (config.server_topology == .shared)
        config.shared_receive_batch
    else
        1;
}

fn printClientResult(
    config: Config,
    latencies: []u64,
    elapsed_ns: u64,
    bytes: u64,
    checksum: u64,
) !void {
    const implementation = if (config.mode == .aggregate and
        config.sender == .server)
        serverImplementation(config.role_pair)
    else
        clientImplementation(config.role_pair);
    if (config.mode == .echo) {
        std.mem.sort(u64, latencies, {}, std.sort.asc(u64));
        var total_ns: u64 = 0;
        for (latencies) |latency| total_ns +|= latency;
        std.debug.print(
            "record=result implementation={s} protocol=quic-stream mode=echo " ++
                "direction=roundtrip role_pair={s} result_owner=client run={d} " ++
                "connection_scope=persistent endpoint_topology=independent-udp " ++
                "benchmark_scope=same-application-shape warmup={d} iterations={d} " ++
                "connections=1 streams=1 payload_bytes={d} measured_bytes={d} " ++
                "total_bytes={d} checksum={d} total_elapsed_ns={d} mean_ns={d} " ++
                "min_ns={d} p50_ns={d} p90_ns={d} p99_ns={d} p999_ns={d} " ++
                "max_ns={d} cert_verify=true quic_version=1 gso=false gro=false " ++
                "sender_role=client completion_exchange_verified=true complete=true\n",
            .{
                implementation,                 config.role_pair,               config.run,                                         config.warmup,
                config.iterations,              config.payload_bytes,           @as(u64, config.iterations) * config.payload_bytes, bytes,
                checksum,                       total_ns,                       total_ns / config.iterations,                       latencies[0],
                percentile(latencies, 50, 100), percentile(latencies, 90, 100), percentile(latencies, 99, 100),                     percentile(latencies, 999, 1000),
                latencies[latencies.len - 1],
            },
        );
        return;
    }
    const mib_s = @as(f64, @floatFromInt(bytes)) *
        @as(f64, @floatFromInt(std.time.ns_per_s)) /
        @as(f64, @floatFromInt(elapsed_ns)) / (1024.0 * 1024.0);
    std.debug.print(
        "record=result implementation={s} protocol=quic-stream mode=aggregate " ++
            "direction=upload role_pair={s} result_owner=client run={d} " ++
            "connection_scope={s} " ++
            "endpoint_topology={s} " ++
            "benchmark_scope=same-application-shape " ++
            "timing_scope=stream-setup-through-verified-completion " ++
            "connections={d} streams={d} " ++
            "bytes_per_stream={d} transferred_bytes={d} checksum={d} " ++
            "server_receive_batch={d} " ++
            "elapsed_ns={d} logical_MiB_s={d:.3} sender_role={s} " ++
            "cert_verify=true quic_version=1 gso=false gro=false " ++
            "completion_exchange_verified=true complete=true\n",
        .{
            implementation,          config.role_pair,           config.run,
            connectionScope(config), endpointTopology(config),   config.connections,
            config.streams,          config.bytes_per_stream,    bytes,
            checksum,                serverReceiveBatch(config), elapsed_ns,
            mib_s,                   @tagName(config.sender),
        },
    );
}

fn printServerCompletion(
    config: Config,
    results: []const WorkerResult,
    shared_receive: ?SharedReceiveStats,
    socket_traffic: ?netz.quic.runtime.SocketTrafficStats,
) !void {
    for (results) |result| if (result.err) |err| return err;
    var bytes: u64 = 0;
    var checksum: u64 = 0;
    for (results) |result| {
        bytes +|= result.bytes;
        checksum +%= result.checksum;
    }
    if (config.mode == .echo) {
        std.debug.print(
            "record=server-complete implementation={s} protocol=quic-stream " ++
                "mode=echo direction=roundtrip role_pair={s} endpoint_role=server " ++
                "run={d} connection_scope=persistent endpoint_topology=independent-udp " ++
                "benchmark_scope=same-application-shape warmup={d} iterations={d} " ++
                "connections=1 streams=1 payload_bytes={d} total_bytes={d} " ++
                "checksum={d} sender_role=client connections_complete=1 " ++
                "cert_verify=true quic_version=1 gso=false gro=false " ++
                "completion_exchange_verified=true complete=true\n",
            .{
                serverImplementation(config.role_pair), config.role_pair,
                config.run,                             config.warmup,
                config.iterations,                      config.payload_bytes,
                bytes,                                  checksum,
            },
        );
        return;
    }
    const receive = shared_receive orelse SharedReceiveStats{};
    const traffic = socket_traffic orelse netz.quic.runtime.SocketTrafficStats{};
    std.debug.print(
        "record=server-complete implementation={s} protocol=quic-stream " ++
            "mode=aggregate direction=upload role_pair={s} endpoint_role=server " ++
            "run={d} connection_scope={s} " ++
            "endpoint_topology={s} " ++
            "benchmark_scope=same-application-shape warmup=0 iterations=1 " ++
            "connections={d} streams={d} bytes_per_stream={d} payload_bytes={d} " ++
            "transferred_bytes={d} checksum={d} sender_role={s} " ++
            "server_receive_batch={d} " ++
            "server_receive_calls={d} server_receive_events={d} " ++
            "server_receive_max_events={d} " ++
            "server_received_datagrams={d} " ++
            "server_receive_max_datagrams={d} " ++
            "server_connected_events={d} server_packet_events={d} " ++
            "server_timer_events={d} server_socket_sent_datagrams={d} " ++
            "server_socket_sent_bytes={d} server_socket_received_datagrams={d} " ++
            "server_socket_received_bytes={d} " ++
            "connections_complete={d} cert_verify=true quic_version=1 " ++
            "gso=false gro=false completion_exchange_verified=true complete=true\n",
        .{
            serverImplementation(config.role_pair), config.role_pair,           config.run,
            connectionScope(config),                endpointTopology(config),   config.connections,
            config.streams,                         config.bytes_per_stream,    config.payload_bytes,
            bytes,                                  checksum,                   @tagName(config.sender),
            serverReceiveBatch(config),             receive.calls,              receive.events,
            receive.max_events,                     receive.received_datagrams, receive.max_received_datagrams,
            receive.connected_events,               receive.packet_events,      receive.timer_events,
            traffic.sent_datagrams,                 traffic.sent_bytes,         traffic.received_datagrams,
            traffic.received_bytes,                 config.connections,
        },
    );
}

fn parsePorts(allocator: std.mem.Allocator, text: []const u8, expected: usize) ![]u16 {
    const ports = try allocator.alloc(u16, expected);
    errdefer allocator.free(ports);
    var iterator = std.mem.splitScalar(u8, text, ',');
    var count: usize = 0;
    while (iterator.next()) |value| {
        if (count == ports.len) return error.InvalidArgument;
        ports[count] = try parsePositive(u16, value);
        count += 1;
    }
    if (count != ports.len) return error.InvalidArgument;
    return ports;
}

fn option(arg: []const u8, prefix: []const u8) ?[]const u8 {
    return if (std.mem.startsWith(u8, arg, prefix)) arg[prefix.len..] else null;
}

fn parsePositive(comptime T: type, text: []const u8) !T {
    const value = std.fmt.parseInt(T, text, 10) catch return error.InvalidArgument;
    if (value == 0) return error.InvalidArgument;
    return value;
}

fn parseNonNegative(comptime T: type, text: []const u8) !T {
    return std.fmt.parseInt(T, text, 10) catch error.InvalidArgument;
}

fn percentile(sorted: []const u64, numerator: usize, denominator: usize) u64 {
    return sorted[@min(sorted.len - 1, sorted.len * numerator / denominator)];
}

fn validRolePair(value: []const u8) bool {
    return std.mem.eql(u8, value, "netz-client+quic-go-server") or
        std.mem.eql(u8, value, "quic-go-client+quic-go-server") or
        std.mem.eql(u8, value, "quic-go-client+netz-server") or
        std.mem.eql(u8, value, "netz-client+netz-server");
}

fn clientImplementation(role_pair: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, role_pair, "netz-client"))
        "netz"
    else
        "quic-go";
}

fn serverImplementation(role_pair: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, role_pair, "netz-server"))
        "netz"
    else
        "quic-go";
}

test "persistent QUIC benchmark config rejects ambiguous shapes" {
    try std.testing.expectError(error.InvalidArgument, Config.parse(&.{
        "--mode=echo",     "--role-pair=netz-client+netz-server",
        "--connections=2",
    }));
    const aggregate = try Config.parse(&.{
        "--mode=aggregate",         "--role-pair=quic-go-client+netz-server",
        "--connections=4",          "--streams=4",
        "--bytes-per-stream=65536", "--warmup=0",
        "--iterations=1",
    });
    try std.testing.expectEqual(@as(u64, 1_048_576), try aggregate.aggregateBytes());
    const shared = try Config.parse(&.{
        "--mode=aggregate",         "--role-pair=netz-client+netz-server",
        "--sender=client",          "--connections=4",
        "--streams=1",              "--bytes-per-stream=65536",
        "--warmup=0",               "--iterations=1",
        "--server-topology=shared",
    });
    try std.testing.expectEqual(ServerTopology.shared, shared.server_topology);
    try std.testing.expectEqualStrings(
        "shared-server-udp",
        endpointTopology(shared),
    );
    try std.testing.expectEqual(@as(u8, 32), shared.shared_receive_batch);
    const single_receive = try Config.parse(&.{
        "--mode=aggregate",         "--role-pair=netz-client+netz-server",
        "--sender=client",          "--connections=4",
        "--streams=1",              "--bytes-per-stream=65536",
        "--warmup=0",               "--iterations=1",
        "--server-topology=shared", "--shared-receive-batch=1",
    });
    try std.testing.expectEqual(
        @as(u8, 1),
        single_receive.shared_receive_batch,
    );
    try std.testing.expectError(error.InvalidArgument, Config.parse(&.{
        "--mode=aggregate",         "--role-pair=netz-client+netz-server",
        "--sender=client",          "--connections=4",
        "--streams=1",              "--bytes-per-stream=65536",
        "--warmup=0",               "--iterations=1",
        "--server-topology=shared", "--shared-receive-batch=65",
    }));
    try std.testing.expectError(error.InvalidArgument, Config.parse(&.{
        "--mode=aggregate",         "--role-pair=netz-client+quic-go-server",
        "--sender=client",          "--connections=4",
        "--streams=1",              "--bytes-per-stream=65536",
        "--warmup=0",               "--iterations=1",
        "--server-topology=shared",
    }));
    try std.testing.expectError(error.InvalidArgument, Config.parse(&.{
        "--mode=echo",         "--role-pair=netz-client+netz-server",
        "--iterations=100001",
    }));
}

test "persistent QUIC echo payload is sequence distinct" {
    var first: [1024]u8 = undefined;
    var second: [1024]u8 = undefined;
    const first_sum = fillEchoPayload(&first, 0);
    const second_sum = fillEchoPayload(&second, 1);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    try std.testing.expectEqual(@as(u64, 130_560), first_sum);
    try std.testing.expectEqual(@as(u64, 130_560), second_sum);
}

test "persistent QUIC START record round trips" {
    const config = transfer.Config{ .streams = 4 };
    const encoded = try transfer.Record.init(
        .start,
        .server,
        3,
        config,
    ).encode();
    const decoded = try transfer.Record.decode(&encoded);
    try transfer.validateRecord(decoded, .start, .server, 3, config);
}

const std = @import("std");
const netz = @import("netz");

pub const mtu: usize = 1280;
pub const max_frames: usize = 256;
pub const max_streams: usize = 16;

pub const Mode = enum {
    upload,
    download,

    pub fn parse(value: []const u8) !Mode {
        if (std.mem.eql(u8, value, "upload")) return .upload;
        if (std.mem.eql(u8, value, "download")) return .download;
        return error.InvalidArgument;
    }

    pub fn name(self: Mode) []const u8 {
        return @tagName(self);
    }
};

pub const Config = struct {
    mode: Mode,
    version: netz.quic.Version = .version_1,
    streams: u16 = 1,
    warmup: u32 = 10,
    iterations: u32 = 5,
    body_bytes: u64 = 4 * 1024 * 1024,
    chunk_bytes: u32 = 16 * 1024,
    stream_window: u64 = 1024 * 1024,
    timeout_ms: u32 = 30_000,
    capture: bool = false,
    socket_traffic: bool = false,

    pub fn parse(args: []const []const u8) !Config {
        var mode: ?Mode = null;
        var config: Config = undefined;
        config.version = .version_1;
        config.streams = 1;
        config.warmup = 10;
        config.iterations = 5;
        config.body_bytes = 4 * 1024 * 1024;
        config.chunk_bytes = 16 * 1024;
        config.stream_window = 1024 * 1024;
        config.timeout_ms = 30_000;
        config.capture = false;
        config.socket_traffic = false;
        for (args) |arg| {
            if (option(arg, "--mode=")) |value| {
                mode = try Mode.parse(value);
            } else if (std.mem.eql(u8, arg, "--version=2")) {
                if (config.version == .version_2) return error.InvalidArgument;
                config.version = .version_2;
            } else if (option(arg, "--streams=")) |value| {
                config.streams = try parsePositive(u16, value);
            } else if (option(arg, "--warmup=")) |value| {
                config.warmup = try parsePositive(u32, value);
            } else if (option(arg, "--iterations=")) |value| {
                config.iterations = try parsePositive(u32, value);
            } else if (option(arg, "--body-bytes=")) |value| {
                config.body_bytes = try parsePositive(u64, value);
            } else if (option(arg, "--chunk-bytes=")) |value| {
                config.chunk_bytes = try parsePositive(u32, value);
            } else if (option(arg, "--stream-window=")) |value| {
                config.stream_window = try parsePositive(u64, value);
            } else if (option(arg, "--timeout-ms=")) |value| {
                config.timeout_ms = try parsePositive(u32, value);
            } else if (std.mem.eql(u8, arg, "--capture") and
                !config.capture)
            {
                config.capture = true;
            } else if (std.mem.eql(u8, arg, "--socket-traffic") and
                !config.socket_traffic)
            {
                config.socket_traffic = true;
            } else {
                return error.InvalidArgument;
            }
        }
        config.mode = mode orelse return error.InvalidArgument;
        if (config.capture and config.socket_traffic) {
            return error.InvalidArgument;
        }
        const round_count = try config.rounds();
        if (config.streams != 1 and config.streams != 4 and
            config.streams != 16)
        {
            return error.InvalidArgument;
        }
        if (round_count > 4096 or config.body_bytes > 1024 * 1024 * 1024 or
            config.chunk_bytes > 1024 * 1024 or
            config.stream_window > 1024 * 1024 * 1024 or
            config.timeout_ms > 10 * 60 * 1000)
        {
            return error.InvalidArgument;
        }
        if (config.chunk_bytes > config.body_bytes or
            config.chunk_bytes > std.math.maxInt(usize))
        {
            return error.InvalidArgument;
        }
        _ = std.math.cast(usize, config.body_bytes) orelse
            return error.InvalidArgument;
        _ = try config.totalBytes();
        _ = try config.connectionWindow();
        return config;
    }

    pub fn rounds(self: Config) !u32 {
        return std.math.add(u32, self.warmup, self.iterations) catch
            error.InvalidArgument;
    }

    pub fn timeout(self: Config) std.Io.Duration {
        return .fromMilliseconds(self.timeout_ms);
    }

    pub fn effectiveChunk(self: Config) usize {
        return @min(@as(usize, self.chunk_bytes), mtu - 128);
    }

    pub fn connectionWindow(self: Config) !u64 {
        return std.math.mul(u64, self.stream_window, @max(self.streams, 8)) catch
            error.InvalidArgument;
    }

    pub fn totalBytes(self: Config) !u64 {
        return std.math.mul(u64, self.body_bytes, self.streams) catch
            error.InvalidArgument;
    }

    pub fn transportParameters(self: Config) !netz.quic.TransportParameters {
        return .{
            // Handshake flights may coalesce above the steady-state packet
            // size. `oneRttConfig` below fixes measured application packets
            // at 1280 bytes after the untimed handshake.
            .max_udp_payload_size = 4096,
            .initial_max_data = try self.connectionWindow(),
            .initial_max_stream_data_bidi_local = self.stream_window,
            .initial_max_stream_data_bidi_remote = self.stream_window,
            .initial_max_stream_data_uni = self.stream_window,
            .initial_max_streams_bidi = @as(u64, self.streams) + 8,
            .initial_max_streams_uni = 16,
            .active_connection_id_limit = 4,
        };
    }

    pub fn oneRttConfig(self: Config) !netz.quic.handshake.OneRttConfig {
        return .{
            // quic-go v0.59 predates RFC 9369's v2 `quicv2 ku` label and
            // rotates after roughly 100 packets in this benchmark. Keep this
            // compatibility choice local to the pinned external fixture.
            .key_update_profile = if (self.version == .version_2)
                .quic_go_v0_59
            else
                .rfc,
            .max_frames_per_packet = max_frames,
            .receive_window = try self.connectionWindow(),
            .max_receive_window = try self.connectionWindow(),
            .stream_receive_window = self.stream_window,
            .max_stream_receive_window = self.stream_window,
            .max_datagram_size = mtu,
        };
    }

    pub fn sessionOptions(self: Config) !netz.http3.runtime.HandshakeSessionOptions {
        return .{
            .max_stream_buffer = try self.aggregateStreamBufferLimit(),
            .max_stream_frame_data = mtu,
            .paced_body_chunk_bytes = @intCast(self.effectiveChunk()),
            .enable_data_prefix_fast_path = true,
            .max_concurrent_request_streams = std.math.cast(usize, @as(u64, self.streams) + 8) orelse
                return error.InvalidArgument,
        };
    }

    fn aggregateStreamBufferLimit(self: Config) !usize {
        const body = std.math.cast(usize, self.body_bytes) orelse
            return error.InvalidArgument;
        const chunk = self.effectiveChunk();
        const chunk_count = body / chunk + @intFromBool(body % chunk != 0);
        // The quic-go peer turns each application Write into one HTTP/3 DATA
        // frame. Account for every DATA type and length varint in addition to
        // the logical body. The fixed margin covers the benchmark's bounded
        // response HEADERS block and avoids changing the production default.
        const data_header_bytes = std.math.mul(
            usize,
            chunk_count,
            1 + try netz.quic.varint.length(chunk),
        ) catch return error.InvalidArgument;
        const framed_body = std.math.add(
            usize,
            body,
            data_header_bytes,
        ) catch return error.InvalidArgument;
        const aggregate_limit = std.math.add(
            usize,
            framed_body,
            1024,
        ) catch return error.InvalidArgument;
        return @max(aggregate_limit, 64 * 1024);
    }
};

pub const PayloadSet = struct {
    storage: []u8,
    streams: [max_streams][]const u8 = .{&.{}} ** max_streams,
    checksums: [max_streams]u64 = .{0} ** max_streams,
    aggregate_checksum: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
    ) !PayloadSet {
        const body_bytes = std.math.cast(usize, config.body_bytes) orelse
            return error.InvalidArgument;
        const total = std.math.mul(usize, body_bytes, config.streams) catch
            return error.InvalidArgument;
        const storage = try allocator.alloc(u8, total);
        errdefer allocator.free(storage);
        var result = PayloadSet{ .storage = storage };
        for (0..config.streams) |index| {
            const bytes = storage[index * body_bytes ..][0..body_bytes];
            result.checksums[index] = fillStreamPayload(bytes, index);
            result.aggregate_checksum +%= result.checksums[index];
            result.streams[index] = bytes;
        }
        return result;
    }

    pub fn deinit(self: *PayloadSet, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }
};

fn option(arg: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, arg, prefix)) return null;
    return arg[prefix.len..];
}

fn parsePositive(comptime T: type, value: []const u8) !T {
    const parsed = std.fmt.parseInt(T, value, 10) catch
        return error.InvalidArgument;
    if (parsed == 0) return error.InvalidArgument;
    return parsed;
}

pub fn payloadByte(offset: usize) u8 {
    return streamPayloadByte(0, offset);
}

pub fn streamPayloadByte(stream_index: usize, offset: usize) u8 {
    return @truncate(offset *% 131 +% stream_index *% 17);
}

pub fn fillPayload(bytes: []u8) u64 {
    return fillStreamPayload(bytes, 0);
}

pub fn fillStreamPayload(bytes: []u8, stream_index: usize) u64 {
    var checksum: u64 = 0;
    for (bytes, 0..) |*byte, offset| {
        byte.* = streamPayloadByte(stream_index, offset);
        checksum +%= byte.*;
    }
    return checksum;
}

pub fn verifyPayload(bytes: []const u8, offset: usize, checksum: *u64) !void {
    return verifyStreamPayload(bytes, 0, offset, checksum);
}

pub fn verifyStreamPayload(
    bytes: []const u8,
    stream_index: usize,
    offset: usize,
    checksum: *u64,
) !void {
    for (bytes, 0..) |byte, index| {
        if (byte != streamPayloadByte(stream_index, offset + index)) {
            return error.InvalidBenchmarkPayload;
        }
        checksum.* +%= byte;
    }
}

pub fn streamChecksum(body_bytes: usize, stream_index: usize) u64 {
    var checksum: u64 = 0;
    for (0..body_bytes) |offset| {
        checksum +%= streamPayloadByte(stream_index, offset);
    }
    return checksum;
}

pub fn aggregateChecksum(config: Config) u64 {
    const body_bytes: usize = @intCast(config.body_bytes);
    var checksum: u64 = 0;
    for (0..config.streams) |stream_index| {
        checksum +%= streamChecksum(body_bytes, stream_index);
    }
    return checksum;
}

pub fn streamIndexForId(
    stream_ids: []const u62,
    stream_id: u62,
) ?usize {
    for (stream_ids, 0..) |candidate, index| {
        if (candidate == stream_id) return index;
    }
    return null;
}

pub fn header(
    headers: []const netz.http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}

pub fn parseHeaderInt(
    headers: []const netz.http3.Qpack.HeaderField,
    name: []const u8,
) !u64 {
    return std.fmt.parseInt(u64, header(headers, name) orelse
        return error.InvalidBenchmarkHeader, 10) catch
        return error.InvalidBenchmarkHeader;
}

pub fn nowNs(io: std.Io) u64 {
    const value = std.Io.Clock.awake.now(io).nanoseconds;
    if (value <= 0) return 0;
    return std.math.cast(u64, value) orelse std.math.maxInt(u64);
}

pub fn printConfig(
    implementation: []const u8,
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
) !void {
    const effective_chunk = config.effectiveChunk();
    std.debug.print(
        "record=config implementation={s} protocol=http3 mode={s} role_pair={s} " ++
            "endpoint_role={s} sender_role={s} client_io={s} server_io={s} " ++
            "connection_scope=fresh-per-sample " ++
            "benchmark_scope={s} timing_usable={} body_deadline_scope=sample warmup={d} " ++
            "iterations={d} streams={d} body_bytes={d} " ++
            "application_chunk_requested={d} application_chunk_effective={d} " ++
            "stream_window={d} connection_window={d} timeout_ms={d} " ++
            "steady_state_mtu=1280 " ++
            "quic_version={d} cipher=negotiated-unexposed cert_verify=true " ++
            "gso=false gro=false pacing=true\n",
        .{
            implementation,
            config.mode.name(),
            role_pair,
            endpoint_role,
            senderRole(config),
            clientIo(role_pair),
            serverIo(role_pair),
            benchmarkScope(config),
            timingUsable(config),
            config.warmup,
            config.iterations,
            config.streams,
            config.body_bytes,
            config.chunk_bytes,
            effective_chunk,
            config.stream_window,
            try config.connectionWindow(),
            config.timeout_ms,
            if (config.version == .version_2) @as(u8, 2) else 1,
        },
    );
}

pub fn printSample(
    implementation: []const u8,
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    sample: u32,
    elapsed_ns: u64,
    checksum: u64,
) void {
    const total_bytes = config.totalBytes() catch unreachable;
    const mib_s = if (elapsed_ns == 0) 0.0 else @as(f64, @floatFromInt(total_bytes)) *
        @as(f64, @floatFromInt(std.time.ns_per_s)) /
        @as(f64, @floatFromInt(elapsed_ns)) / (1024.0 * 1024.0);
    std.debug.print(
        "record=result implementation={s} protocol=http3 mode={s} role_pair={s} " ++
            "result_owner=client endpoint_role={s} sender_role={s} " ++
            "client_io={s} server_io={s} " ++
            "connection_scope=fresh-per-sample " ++
            "benchmark_scope={s} timing_usable={} body_deadline_scope=sample sample={d} streams={d} " ++
            "body_bytes={d} elapsed_ns={d} logical_MiB_s={d:.3} sent_bytes={d} " ++
            "received_bytes={d} checksum={d} status=200 streams_finished={d} " ++
            "per_stream_verified=true quic_version={d} complete=true\n",
        .{ implementation, config.mode.name(), role_pair, endpoint_role, senderRole(config), clientIo(role_pair), serverIo(role_pair), benchmarkScope(config), timingUsable(config), sample, config.streams, config.body_bytes, elapsed_ns, mib_s, total_bytes, total_bytes, checksum, config.streams, if (config.version == .version_2) @as(u8, 2) else 1 },
    );
}

pub fn printServerComplete(
    implementation: []const u8,
    role_pair: []const u8,
    config: Config,
    sample: u32,
    checksum: u64,
) void {
    const total_bytes = config.totalBytes() catch unreachable;
    const sent_bytes: u64 = if (config.mode == .download) total_bytes else 0;
    const received_bytes: u64 = if (config.mode == .upload) total_bytes else 0;
    std.debug.print(
        "record=server-complete implementation={s} protocol=http3 mode={s} " ++
            "role_pair={s} endpoint_role=server connection_scope=fresh-per-sample " ++
            "sender_role={s} client_io={s} server_io={s} " ++
            "benchmark_scope={s} timing_usable={} body_deadline_scope=sample " ++
            "sample={d} streams={d} body_bytes={d} sent_bytes={d} " ++
            "received_bytes={d} checksum={d} status=200 streams_finished={d} " ++
            "per_stream_verified=true quic_version={d} complete=true\n",
        .{
            implementation,      config.mode.name(),  role_pair,              senderRole(config),
            clientIo(role_pair), serverIo(role_pair), benchmarkScope(config), timingUsable(config),
            sample,              config.streams,      config.body_bytes,      sent_bytes,
            received_bytes,      checksum,            config.streams,         if (config.version == .version_2) @as(u8, 2) else 1,
        },
    );
}

pub fn printSocketTraffic(
    implementation: []const u8,
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    traffic: netz.quic.runtime.SocketTrafficStats,
) void {
    std.debug.print(
        "record=socket-traffic implementation={s} protocol=http3 mode={s} role_pair={s} " ++
            "endpoint_role={s} sender_role={s} client_io={s} server_io={s} " ++
            "warmup={d} iterations={d} streams={d} body_bytes={d} " ++
            "application_chunk_effective={d} stream_window={d} quic_version={d} " ++
            "traffic_scope=all-rounds socket_boundary=userspace-udp-payload " ++
            "benchmark_scope=socket-traffic-same-application-shape " ++
            "udp_sent_datagrams={d} udp_sent_payload_bytes={d} " ++
            "udp_received_datagrams={d} udp_received_payload_bytes={d} " ++
            "logical_udp_segments=true complete=true\n",
        .{
            implementation,
            config.mode.name(),
            role_pair,
            endpoint_role,
            senderRole(config),
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.streams,
            config.body_bytes,
            config.effectiveChunk(),
            config.stream_window,
            if (config.version == .version_2) @as(u8, 2) else 1,
            traffic.sent_datagrams,
            traffic.sent_bytes,
            traffic.received_datagrams,
            traffic.received_bytes,
        },
    );
}

pub const TransportStats = struct {
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    packets_lost: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    authentication_failures: u64 = 0,
    local_key_updates: u64 = 0,
    peer_key_updates: u64 = 0,

    pub fn add(self: *TransportStats, stats: anytype) void {
        self.packets_sent +|= stats.packets_sent;
        self.packets_received +|= stats.packets_received;
        self.packets_lost +|= stats.packets_lost;
        self.bytes_sent +|= stats.bytes_sent;
        self.bytes_received +|= stats.bytes_received;
        self.authentication_failures +|= stats.authentication_failures;
        self.local_key_updates +|= stats.local_key_update_count;
        self.peer_key_updates +|= stats.peer_key_update_count;
    }
};

pub fn printTransportStats(
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    stats: TransportStats,
) void {
    std.debug.print(
        "record=transport-stats implementation=netz protocol=http3 mode={s} " ++
            "role_pair={s} endpoint_role={s} sender_role={s} " ++
            "client_io={s} server_io={s} warmup={d} iterations={d} streams={d} " ++
            "body_bytes={d} traffic_scope=all-rounds " ++
            "benchmark_scope=socket-traffic-same-application-shape packets_sent={d} " ++
            "packets_received={d} packets_lost={d} bytes_sent={d} " ++
            "bytes_received={d} authentication_failures={d} " ++
            "local_key_updates={d} peer_key_updates={d} complete=true\n",
        .{
            config.mode.name(),
            role_pair,
            endpoint_role,
            senderRole(config),
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.streams,
            config.body_bytes,
            stats.packets_sent,
            stats.packets_received,
            stats.packets_lost,
            stats.bytes_sent,
            stats.bytes_received,
            stats.authentication_failures,
            stats.local_key_updates,
            stats.peer_key_updates,
        },
    );
}

test "HTTP/3 external benchmark multi-stream checksum is index-aware" {
    const config: Config = .{
        .mode = .upload,
        .streams = 4,
        .body_bytes = 1024,
        .chunk_bytes = 1024,
        .stream_window = 1024,
    };
    try std.testing.expectEqual(@as(u64, 4096), try config.totalBytes());
    try std.testing.expectEqual(@as(u64, 8192), try config.connectionWindow());
    var expected: u64 = 0;
    for (0..4) |index| expected +%= streamChecksum(1024, index);
    try std.testing.expectEqual(expected, aggregateChecksum(config));
    try std.testing.expect(streamChecksum(1000, 0) != streamChecksum(1000, 1));
}

test "HTTP/3 external benchmark version selects peer compatibility" {
    const v1 = try Config.parse(&.{ "--mode=upload", "--streams=4" });
    try std.testing.expect(!v1.capture);
    try std.testing.expectEqual(netz.quic.Version.version_1, v1.version);
    try std.testing.expectEqual(
        netz.quic.protection.KeyPhaseState.UpdateProfile.rfc,
        (try v1.oneRttConfig()).key_update_profile,
    );

    const v2 = try Config.parse(&.{
        "--mode=download",
        "--streams=16",
        "--version=2",
    });
    try std.testing.expectEqual(netz.quic.Version.version_2, v2.version);
    try std.testing.expectEqual(
        netz.quic.protection.KeyPhaseState.UpdateProfile.quic_go_v0_59,
        (try v2.oneRttConfig()).key_update_profile,
    );
    try std.testing.expectError(
        error.InvalidArgument,
        Config.parse(&.{ "--mode=upload", "--version=2", "--version=2" }),
    );
}

test "HTTP/3 external benchmark capture changes evidence scope" {
    const config = try Config.parse(&.{ "--mode=upload", "--capture" });
    try std.testing.expect(config.capture);
    try std.testing.expectEqualStrings(
        "capture-backed-same-application-shape",
        benchmarkScope(config),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        Config.parse(&.{ "--mode=upload", "--capture", "--capture" }),
    );
}

test "HTTP/3 external benchmark socket traffic has a distinct evidence scope" {
    const config = try Config.parse(&.{
        "--mode=download",
        "--socket-traffic",
    });
    try std.testing.expect(config.socket_traffic);
    try std.testing.expect(!timingUsable(config));
    try std.testing.expectEqualStrings(
        "socket-traffic-same-application-shape",
        benchmarkScope(config),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        Config.parse(&.{
            "--mode=download",
            "--socket-traffic",
            "--capture",
        }),
    );
}

test "HTTP/3 external benchmark transport stats aggregate connection totals" {
    var totals: TransportStats = .{};
    totals.add(.{
        .packets_sent = @as(u64, 10),
        .packets_received = @as(u64, 9),
        .packets_lost = @as(u64, 2),
        .bytes_sent = @as(u64, 1000),
        .bytes_received = @as(u64, 900),
        .authentication_failures = @as(u64, 1),
        .local_key_update_count = @as(u64, 3),
        .peer_key_update_count = @as(u64, 4),
    });
    totals.add(.{
        .packets_sent = @as(u64, 5),
        .packets_received = @as(u64, 6),
        .packets_lost = @as(u64, 1),
        .bytes_sent = @as(u64, 500),
        .bytes_received = @as(u64, 600),
        .authentication_failures = @as(u64, 0),
        .local_key_update_count = @as(u64, 1),
        .peer_key_update_count = @as(u64, 2),
    });
    try std.testing.expectEqual(@as(u64, 15), totals.packets_sent);
    try std.testing.expectEqual(@as(u64, 15), totals.packets_received);
    try std.testing.expectEqual(@as(u64, 3), totals.packets_lost);
    try std.testing.expectEqual(@as(u64, 1500), totals.bytes_sent);
    try std.testing.expectEqual(@as(u64, 1500), totals.bytes_received);
    try std.testing.expectEqual(@as(u64, 1), totals.authentication_failures);
    try std.testing.expectEqual(@as(u64, 4), totals.local_key_updates);
    try std.testing.expectEqual(@as(u64, 6), totals.peer_key_updates);
}

test "HTTP/3 external benchmark budgets aggregate DATA framing" {
    const config: Config = .{
        .mode = .download,
        .body_bytes = 1024 * 1024,
        .chunk_bytes = 16 * 1024,
        .stream_window = 1024 * 1024,
    };
    try std.testing.expectEqual(@as(usize, 1152), config.effectiveChunk());
    try std.testing.expectEqual(
        @as(usize, 1024 * 1024 + 911 * 3 + 1024),
        (try config.sessionOptions()).max_stream_buffer,
    );
}

pub fn printNetzMemory(
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    snapshot: anytype,
) void {
    std.debug.print(
        "record=memory implementation=netz protocol=http3 mode={s} role_pair={s} " ++
            "endpoint_role={s} sender_role={s} client_io={s} server_io={s} " ++
            "streams={d} body_bytes={d} " ++
            "warmup={d} iterations={d} " ++
            "memory_scope=benchmark-run-after-argument-parse " ++
            "quic_version={d} " ++
            "allocator_scope=netz-explicit alloc_count={d} free_count={d} " ++
            "resize_count={d} remap_count={d} total_allocated_bytes={d} " ++
            "live_bytes={d} peak_live_bytes={d} complete=true\n",
        .{
            config.mode.name(),
            role_pair,
            endpoint_role,
            senderRole(config),
            clientIo(role_pair),
            serverIo(role_pair),
            config.streams,
            config.body_bytes,
            config.warmup,
            config.iterations,
            if (config.version == .version_2) @as(u8, 2) else 1,
            snapshot.alloc_count,
            snapshot.free_count,
            snapshot.resize_count,
            snapshot.remap_count,
            snapshot.total_allocated,
            snapshot.current_bytes,
            snapshot.peak_bytes,
        },
    );
}

fn senderRole(config: Config) []const u8 {
    return if (config.mode == .upload) "client" else "server";
}

fn benchmarkScope(config: Config) []const u8 {
    return if (config.capture)
        "capture-backed-same-application-shape"
    else if (config.socket_traffic)
        "socket-traffic-same-application-shape"
    else
        "same-application-shape";
}

fn timingUsable(config: Config) bool {
    return !config.capture and !config.socket_traffic;
}

pub fn clientIo(role_pair: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, role_pair, "netz-client"))
        "zio-std-io"
    else
        "quic-go-netpoll";
}

pub fn serverIo(role_pair: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, role_pair, "netz-server"))
        "zio-std-io"
    else
        "quic-go-netpoll";
}

pub fn senderImplementation(role_pair: []const u8, config: Config) []const u8 {
    return if (config.mode == .upload)
        (if (std.mem.startsWith(u8, role_pair, "netz-client")) "netz" else "quic-go")
    else
        (if (std.mem.endsWith(u8, role_pair, "netz-server")) "netz" else "quic-go");
}

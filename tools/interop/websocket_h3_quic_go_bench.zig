const std = @import("std");
const netz = @import("netz");

pub const path = "/rfc9220-benchmark";
pub const origin = "https://example.test";
pub const protocol = "netz-benchmark";
pub const mtu: usize = 1280;
pub const effective_chunk: usize = mtu - 128;

pub const Config = struct {
    warmup: u32 = 20,
    iterations: u32 = 1000,
    payload_bytes: u32 = 4096,
    timeout_ms: u32 = 30_000,

    pub fn parse(args: []const []const u8) !Config {
        var config: Config = .{};
        for (args) |arg| {
            if (option(arg, "--warmup=")) |value| {
                config.warmup = std.fmt.parseInt(u32, value, 10) catch
                    return error.InvalidArgument;
            } else if (option(arg, "--iterations=")) |value| {
                config.iterations = try parsePositive(u32, value);
            } else if (option(arg, "--payload-bytes=")) |value| {
                config.payload_bytes = try parsePositive(u32, value);
            } else if (option(arg, "--timeout-ms=")) |value| {
                config.timeout_ms = try parsePositive(u32, value);
            } else {
                return error.InvalidArgument;
            }
        }
        if (config.warmup > 100_000 or config.iterations > 1_000_000 or
            config.payload_bytes > 4096 or config.timeout_ms > 10 * 60 * 1000)
        {
            return error.InvalidArgument;
        }
        _ = try config.rounds();
        return config;
    }

    pub fn rounds(self: Config) !u32 {
        return std.math.add(u32, self.warmup, self.iterations) catch
            error.InvalidArgument;
    }

    pub fn timeout(self: Config) std.Io.Duration {
        return .fromMilliseconds(self.timeout_ms);
    }

    pub fn transportParameters(self: Config) netz.quic.TransportParameters {
        _ = self;
        return .{
            .max_udp_payload_size = 4096,
            .initial_max_data = 8 * 1024 * 1024,
            .initial_max_stream_data_bidi_local = 1024 * 1024,
            .initial_max_stream_data_bidi_remote = 1024 * 1024,
            .initial_max_stream_data_uni = 1024 * 1024,
            .initial_max_streams_bidi = 16,
            .initial_max_streams_uni = 16,
            .active_connection_id_limit = 4,
        };
    }

    pub fn oneRttConfig(self: Config) netz.quic.handshake.OneRttConfig {
        _ = self;
        return .{
            .max_frames_per_packet = 256,
            .receive_window = 8 * 1024 * 1024,
            .max_receive_window = 8 * 1024 * 1024,
            .stream_receive_window = 1024 * 1024,
            .max_stream_receive_window = 1024 * 1024,
            .max_datagram_size = mtu,
        };
    }

    pub fn sessionOptions(self: Config) netz.http3.runtime.HandshakeSessionOptions {
        return .{
            .max_stream_buffer = @max(@as(usize, self.payload_bytes) + 1024, 64 * 1024),
            .max_stream_frame_data = mtu,
            .paced_body_chunk_bytes = effective_chunk,
            .enable_data_prefix_fast_path = true,
        };
    }

    pub fn websocketLimits(self: Config) netz.websocket.runtime.Limits {
        return .{
            .max_frame_bytes = self.payload_bytes,
            .max_message_bytes = self.payload_bytes,
        };
    }

    pub fn headers(
        self: Config,
        warmup: *[10]u8,
        iterations: *[10]u8,
        payload_bytes: *[10]u8,
        timeout_ms: *[10]u8,
    ) ![4]netz.http3.Qpack.HeaderField {
        return .{
            .{ .name = "x-netz-bench-warmup", .value = try std.fmt.bufPrint(warmup, "{d}", .{self.warmup}) },
            .{ .name = "x-netz-bench-iterations", .value = try std.fmt.bufPrint(iterations, "{d}", .{self.iterations}) },
            .{ .name = "x-netz-bench-payload-bytes", .value = try std.fmt.bufPrint(payload_bytes, "{d}", .{self.payload_bytes}) },
            .{ .name = "x-netz-bench-timeout-ms", .value = try std.fmt.bufPrint(timeout_ms, "{d}", .{self.timeout_ms}) },
        };
    }

    pub fn fromUpgrade(upgrade: anytype) !Config {
        const config: Config = .{
            .warmup = try parseHeader(u32, upgrade, "x-netz-bench-warmup", false),
            .iterations = try parseHeader(u32, upgrade, "x-netz-bench-iterations", true),
            .payload_bytes = try parseHeader(u32, upgrade, "x-netz-bench-payload-bytes", true),
            .timeout_ms = try parseHeader(u32, upgrade, "x-netz-bench-timeout-ms", true),
        };
        return Config.parseValues(config);
    }

    fn parseValues(self: Config) !Config {
        if (self.iterations == 0 or self.payload_bytes == 0 or
            self.warmup > 100_000 or self.iterations > 1_000_000 or
            self.payload_bytes > 4096 or self.timeout_ms == 0 or
            self.timeout_ms > 10 * 60 * 1000)
        {
            return error.InvalidArgument;
        }
        _ = try self.rounds();
        return self;
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

fn parseHeader(
    comptime T: type,
    upgrade: anytype,
    name: []const u8,
    positive: bool,
) !T {
    const parsed = std.fmt.parseInt(
        T,
        upgrade.header(name) orelse return error.InvalidArgument,
        10,
    ) catch return error.InvalidArgument;
    if (positive and parsed == 0) return error.InvalidArgument;
    return parsed;
}

pub fn payloadByte(round: u32, offset: usize) u8 {
    return @truncate(offset *% 131 +% @as(usize, round) *% 17);
}

pub fn fillPayload(payload: []u8, round: u32) u64 {
    var checksum: u64 = 0;
    for (payload, 0..) |*byte, offset| {
        byte.* = payloadByte(round, offset);
        checksum +%= byte.*;
    }
    return checksum;
}

pub fn verifyPayload(payload: []const u8, round: u32) !u64 {
    var checksum: u64 = 0;
    for (payload, 0..) |byte, offset| {
        if (byte != payloadByte(round, offset)) {
            return error.InvalidBenchmarkPayload;
        }
        checksum +%= byte;
    }
    return checksum;
}

pub fn nowNs(io: std.Io) u64 {
    const value = std.Io.Clock.awake.now(io).nanoseconds;
    if (value <= 0) return 0;
    return std.math.cast(u64, value) orelse std.math.maxInt(u64);
}

pub fn printConfig(role_pair: []const u8, config: Config) void {
    std.debug.print(
        "protocol=websocket-h3 mode=binary-echo role_pair={s} " ++
            "connection_scope=persistent benchmark_scope=same-application-shape " ++
            "warmup={d} iterations={d} payload_bytes={d} " ++
            "stream_window=1048576 connection_window=8388608 " ++
            "steady_state_mtu=1280 quic_version=1 " ++
            "cipher=negotiated-unexposed cert_verify=true compression=false " ++
            "netz_gso=false netz_gro=false " ++
            "quic_go_gso=implementation-default " ++
            "quic_go_gro=implementation-default pacing=implementation-specific\n",
        .{ role_pair, config.warmup, config.iterations, config.payload_bytes },
    );
}

pub fn printResult(
    role_pair: []const u8,
    config: Config,
    elapsed_ns: u64,
    checksum: u64,
) void {
    const roundtrips_per_second = if (elapsed_ns == 0)
        0.0
    else
        @as(f64, @floatFromInt(config.iterations)) *
            @as(f64, @floatFromInt(std.time.ns_per_s)) /
            @as(f64, @floatFromInt(elapsed_ns));
    const logical_mib_s = roundtrips_per_second *
        @as(f64, @floatFromInt(config.payload_bytes)) * 2.0 /
        (1024.0 * 1024.0);
    std.debug.print(
        "protocol=websocket-h3 mode=binary-echo role_pair={s} " ++
            "connection_scope=persistent benchmark_scope=same-application-shape " ++
            "elapsed_ns={d} ns_per_roundtrip={d:.3} " ++
            "roundtrips_per_s={d:.3} logical_MiB_s={d:.3} " ++
            "sent_bytes={d} received_bytes={d} checksum={d} complete=true\n",
        .{
            role_pair,
            elapsed_ns,
            @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(config.iterations)),
            roundtrips_per_second,
            logical_mib_s,
            @as(u64, config.iterations) * config.payload_bytes,
            @as(u64, config.iterations) * config.payload_bytes,
            checksum,
        },
    );
}

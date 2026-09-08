const std = @import("std");
const netz = @import("netz");

pub const mtu: usize = 1280;
pub const max_frames: usize = 256;

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
    warmup: u32 = 10,
    iterations: u32 = 5,
    body_bytes: u64 = 4 * 1024 * 1024,
    chunk_bytes: u32 = 16 * 1024,
    stream_window: u64 = 1024 * 1024,
    timeout_ms: u32 = 30_000,

    pub fn parse(args: []const []const u8) !Config {
        var mode: ?Mode = null;
        var config: Config = undefined;
        config.warmup = 10;
        config.iterations = 5;
        config.body_bytes = 4 * 1024 * 1024;
        config.chunk_bytes = 16 * 1024;
        config.stream_window = 1024 * 1024;
        config.timeout_ms = 30_000;
        for (args) |arg| {
            if (option(arg, "--mode=")) |value| {
                mode = try Mode.parse(value);
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
            } else {
                return error.InvalidArgument;
            }
        }
        config.mode = mode orelse return error.InvalidArgument;
        const round_count = try config.rounds();
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
        return std.math.mul(u64, self.stream_window, 8) catch
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
            .initial_max_streams_bidi = @as(u64, try self.rounds()) + 8,
            .initial_max_streams_uni = 16,
            .active_connection_id_limit = 4,
        };
    }

    pub fn oneRttConfig(self: Config) !netz.quic.handshake.OneRttConfig {
        return .{
            .max_frames_per_packet = max_frames,
            .receive_window = try self.connectionWindow(),
            .max_receive_window = try self.connectionWindow(),
            .stream_receive_window = self.stream_window,
            .max_stream_receive_window = self.stream_window,
            .max_datagram_size = mtu,
        };
    }

    pub fn sessionOptions(self: Config) !netz.http3.runtime.HandshakeSessionOptions {
        const body = std.math.cast(usize, self.body_bytes) orelse
            return error.InvalidArgument;
        return .{
            .max_stream_buffer = @max(body +| 1024, 64 * 1024),
            .max_stream_frame_data = mtu,
            .paced_body_chunk_bytes = @intCast(self.effectiveChunk()),
            .enable_data_prefix_fast_path = true,
            .max_concurrent_request_streams = std.math.cast(usize, @as(u64, try self.rounds()) + 8) orelse
                return error.InvalidArgument,
        };
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
    return @truncate(offset *% 131);
}

pub fn fillPayload(bytes: []u8) u64 {
    var checksum: u64 = 0;
    for (bytes, 0..) |*byte, offset| {
        byte.* = payloadByte(offset);
        checksum +%= byte.*;
    }
    return checksum;
}

pub fn verifyPayload(bytes: []const u8, offset: usize, checksum: *u64) !void {
    for (bytes, 0..) |byte, index| {
        if (byte != payloadByte(offset + index)) {
            return error.InvalidBenchmarkPayload;
        }
        checksum.* +%= byte;
    }
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

pub fn printConfig(implementation: []const u8, role_pair: []const u8, config: Config) !void {
    const effective_chunk = config.effectiveChunk();
    std.debug.print(
        "implementation={s} protocol=http3 mode={s} role_pair={s} " ++
            "connection_scope=fresh-per-sample " ++
            "benchmark_scope=same-application-shape warmup={d} " ++
            "iterations={d} streams=1 body_bytes={d} " ++
            "application_chunk_requested={d} application_chunk_effective={d} " ++
            "stream_window={d} connection_window={d} steady_state_mtu=1280 " ++
            "quic_version=1 cipher=negotiated-unexposed cert_verify=true " ++
            "gso=false gro=false pacing=true\n",
        .{
            implementation,
            config.mode.name(),
            role_pair,
            config.warmup,
            config.iterations,
            config.body_bytes,
            config.chunk_bytes,
            effective_chunk,
            config.stream_window,
            try config.connectionWindow(),
        },
    );
}

pub fn printSample(
    implementation: []const u8,
    role_pair: []const u8,
    config: Config,
    sample: u32,
    elapsed_ns: u64,
    checksum: u64,
) void {
    const mib_s = if (elapsed_ns == 0) 0.0 else @as(f64, @floatFromInt(config.body_bytes)) *
        @as(f64, @floatFromInt(std.time.ns_per_s)) /
        @as(f64, @floatFromInt(elapsed_ns)) / (1024.0 * 1024.0);
    std.debug.print(
        "implementation={s} protocol=http3 mode={s} role_pair={s} " ++
            "connection_scope=fresh-per-sample " ++
            "benchmark_scope=same-application-shape sample={d} streams=1 " ++
            "elapsed_ns={d} logical_MiB_s={d:.3} sent_bytes={d} " ++
            "received_bytes={d} checksum={d} status=200 complete=true\n",
        .{ implementation, config.mode.name(), role_pair, sample, elapsed_ns, mib_s, config.body_bytes, config.body_bytes, checksum },
    );
}

pub fn printNetzMemory(
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    snapshot: anytype,
) void {
    std.debug.print(
        "implementation=netz protocol=http3 mode={s} role_pair={s} " ++
            "endpoint_role={s} sender_role={s} streams=1 body_bytes={d} " ++
            "warmup={d} iterations={d} " ++
            "memory_scope=benchmark-run-after-argument-parse " ++
            "allocator_scope=netz-explicit alloc_count={d} free_count={d} " ++
            "resize_count={d} remap_count={d} total_allocated_bytes={d} " ++
            "live_bytes={d} peak_live_bytes={d} complete=true\n",
        .{
            config.mode.name(),
            role_pair,
            endpoint_role,
            if (config.mode == .upload) "client" else "server",
            config.body_bytes,
            config.warmup,
            config.iterations,
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

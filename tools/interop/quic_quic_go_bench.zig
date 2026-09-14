const std = @import("std");
const netz = @import("netz");

pub const alpn = "netz-raw-stream-bench";
pub const mtu: usize = 1280;
pub const max_frames: usize = 256;
pub const record_len: usize = 64;
pub const prelude_len: usize = 16;
const record_magic = "NZQSB1";
const data_magic = "NZQSD1";

pub const Kind = enum(u8) {
    config = 1,
    config_ack = 2,
    ready = 3,
    done = 4,
    done_ack = 5,
    start = 6,
};

pub const Sender = enum(u8) { client = 1, server = 2 };

pub const Config = struct {
    warmup: u32 = 2,
    iterations: u32 = 5,
    streams: u16,
    bytes_per_stream: u64 = 4 * 1024 * 1024,
    chunk_bytes: u32 = 16 * 1024,
    stream_window: u64 = 1024 * 1024,
    timeout_ms: u32 = 30_000,

    pub fn parse(args: []const []const u8) !Config {
        var streams: ?u16 = null;
        var config: Config = undefined;
        config.warmup = 2;
        config.iterations = 5;
        config.bytes_per_stream = 4 * 1024 * 1024;
        config.chunk_bytes = 16 * 1024;
        config.stream_window = 1024 * 1024;
        config.timeout_ms = 30_000;
        for (args) |arg| {
            if (option(arg, "--warmup=")) |value| {
                config.warmup = try parseNonNegative(u32, value);
            } else if (option(arg, "--iterations=")) |value| {
                config.iterations = try parsePositive(u32, value);
            } else if (option(arg, "--streams=")) |value| {
                streams = try parsePositive(u16, value);
            } else if (option(arg, "--bytes-per-stream=")) |value| {
                config.bytes_per_stream = try parsePositive(u64, value);
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
        config.streams = streams orelse return error.InvalidArgument;
        try config.validate();
        return config;
    }

    pub fn validate(self: Config) !void {
        if (self.streams != 1 and self.streams != 4) {
            return error.InvalidArgument;
        }
        if (self.warmup > 4096 or self.iterations == 0 or
            self.iterations > 100_000 or self.bytes_per_stream == 0 or
            self.bytes_per_stream > 1024 * 1024 * 1024 or
            self.chunk_bytes == 0 or self.chunk_bytes > 1024 * 1024 or
            self.chunk_bytes > self.bytes_per_stream or
            self.stream_window == 0 or self.stream_window > 1024 * 1024 * 1024 or
            self.timeout_ms == 0 or self.timeout_ms > 10 * 60 * 1000)
        {
            return error.InvalidArgument;
        }
        _ = try self.rounds();
        _ = try self.totalBytes();
        _ = try self.connectionWindow();
        _ = std.math.cast(usize, self.bytes_per_stream) orelse
            return error.InvalidArgument;
    }

    pub fn rounds(self: Config) !u32 {
        return std.math.add(u32, self.warmup, self.iterations) catch
            error.InvalidArgument;
    }

    pub fn totalBytes(self: Config) !u64 {
        return std.math.mul(u64, self.bytes_per_stream, self.streams) catch
            error.InvalidArgument;
    }

    pub fn connectionWindow(self: Config) !u64 {
        return std.math.mul(u64, self.stream_window, 8) catch
            error.InvalidArgument;
    }

    pub fn effectiveChunk(self: Config) usize {
        return @min(@as(usize, self.chunk_bytes), mtu - 128);
    }

    pub fn timeout(self: Config) std.Io.Duration {
        return .fromMilliseconds(self.timeout_ms);
    }

    pub fn transportParameters(self: Config) !netz.quic.TransportParameters {
        return .{
            .max_udp_payload_size = 4096,
            .initial_max_data = try self.connectionWindow(),
            .initial_max_stream_data_bidi_local = self.stream_window,
            .initial_max_stream_data_bidi_remote = self.stream_window,
            .initial_max_stream_data_uni = self.stream_window,
            .initial_max_streams_bidi = 4,
            .initial_max_streams_uni = @as(u64, self.streams) + 4,
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

fn parseNonNegative(comptime T: type, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10) catch error.InvalidArgument;
}

pub const Record = struct {
    kind: Kind,
    sender: Sender,
    round: u32,
    config: Config,
    received_bytes: u64 = 0,
    checksum: u64 = 0,

    pub fn init(kind: Kind, sender: Sender, round: u32, config: Config) Record {
        return .{ .kind = kind, .sender = sender, .round = round, .config = config };
    }

    pub fn encode(self: Record) ![record_len]u8 {
        var out = [_]u8{0} ** record_len;
        @memcpy(out[0..6], record_magic);
        out[6] = @intFromEnum(self.kind);
        out[7] = 1;
        std.mem.writeInt(u32, out[8..12], self.round, .big);
        std.mem.writeInt(u32, out[12..16], self.config.warmup, .big);
        std.mem.writeInt(u32, out[16..20], self.config.iterations, .big);
        std.mem.writeInt(u16, out[20..22], self.config.streams, .big);
        out[22] = @intFromEnum(self.sender);
        out[23] = 0;
        std.mem.writeInt(u64, out[24..32], self.config.bytes_per_stream, .big);
        std.mem.writeInt(u32, out[32..36], self.config.chunk_bytes, .big);
        std.mem.writeInt(u32, out[36..40], self.config.timeout_ms, .big);
        std.mem.writeInt(u64, out[40..48], self.config.stream_window, .big);
        std.mem.writeInt(u64, out[48..56], self.received_bytes, .big);
        std.mem.writeInt(u64, out[56..64], self.checksum, .big);
        return out;
    }

    pub fn decode(bytes: *const [record_len]u8) !Record {
        if (!std.mem.eql(u8, bytes[0..6], record_magic) or bytes[7] != 1 or
            bytes[23] != 0)
        {
            return error.InvalidBenchmarkControl;
        }
        const record: Record = .{
            .kind = std.enums.fromInt(Kind, bytes[6]) orelse
                return error.InvalidBenchmarkControl,
            .sender = std.enums.fromInt(Sender, bytes[22]) orelse
                return error.InvalidBenchmarkControl,
            .round = std.mem.readInt(u32, bytes[8..12], .big),
            .config = .{
                .warmup = std.mem.readInt(u32, bytes[12..16], .big),
                .iterations = std.mem.readInt(u32, bytes[16..20], .big),
                .streams = std.mem.readInt(u16, bytes[20..22], .big),
                .bytes_per_stream = std.mem.readInt(u64, bytes[24..32], .big),
                .chunk_bytes = std.mem.readInt(u32, bytes[32..36], .big),
                .timeout_ms = std.mem.readInt(u32, bytes[36..40], .big),
                .stream_window = std.mem.readInt(u64, bytes[40..48], .big),
            },
            .received_bytes = std.mem.readInt(u64, bytes[48..56], .big),
            .checksum = std.mem.readInt(u64, bytes[56..64], .big),
        };
        try record.config.validate();
        return record;
    }
};

pub fn prelude(round: u32, stream_index: u16) [prelude_len]u8 {
    var out = [_]u8{0} ** prelude_len;
    @memcpy(out[0..6], data_magic);
    std.mem.writeInt(u32, out[6..10], round, .big);
    std.mem.writeInt(u16, out[10..12], stream_index, .big);
    std.mem.writeInt(u32, out[12..16], 0, .big);
    return out;
}

pub fn decodePrelude(bytes: *const [prelude_len]u8, round: u32, streams: u16) !usize {
    if (!std.mem.eql(u8, bytes[0..6], data_magic) or
        std.mem.readInt(u32, bytes[6..10], .big) != round or
        std.mem.readInt(u32, bytes[12..16], .big) != 0)
    {
        return error.InvalidBenchmarkPrelude;
    }
    const index = std.mem.readInt(u16, bytes[10..12], .big);
    if (index >= streams) return error.InvalidBenchmarkPrelude;
    return index;
}

pub fn payloadByte(round: u32, stream_index: usize, offset: usize) u8 {
    return @truncate(offset *% 131 +% stream_index *% 17 +% @as(usize, round) *% 29);
}

pub fn fillPayload(payload: []u8, round: u32, stream_index: usize) u64 {
    var checksum: u64 = 0;
    for (payload, 0..) |*byte, offset| {
        byte.* = payloadByte(round, stream_index, offset);
        checksum +%= byte.*;
    }
    return checksum;
}

pub fn verifyPayload(bytes: []const u8, round: u32, stream_index: usize, offset: usize) !u64 {
    var checksum: u64 = 0;
    for (bytes, 0..) |byte, index| {
        if (byte != payloadByte(round, stream_index, offset + index)) {
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

pub fn printConfig(sender: []const u8, role_pair: []const u8, config: Config) !void {
    std.debug.print(
        "implementation={s} protocol=quic-stream direction=upload role_pair={s} " ++
            "connection_scope=fresh-per-sample benchmark_scope=same-application-shape " ++
            "warmup={d} iterations={d} streams={d} bytes_per_stream={d} " ++
            "application_chunk_requested={d} application_chunk_effective={d} " ++
            "stream_window={d} connection_window={d} steady_state_mtu=1280 " ++
            "quic_version=1 cipher=negotiated-unexposed cert_verify=true " ++
            "netz_gso=false netz_gro=false quic_go_gso=false " ++
            "quic_go_gro=false pacing=implementation-specific\n",
        .{
            sender,                  role_pair,          config.warmup,           config.iterations,    config.streams,
            config.bytes_per_stream, config.chunk_bytes, config.effectiveChunk(), config.stream_window, try config.connectionWindow(),
        },
    );
}

pub fn printSample(sender: []const u8, role_pair: []const u8, config: Config, sample: u32, elapsed_ns: u64, checksum: u64) !void {
    const total = try config.totalBytes();
    const mib_s = if (elapsed_ns == 0) 0.0 else @as(f64, @floatFromInt(total)) * @as(f64, @floatFromInt(std.time.ns_per_s)) /
        @as(f64, @floatFromInt(elapsed_ns)) / (1024.0 * 1024.0);
    std.debug.print(
        "implementation={s} protocol=quic-stream direction=upload role_pair={s} " ++
            "connection_scope=fresh-per-sample benchmark_scope=same-application-shape " ++
            "sample={d} elapsed_ns={d} logical_MiB_s={d:.3} streams={d} " ++
            "sent_bytes={d} received_bytes={d} checksum={d} complete=true\n",
        .{ sender, role_pair, sample, elapsed_ns, mib_s, config.streams, total, total, checksum },
    );
}

pub fn printSocketTraffic(
    implementation: []const u8,
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    sample: u32,
    traffic: netz.quic.runtime.SocketTrafficStats,
) void {
    std.debug.print(
        "implementation={s} protocol=quic-stream role_pair={s} " ++
            "endpoint_role={s} sample={d} streams={d} " ++
            "traffic_scope=connection socket_boundary=userspace-udp-payload " ++
            "udp_sent_datagrams={d} udp_sent_payload_bytes={d} " ++
            "udp_received_datagrams={d} udp_received_payload_bytes={d} " ++
            "logical_udp_segments=true complete=true\n",
        .{
            implementation,
            role_pair,
            endpoint_role,
            sample,
            config.streams,
            traffic.sent_datagrams,
            traffic.sent_bytes,
            traffic.received_datagrams,
            traffic.received_bytes,
        },
    );
}

pub fn printNetzMemory(
    role_pair: []const u8,
    endpoint_role: []const u8,
    sender: Sender,
    config: Config,
    snapshot: anytype,
) void {
    std.debug.print(
        "implementation=netz protocol=quic-stream role_pair={s} " ++
            "endpoint_role={s} sender_role={s} streams={d} " ++
            "memory_scope=benchmark-run-after-argument-parse " ++
            "allocator_scope=netz-explicit alloc_count={d} free_count={d} " ++
            "resize_count={d} remap_count={d} total_allocated_bytes={d} " ++
            "live_bytes={d} peak_live_bytes={d} complete=true\n",
        .{
            role_pair,
            endpoint_role,
            @tagName(sender),
            config.streams,
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

pub const PayloadSet = struct {
    storage: []u8,
    streams: [4][]const u8,
    checksum: u64,

    pub fn init(allocator: std.mem.Allocator, config: Config, round: u32) !PayloadSet {
        const per_stream = std.math.cast(usize, config.bytes_per_stream) orelse
            return error.InvalidArgument;
        const total = std.math.mul(usize, per_stream, config.streams) catch
            return error.InvalidArgument;
        const storage = try allocator.alloc(u8, total);
        errdefer allocator.free(storage);
        var result = PayloadSet{
            .storage = storage,
            .streams = .{ &.{}, &.{}, &.{}, &.{} },
            .checksum = 0,
        };
        for (0..config.streams) |index| {
            const bytes = storage[index * per_stream ..][0..per_stream];
            result.checksum +%= fillPayload(bytes, round, index);
            result.streams[index] = bytes;
        }
        return result;
    }

    pub fn deinit(self: *PayloadSet, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }
};

pub fn sendBytes(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    offset: u64,
    bytes: []const u8,
    fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    try connection.sendWithDeadline(&.{.{ .stream = .{
        .stream_id = stream_id,
        .offset = offset,
        .data = bytes,
        .fin = fin,
    } }}, deadline);
}

pub fn sendRecord(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    offset: *u64,
    record: Record,
    fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    const bytes = try record.encode();
    try sendBytes(connection, stream_id, offset.*, &bytes, fin, deadline);
    offset.* = std.math.add(u64, offset.*, bytes.len) catch
        return error.InvalidBenchmarkControl;
}

pub fn receiveRecord(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u62,
    deadline: std.Io.Clock.Timestamp,
    expect_fin: bool,
) !Record {
    var bytes: [record_len]u8 = undefined;
    var received: usize = 0;
    var fin = false;
    while (received < bytes.len or !fin and expect_fin) {
        const event = try connection.receiveStreamIdWithDeadline(
            stream_id,
            bytes[received..],
            deadline,
        );
        switch (event) {
            .reset => return error.InvalidBenchmarkControl,
            .data => |data| {
                if (data.stream_id != stream_id or received + data.bytes > bytes.len) {
                    return error.InvalidBenchmarkControl;
                }
                received += data.bytes;
                if (data.fin) fin = true;
                if (fin and received != bytes.len) return error.InvalidBenchmarkControl;
            },
        }
        if (received == bytes.len and !expect_fin) break;
    }
    if (fin != expect_fin) return error.InvalidBenchmarkControl;
    return Record.decode(&bytes);
}

pub fn validateRecord(
    record: Record,
    kind: Kind,
    sender: Sender,
    round: u32,
    config: Config,
) !void {
    if (record.kind != kind or record.sender != sender or
        record.round != round or !std.meta.eql(record.config, config))
    {
        return error.InvalidBenchmarkControl;
    }
}

pub fn prepareDataStreams(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    round: u32,
    deadline: std.Io.Clock.Timestamp,
) ![4]u64 {
    var ids = [_]u64{0} ** 4;
    for (0..config.streams) |index| {
        const id = try connection.openUnidirectionalStreamWithDeadline(deadline);
        ids[index] = id;
        const bytes = prelude(round, @intCast(index));
        try sendBytes(connection, id, 0, &bytes, false, deadline);
    }
    return ids;
}

pub fn receiveDataPreludes(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    round: u32,
    sender: Sender,
    deadline: std.Io.Clock.Timestamp,
) ![4]u64 {
    var discovered = [_]u64{std.math.maxInt(u64)} ** 4;
    var buffers: [4][prelude_len]u8 = undefined;
    var lengths = [_]usize{0} ** 4;
    var by_index = [_]u64{std.math.maxInt(u64)} ** 4;
    var completed: usize = 0;
    var scratch: [prelude_len]u8 = undefined;
    while (completed < config.streams) {
        const event = try connection.receiveStreamWithDeadline(&scratch, deadline);
        const data = switch (event) {
            .reset => return error.InvalidBenchmarkPrelude,
            .data => |value| value,
        };
        if (data.stream_id == 0 or data.fin) return error.InvalidBenchmarkPrelude;
        var slot: ?usize = null;
        for (0..config.streams) |index| {
            if (discovered[index] == data.stream_id) slot = index;
        }
        if (slot == null) {
            for (0..config.streams) |index| {
                if (discovered[index] == std.math.maxInt(u64)) {
                    discovered[index] = data.stream_id;
                    slot = index;
                    break;
                }
            }
        }
        const found = slot orelse return error.InvalidBenchmarkPrelude;
        if (lengths[found] + data.bytes > prelude_len) {
            return error.InvalidBenchmarkPrelude;
        }
        @memcpy(buffers[found][lengths[found]..][0..data.bytes], scratch[0..data.bytes]);
        lengths[found] += data.bytes;
        if (lengths[found] == prelude_len) {
            const stream_index = try decodePrelude(&buffers[found], round, config.streams);
            if (by_index[stream_index] != std.math.maxInt(u64)) {
                return error.InvalidBenchmarkPrelude;
            }
            const expected: u64 = @as(u64, if (sender == .client) 2 else 3) +
                @as(u64, stream_index) * 4;
            if (data.stream_id != expected) return error.InvalidBenchmarkPrelude;
            by_index[stream_index] = data.stream_id;
            completed += 1;
        }
    }
    return by_index;
}

pub fn sendPayloads(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    stream_ids: *const [4]u64,
    payloads: *const PayloadSet,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var offsets = [_]usize{0} ** 4;
    var remaining: usize = config.streams;
    while (remaining != 0) {
        remaining = 0;
        for (0..config.streams) |index| {
            const payload = payloads.streams[index];
            if (offsets[index] == payload.len) continue;
            remaining += 1;
            const chunk_end = @min(
                payload.len,
                offsets[index] + config.effectiveChunk(),
            );
            const available = connection.streamSendCredit(
                stream_ids[index],
            ).available();
            // `sendWithDeadline` is transactional: it waits until the entire
            // requested STREAM frame fits. Consume a positive window tail
            // before asking for more credit; at zero, a one-byte request emits
            // the appropriate BLOCKED signal and then waits for progress.
            const chunk_len = chunk_end - offsets[index];
            if (available < chunk_len) {
                var committed: usize = 0;
                try connection.sendStreamWithDeadline(
                    stream_ids[index],
                    prelude_len + offsets[index],
                    payload[offsets[index]..chunk_end],
                    chunk_end == payload.len,
                    &committed,
                    deadline,
                );
                if (committed != chunk_len) {
                    return error.InvalidBenchmarkResult;
                }
                offsets[index] = chunk_end;
                continue;
            }
            const count = @min(
                chunk_len,
                @max(@as(usize, 1), available),
            );
            const end = offsets[index] + count;
            try sendBytes(
                connection,
                stream_ids[index],
                prelude_len + offsets[index],
                payload[offsets[index]..end],
                end == payload.len,
                deadline,
            );
            offsets[index] = end;
        }
    }
}

pub const ReceiveResult = struct { bytes: u64, checksum: u64 };

pub fn receivePayloads(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    round: u32,
    stream_ids: *const [4]u64,
    buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) !ReceiveResult {
    var offsets = [_]usize{0} ** 4;
    var checksums = [_]u64{0} ** 4;
    var finished = [_]bool{false} ** 4;
    var complete: usize = 0;
    while (complete < config.streams) {
        const event = try connection.receiveStreamWithDeadline(buffer, deadline);
        const data = switch (event) {
            .reset => return error.InvalidBenchmarkPayload,
            .data => |value| value,
        };
        var stream_index: ?usize = null;
        for (0..config.streams) |index| {
            if (stream_ids[index] == data.stream_id) stream_index = index;
        }
        const index = stream_index orelse return error.InvalidBenchmarkPayload;
        if (finished[index] or offsets[index] + data.bytes > config.bytes_per_stream) {
            return error.InvalidBenchmarkPayload;
        }
        checksums[index] +%= try verifyPayload(
            buffer[0..data.bytes],
            round,
            index,
            offsets[index],
        );
        offsets[index] += data.bytes;
        if (data.fin) {
            if (offsets[index] != config.bytes_per_stream) {
                return error.InvalidBenchmarkPayload;
            }
            finished[index] = true;
            complete += 1;
        }
    }
    var checksum: u64 = 0;
    for (checksums[0..config.streams]) |value| checksum +%= value;
    return .{ .bytes = try config.totalBytes(), .checksum = checksum };
}

pub fn drainDeliveryRecovery(
    connection: *netz.quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) !void {
    while (connection.pendingDeliveryRecovery()) {
        connection.servicePacketServicingTimersDeadline(deadline) catch |err|
            switch (err) {
                error.ConnectionClosed => {
                    try validateBenchmarkClose(connection);
                    return;
                },
                else => return err,
            };
    }
}

pub fn validateBenchmarkClose(
    connection: *netz.quic.one_rtt.Connection,
) !void {
    const close = connection.peerCloseInfo() orelse
        return error.MissingPeerClose;
    switch (close) {
        .application => |application| if (application.error_code != 0 or
            !std.mem.eql(u8, application.reason_phrase, "benchmark complete"))
        {
            return error.UnexpectedPeerClose;
        },
        .transport => return error.UnexpectedPeerClose,
    }
}

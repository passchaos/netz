const std = @import("std");
const netz = @import("netz");

pub const alpn = "netz-datagram-bench";
pub const mtu: usize = 1200;
pub const max_payload: usize = 1024;
pub const max_window: usize = 64;
const record_len = 40;
const record_magic = "NZDGBN01";
const payload_magic = "NZDG";

const Kind = enum(u8) { config = 1, ready = 2, done = 3, ack = 4 };

pub const Config = struct {
    warmup: u32 = 200,
    iterations: u32 = 5000,
    payload_bytes: u16 = 32,
    window: u16 = 1,
    timeout_ms: u32 = 30_000,

    pub fn parse(args: []const []const u8) !Config {
        var config: Config = .{};
        for (args) |arg| {
            if (option(arg, "--warmup=")) |value| {
                config.warmup = try parseNonNegative(u32, value);
            } else if (option(arg, "--iterations=")) |value| {
                config.iterations = try parsePositive(u32, value);
            } else if (option(arg, "--payload-bytes=")) |value| {
                config.payload_bytes = try parsePositive(u16, value);
            } else if (option(arg, "--window=")) |value| {
                config.window = try parsePositive(u16, value);
            } else if (option(arg, "--timeout-ms=")) |value| {
                config.timeout_ms = try parsePositive(u32, value);
            } else {
                return error.InvalidArgument;
            }
        }
        try config.validate();
        return config;
    }

    pub fn validate(self: Config) !void {
        if (self.warmup > 100_000 or self.iterations > 1_000_000 or
            self.payload_bytes < 12 or self.payload_bytes > max_payload or
            self.window == 0 or self.window > max_window or
            self.timeout_ms > 10 * 60 * 1000)
        {
            return error.InvalidArgument;
        }
        _ = try self.rounds();
        if (try self.totalBytes() > std.math.maxInt(u32)) {
            return error.InvalidArgument;
        }
    }

    pub fn rounds(self: Config) !u32 {
        return std.math.add(u32, self.warmup, self.iterations) catch
            error.InvalidArgument;
    }

    pub fn totalBytes(self: Config) !u64 {
        return std.math.mul(u64, try self.totalDatagrams(), self.payload_bytes) catch
            error.InvalidArgument;
    }

    pub fn totalDatagrams(self: Config) !u64 {
        return std.math.mul(u64, try self.rounds(), self.window) catch
            error.InvalidArgument;
    }

    pub fn timeout(self: Config) std.Io.Duration {
        return .fromMilliseconds(self.timeout_ms);
    }

    pub fn transportParameters(self: Config) netz.quic.TransportParameters {
        _ = self;
        var parameters = netz.quic.practical_transport_parameters;
        parameters.max_udp_payload_size = mtu;
        parameters.max_datagram_frame_size = 65_535;
        return parameters;
    }

    pub fn oneRttConfig(self: Config) netz.quic.handshake.OneRttConfig {
        return .{
            .max_datagram_size = mtu,
            .max_datagram_queue_items = self.window,
            .max_datagram_queue_bytes = @as(usize, self.window) * @as(usize, self.payload_bytes),
            .max_frames_per_packet = @max(16, self.window),
        };
    }
};

const Record = struct {
    kind: Kind,
    config: Config,
    received_bytes: u64 = 0,
    checksum: u64 = 0,

    fn init(kind: Kind, config: Config) Record {
        return .{ .kind = kind, .config = config };
    }

    fn encode(self: Record) ![record_len]u8 {
        var out = [_]u8{0} ** record_len;
        @memcpy(out[0..8], record_magic);
        out[8] = @intFromEnum(self.kind);
        out[9] = 2;
        std.mem.writeInt(u32, out[12..16], self.config.warmup, .big);
        std.mem.writeInt(u32, out[16..20], self.config.iterations, .big);
        std.mem.writeInt(u16, out[20..22], self.config.payload_bytes, .big);
        std.mem.writeInt(u16, out[22..24], self.config.window, .big);
        std.mem.writeInt(u32, out[24..28], self.config.timeout_ms, .big);
        std.mem.writeInt(u32, out[28..32], @intCast(self.received_bytes), .big);
        std.mem.writeInt(u64, out[32..40], self.checksum, .big);
        return out;
    }

    fn decode(bytes: *const [record_len]u8) !Record {
        if (!std.mem.eql(u8, bytes[0..8], record_magic) or bytes[9] != 2 or
            !std.mem.allEqual(u8, bytes[10..12], 0))
        {
            return error.InvalidBenchmarkControl;
        }
        const record: Record = .{
            .kind = std.enums.fromInt(Kind, bytes[8]) orelse
                return error.InvalidBenchmarkControl,
            .config = .{
                .warmup = std.mem.readInt(u32, bytes[12..16], .big),
                .iterations = std.mem.readInt(u32, bytes[16..20], .big),
                .payload_bytes = std.mem.readInt(u16, bytes[20..22], .big),
                .window = std.mem.readInt(u16, bytes[22..24], .big),
                .timeout_ms = std.mem.readInt(u32, bytes[24..28], .big),
            },
            .received_bytes = std.mem.readInt(u32, bytes[28..32], .big),
            .checksum = std.mem.readInt(u64, bytes[32..40], .big),
        };
        try record.config.validate();
        return record;
    }
};

pub const Result = struct {
    received_bytes: u64,
    checksum: u64,
};

pub fn runClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    implementation: []const u8,
    role_pair: []const u8,
) !Result {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = config.timeout(),
    });
    const control_id = try connection.openStreamWithDeadline(deadline);
    if (control_id != 0) return error.UnexpectedStreamId;
    var control_offset: u64 = 0;
    try sendRecord(
        connection,
        control_id,
        &control_offset,
        .init(.config, config),
        false,
        deadline,
    );
    try expectRecord(
        try receiveRecord(connection, @intCast(control_id), false, deadline),
        .ready,
        config,
    );

    const samples = try allocator.alloc(u64, config.iterations);
    defer allocator.free(samples);
    var payload_storage: [max_window][max_payload]u8 = undefined;
    var payloads: [max_window][]const u8 = undefined;
    var received_storage: [max_window][max_payload]u8 = undefined;
    var received: [max_window][]u8 = undefined;
    var seen: [max_window]bool = undefined;
    var checksum: u64 = 0;
    const window: usize = config.window;
    for (0..try config.rounds()) |round| {
        const first_sequence: u32 = @intCast(round * window);
        for (0..window) |index| {
            const payload = payload_storage[index][0..config.payload_bytes];
            fillPayload(payload, first_sequence + @as(u32, @intCast(index)));
            payloads[index] = payload;
        }
        const started = nowNs(io);
        var committed: usize = 0;
        try connection.sendDatagramsWithDeadline(
            payloads[0..window],
            &committed,
            deadline,
        );
        if (committed != window) return error.IncompleteDatagramWindow;
        for (received_storage[0..window], received[0..window]) |*storage, *output| {
            output.* = storage;
        }
        var received_count: usize = 0;
        try connection.receiveDatagramsWithDeadline(
            received[0..window],
            &received_count,
            deadline,
        );
        if (received_count != window) return error.IncompleteDatagramWindow;
        @memset(seen[0..window], false);
        for (received[0..window]) |echoed| {
            const sequence = try verifyWindowPayload(
                echoed,
                first_sequence,
                config,
            );
            const index: usize = @intCast(sequence - first_sequence);
            if (seen[index]) return error.DuplicateBenchmarkPayload;
            seen[index] = true;
            addChecksum(&checksum, echoed);
        }
        const elapsed = nowNs(io) -| started;
        if (round >= config.warmup) {
            samples[round - config.warmup] = elapsed;
        }
    }

    var done = Record.init(.done, config);
    done.received_bytes = try config.totalBytes();
    done.checksum = checksum;
    try sendRecord(
        connection,
        control_id,
        &control_offset,
        done,
        true,
        deadline,
    );
    const ack = try receiveRecord(
        connection,
        @intCast(control_id),
        true,
        deadline,
    );
    try expectRecord(ack, .ack, config);
    if (ack.received_bytes != done.received_bytes or ack.checksum != checksum) {
        return error.InvalidBenchmarkResult;
    }

    std.mem.sortUnstable(u64, samples, {}, std.sort.asc(u64));
    var sum: u128 = 0;
    for (samples) |sample| sum += sample;
    printResult(
        implementation,
        role_pair,
        config,
        connection.maxDatagramPayloadSize().?,
        samples,
        sum,
        checksum,
    );
    return .{ .received_bytes = done.received_bytes, .checksum = checksum };
}

pub fn runServer(
    connection: *netz.quic.one_rtt.Connection,
    expected: Config,
) !Result {
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{
        .clock = .awake,
        .raw = expected.timeout(),
    });
    const config_record = try receiveRecord(connection, 0, false, deadline);
    try expectRecord(config_record, .config, expected);
    var control_offset: u64 = 0;
    try sendRecord(
        connection,
        0,
        &control_offset,
        .init(.ready, expected),
        false,
        deadline,
    );

    var payload_storage: [max_window][max_payload]u8 = undefined;
    var received: [max_window][]u8 = undefined;
    var payloads: [max_window][]const u8 = undefined;
    var seen: [max_window]bool = undefined;
    var checksum: u64 = 0;
    const window: usize = expected.window;
    for (0..try expected.rounds()) |round| {
        const first_sequence: u32 = @intCast(round * window);
        for (payload_storage[0..window], received[0..window]) |*storage, *output| {
            output.* = storage;
        }
        var received_count: usize = 0;
        try connection.receiveDatagramsWithDeadline(
            received[0..window],
            &received_count,
            deadline,
        );
        if (received_count != window) return error.IncompleteDatagramWindow;
        @memset(seen[0..window], false);
        for (received[0..window], payloads[0..window]) |payload, *echo| {
            const sequence = try verifyWindowPayload(
                payload,
                first_sequence,
                expected,
            );
            const index: usize = @intCast(sequence - first_sequence);
            if (seen[index]) return error.DuplicateBenchmarkPayload;
            seen[index] = true;
            addChecksum(&checksum, payload);
            echo.* = payload;
        }
        var committed: usize = 0;
        try connection.sendDatagramsWithDeadline(
            payloads[0..window],
            &committed,
            deadline,
        );
        if (committed != window) return error.IncompleteDatagramWindow;
    }

    const done = try receiveRecord(connection, 0, true, deadline);
    try expectRecord(done, .done, expected);
    const received_bytes = try expected.totalBytes();
    if (done.received_bytes != received_bytes or done.checksum != checksum) {
        return error.InvalidBenchmarkResult;
    }
    var ack = Record.init(.ack, expected);
    ack.received_bytes = received_bytes;
    ack.checksum = checksum;
    try sendRecord(connection, 0, &control_offset, ack, true, deadline);
    return .{ .received_bytes = received_bytes, .checksum = checksum };
}

pub fn printConfig(
    implementation: []const u8,
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    datagram_limit: usize,
) void {
    std.debug.print(
        "record=config implementation={s} protocol=quic-datagram mode={s} " ++
            "role_pair={s} endpoint_role={s} client_io={s} server_io={s} " ++
            "connection_scope=fresh-per-sample benchmark_scope=same-application-shape " ++
            "timing_scope={s} warmup={d} iterations={d} payload_bytes={d} " ++
            "window={d} total_datagrams={d} timeout_ms={d} " ++
            "steady_state_mtu=1200 datagram_limit={d} quic_version=1 " ++
            "cert_verify=true pacing=implementation-specific udp_batching={s} " ++
            "complete=true\n",
        .{
            implementation,
            mode(config),
            role_pair,
            endpoint_role,
            clientIo(role_pair),
            serverIo(role_pair),
            timingScope(config),
            config.warmup,
            config.iterations,
            config.payload_bytes,
            config.window,
            config.totalDatagrams() catch unreachable,
            config.timeout_ms,
            datagram_limit,
            udpBatching(implementation, config),
        },
    );
}

pub fn printServerComplete(
    implementation: []const u8,
    role_pair: []const u8,
    config: Config,
    result: Result,
) void {
    std.debug.print(
        "record=server-complete implementation={s} protocol=quic-datagram " ++
            "mode={s} role_pair={s} endpoint_role=server client_io={s} " ++
            "server_io={s} warmup={d} iterations={d} payload_bytes={d} " ++
            "window={d} total_datagrams={d} timeout_ms={d} timing_scope={s} " ++
            "received_bytes={d} checksum={d} " ++
            "completion_exchange_verified=true close_code=59 complete=true\n",
        .{
            implementation,
            mode(config),
            role_pair,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.payload_bytes,
            config.window,
            config.totalDatagrams() catch unreachable,
            config.timeout_ms,
            timingScope(config),
            result.received_bytes,
            result.checksum,
        },
    );
}

pub fn waitForBenchmarkClose(
    connection: *netz.quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) !void {
    while (connection.peerCloseInfo() == null) {
        connection.servicePacketServicingTimersDeadline(deadline) catch |err|
            switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
    }
    const close = connection.peerCloseInfo() orelse return error.MissingPeerClose;
    switch (close) {
        .application => |application| if (application.error_code != 59 or
            !std.mem.eql(u8, application.reason_phrase, "datagram benchmark complete"))
        {
            return error.UnexpectedPeerClose;
        },
        .transport => return error.UnexpectedPeerClose,
    }
}

fn printResult(
    implementation: []const u8,
    role_pair: []const u8,
    config: Config,
    datagram_limit: usize,
    samples: []const u64,
    sum: u128,
    checksum: u64,
) void {
    std.debug.print(
        "record=result implementation={s} protocol=quic-datagram mode={s} " ++
            "role_pair={s} endpoint_role=client client_io={s} server_io={s} " ++
            "connection_scope=fresh-per-sample " ++
            "benchmark_scope=same-application-shape warmup={d} iterations={d} " ++
            "timing_scope={s} payload_bytes={d} window={d} total_datagrams={d} " ++
            "timeout_ms={d} datagram_limit={d} " ++
            "p50_ns={d} p90_ns={d} p99_ns={d} p999_ns={d} mean_ns={d} " ++
            "min_ns={d} max_ns={d} received_bytes={d} checksum={d} " ++
            "completion_exchange_verified=true close_code=59 complete=true\n",
        .{
            implementation,
            mode(config),
            role_pair,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            timingScope(config),
            config.payload_bytes,
            config.window,
            config.totalDatagrams() catch unreachable,
            config.timeout_ms,
            datagram_limit,
            percentile(samples, 50, 100),
            percentile(samples, 90, 100),
            percentile(samples, 99, 100),
            percentile(samples, 999, 1000),
            sum / samples.len,
            samples[0],
            samples[samples.len - 1],
            config.totalBytes() catch unreachable,
            checksum,
        },
    );
}

fn option(arg: []const u8, prefix: []const u8) ?[]const u8 {
    return if (std.mem.startsWith(u8, arg, prefix)) arg[prefix.len..] else null;
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

fn fillPayload(payload: []u8, sequence: u32) void {
    @memcpy(payload[0..4], payload_magic);
    std.mem.writeInt(u64, payload[4..12], sequence, .big);
    for (payload[12..], 0..) |*byte, index| {
        byte.* = @truncate(@as(usize, sequence) *% 17 +% index *% 131);
    }
}

fn verifyWindowPayload(
    payload: []const u8,
    first_sequence: u32,
    config: Config,
) !u32 {
    if (payload.len != config.payload_bytes or
        !std.mem.eql(u8, payload[0..4], payload_magic))
    {
        return error.InvalidBenchmarkPayload;
    }
    const sequence_u64 = std.mem.readInt(u64, payload[4..12], .big);
    const sequence = std.math.cast(u32, sequence_u64) orelse
        return error.InvalidBenchmarkPayload;
    const end = first_sequence + @as(u32, config.window);
    if (sequence < first_sequence or sequence >= end) {
        return error.InvalidBenchmarkPayload;
    }
    try verifyPayload(payload, sequence, config.payload_bytes);
    return sequence;
}

fn verifyPayload(payload: []const u8, sequence: u32, expected_len: u16) !void {
    if (payload.len != expected_len or
        !std.mem.eql(u8, payload[0..4], payload_magic) or
        std.mem.readInt(u64, payload[4..12], .big) != sequence)
    {
        return error.InvalidBenchmarkPayload;
    }
    for (payload[12..], 0..) |byte, index| {
        if (byte != @as(u8, @truncate(
            @as(usize, sequence) *% 17 +% index *% 131,
        ))) return error.InvalidBenchmarkPayload;
    }
}

fn addChecksum(checksum: *u64, payload: []const u8) void {
    for (payload) |byte| checksum.* +%= byte;
}

fn sendRecord(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    offset: *u64,
    record: Record,
    fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    const encoded = try record.encode();
    var committed: usize = 0;
    try connection.sendStreamWithDeadline(
        stream_id,
        offset.*,
        &encoded,
        fin,
        &committed,
        deadline,
    );
    if (committed != encoded.len) return error.IncompleteBenchmarkControlSend;
    offset.* += committed;
}

fn receiveRecord(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u62,
    expect_fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !Record {
    var encoded: [record_len]u8 = undefined;
    var received: usize = 0;
    var fin = false;
    var scratch: [1]u8 = undefined;
    while (received < encoded.len or expect_fin and !fin) {
        const target = if (received < encoded.len) encoded[received..] else scratch[0..];
        const event = try connection.receiveStreamIdWithDeadline(
            stream_id,
            target,
            deadline,
        );
        const data = switch (event) {
            .reset => return error.UnexpectedReset,
            .data => |value| value,
        };
        if (data.stream_id != stream_id or received + data.bytes > encoded.len) {
            return error.InvalidBenchmarkControl;
        }
        received += data.bytes;
        fin = fin or data.fin;
    }
    if (fin != expect_fin) return error.InvalidBenchmarkControl;
    return Record.decode(&encoded);
}

fn expectRecord(actual: Record, kind: Kind, expected: Config) !void {
    if (actual.kind != kind or !std.meta.eql(actual.config, expected)) {
        return error.InvalidBenchmarkControl;
    }
}

fn percentile(sorted: []const u64, numerator: usize, denominator: usize) u64 {
    const rank = std.math.divCeil(usize, sorted.len * numerator, denominator) catch
        unreachable;
    return sorted[@max(rank, 1) - 1];
}

fn nowNs(io: std.Io) u64 {
    const value = std.Io.Clock.awake.now(io).nanoseconds;
    if (value <= 0) return 0;
    return std.math.cast(u64, value) orelse std.math.maxInt(u64);
}

pub fn clientIo(role_pair: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, role_pair, "netz-client"))
        "zio-std-io"
    else
        "quinn-tokio-rustls";
}

pub fn serverIo(role_pair: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, role_pair, "netz-server"))
        "zio-std-io"
    else
        "quinn-tokio-rustls";
}

fn mode(config: Config) []const u8 {
    return if (config.window == 1) "pingpong" else "windowed-pingpong";
}

fn timingScope(config: Config) []const u8 {
    return if (config.window == 1)
        "post-handshake-single-outstanding-roundtrip"
    else
        "post-handshake-window-roundtrip";
}

fn udpBatching(implementation: []const u8, config: Config) []const u8 {
    if (config.window == 1) return "single-message";
    return if (std.mem.eql(u8, implementation, "netz"))
        "gso-send-auto-recvmmsg-receive"
    else
        "quinn-runtime-auto";
}

test "DATAGRAM benchmark config round trips window on the wire" {
    const config: Config = .{
        .warmup = 3,
        .iterations = 5,
        .payload_bytes = 64,
        .window = 8,
        .timeout_ms = 1_000,
    };
    try config.validate();
    try std.testing.expectEqual(@as(u64, 64), try config.totalDatagrams());
    try std.testing.expectEqual(@as(u64, 4096), try config.totalBytes());
    const decoded = try Record.decode(&(try Record.init(.config, config).encode()));
    try std.testing.expectEqual(Kind.config, decoded.kind);
    try std.testing.expectEqual(config, decoded.config);
    try std.testing.expectEqual(@as(u64, 0), decoded.received_bytes);
    try std.testing.expectEqual(@as(u64, 0), decoded.checksum);
}

test "DATAGRAM benchmark config rejects unsafe windows and wire byte overflow" {
    try std.testing.expectError(
        error.InvalidArgument,
        (Config{ .window = 0 }).validate(),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        (Config{ .window = max_window + 1 }).validate(),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        (Config{
            .warmup = 100_000,
            .iterations = 1_000_000,
            .payload_bytes = max_payload,
            .window = max_window,
        }).validate(),
    );
}

test "DATAGRAM benchmark accepts each sequence once inside a window" {
    const config: Config = .{ .payload_bytes = 32, .window = 4 };
    var payload: [32]u8 = undefined;
    fillPayload(&payload, 42);
    try std.testing.expectEqual(
        @as(u32, 42),
        try verifyWindowPayload(&payload, 40, config),
    );
    try std.testing.expectError(
        error.InvalidBenchmarkPayload,
        verifyWindowPayload(&payload, 43, config),
    );
}

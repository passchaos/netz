const std = @import("std");
const netz = @import("netz");

pub const alpn = "netz-datagram-bench";
pub const mtu: usize = 1200;
pub const max_payload: usize = 1024;
const record_len = 40;
const record_magic = "NZDGBN01";
const payload_magic = "NZDG";

const Kind = enum(u8) { config = 1, ready = 2, done = 3, ack = 4 };

pub const Config = struct {
    warmup: u32 = 200,
    iterations: u32 = 5000,
    payload_bytes: u16 = 32,
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
            self.timeout_ms > 10 * 60 * 1000)
        {
            return error.InvalidArgument;
        }
        _ = try self.rounds();
        _ = try self.totalBytes();
    }

    pub fn rounds(self: Config) !u32 {
        return std.math.add(u32, self.warmup, self.iterations) catch
            error.InvalidArgument;
    }

    pub fn totalBytes(self: Config) !u64 {
        return std.math.mul(u64, try self.rounds(), self.payload_bytes) catch
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
        _ = self;
        return .{
            .max_datagram_size = mtu,
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
        out[9] = 1;
        std.mem.writeInt(u32, out[12..16], self.config.warmup, .big);
        std.mem.writeInt(u32, out[16..20], self.config.iterations, .big);
        std.mem.writeInt(u16, out[20..22], self.config.payload_bytes, .big);
        std.mem.writeInt(u32, out[24..28], self.config.timeout_ms, .big);
        std.mem.writeInt(u32, out[28..32], @intCast(self.received_bytes), .big);
        std.mem.writeInt(u64, out[32..40], self.checksum, .big);
        return out;
    }

    fn decode(bytes: *const [record_len]u8) !Record {
        if (!std.mem.eql(u8, bytes[0..8], record_magic) or bytes[9] != 1 or
            !std.mem.allEqual(u8, bytes[10..12], 0) or
            !std.mem.allEqual(u8, bytes[22..24], 0))
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
    var payload_storage: [max_payload]u8 = undefined;
    const payload = payload_storage[0..config.payload_bytes];
    var received_storage: [max_payload]u8 = undefined;
    var checksum: u64 = 0;
    for (0..try config.rounds()) |sequence_index| {
        const sequence: u32 = @intCast(sequence_index);
        fillPayload(payload, sequence);
        const started = nowNs(io);
        try connection.sendDatagramWithDeadline(payload, deadline);
        const echoed = try receiveDatagram(
            connection,
            &received_storage,
            deadline,
        );
        const elapsed = nowNs(io) -| started;
        try verifyPayload(echoed, sequence, config.payload_bytes);
        addChecksum(&checksum, echoed);
        if (sequence >= config.warmup) {
            samples[sequence - config.warmup] = elapsed;
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

    var storage: [max_payload]u8 = undefined;
    var checksum: u64 = 0;
    for (0..try expected.rounds()) |sequence_index| {
        const sequence: u32 = @intCast(sequence_index);
        const payload = try receiveDatagram(connection, &storage, deadline);
        try verifyPayload(payload, sequence, expected.payload_bytes);
        addChecksum(&checksum, payload);
        try connection.sendDatagramWithDeadline(payload, deadline);
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
        "record=config implementation={s} protocol=quic-datagram mode=pingpong " ++
            "role_pair={s} endpoint_role={s} client_io={s} server_io={s} " ++
            "connection_scope=fresh-per-sample benchmark_scope=same-application-shape " ++
            "timing_scope=post-handshake-single-outstanding-roundtrip " ++
            "warmup={d} iterations={d} payload_bytes={d} timeout_ms={d} " ++
            "steady_state_mtu=1200 datagram_limit={d} quic_version=1 " ++
            "cert_verify=true pacing=implementation-specific complete=true\n",
        .{
            implementation,
            role_pair,
            endpoint_role,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.payload_bytes,
            config.timeout_ms,
            datagram_limit,
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
            "mode=pingpong role_pair={s} endpoint_role=server client_io={s} " ++
            "server_io={s} warmup={d} iterations={d} payload_bytes={d} " ++
            "timeout_ms={d} timing_scope=post-handshake-single-outstanding-roundtrip " ++
            "received_bytes={d} checksum={d} " ++
            "completion_exchange_verified=true close_code=59 complete=true\n",
        .{
            implementation,
            role_pair,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.payload_bytes,
            config.timeout_ms,
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
        "record=result implementation={s} protocol=quic-datagram mode=pingpong " ++
            "role_pair={s} endpoint_role=client client_io={s} server_io={s} " ++
            "connection_scope=fresh-per-sample " ++
            "benchmark_scope=same-application-shape warmup={d} iterations={d} " ++
            "timing_scope=post-handshake-single-outstanding-roundtrip " ++
            "payload_bytes={d} timeout_ms={d} datagram_limit={d} " ++
            "p50_ns={d} p90_ns={d} p99_ns={d} p999_ns={d} mean_ns={d} " ++
            "min_ns={d} max_ns={d} received_bytes={d} checksum={d} " ++
            "completion_exchange_verified=true close_code=59 complete=true\n",
        .{
            implementation,
            role_pair,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.payload_bytes,
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

fn receiveDatagram(
    connection: *netz.quic.one_rtt.Connection,
    storage: []u8,
    deadline: std.Io.Clock.Timestamp,
) ![]u8 {
    return connection.receiveDatagramWithDeadline(storage, deadline);
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

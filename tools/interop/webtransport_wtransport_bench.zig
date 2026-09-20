const std = @import("std");
const netz = @import("netz");

const control_magic = "NZWTB2";
const control_len: usize = 82;
const ping_magic = "NZPING";
const ping_header_len: usize = 14;
pub const max_datagram_size: usize = 1200;
const max_benchmark_streams: u64 = 4096;
const max_parallel_streams: u16 = 256;
const StreamMask = std.meta.Int(.unsigned, max_parallel_streams);

pub const Mode = enum(u8) {
    stream = 1,
    datagram_pingpong = 2,

    fn parse(value: []const u8) !Mode {
        if (std.mem.eql(u8, value, "stream") or
            std.mem.eql(u8, value, "stream-upload")) return .stream;
        if (std.mem.eql(u8, value, "datagram-pingpong")) {
            return .datagram_pingpong;
        }
        return error.InvalidArgument;
    }

    pub fn name(self: Mode) []const u8 {
        return switch (self) {
            .stream => "stream-upload",
            .datagram_pingpong => "datagram-pingpong",
        };
    }

    pub fn direction(self: Mode) []const u8 {
        return switch (self) {
            .stream => "upload",
            .datagram_pingpong => "roundtrip",
        };
    }
};

pub const Config = struct {
    mode: Mode,
    warmup: u32 = 20,
    iterations: u32,
    streams: u16 = 1,
    payload_bytes: u32 = 32,
    bytes_per_stream: u64 = 4 * 1024 * 1024,
    chunk_bytes: u32 = 16 * 1024,
    stream_window: u64 = 1024 * 1024,
    timeout_ms: u32 = 30_000,
    netz_ack_every: u64 = 2,
    netz_max_ack_delay_us: u64 = 25_000,

    pub fn parse(args: []const []const u8) !Config {
        var mode: ?Mode = null;
        var warmup: ?u32 = null;
        var iterations: ?u32 = null;
        var streams: u16 = 1;
        var payload_bytes: u32 = 32;
        var bytes_per_stream: u64 = 4 * 1024 * 1024;
        var chunk_bytes: u32 = 16 * 1024;
        var stream_window: u64 = 1024 * 1024;
        var timeout_ms: u32 = 30_000;
        var netz_ack_every: u64 = 2;
        var netz_max_ack_delay_us: u64 = 25_000;
        for (args) |arg| {
            if (option(arg, "--mode=")) |value| {
                mode = try Mode.parse(value);
            } else if (option(arg, "--warmup=")) |value| {
                warmup = try parsePositive(u32, value);
            } else if (option(arg, "--iterations=")) |value| {
                iterations = try parsePositive(u32, value);
            } else if (option(arg, "--streams=")) |value| {
                streams = try parsePositive(u16, value);
            } else if (option(arg, "--payload-bytes=")) |value| {
                payload_bytes = try parsePositive(u32, value);
            } else if (option(arg, "--bytes-per-stream=")) |value| {
                bytes_per_stream = try parsePositive(u64, value);
            } else if (option(arg, "--chunk-bytes=")) |value| {
                chunk_bytes = try parsePositive(u32, value);
            } else if (option(arg, "--stream-window=")) |value| {
                stream_window = try parsePositive(u64, value);
            } else if (option(arg, "--timeout-ms=")) |value| {
                timeout_ms = try parsePositive(u32, value);
            } else if (option(arg, "--netz-ack-every=")) |value| {
                netz_ack_every = try parsePositive(u64, value);
            } else if (option(arg, "--netz-max-ack-delay-us=")) |value| {
                netz_max_ack_delay_us = try parseNonNegative(u64, value);
            } else if (option(arg, "--direction=")) |value| {
                if (!std.mem.eql(u8, value, "upload")) {
                    return error.InvalidArgument;
                }
            } else if (option(arg, "--verify-cert=")) |value| {
                if (!std.mem.eql(u8, value, "false")) {
                    return error.InvalidArgument;
                }
            } else {
                return error.InvalidArgument;
            }
        }
        const selected = mode orelse return error.InvalidArgument;
        const warmup_rounds: u32 = warmup orelse switch (selected) {
            .stream => 20,
            .datagram_pingpong => 200,
        };
        const measured: u32 = iterations orelse switch (selected) {
            .stream => 5,
            .datagram_pingpong => 5000,
        };
        if (streams > max_parallel_streams or
            chunk_bytes > bytes_per_stream or
            netz_max_ack_delay_us > 25_000)
        {
            return error.InvalidArgument;
        }
        if (selected == .datagram_pingpong and
            payload_bytes < ping_header_len)
        {
            return error.InvalidArgument;
        }
        const round_count = std.math.add(u32, warmup_rounds, measured) catch
            return error.InvalidArgument;
        const total_streams = std.math.mul(u64, round_count, streams) catch
            return error.InvalidArgument;
        if (selected == .stream and total_streams > max_benchmark_streams) {
            return error.InvalidArgument;
        }
        return .{
            .mode = selected,
            .warmup = warmup_rounds,
            .iterations = measured,
            .streams = streams,
            .payload_bytes = payload_bytes,
            .bytes_per_stream = bytes_per_stream,
            .chunk_bytes = chunk_bytes,
            .stream_window = stream_window,
            .timeout_ms = timeout_ms,
            .netz_ack_every = netz_ack_every,
            .netz_max_ack_delay_us = netz_max_ack_delay_us,
        };
    }

    pub fn rounds(self: Config) u32 {
        return self.warmup + self.iterations;
    }

    pub fn timeout(self: Config) std.Io.Duration {
        return .fromMilliseconds(self.timeout_ms);
    }

    pub fn connectionWindow(self: Config) !u64 {
        return std.math.mul(
            u64,
            self.stream_window,
            @as(u64, self.streams) + 8,
        ) catch error.InvalidArgument;
    }

    pub fn streamLimit(self: Config) !u64 {
        const used = if (self.mode == .stream)
            std.math.mul(
                u64,
                self.rounds(),
                self.streams,
            ) catch return error.InvalidArgument
        else
            0;
        return std.math.add(u64, used, 8) catch error.InvalidArgument;
    }

    pub fn transportParameters(self: Config) !netz.quic.TransportParameters {
        const connection_window = try self.connectionWindow();
        return .{
            .max_udp_payload_size = max_datagram_size,
            .initial_max_data = connection_window,
            .initial_max_stream_data_bidi_local = self.stream_window,
            .initial_max_stream_data_bidi_remote = self.stream_window,
            .initial_max_stream_data_uni = self.stream_window,
            .initial_max_streams_bidi = try self.streamLimit(),
            .initial_max_streams_uni = try self.streamLimit(),
            .active_connection_id_limit = 4,
            .max_datagram_frame_size = max_datagram_size,
        };
    }

    pub fn oneRttConfig(self: Config) !netz.quic.handshake.OneRttConfig {
        return .{
            .max_frames_per_packet = 256,
            .receive_window = try self.connectionWindow(),
            .max_receive_window = try self.connectionWindow(),
            .stream_receive_window = self.stream_window,
            .max_stream_receive_window = self.stream_window,
            .max_datagram_size = max_datagram_size,
            .local_ack_eliciting_threshold = self.netz_ack_every,
            .local_max_ack_delay_us = self.netz_max_ack_delay_us,
            .local_ack_reordering_threshold = 3,
        };
    }

    pub fn sessionStreams(self: Config) !usize {
        return std.math.cast(usize, try self.streamLimit()) orelse
            error.InvalidArgument;
    }

    pub fn sessionOptions(
        self: Config,
    ) !netz.http3.runtime.HandshakeSessionOptions {
        const stream_limit = try self.streamLimit();
        const whole_stream_limit = std.math.add(
            u64,
            self.bytes_per_stream,
            12,
        ) catch return error.InvalidArgument;
        return .{
            .local_settings = .{
                .webtransport_initial_max_data = try self.connectionWindow(),
                .webtransport_initial_max_streams_bidi = stream_limit,
                .webtransport_initial_max_streams_uni = stream_limit,
            },
            // This is a protocol-level whole-stream aggregation bound, not
            // the sliding QUIC receive window configured above. Incremental
            // benchmark reads do not retain the full body, but keeping the
            // declared bound aligned makes alternate readers unambiguous.
            .max_stream_buffer = std.math.cast(
                usize,
                whole_stream_limit,
            ) orelse return error.InvalidArgument,
            .max_stream_frame_data = max_datagram_size,
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

const Kind = enum(u8) {
    config = 1,
    config_ack = 2,
    round_ready = 3,
    go = 4,
    round_done = 5,
    benchmark_done = 6,
    benchmark_ack = 7,
    close_ready = 8,
    close_ack = 9,
    round_ack = 10,
};

const Control = struct {
    kind: Kind,
    round: u32,
    config: Config,
    received_bytes: u64 = 0,
    checksum: u64 = 0,

    fn init(kind: Kind, config: Config, round: u32) Control {
        return .{ .kind = kind, .round = round, .config = config };
    }

    fn encode(self: Control) [control_len]u8 {
        var bytes = [_]u8{0} ** control_len;
        @memcpy(bytes[0..6], control_magic);
        bytes[6] = @intFromEnum(self.kind);
        bytes[7] = @intFromEnum(self.config.mode);
        std.mem.writeInt(u32, bytes[8..12], self.round, .big);
        std.mem.writeInt(u32, bytes[12..16], self.config.warmup, .big);
        std.mem.writeInt(u32, bytes[16..20], self.config.iterations, .big);
        std.mem.writeInt(u16, bytes[20..22], self.config.streams, .big);
        std.mem.writeInt(u32, bytes[22..26], self.config.payload_bytes, .big);
        std.mem.writeInt(u64, bytes[26..34], self.config.bytes_per_stream, .big);
        std.mem.writeInt(u32, bytes[34..38], self.config.chunk_bytes, .big);
        std.mem.writeInt(u64, bytes[38..46], self.config.stream_window, .big);
        std.mem.writeInt(u32, bytes[46..50], self.config.timeout_ms, .big);
        std.mem.writeInt(u64, bytes[50..58], self.config.netz_ack_every, .big);
        std.mem.writeInt(u64, bytes[58..66], self.config.netz_max_ack_delay_us, .big);
        std.mem.writeInt(u64, bytes[66..74], self.received_bytes, .big);
        std.mem.writeInt(u64, bytes[74..82], self.checksum, .big);
        return bytes;
    }

    fn decode(bytes: []const u8) !Control {
        if (bytes.len != control_len or
            !std.mem.eql(u8, bytes[0..6], control_magic))
        {
            return error.InvalidBenchmarkControl;
        }
        const kind = std.enums.fromInt(Kind, bytes[6]) orelse
            return error.InvalidBenchmarkControl;
        const mode = std.enums.fromInt(Mode, bytes[7]) orelse
            return error.InvalidBenchmarkControl;
        return .{
            .kind = kind,
            .round = std.mem.readInt(u32, bytes[8..12], .big),
            .config = .{
                .mode = mode,
                .warmup = std.mem.readInt(u32, bytes[12..16], .big),
                .iterations = std.mem.readInt(u32, bytes[16..20], .big),
                .streams = std.mem.readInt(u16, bytes[20..22], .big),
                .payload_bytes = std.mem.readInt(u32, bytes[22..26], .big),
                .bytes_per_stream = std.mem.readInt(u64, bytes[26..34], .big),
                .chunk_bytes = std.mem.readInt(u32, bytes[34..38], .big),
                .stream_window = std.mem.readInt(u64, bytes[38..46], .big),
                .timeout_ms = std.mem.readInt(u32, bytes[46..50], .big),
                .netz_ack_every = std.mem.readInt(u64, bytes[50..58], .big),
                .netz_max_ack_delay_us = std.mem.readInt(u64, bytes[58..66], .big),
            },
            .received_bytes = std.mem.readInt(u64, bytes[66..74], .big),
            .checksum = std.mem.readInt(u64, bytes[74..82], .big),
        };
    }
};

pub const ControlChannel = struct {
    stream_id: u62,
};

fn sendControl(
    session: anytype,
    channel: ControlChannel,
    control: Control,
) !void {
    const bytes = control.encode();
    var committed: usize = 0;
    try session.sendStreamWithTimeout(
        channel.stream_id,
        &bytes,
        false,
        &committed,
        control.config.timeout(),
    );
    if (committed != bytes.len) return error.InvalidBenchmarkControl;
}

fn receiveControl(
    session: anytype,
    channel: ControlChannel,
    config: Config,
    kind: Kind,
) !Control {
    var bytes: [control_len]u8 = undefined;
    var received: usize = 0;
    while (received < bytes.len) {
        const event = try session.readStreamIdWithTimeout(
            channel.stream_id,
            bytes[received..],
            config.timeout(),
        );
        if (event != .data or event.data.stream_id != channel.stream_id or
            event.data.direction != .bidirectional or event.data.bytes == 0 or
            event.data.fin)
        {
            return error.InvalidBenchmarkControl;
        }
        received += event.data.bytes;
    }
    const control = try Control.decode(&bytes);
    if (control.kind != kind or !std.meta.eql(control.config, config)) {
        return error.InvalidBenchmarkControl;
    }
    return control;
}

pub fn openControlClient(
    session: anytype,
    config: Config,
) !ControlChannel {
    const channel: ControlChannel = .{
        .stream_id = try session.openBidirectionalStreamWithTimeout(
            config.timeout(),
        ),
    };
    try sendControl(session, channel, .init(.config, config, 0));
    const ack = try receiveControl(session, channel, config, .config_ack);
    if (ack.round != 0) return error.InvalidBenchmarkControl;
    return channel;
}

pub fn acceptControlServer(
    session: anytype,
    config: Config,
) !ControlChannel {
    var bytes: [control_len]u8 = undefined;
    var received: usize = 0;
    var stream_id: ?u62 = null;
    while (received < bytes.len) {
        const event = if (stream_id) |id|
            try session.readStreamIdWithTimeout(
                id,
                bytes[received..],
                config.timeout(),
            )
        else
            try session.readStreamWithTimeout(
                bytes[received..],
                config.timeout(),
            );
        if (event != .data or event.data.direction != .bidirectional or
            event.data.locally_initiated or event.data.bytes == 0 or
            event.data.fin)
        {
            return error.InvalidBenchmarkControl;
        }
        if (stream_id) |id| {
            if (event.data.stream_id != id) return error.InvalidBenchmarkControl;
        } else {
            stream_id = event.data.stream_id;
        }
        received += event.data.bytes;
    }
    const request = try Control.decode(&bytes);
    if (request.kind != .config or !std.meta.eql(request.config, config)) {
        return error.InvalidBenchmarkControl;
    }
    if (request.round != 0) return error.InvalidBenchmarkControl;
    const channel: ControlChannel = .{ .stream_id = stream_id.? };
    try sendControl(session, channel, .init(.config_ack, config, 0));
    return channel;
}

pub fn validateDatagramLimit(session: anytype, config: Config) !usize {
    const limit = session.maxDatagramSize();
    if (config.mode == .datagram_pingpong and config.payload_bytes > limit) {
        return error.UnexpectedDatagramLimit;
    }
    return limit;
}

pub fn printConfig(
    implementation: []const u8,
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    datagram_limit: usize,
) !void {
    std.debug.print(
        "record=config implementation={s} protocol=webtransport transport=h3 mode={s} " ++
            "direction={s} role_pair={s} endpoint_role={s} " ++
            "client_io={s} server_io={s} connection_scope=persistent " ++
            "benchmark_scope=same-application-shape warmup={d} " ++
            "iterations={d} streams={d} bytes_per_stream={d} " ++
            "payload_bytes={d} chunk_bytes={d} " ++
            "stream_window_requested={d} stream_window_effective={d} " ++
            "connection_window={d} max_datagram_size={d} timeout_ms={d} " ++
            "quic_version=1 " ++
            "netz_ack_every={d} netz_max_ack_delay_us={d} " ++
            "cipher=negotiated-unexposed cert_verify=false gso=false " ++
            "gro=false pacing=true\n",
        .{
            implementation,
            config.mode.name(),
            config.mode.direction(),
            role_pair,
            endpoint_role,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.streams,
            config.bytes_per_stream,
            config.payload_bytes,
            config.chunk_bytes,
            config.stream_window,
            config.stream_window,
            try config.connectionWindow(),
            datagram_limit,
            config.timeout_ms,
            config.netz_ack_every,
            config.netz_max_ack_delay_us,
        },
    );
}

fn streamByte(offset: usize, stream_index: usize) u8 {
    return @truncate(offset *% 131 +% stream_index *% 17);
}

fn streamPrelude(round: u32, stream_index: u16) [12]u8 {
    var prelude = [_]u8{0} ** 12;
    @memcpy(prelude[0..6], "NZSTRM");
    std.mem.writeInt(u32, prelude[6..10], round, .big);
    std.mem.writeInt(u16, prelude[10..12], stream_index, .big);
    return prelude;
}

fn verifyStreamPrelude(
    prelude: *const [12]u8,
    config: Config,
    round: u32,
) !usize {
    if (!std.mem.eql(u8, prelude[0..6], "NZSTRM") or
        std.mem.readInt(u32, prelude[6..10], .big) != round)
    {
        return error.InvalidBenchmarkStream;
    }
    const index = std.mem.readInt(u16, prelude[10..12], .big);
    if (index >= config.streams) return error.InvalidBenchmarkStream;
    return index;
}

fn nowNs(io: std.Io) u64 {
    const value = std.Io.Clock.awake.now(io).nanoseconds;
    if (value <= 0) return 0;
    return std.math.cast(u64, value) orelse std.math.maxInt(u64);
}

pub fn runClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    switch (config.mode) {
        .stream => try runStreamClient(allocator, io, session, control, config),
        .datagram_pingpong => try runPingClient(allocator, io, session, control, config),
    }
}

pub fn runServer(
    allocator: std.mem.Allocator,
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    switch (config.mode) {
        .stream => try runStreamServer(allocator, session, control, config),
        .datagram_pingpong => try runPingServer(allocator, session, control, config),
    }
}

pub fn sendCloseReady(
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    try sendControl(
        session,
        control,
        .init(.close_ready, config, config.rounds()),
    );
}

pub fn receiveCloseAck(
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    const ack = try receiveControl(
        session,
        control,
        config,
        .close_ack,
    );
    if (ack.round != config.rounds()) {
        return error.InvalidBenchmarkControl;
    }
}

pub fn receiveCloseReady(
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    const ready = try receiveControl(
        session,
        control,
        config,
        .close_ready,
    );
    if (ready.round != config.rounds()) {
        return error.InvalidBenchmarkControl;
    }
}

pub fn sendCloseAck(
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    try sendControl(
        session,
        control,
        .init(.close_ack, config, config.rounds()),
    );
}

pub fn finishControlAndReceivePeerFin(
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    try session.finishStreamWithTimeout(
        control.stream_id,
        config.timeout(),
    );
    try receiveControlFin(session, control, config);
}

pub fn receiveControlFinAndFinish(
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    try receiveControlFin(session, control, config);
    try session.finishStreamWithTimeout(
        control.stream_id,
        config.timeout(),
    );
}

fn receiveControlFin(
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    var empty: [1]u8 = undefined;
    const event = try session.readStreamIdWithTimeout(
        control.stream_id,
        &empty,
        config.timeout(),
    );
    if (event != .data or event.data.stream_id != control.stream_id or
        event.data.direction != .bidirectional or event.data.bytes != 0 or
        !event.data.fin)
    {
        return error.InvalidBenchmarkControl;
    }
    _ = try session.flushPendingAck();
}

fn buildStreamPayloads(
    allocator: std.mem.Allocator,
    config: Config,
) !struct { storage: []u8, checksum: u64 } {
    const bytes_per_stream = std.math.cast(usize, config.bytes_per_stream) orelse
        return error.InvalidArgument;
    const total = std.math.mul(usize, bytes_per_stream, config.streams) catch
        return error.InvalidArgument;
    const storage = try allocator.alloc(u8, total);
    errdefer allocator.free(storage);
    var checksum: u64 = 0;
    for (0..config.streams) |stream_index| {
        const payload = storage[stream_index * bytes_per_stream ..][0..bytes_per_stream];
        for (payload, 0..) |*byte, offset| {
            byte.* = streamByte(offset, stream_index);
            checksum +%= byte.*;
        }
    }
    return .{ .storage = storage, .checksum = checksum };
}

fn runStreamClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    const payloads = try buildStreamPayloads(allocator, config);
    defer allocator.free(payloads.storage);
    const bytes_per_stream = std.math.cast(usize, config.bytes_per_stream) orelse
        return error.InvalidArgument;
    const logical_bytes = std.math.mul(
        u64,
        config.bytes_per_stream,
        config.streams,
    ) catch return error.InvalidArgument;
    const stream_ids = try allocator.alloc(u62, config.streams);
    defer allocator.free(stream_ids);

    for (0..config.rounds()) |round_index| {
        const round: u32 = @intCast(round_index);
        for (stream_ids, 0..) |*stream_id, stream_index| {
            stream_id.* = try session.openBidirectionalStreamWithTimeout(
                config.timeout(),
            );
            const prelude = streamPrelude(round, @intCast(stream_index));
            var committed: usize = 0;
            try session.sendStreamWithTimeout(
                stream_id.*,
                &prelude,
                false,
                &committed,
                config.timeout(),
            );
            if (committed != prelude.len) return error.InvalidBenchmarkStream;
        }
        try sendControl(session, control, .init(.round_ready, config, round));
        const go = try receiveControl(session, control, config, .go);
        if (go.round != round) return error.InvalidBenchmarkControl;
        const send_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = config.timeout(),
            .clock = .awake,
        });
        const started = nowNs(io);
        var offset: usize = 0;
        while (offset < bytes_per_stream) {
            const end = @min(
                bytes_per_stream,
                offset + @as(usize, config.chunk_bytes),
            );
            for (stream_ids, 0..) |stream_id, stream_index| {
                const payload = payloads.storage[stream_index * bytes_per_stream + offset ..][0 .. end - offset];
                var committed: usize = 0;
                try session.sendStreamWithDeadline(
                    stream_id,
                    payload,
                    false,
                    &committed,
                    send_deadline,
                );
                if (committed != payload.len) {
                    return error.InvalidBenchmarkStream;
                }
            }
            offset = end;
        }
        for (stream_ids) |stream_id| {
            try session.finishStreamWithDeadline(stream_id, send_deadline);
        }
        const done = try receiveControl(session, control, config, .round_done);
        const elapsed = nowNs(io) -| started;
        if (done.round != round or
            done.received_bytes != logical_bytes or
            done.checksum != payloads.checksum)
        {
            return error.InvalidBenchmarkResult;
        }
        try sendControl(session, control, .init(.round_ack, config, round));
        var reverse_fin: StreamMask = 0;
        while (@popCount(reverse_fin) < stream_ids.len) {
            var empty: [1]u8 = undefined;
            const event = try session.readStreamWithTimeout(
                &empty,
                config.timeout(),
            );
            if (event != .data) return error.InvalidBenchmarkStream;
            const data = event.data;
            if (data.direction != .bidirectional or
                !data.locally_initiated or data.bytes != 0 or !data.fin)
            {
                return error.InvalidBenchmarkStream;
            }
            var found: ?usize = null;
            for (stream_ids, 0..) |stream_id, index| {
                if (stream_id == data.stream_id) {
                    found = index;
                    break;
                }
            }
            const index = found orelse return error.InvalidBenchmarkStream;
            if (!markStream(&reverse_fin, index)) {
                return error.InvalidBenchmarkStream;
            }
        }
        if (round >= config.warmup) {
            const mib_s = if (elapsed == 0)
                0.0
            else
                @as(f64, @floatFromInt(logical_bytes)) *
                    @as(f64, @floatFromInt(std.time.ns_per_s)) /
                    @as(f64, @floatFromInt(elapsed)) /
                    (1024.0 * 1024.0);
            std.debug.print(
                "record=result implementation=netz protocol=webtransport " ++
                    "transport=h3 mode={s} direction={s} " ++
                    "role_pair=netz-client+wtransport-server " ++
                    "endpoint_role=client client_io=zio-std-io " ++
                    "server_io=wtransport-quinn-tokio connection_scope=persistent " ++
                    "benchmark_scope=same-application-shape warmup={d} " ++
                    "iterations={d} streams={d} bytes_per_stream={d} " ++
                    "payload_bytes={d} chunk_bytes={d} stream_window={d} " ++
                    "timeout_ms={d} netz_ack_every={d} " ++
                    "netz_max_ack_delay_us={d} sample={d} " ++
                    "elapsed_ns={d} logical_MiB_s={d:.3} " ++
                    "sent_bytes={d} received_bytes={d} " ++
                    "streams_finished={d} checksum={d} complete=true\n",
                .{
                    config.mode.name(),
                    config.mode.direction(),
                    config.warmup,
                    config.iterations,
                    config.streams,
                    config.bytes_per_stream,
                    config.payload_bytes,
                    config.chunk_bytes,
                    config.stream_window,
                    config.timeout_ms,
                    config.netz_ack_every,
                    config.netz_max_ack_delay_us,
                    round - config.warmup + 1,
                    elapsed,
                    mib_s,
                    logical_bytes,
                    done.received_bytes,
                    config.streams,
                    done.checksum,
                },
            );
        }
    }
    try sendControl(
        session,
        control,
        .init(.benchmark_done, config, config.rounds()),
    );
    const ack = try receiveControl(session, control, config, .benchmark_ack);
    if (ack.round != config.rounds()) return error.InvalidBenchmarkControl;
}

const ReceiveStream = struct {
    stream_id: u62,
    index: usize,
    prelude: [12]u8 = undefined,
    prelude_bytes: usize = 0,
    received: usize = 0,
    checksum: u64 = 0,
    finished: bool = false,
};

fn findStream(streams: []ReceiveStream, stream_id: u62) ?*ReceiveStream {
    for (streams) |*stream| {
        if (stream.stream_id == stream_id) return stream;
    }
    return null;
}

fn runStreamServer(
    allocator: std.mem.Allocator,
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    const streams = try allocator.alloc(ReceiveStream, config.streams);
    defer allocator.free(streams);
    const buffer = try allocator.alloc(u8, @max(12, config.chunk_bytes));
    defer allocator.free(buffer);
    const bytes_per_stream = std.math.cast(usize, config.bytes_per_stream) orelse
        return error.InvalidArgument;

    for (0..config.rounds()) |round_index| {
        const round: u32 = @intCast(round_index);
        for (streams) |*stream| stream.* = .{
            .stream_id = 0,
            .index = 0,
        };
        const ready = try receiveControl(session, control, config, .round_ready);
        if (ready.round != round) return error.InvalidBenchmarkControl;

        var discovered: usize = 0;
        var preludes_complete: usize = 0;
        var seen: StreamMask = 0;
        while (preludes_complete < streams.len) {
            const event = try session.readStreamWithTimeout(buffer, config.timeout());
            if (event != .data) return error.InvalidBenchmarkStream;
            const data = event.data;
            if (data.direction != .bidirectional or
                data.locally_initiated or data.fin)
            {
                return error.InvalidBenchmarkStream;
            }
            var stream = findStream(streams[0..discovered], data.stream_id);
            if (stream == null) {
                streams[discovered] = .{
                    .stream_id = data.stream_id,
                    .index = 0,
                };
                stream = &streams[discovered];
                discovered += 1;
            }
            const entry = stream.?;
            if (data.bytes > entry.prelude.len - entry.prelude_bytes) {
                return error.InvalidBenchmarkStream;
            }
            @memcpy(
                entry.prelude[entry.prelude_bytes..][0..data.bytes],
                buffer[0..data.bytes],
            );
            entry.prelude_bytes += data.bytes;
            if (entry.prelude_bytes == entry.prelude.len) {
                entry.index = try verifyStreamPrelude(&entry.prelude, config, round);
                if (!markStream(&seen, entry.index)) {
                    return error.InvalidBenchmarkStream;
                }
                preludes_complete += 1;
            }
        }
        for (streams) |stream| {
            if (stream.prelude_bytes != stream.prelude.len) {
                return error.InvalidBenchmarkStream;
            }
        }
        try sendControl(session, control, .init(.go, config, round));

        var finished: usize = 0;
        while (finished < streams.len) {
            const event = try session.readStreamWithTimeout(buffer, config.timeout());
            if (event != .data) return error.InvalidBenchmarkStream;
            const data = event.data;
            const stream = findStream(streams, data.stream_id) orelse
                return error.InvalidBenchmarkStream;
            if (stream.finished or data.direction != .bidirectional or
                data.locally_initiated or
                data.bytes > bytes_per_stream - stream.received)
            {
                return error.InvalidBenchmarkStream;
            }
            for (buffer[0..data.bytes], 0..) |byte, index| {
                if (byte != streamByte(stream.received + index, stream.index)) {
                    return error.InvalidBenchmarkStream;
                }
                stream.checksum +%= byte;
            }
            stream.received += data.bytes;
            if (data.fin) {
                if (stream.received != bytes_per_stream) {
                    return error.InvalidBenchmarkStream;
                }
                stream.finished = true;
                finished += 1;
            }
        }
        var done = Control.init(.round_done, config, round);
        for (streams) |stream| {
            done.received_bytes +%= stream.received;
            done.checksum +%= stream.checksum;
        }
        try sendControl(session, control, done);
        const ack = try receiveControl(session, control, config, .round_ack);
        if (ack.round != round) return error.InvalidBenchmarkControl;
        for (streams) |stream| {
            try session.finishStreamWithTimeout(
                stream.stream_id,
                config.timeout(),
            );
        }
    }
    const done = try receiveControl(session, control, config, .benchmark_done);
    if (done.round != config.rounds()) return error.InvalidBenchmarkControl;
    try sendControl(
        session,
        control,
        .init(.benchmark_ack, config, config.rounds()),
    );
}

fn fillPing(bytes: []u8, sequence: u64) void {
    @memcpy(bytes[0..6], ping_magic);
    std.mem.writeInt(u64, bytes[6..14], sequence, .big);
    for (bytes[ping_header_len..], 0..) |*byte, index| {
        byte.* = @truncate(sequence *% 17 +% index *% 131);
    }
}

fn verifyPing(bytes: []const u8, sequence: u64) !void {
    if (bytes.len < ping_header_len or
        !std.mem.eql(u8, bytes[0..6], ping_magic) or
        std.mem.readInt(u64, bytes[6..14], .big) != sequence)
    {
        return error.InvalidBenchmarkPing;
    }
    for (bytes[ping_header_len..], 0..) |byte, index| {
        if (byte != @as(u8, @truncate(sequence *% 17 +% index *% 131))) {
            return error.InvalidBenchmarkPing;
        }
    }
}

fn addChecksum(checksum: *u64, bytes: []const u8) void {
    for (bytes) |byte| checksum.* +%= byte;
}

fn runPingClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    try sendControl(session, control, .init(.round_ready, config, 0));
    const go = try receiveControl(session, control, config, .go);
    if (go.round != 0) return error.InvalidBenchmarkControl;
    const payload = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(payload);
    const samples = try allocator.alloc(u64, config.iterations);
    defer allocator.free(samples);
    var checksum: u64 = 0;
    for (0..config.rounds()) |sequence_index| {
        const sequence: u64 = @intCast(sequence_index);
        fillPing(payload, sequence);
        const started = nowNs(io);
        try session.sendDatagramWithTimeout(payload, config.timeout());
        var echo = try session.receiveDatagramWithTimeout(config.timeout());
        defer echo.deinit(allocator);
        const elapsed = nowNs(io) -| started;
        if (!std.mem.eql(u8, echo.datagram.payload, payload)) {
            return error.InvalidBenchmarkPing;
        }
        try verifyPing(echo.datagram.payload, sequence);
        addChecksum(&checksum, echo.datagram.payload);
        if (sequence >= config.warmup) {
            samples[sequence - config.warmup] = elapsed;
        }
    }
    var done = Control.init(.benchmark_done, config, config.rounds());
    done.received_bytes = @as(u64, config.rounds()) * config.payload_bytes;
    done.checksum = checksum;
    try sendControl(session, control, done);
    const ack = try receiveControl(session, control, config, .benchmark_ack);
    if (ack.round != config.rounds() or
        ack.received_bytes != done.received_bytes or
        ack.checksum != checksum)
    {
        return error.InvalidBenchmarkResult;
    }
    std.mem.sortUnstable(u64, samples, {}, std.sort.asc(u64));
    var sum: u128 = 0;
    for (samples) |sample| sum += sample;
    std.debug.print(
        "record=result implementation=netz protocol=webtransport " ++
            "transport=h3 mode={s} direction={s} " ++
            "role_pair=netz-client+wtransport-server " ++
            "endpoint_role=client client_io=zio-std-io " ++
            "server_io=wtransport-quinn-tokio connection_scope=persistent " ++
            "benchmark_scope=same-application-shape warmup={d} " ++
            "iterations={d} streams={d} bytes_per_stream={d} " ++
            "payload_bytes={d} chunk_bytes={d} stream_window={d} " ++
            "timeout_ms={d} netz_ack_every={d} " ++
            "netz_max_ack_delay_us={d} " ++
            "p50_ns={d} p90_ns={d} p99_ns={d} p999_ns={d} " ++
            "mean_ns={d} min_ns={d} max_ns={d} sent_bytes={d} " ++
            "received_bytes={d} checksum={d} " ++
            "complete=true\n",
        .{
            config.mode.name(),
            config.mode.direction(),
            config.warmup,
            config.iterations,
            config.streams,
            config.bytes_per_stream,
            config.payload_bytes,
            config.chunk_bytes,
            config.stream_window,
            config.timeout_ms,
            config.netz_ack_every,
            config.netz_max_ack_delay_us,
            percentile(samples, 50, 100),
            percentile(samples, 90, 100),
            percentile(samples, 99, 100),
            percentile(samples, 999, 1000),
            sum / samples.len,
            samples[0],
            samples[samples.len - 1],
            @as(u64, config.rounds()) * config.payload_bytes,
            @as(u64, config.rounds()) * config.payload_bytes,
            checksum,
        },
    );
}

fn streamChecksum(config: Config) u64 {
    var checksum: u64 = 0;
    for (0..config.streams) |stream_index| {
        for (0..config.bytes_per_stream) |offset| {
            checksum +%= streamByte(@intCast(offset), stream_index);
        }
    }
    return checksum;
}

fn pingChecksum(config: Config) u64 {
    var storage: [max_datagram_size]u8 = undefined;
    const payload = storage[0..config.payload_bytes];
    var checksum: u64 = 0;
    for (0..config.rounds()) |sequence| {
        fillPing(payload, sequence);
        addChecksum(&checksum, payload);
    }
    return checksum;
}

pub fn printServerComplete(
    role_pair: []const u8,
    config: Config,
) void {
    const bytes, const checksum = switch (config.mode) {
        .stream => .{
            @as(u64, config.iterations) * config.streams * config.bytes_per_stream,
            @as(u64, config.iterations) *% streamChecksum(config),
        },
        .datagram_pingpong => .{
            @as(u64, config.rounds()) * config.payload_bytes,
            pingChecksum(config),
        },
    };
    std.debug.print(
        "record=server-complete implementation=netz protocol=webtransport " ++
            "transport=h3 mode={s} direction={s} role_pair={s} " ++
            "endpoint_role=server client_io={s} server_io={s} " ++
            "connection_scope=persistent benchmark_scope=same-application-shape " ++
            "warmup={d} " ++
            "iterations={d} streams={d} bytes_per_stream={d} " ++
            "payload_bytes={d} chunk_bytes={d} stream_window={d} " ++
            "timeout_ms={d} netz_ack_every={d} " ++
            "netz_max_ack_delay_us={d} sent_bytes={d} " ++
            "received_bytes={d} checksum={d} server_complete=true\n",
        .{
            config.mode.name(),
            config.mode.direction(),
            role_pair,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.streams,
            config.bytes_per_stream,
            config.payload_bytes,
            config.chunk_bytes,
            config.stream_window,
            config.timeout_ms,
            config.netz_ack_every,
            config.netz_max_ack_delay_us,
            bytes,
            bytes,
            checksum,
        },
    );
}

pub fn printNetzMemory(
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    snapshot: anytype,
) void {
    std.debug.print(
        "record=memory implementation=netz protocol=webtransport transport=h3 " ++
            "mode={s} direction={s} role_pair={s} endpoint_role={s} " ++
            "client_io={s} server_io={s} connection_scope=persistent " ++
            "warmup={d} iterations={d} " ++
            "streams={d} bytes_per_stream={d} payload_bytes={d} " ++
            "chunk_bytes={d} stream_window={d} timeout_ms={d} " ++
            "netz_ack_every={d} netz_max_ack_delay_us={d} " ++
            "memory_scope=benchmark-run-after-argument-parse " ++
            "allocator_scope=netz-explicit alloc_count={d} free_count={d} " ++
            "resize_count={d} remap_count={d} total_allocated_bytes={d} " ++
            "live_bytes={d} peak_live_bytes={d} complete=true\n",
        .{
            config.mode.name(),
            config.mode.direction(),
            role_pair,
            endpoint_role,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.streams,
            config.bytes_per_stream,
            config.payload_bytes,
            config.chunk_bytes,
            config.stream_window,
            config.timeout_ms,
            config.netz_ack_every,
            config.netz_max_ack_delay_us,
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

pub fn printNetzTraffic(
    role_pair: []const u8,
    endpoint_role: []const u8,
    config: Config,
    traffic: netz.quic.runtime.SocketTrafficStats,
) void {
    std.debug.print(
        "record=traffic implementation=netz protocol=webtransport transport=h3 " ++
            "mode={s} direction={s} role_pair={s} endpoint_role={s} " ++
            "client_io={s} server_io={s} connection_scope=persistent " ++
            "warmup={d} iterations={d} " ++
            "streams={d} bytes_per_stream={d} payload_bytes={d} " ++
            "chunk_bytes={d} stream_window={d} timeout_ms={d} " ++
            "netz_ack_every={d} netz_max_ack_delay_us={d} " ++
            "traffic_scope=connection socket_boundary=userspace-udp-payload " ++
            "traffic_source=netz-socket-counters " ++
            "udp_sent_datagrams={d} udp_sent_payload_bytes={d} " ++
            "udp_received_datagrams={d} udp_received_payload_bytes={d} " ++
            "logical_udp_segments=true complete=true\n",
        .{
            config.mode.name(),
            config.mode.direction(),
            role_pair,
            endpoint_role,
            clientIo(role_pair),
            serverIo(role_pair),
            config.warmup,
            config.iterations,
            config.streams,
            config.bytes_per_stream,
            config.payload_bytes,
            config.chunk_bytes,
            config.stream_window,
            config.timeout_ms,
            config.netz_ack_every,
            config.netz_max_ack_delay_us,
            traffic.sent_datagrams,
            traffic.sent_bytes,
            traffic.received_datagrams,
            traffic.received_bytes,
        },
    );
}

pub fn clientIo(role_pair: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, role_pair, "netz-client"))
        "zio-std-io"
    else
        "wtransport-quinn-tokio";
}

pub fn serverIo(role_pair: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, role_pair, "netz-server"))
        "zio-std-io"
    else
        "wtransport-quinn-tokio";
}

fn runPingServer(
    allocator: std.mem.Allocator,
    session: anytype,
    control: ControlChannel,
    config: Config,
) !void {
    const ready = try receiveControl(session, control, config, .round_ready);
    if (ready.round != 0) return error.InvalidBenchmarkControl;
    try sendControl(session, control, .init(.go, config, 0));
    var checksum: u64 = 0;
    for (0..config.rounds()) |sequence_index| {
        const sequence: u64 = @intCast(sequence_index);
        var datagram = try session.receiveDatagramWithTimeout(config.timeout());
        defer datagram.deinit(allocator);
        if (datagram.datagram.payload.len != config.payload_bytes) {
            return error.InvalidBenchmarkPing;
        }
        try verifyPing(datagram.datagram.payload, sequence);
        addChecksum(&checksum, datagram.datagram.payload);
        try session.sendDatagramWithTimeout(
            datagram.datagram.payload,
            config.timeout(),
        );
    }
    const done = try receiveControl(session, control, config, .benchmark_done);
    const expected_bytes = @as(u64, config.rounds()) * config.payload_bytes;
    if (done.round != config.rounds() or
        done.received_bytes != expected_bytes or done.checksum != checksum)
    {
        return error.InvalidBenchmarkResult;
    }
    var ack = Control.init(.benchmark_ack, config, config.rounds());
    ack.received_bytes = expected_bytes;
    ack.checksum = checksum;
    try sendControl(session, control, ack);
}

fn percentile(
    sorted: []const u64,
    numerator: usize,
    denominator: usize,
) u64 {
    const rank = std.math.divCeil(
        usize,
        sorted.len * numerator,
        denominator,
    ) catch unreachable;
    return sorted[@min(sorted.len - 1, rank -| 1)];
}

fn markStream(mask: *StreamMask, index: usize) bool {
    std.debug.assert(index < max_parallel_streams);
    const bit = @as(StreamMask, 1) << @intCast(index);
    if (mask.* & bit != 0) return false;
    mask.* |= bit;
    return true;
}

test "WebTransport benchmark supports 256 parallel streams" {
    const config = try Config.parse(&.{
        "--mode=stream",
        "--warmup=1",
        "--iterations=1",
        "--streams=256",
    });
    try std.testing.expectEqual(@as(u16, 256), config.streams);
    try std.testing.expectError(error.InvalidArgument, Config.parse(&.{
        "--mode=stream",
        "--warmup=1",
        "--iterations=1",
        "--streams=257",
    }));

    var mask: StreamMask = 0;
    try std.testing.expect(markStream(&mask, 63));
    try std.testing.expect(markStream(&mask, 64));
    try std.testing.expect(markStream(&mask, 255));
    try std.testing.expect(!markStream(&mask, 64));
    try std.testing.expectEqual(@as(usize, 3), @popCount(mask));
}

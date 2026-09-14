const std = @import("std");
const netz = @import("netz");

pub const alpn = "netz-raw-stream-churn";
pub const max_streams: usize = 64;
pub const mtu: usize = 1280;
pub const max_frames: usize = 256;
pub const reset_code_base: u64 = 0x4000;
pub const stream_prelude_len: usize = 12;
pub const config_len: usize = 40;
pub const result_len: usize = 48;
pub const kick_len: usize = mtu * 2;

pub const config_ack = "NZQCACK1";
pub const ready = "NZQCRDY1";
pub const sibling_ready = "NZQCSIB1";
pub const reset_sent = "NZQCRST1";
pub const resets_observed = "NZQCOBS1";
pub const fin_sent = "NZQCFIN1";
pub const result_ack = "NZQCRAK1";
pub const close_ready = "NZQCCLS1";
pub const sibling_start = "raw-sibling-before-churn";
pub const sibling_end = "-after-churn";
pub const sibling_response = "raw-sibling-survived";
pub const kick = [_]u8{0xa7} ** kick_len;

pub const Sender = enum(u8) { client = 1, server = 2 };
pub const Fault = enum(u8) { loss = 1, reorder = 2 };

pub const Config = struct {
    sender: Sender,
    fault: Fault,
    streams: u16 = 32,
    bytes_per_stream: u64 = 16 * 1024,
    reset_after_bytes: u32 = 256,
    reset_every: u16 = 2,
    timeout_ms: u32 = 30_000,
    stream_window: u64 = 64 * 1024,

    pub fn parse(args: []const []const u8) !Config {
        var sender: ?Sender = null;
        var fault: ?Fault = null;
        var config: Config = undefined;
        config.streams = 32;
        config.bytes_per_stream = 16 * 1024;
        config.reset_after_bytes = 256;
        config.reset_every = 2;
        config.timeout_ms = 30_000;
        config.stream_window = 64 * 1024;
        for (args) |arg| {
            if (option(arg, "--sender=")) |value| {
                if (sender != null) return error.InvalidArgument;
                sender = std.meta.stringToEnum(Sender, value) orelse
                    return error.InvalidArgument;
            } else if (option(arg, "--fault=")) |value| {
                if (fault != null) return error.InvalidArgument;
                fault = std.meta.stringToEnum(Fault, value) orelse
                    return error.InvalidArgument;
            } else if (option(arg, "--streams=")) |value| {
                config.streams = try positive(u16, value);
            } else if (option(arg, "--bytes-per-stream=")) |value| {
                config.bytes_per_stream = try positive(u64, value);
            } else if (option(arg, "--reset-after-bytes=")) |value| {
                config.reset_after_bytes = try positive(u32, value);
            } else if (option(arg, "--reset-every=")) |value| {
                config.reset_every = try positive(u16, value);
            } else if (option(arg, "--timeout-ms=")) |value| {
                config.timeout_ms = try positive(u32, value);
            } else if (option(arg, "--stream-window=")) |value| {
                config.stream_window = try positive(u64, value);
            } else {
                return error.InvalidArgument;
            }
        }
        config.sender = sender orelse return error.InvalidArgument;
        config.fault = fault orelse return error.InvalidArgument;
        try config.validate();
        return config;
    }

    pub fn validate(self: Config) !void {
        if (self.streams != 32 and self.streams != 64) {
            return error.InvalidArgument;
        }
        if (self.bytes_per_stream < self.reset_after_bytes or
            self.bytes_per_stream > 1024 * 1024 * 1024 or
            self.reset_every == 0 or self.reset_every > self.streams or
            self.timeout_ms == 0 or self.timeout_ms > 10 * 60 * 1000 or
            self.stream_window < self.bytes_per_stream or
            self.stream_window > 1024 * 1024 * 1024)
        {
            return error.InvalidArgument;
        }
        _ = std.math.cast(usize, self.bytes_per_stream) orelse
            return error.InvalidArgument;
        _ = try self.connectionWindow();
    }

    pub fn timeout(self: Config) std.Io.Duration {
        return .fromMilliseconds(self.timeout_ms);
    }

    pub fn connectionWindow(self: Config) !u64 {
        return std.math.mul(
            u64,
            self.stream_window,
            @as(u64, self.streams) + 4,
        ) catch error.InvalidArgument;
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

    pub fn encode(self: Config) [config_len]u8 {
        var out = [_]u8{0} ** config_len;
        @memcpy(out[0..8], "NZQCHN1!");
        std.mem.writeInt(u16, out[8..10], self.streams, .big);
        std.mem.writeInt(u16, out[10..12], self.reset_every, .big);
        std.mem.writeInt(u64, out[12..20], self.bytes_per_stream, .big);
        std.mem.writeInt(u32, out[20..24], self.reset_after_bytes, .big);
        std.mem.writeInt(u32, out[24..28], self.timeout_ms, .big);
        out[28] = @intFromEnum(self.sender);
        out[29] = @intFromEnum(self.fault);
        std.mem.writeInt(u64, out[32..40], self.stream_window, .big);
        return out;
    }

    pub fn decode(bytes: *const [config_len]u8) !Config {
        if (!std.mem.eql(u8, bytes[0..8], "NZQCHN1!") or
            bytes[30] != 0 or bytes[31] != 0)
        {
            return error.InvalidChurnConfig;
        }
        const config: Config = .{
            .streams = std.mem.readInt(u16, bytes[8..10], .big),
            .reset_every = std.mem.readInt(u16, bytes[10..12], .big),
            .bytes_per_stream = std.mem.readInt(u64, bytes[12..20], .big),
            .reset_after_bytes = std.mem.readInt(u32, bytes[20..24], .big),
            .timeout_ms = std.mem.readInt(u32, bytes[24..28], .big),
            .sender = std.enums.fromInt(Sender, bytes[28]) orelse
                return error.InvalidChurnConfig,
            .fault = std.enums.fromInt(Fault, bytes[29]) orelse
                return error.InvalidChurnConfig,
            .stream_window = std.mem.readInt(u64, bytes[32..40], .big),
        };
        try config.validate();
        return config;
    }
};

fn option(arg: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, arg, prefix)) return null;
    return arg[prefix.len..];
}

fn positive(comptime T: type, value: []const u8) !T {
    const parsed = std.fmt.parseInt(T, value, 10) catch
        return error.InvalidArgument;
    if (parsed == 0) return error.InvalidArgument;
    return parsed;
}

pub const Result = struct {
    streams: u16,
    fins: u16,
    resets: u16,
    received_bytes: u64,
    checksum: u64,
    reset_mask: u64,
    reset_code_sum: u64,

    pub fn encode(self: Result) [result_len]u8 {
        var out = [_]u8{0} ** result_len;
        @memcpy(out[0..8], "NZQCRSL1");
        std.mem.writeInt(u16, out[8..10], self.streams, .big);
        std.mem.writeInt(u16, out[10..12], self.fins, .big);
        std.mem.writeInt(u16, out[12..14], self.resets, .big);
        std.mem.writeInt(u64, out[16..24], self.received_bytes, .big);
        std.mem.writeInt(u64, out[24..32], self.checksum, .big);
        std.mem.writeInt(u64, out[32..40], self.reset_mask, .big);
        std.mem.writeInt(u64, out[40..48], self.reset_code_sum, .big);
        return out;
    }

    pub fn decode(bytes: *const [result_len]u8) !Result {
        if (!std.mem.eql(u8, bytes[0..8], "NZQCRSL1") or
            bytes[14] != 0 or bytes[15] != 0)
        {
            return error.InvalidChurnResult;
        }
        return .{
            .streams = std.mem.readInt(u16, bytes[8..10], .big),
            .fins = std.mem.readInt(u16, bytes[10..12], .big),
            .resets = std.mem.readInt(u16, bytes[12..14], .big),
            .received_bytes = std.mem.readInt(u64, bytes[16..24], .big),
            .checksum = std.mem.readInt(u64, bytes[24..32], .big),
            .reset_mask = std.mem.readInt(u64, bytes[32..40], .big),
            .reset_code_sum = std.mem.readInt(u64, bytes[40..48], .big),
        };
    }
};

pub fn shouldReset(config: Config, stream_index: usize) bool {
    return (stream_index + 1) % config.reset_every == 0;
}

pub fn expectedResult(config: Config) Result {
    var result: Result = .{
        .streams = config.streams,
        .fins = 0,
        .resets = 0,
        .received_bytes = 0,
        .checksum = 0,
        .reset_mask = 0,
        .reset_code_sum = 0,
    };
    for (0..config.streams) |index| {
        const count: usize = if (shouldReset(config, index))
            config.reset_after_bytes
        else
            @intCast(config.bytes_per_stream);
        result.received_bytes += count;
        for (0..count) |offset| result.checksum +%= payloadByte(index, offset);
        if (shouldReset(config, index)) {
            result.resets += 1;
            result.reset_mask |= @as(u64, 1) << @intCast(index);
            result.reset_code_sum += reset_code_base + index;
        } else {
            result.fins += 1;
        }
    }
    return result;
}

pub fn streamPrelude(stream_index: usize) [stream_prelude_len]u8 {
    var out = [_]u8{0} ** stream_prelude_len;
    @memcpy(out[0..8], "NZQCSTRM");
    std.mem.writeInt(u16, out[8..10], @intCast(stream_index), .big);
    return out;
}

pub fn decodeStreamPrelude(bytes: *const [stream_prelude_len]u8, streams: u16) !usize {
    if (!std.mem.eql(u8, bytes[0..8], "NZQCSTRM") or
        bytes[10] != 0 or bytes[11] != 0)
    {
        return error.InvalidChurnPrelude;
    }
    const index = std.mem.readInt(u16, bytes[8..10], .big);
    if (index >= streams) return error.InvalidChurnPrelude;
    return index;
}

pub fn payloadByte(stream_index: usize, offset: usize) u8 {
    return @truncate(offset *% 131 +% stream_index *% 17);
}

pub fn fillPayload(bytes: []u8, stream_index: usize, offset: usize) void {
    for (bytes, 0..) |*byte, index| byte.* = payloadByte(stream_index, offset + index);
}

pub fn verifyPayload(bytes: []const u8, stream_index: usize, offset: usize) !u64 {
    var checksum: u64 = 0;
    for (bytes, 0..) |byte, index| {
        if (byte != payloadByte(stream_index, offset + index)) {
            return error.InvalidChurnPayload;
        }
        checksum +%= byte;
    }
    return checksum;
}

pub fn dataStreamId(sender: Sender, stream_index: usize) u62 {
    return @intCast(@as(u64, if (sender == .client) 2 else 3) + stream_index * 4);
}

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

pub fn sendExact(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    offset: *u64,
    bytes: []const u8,
    fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = @min(bytes.len - written, mtu - 128);
        const terminal = fin and written + count == bytes.len;
        try sendBytes(connection, stream_id, offset.*, bytes[written..][0..count], terminal, deadline);
        offset.* += count;
        written += count;
    }
    if (bytes.len == 0 and fin) try sendBytes(connection, stream_id, offset.*, &.{}, true, deadline);
}

pub fn receiveExact(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u62,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
    expect_fin: bool,
) !void {
    var received: usize = 0;
    var fin = false;
    var scratch: [1]u8 = undefined;
    while (received < out.len or expect_fin and !fin) {
        const target = if (received < out.len) out[received..] else scratch[0..];
        const event = try connection.receiveStreamIdWithDeadline(stream_id, target, deadline);
        switch (event) {
            .reset => return error.UnexpectedReset,
            .data => |data| {
                if (data.stream_id != stream_id or received + data.bytes > out.len) {
                    return error.InvalidChurnStream;
                }
                received += data.bytes;
                if (data.fin) fin = true;
                if (fin and received != out.len) return error.InvalidChurnStream;
            },
        }
        if (received == out.len and !expect_fin) break;
    }
    if (fin != expect_fin) return error.InvalidChurnStream;
}

pub fn prepareSenderStreams(
    allocator: std.mem.Allocator,
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    deadline: std.Io.Clock.Timestamp,
) ![]u64 {
    const ids = try allocator.alloc(u64, config.streams);
    errdefer allocator.free(ids);
    const prefix = try allocator.alloc(u8, config.reset_after_bytes);
    defer allocator.free(prefix);
    for (ids, 0..) |*stream_id, index| {
        stream_id.* = try connection.openUnidirectionalStreamWithDeadline(deadline);
        if (stream_id.* != dataStreamId(config.sender, index)) {
            return error.UnexpectedStreamId;
        }
        var offset: u64 = 0;
        const prelude = streamPrelude(index);
        try sendExact(connection, stream_id.*, &offset, &prelude, false, deadline);
        fillPayload(prefix, index, 0);
        try sendExact(connection, stream_id.*, &offset, prefix, false, deadline);
    }
    return ids;
}

pub fn receivePrefixes(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    prefix_checksums: *[max_streams]u64,
    deadline: std.Io.Clock.Timestamp,
) !void {
    const prefix_len: usize = @intCast(config.reset_after_bytes);
    const prefix = try connection.endpoint.allocator.alloc(u8, prefix_len);
    defer connection.endpoint.allocator.free(prefix);
    for (0..config.streams) |index| {
        const stream_id = dataStreamId(config.sender, index);
        var prelude: [stream_prelude_len]u8 = undefined;
        try receiveExact(connection, stream_id, &prelude, deadline, false);
        if (try decodeStreamPrelude(&prelude, config.streams) != index) {
            return error.InvalidChurnPrelude;
        }
        try receiveExact(connection, stream_id, prefix, deadline, false);
        prefix_checksums[index] = try verifyPayload(prefix, index, 0);
    }
}

pub fn sendResets(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    stream_ids: []const u64,
    deadline: std.Io.Clock.Timestamp,
) !void {
    for (stream_ids, 0..) |stream_id, index| {
        if (shouldReset(config, index)) {
            try connection.resetStreamWithDeadline(
                stream_id,
                reset_code_base + index,
                deadline,
            );
        }
    }
}

pub fn receiveResets(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    result: *Result,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var scratch: [1]u8 = undefined;
    for (0..config.streams) |index| {
        if (!shouldReset(config, index)) continue;
        const stream_id = dataStreamId(config.sender, index);
        const event = try connection.receiveStreamIdWithDeadline(
            stream_id,
            &scratch,
            deadline,
        );
        switch (event) {
            .data => return error.ExpectedReset,
            .reset => |reset| {
                if (reset.stream_id != stream_id or
                    reset.application_error_code != reset_code_base + index or
                    reset.final_size != stream_prelude_len + config.reset_after_bytes)
                {
                    return error.InvalidChurnReset;
                }
            },
        }
        result.resets += 1;
        result.reset_mask |= @as(u64, 1) << @intCast(index);
        result.reset_code_sum += reset_code_base + index;
    }
}

pub fn sendFinStreams(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    stream_ids: []const u64,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var payload: [mtu - 128]u8 = undefined;
    for (stream_ids, 0..) |stream_id, index| {
        if (shouldReset(config, index)) continue;
        var application_offset: usize = config.reset_after_bytes;
        var wire_offset: u64 = stream_prelude_len + config.reset_after_bytes;
        const total: usize = @intCast(config.bytes_per_stream);
        while (application_offset < total) {
            const count = @min(payload.len, total - application_offset);
            fillPayload(payload[0..count], index, application_offset);
            try sendBytes(
                connection,
                stream_id,
                wire_offset,
                payload[0..count],
                application_offset + count == total,
                deadline,
            );
            application_offset += count;
            wire_offset += count;
        }
        if (application_offset == config.reset_after_bytes and
            application_offset == total)
        {
            try sendBytes(connection, stream_id, wire_offset, &.{}, true, deadline);
        }
    }
}

pub fn receiveFins(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    prefix_checksums: *const [max_streams]u64,
    result: *Result,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var buffer: [mtu - 128]u8 = undefined;
    for (0..config.streams) |index| {
        if (shouldReset(config, index)) continue;
        const stream_id = dataStreamId(config.sender, index);
        var offset: usize = config.reset_after_bytes;
        var checksum = prefix_checksums[index];
        while (true) {
            const event = try connection.receiveStreamIdWithDeadline(
                stream_id,
                &buffer,
                deadline,
            );
            const data = switch (event) {
                .reset => return error.UnexpectedReset,
                .data => |value| value,
            };
            if (data.stream_id != stream_id or
                offset + data.bytes > config.bytes_per_stream)
            {
                return error.InvalidChurnStream;
            }
            checksum +%= try verifyPayload(buffer[0..data.bytes], index, offset);
            offset += data.bytes;
            if (data.fin) {
                if (offset != config.bytes_per_stream) {
                    return error.InvalidChurnStream;
                }
                break;
            }
        }
        result.fins += 1;
        result.received_bytes += offset;
        result.checksum +%= checksum;
    }
    for (0..config.streams) |index| {
        if (!shouldReset(config, index)) continue;
        result.received_bytes += config.reset_after_bytes;
        result.checksum +%= prefix_checksums[index];
    }
}

pub fn receiveConfig(
    connection: *netz.quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) !Config {
    var encoded: [config_len]u8 = undefined;
    try receiveExact(connection, 0, &encoded, deadline, false);
    return Config.decode(&encoded);
}

pub fn receiveResult(
    connection: *netz.quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) !Result {
    var encoded: [result_len]u8 = undefined;
    try receiveExact(connection, 0, &encoded, deadline, false);
    return Result.decode(&encoded);
}

pub fn validatePeerClose(connection: *netz.quic.one_rtt.Connection) !void {
    const close = connection.peerCloseInfo() orelse return error.MissingPeerClose;
    switch (close) {
        .application => |application| if (application.error_code != 0 or
            !std.mem.eql(u8, application.reason_phrase, "churn complete"))
        {
            return error.UnexpectedPeerClose;
        },
        .transport => return error.UnexpectedPeerClose,
    }
}

pub fn waitForPeerClose(
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
    try validatePeerClose(connection);
}

pub fn validateFaults(fault: Fault, reset: ProxyStats, fin: ProxyStats) !void {
    switch (fault) {
        .loss => if (reset.considered != 1 or fin.considered != 1 or
            reset.dropped != 1 or fin.dropped != 1 or
            reset.held != 0 or fin.held != 0 or
            reset.reordered != 0 or fin.reordered != 0) return error.FaultNotExercised,
        .reorder => if (reset.considered != 2 or fin.considered != 2 or
            reset.held != 1 or fin.held != 1 or
            reset.reordered != 1 or fin.reordered != 1 or
            reset.dropped != 0 or fin.dropped != 0) return error.FaultNotExercised,
    }
}

pub const ProxyStats = struct {
    considered: u64,
    dropped: u64,
    held: u64,
    reordered: u64,

    pub fn minus(self: ProxyStats, earlier: ProxyStats) !ProxyStats {
        if (self.considered < earlier.considered or self.dropped < earlier.dropped or
            self.held < earlier.held or self.reordered < earlier.reordered)
        {
            return error.InvalidProxyStats;
        }
        return .{
            .considered = self.considered - earlier.considered,
            .dropped = self.dropped - earlier.dropped,
            .held = self.held - earlier.held,
            .reordered = self.reordered - earlier.reordered,
        };
    }
};

pub const ProxyControl = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    deadline: std.Io.Clock.Timestamp,

    pub fn connect(
        io: std.Io,
        port: u16,
        deadline: std.Io.Clock.Timestamp,
    ) !ProxyControl {
        return .{
            .io = io,
            .stream = try connectTcpWithDeadline(
                io,
                .{ .ip4 = .loopback(port) },
                deadline,
            ),
            .deadline = deadline,
        };
    }

    pub fn deinit(self: *ProxyControl) void {
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn command(self: *ProxyControl, command_text: []const u8, expected: []const u8) !ProxyStats {
        var command_buffer: [32]u8 = undefined;
        const request = try std.fmt.bufPrint(&command_buffer, "{s}\n", .{command_text});
        try writeTcpAllWithDeadline(
            self.io,
            self.stream,
            request,
            self.deadline,
        );
        var response: [256]u8 = undefined;
        const line = try readTcpLineWithDeadline(
            self.io,
            self.stream,
            &response,
            self.deadline,
        );
        if (!std.mem.startsWith(u8, line, expected)) return error.InvalidProxyResponse;
        if (std.mem.eql(u8, expected, "armed")) return .{
            .considered = 0,
            .dropped = 0,
            .held = 0,
            .reordered = 0,
        };
        return parseProxyStats(line[expected.len..]);
    }
};

fn connectTcpWithDeadline(
    io: std.Io,
    address: std.Io.net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) !std.Io.net.Stream {
    const ConnectResult = std.Io.net.IpAddress.ConnectError!std.Io.net.Stream;
    const Wake = union(enum) {
        connected: ConnectResult,
        timeout: std.Io.Cancelable!void,
    };
    if (deadline.clock != .awake or
        deadline.durationFromNow(io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer while (select.cancel()) |wake| switch (wake) {
        .connected => |result| if (result) |stream| {
            stream.close(io);
        } else |_| {},
        .timeout => {},
    };
    select.async(.connected, connectTcp, .{ io, address });
    select.async(.timeout, waitUntil, .{ io, deadline });
    return switch (select.await() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
    }) {
        .connected => |result| result,
        .timeout => |result| {
            result catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Timeout;
        },
    };
}

fn connectTcp(
    io: std.Io,
    address: std.Io.net.IpAddress,
) std.Io.net.IpAddress.ConnectError!std.Io.net.Stream {
    return address.connect(io, .{ .mode = .stream });
}

fn waitUntil(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Cancelable!void {
    try deadline.wait(io);
}

fn writeTcpAll(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (count == 0) return error.SocketUnconnected;
        written += count;
    }
}

fn writeTcpAllWithDeadline(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    const Wake = union(enum) {
        write: ?anyerror,
        timeout: std.Io.Cancelable!void,
    };
    if (deadline.clock != .awake or
        deadline.durationFromNow(io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer select.cancelDiscard();
    select.async(.write, captureWriteTcpAll, .{ io, stream, bytes });
    select.async(.timeout, waitUntil, .{ io, deadline });
    switch (select.await() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
    }) {
        .write => |maybe_error| if (maybe_error) |err| return err,
        .timeout => |result| {
            result catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Timeout;
        },
    }
}

fn captureWriteTcpAll(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) ?anyerror {
    writeTcpAll(io, stream, bytes) catch |err| return err;
    return null;
}

fn readTcpLine(io: std.Io, stream: std.Io.net.Stream, out: []u8) ![]const u8 {
    var length: usize = 0;
    while (length < out.len) {
        var buffers = [_][]u8{out[length..][0..1]};
        const count = try io.vtable.netRead(io.userdata, stream.socket.handle, &buffers);
        if (count == 0) return error.ConnectionClosed;
        if (out[length] == '\n') return out[0..length];
        length += 1;
    }
    return error.InvalidProxyResponse;
}

fn readTcpLineWithDeadline(
    io: std.Io,
    stream: std.Io.net.Stream,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
) ![]const u8 {
    const ReadResult = anyerror!usize;
    const Wake = union(enum) {
        read: ReadResult,
        timeout: std.Io.Cancelable!void,
    };
    if (deadline.clock != .awake or
        deadline.durationFromNow(io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer select.cancelDiscard();
    select.async(.read, readTcpLineLength, .{ io, stream, out });
    select.async(.timeout, waitUntil, .{ io, deadline });
    return switch (select.await() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
    }) {
        .read => |result| out[0..try result],
        .timeout => |result| {
            result catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Timeout;
        },
    };
}

fn readTcpLineLength(
    io: std.Io,
    stream: std.Io.net.Stream,
    out: []u8,
) anyerror!usize {
    return (try readTcpLine(io, stream, out)).len;
}

fn parseProxyStats(text: []const u8) !ProxyStats {
    var result: ProxyStats = .{ .considered = 0, .dropped = 0, .held = 0, .reordered = 0 };
    var seen: u4 = 0;
    var tokens = std.mem.tokenizeScalar(u8, text, ' ');
    while (tokens.next()) |token| {
        if (token.len == 0) continue;
        const split = std.mem.indexOfScalar(u8, token, '=') orelse
            return error.InvalidProxyResponse;
        const key = token[0..split];
        const value = try std.fmt.parseInt(u64, token[split + 1 ..], 10);
        const bit: u4 = if (std.mem.eql(u8, key, "considered")) 1 else if (std.mem.eql(u8, key, "dropped")) 2 else if (std.mem.eql(u8, key, "held")) 4 else if (std.mem.eql(u8, key, "reordered")) 8 else return error.InvalidProxyResponse;
        if (seen & bit != 0) return error.InvalidProxyResponse;
        seen |= bit;
        if (bit == 1) result.considered = value else if (bit == 2) result.dropped = value else if (bit == 4) result.held = value else result.reordered = value;
    }
    if (seen != 15) return error.InvalidProxyResponse;
    return result;
}

test "raw QUIC churn expected shapes are stable" {
    const base: Config = .{ .sender = .client, .fault = .loss };
    try std.testing.expectEqual(Result{
        .streams = 32,
        .fins = 16,
        .resets = 16,
        .received_bytes = 266_240,
        .checksum = 33_945_600,
        .reset_mask = 0x0000_0000_aaaa_aaaa,
        .reset_code_sum = 262_400,
    }, expectedResult(base));
    var large = base;
    large.streams = 64;
    try std.testing.expectEqual(Result{
        .streams = 64,
        .fins = 32,
        .resets = 32,
        .received_bytes = 532_480,
        .checksum = 67_891_200,
        .reset_mask = 0xaaaa_aaaa_aaaa_aaaa,
        .reset_code_sum = 525_312,
    }, expectedResult(large));
}

test "raw QUIC churn config and result reject reserved bytes" {
    const config: Config = .{ .sender = .server, .fault = .reorder };
    var encoded_config = config.encode();
    try std.testing.expectEqual(config, try Config.decode(&encoded_config));
    encoded_config[31] = 1;
    try std.testing.expectError(error.InvalidChurnConfig, Config.decode(&encoded_config));
    const result = expectedResult(config);
    var encoded_result = result.encode();
    try std.testing.expectEqual(result, try Result.decode(&encoded_result));
    encoded_result[14] = 1;
    try std.testing.expectError(error.InvalidChurnResult, Result.decode(&encoded_result));
}

test "raw QUIC churn requires one fault in each phase" {
    try validateFaults(
        .loss,
        .{ .considered = 1, .dropped = 1, .held = 0, .reordered = 0 },
        .{ .considered = 1, .dropped = 1, .held = 0, .reordered = 0 },
    );
    try std.testing.expectError(
        error.FaultNotExercised,
        validateFaults(
            .loss,
            .{ .considered = 1, .dropped = 1, .held = 0, .reordered = 0 },
            .{ .considered = 2, .dropped = 2, .held = 0, .reordered = 0 },
        ),
    );
    try validateFaults(
        .reorder,
        .{ .considered = 2, .dropped = 0, .held = 1, .reordered = 1 },
        .{ .considered = 2, .dropped = 0, .held = 1, .reordered = 1 },
    );
}

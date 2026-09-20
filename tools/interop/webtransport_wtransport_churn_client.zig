const std = @import("std");
const netz = @import("netz");
const benchmark = @import("webtransport_wtransport_bench.zig");
const churn_protocol = @import("webtransport_churn_protocol.zig");

const ready = "NZWTRDY1";
const reset_sent = "NZWTRSNT";
const resets_observed = "NZWTRST1";
const fin_sent = "NZWTFSNT";
const ack = "NZWTACK1";
const stream_magic = "NZWTSTRM";
const stream_prelude_len: usize = 12;
const sibling_start = "sibling-before-churn";
const sibling_end = "-after-churn";
const sibling_response = "sibling-survived";

const Fault = enum(u8) {
    loss = 1,
    reorder = 2,
};

const Config = struct {
    port: u16,
    fault: Fault,
    streams: usize = 32,
    bytes_per_stream: usize = 16 * 1024,
    reset_after_bytes: usize = 256,
    reset_every: usize = 2,
    reset_code: u32 = 0x4000,
    timeout_ms: i64 = 30_000,
    loss_pct: u8 = 5,
    reorder_every: usize = 5,
};

const FaultState = struct {
    enabled: std.atomic.Value(bool) = .init(false),
    state: std.atomic.Value(u64) = .init(0x5754_4558_544c_4f53),
    considered: std.atomic.Value(usize) = .init(0),
    dropped: std.atomic.Value(usize) = .init(0),
    held: std.atomic.Value(usize) = .init(0),
    loss_pct: u8,
    reorder_every: usize,

    fn shouldDrop(context: *anyopaque, _: []const u8) bool {
        const self: *FaultState = @ptrCast(@alignCast(context));
        if (!self.enabled.load(.acquire) or self.loss_pct == 0) return false;
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
            if (next % 100 >= self.loss_pct) return false;
            _ = self.dropped.fetchAdd(1, .monotonic);
            return true;
        }
    }

    fn shouldHold(context: *anyopaque, _: []const u8) bool {
        const self: *FaultState = @ptrCast(@alignCast(context));
        if (!self.enabled.load(.acquire) or self.reorder_every == 0) return false;
        const index = self.considered.fetchAdd(1, .monotonic) + 1;
        if (index % self.reorder_every != 0) return false;
        _ = self.held.fetchAdd(1, .monotonic);
        return true;
    }
};

pub fn run(_: std.process.Init, args: []const []const u8) !void {
    const allocator = std.heap.c_allocator;
    const config = try parseArgs(args);
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var fault = FaultState{
        .loss_pct = if (config.fault == .loss) config.loss_pct else 0,
        .reorder_every = if (config.fault == .reorder) config.reorder_every else 0,
    };
    const original_dcid =
        [_]u8{ 0x6e, 0x7a, 0x77, 0x74, 0x62, 0x00, 0x00, 0x01 };
    const client_cid =
        [_]u8{ 0x6e, 0x7a, 0x77, 0x74, 0x62, 0x00, 0x00, 0x02 };
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/benchmark",
        .{config.port},
    );
    defer allocator.free(uri);
    const bench_config: benchmark.Config = .{
        .mode = .stream,
        .warmup = 1,
        .iterations = 1,
        .streams = @intCast(config.streams),
        .bytes_per_stream = @intCast(config.bytes_per_stream),
        .chunk_bytes = @intCast(@min(config.bytes_per_stream, 16 * 1024)),
        .stream_window = 64 * 1024,
        .timeout_ms = @intCast(config.timeout_ms),
        .netz_ack_every = 2,
        .netz_max_ack_delay_us = 25_000,
    };
    var client = try netz.webtransport.runtime.HandshakeClientSession.connectUri(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .headers = &.{.{
                .name = "user-agent",
                .value = "netz-benchmark",
            }},
            .limits = .{
                .http3 = .{ .quic = .{
                    .max_datagram_size = 1200,
                    .max_frames_per_datagram = 256,
                    .enable_gso_send = false,
                    .enable_gro_receive = false,
                    .send_interceptor = .{
                        .context = &fault,
                        .should_drop = if (config.fault == .loss)
                            FaultState.shouldDrop
                        else
                            null,
                        .should_hold = if (config.fault == .reorder)
                            FaultState.shouldHold
                        else
                            null,
                    },
                } },
                .max_session_streams = try bench_config.sessionStreams(),
            },
            .h3 = .{
                .connect_timeout = .fromMilliseconds(config.timeout_ms),
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .local_transport_parameters = try bench_config.transportParameters(),
                    .initial_one_rtt_config = try bench_config.oneRttConfig(),
                    .max_crypto_buffer = 64 * 1024,
                },
                .session = try bench_config.sessionOptions(),
            },
        },
    );
    defer client.deinit();
    const datagram_limit = try benchmark.validateDatagramLimit(&client, bench_config);
    try benchmark.printConfig(
        "netz",
        "netz-client+wtransport-server",
        "client",
        bench_config,
        datagram_limit,
    );

    const control = try benchmark.openControlClient(&client, bench_config);
    const control_id = control.stream_id;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromMilliseconds(config.timeout_ms),
        .clock = .awake,
    });

    const sibling_id = try client.openBidirectionalStreamWithDeadline(deadline);
    try sendExact(&client, sibling_id, sibling_start, false, deadline);

    const payloads = try allocator.alloc(u8, config.streams * config.bytes_per_stream);
    defer allocator.free(payloads);
    for (0..config.streams) |stream_index| {
        const payload = payloadFor(payloads, config, stream_index);
        for (payload, 0..) |*byte, offset| {
            byte.* = payloadByte(offset, stream_index);
        }
    }
    const stream_ids = try allocator.alloc(u62, config.streams);
    defer allocator.free(stream_ids);
    for (stream_ids, 0..) |*stream_id, stream_index| {
        stream_id.* = try client.openUnidirectionalStreamWithDeadline(deadline);
        const prelude = streamPrelude(stream_index);
        try sendExact(&client, stream_id.*, &prelude, false, deadline);
        try sendExact(
            &client,
            stream_id.*,
            payloadFor(payloads, config, stream_index)[0..config.reset_after_bytes],
            false,
            deadline,
        );
    }
    try receiveMarker(&client, control_id, ready, deadline);

    fault.enabled.store(true, .release);
    for (stream_ids, 0..) |stream_id, stream_index| {
        if (shouldReset(config, stream_index)) {
            try client.resetStreamWithDeadline(
                stream_id,
                config.reset_code + @as(u32, @intCast(stream_index)),
                deadline,
            );
        }
    }
    // Disable selection before the reliable marker. If the final RESET was
    // held, this next send emits the marker first and then flushes that held
    // packet, preserving real pair reordering without turning the tail into
    // accidental loss.
    fault.enabled.store(false, .release);
    try sendExact(&client, control_id, reset_sent, false, deadline);
    try receiveMarker(&client, control_id, resets_observed, deadline);

    fault.enabled.store(true, .release);
    const writes = try allocator.alloc(netz.webtransport.runtime.StreamWrite, config.streams);
    defer allocator.free(writes);
    const counts = try allocator.alloc(usize, config.streams);
    defer allocator.free(counts);
    const offsets = try allocator.alloc(usize, config.streams);
    defer allocator.free(offsets);
    var remaining: usize = 0;
    for (offsets, 0..) |*offset, stream_index| {
        if (shouldReset(config, stream_index)) {
            offset.* = config.bytes_per_stream;
        } else {
            offset.* = config.reset_after_bytes;
            remaining += 1;
        }
    }
    while (remaining != 0) {
        for (writes, stream_ids, offsets, 0..) |*write, stream_id, offset, stream_index| {
            write.* = .{
                .stream_id = stream_id,
                .data = payloadFor(payloads, config, stream_index)[offset..],
            };
        }
        const result = try client.writeStreamsWithDeadline(writes, counts, deadline);
        if (result.send_error) |err| return err;
        if (result.progressed == 0) return error.IncompleteTransfer;
        for (offsets, counts) |*offset, count| {
            if (offset.* == config.bytes_per_stream) continue;
            offset.* += count;
            if (offset.* == config.bytes_per_stream) remaining -= 1;
        }
    }
    for (stream_ids, 0..) |stream_id, stream_index| {
        if (!shouldReset(config, stream_index)) {
            try client.finishStreamWithDeadline(stream_id, deadline);
        }
    }
    // As above, the reliable control write releases any final held FIN packet
    // while no longer selecting a new tail packet for reordering.
    fault.enabled.store(false, .release);
    try sendExact(&client, control_id, fin_sent, false, deadline);

    var encoded_result: [churn_protocol.result_len]u8 = undefined;
    try receiveExact(&client, control_id, &encoded_result, deadline);
    const result = try decodeResult(&encoded_result);
    const expected = expectedResult(config, payloads);
    if (!std.meta.eql(result, expected)) return error.InvalidChurnResult;

    try sendExact(&client, sibling_id, sibling_end, true, deadline);
    var sibling_reply: [sibling_response.len]u8 = undefined;
    try receiveExactAndFin(&client, sibling_id, &sibling_reply, deadline);
    if (!std.mem.eql(u8, &sibling_reply, sibling_response)) {
        return error.InvalidSiblingResponse;
    }
    try sendExact(&client, control_id, ack, true, deadline);
    try receiveFin(&client, control_id, deadline);

    const close = try client.receivePeerConnectionCloseWithDeadline(deadline);
    switch (close) {
        .application => |application| {
            if (application.error_code != 0 or
                !std.mem.eql(u8, application.reason_phrase, "churn complete"))
            {
                return error.InvalidConnectionClose;
            }
        },
        .transport => return error.InvalidConnectionClose,
    }
    const considered = fault.considered.load(.monotonic);
    const dropped = fault.dropped.load(.monotonic);
    const held = fault.held.load(.monotonic);
    if (considered == 0 or
        (config.fault == .loss and dropped == 0) or
        (config.fault == .reorder and held == 0))
    {
        return error.FaultNotExercised;
    }
    std.debug.print(
        "netz client churn passed: fault={s} fault_scope=netz-client-outbound streams={d} fin={d} reset={d} bytes={d} checksum={d} reset_mask=0x{x:0>64} reset_code_sum={d} considered={d} dropped={d} held={d} sibling=true peer-close=true client_io=zio-std-io server_io=wtransport-quinn-tokio\n",
        .{
            @tagName(config.fault),
            config.streams,
            result.fins,
            result.resets,
            result.received_bytes,
            result.checksum,
            result.reset_mask,
            result.reset_code_sum,
            considered,
            dropped,
            held,
        },
    );
}

fn parseArgs(args: []const []const u8) !Config {
    if (args.len == 0) return error.InvalidArgument;
    var config: Config = .{
        .port = try std.fmt.parseInt(u16, args[0], 10),
        .fault = undefined,
    };
    var have_fault = false;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--fault=")) {
            config.fault = std.meta.stringToEnum(Fault, arg["--fault=".len..]) orelse
                return error.InvalidArgument;
            have_fault = true;
        } else if (std.mem.startsWith(u8, arg, "--streams=")) {
            config.streams = try parsePositive(usize, arg["--streams=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--bytes-per-stream=")) {
            config.bytes_per_stream = try parsePositive(usize, arg["--bytes-per-stream=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--timeout-ms=")) {
            config.timeout_ms = try parsePositive(i64, arg["--timeout-ms=".len..]);
        } else return error.InvalidArgument;
    }
    if (!have_fault or config.port == 0 or
        config.streams > churn_protocol.max_streams or
        config.reset_after_bytes > config.bytes_per_stream or
        config.reset_every > config.streams or config.timeout_ms <= 0)
    {
        return error.InvalidArgument;
    }
    return config;
}

fn parsePositive(comptime T: type, raw: []const u8) !T {
    const value = try std.fmt.parseInt(T, raw, 10);
    if (value <= 0) return error.InvalidArgument;
    return value;
}

fn streamPrelude(index: usize) [stream_prelude_len]u8 {
    var bytes = [_]u8{0} ** stream_prelude_len;
    @memcpy(bytes[0..8], stream_magic);
    std.mem.writeInt(u16, bytes[8..10], @intCast(index), .big);
    return bytes;
}

fn sendExact(session: anytype, stream_id: u62, bytes: []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) !void {
    var committed: usize = 0;
    try session.sendStreamWithDeadline(stream_id, bytes, fin, &committed, deadline);
    if (committed != bytes.len) return error.IncompleteTransfer;
}

fn receiveMarker(session: anytype, stream_id: u62, marker: []const u8, deadline: std.Io.Clock.Timestamp) !void {
    var bytes: [ready.len]u8 = undefined;
    if (marker.len != bytes.len) return error.InvalidArgument;
    try receiveExact(session, stream_id, &bytes, deadline);
    if (!std.mem.eql(u8, &bytes, marker)) return error.InvalidChurnControl;
}

fn receiveExact(session: anytype, stream_id: u62, out: []u8, deadline: std.Io.Clock.Timestamp) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const event = try session.readStreamIdWithDeadline(stream_id, out[offset..], deadline);
        if (event != .data or event.data.stream_id != stream_id or
            event.data.direction != .bidirectional or event.data.bytes == 0 or event.data.fin)
        {
            return error.InvalidChurnControl;
        }
        offset += event.data.bytes;
    }
}

fn receiveExactAndFin(
    session: anytype,
    stream_id: u62,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const event = try session.readStreamIdWithDeadline(
            stream_id,
            out[offset..],
            deadline,
        );
        if (event != .data or event.data.stream_id != stream_id or
            event.data.direction != .bidirectional or event.data.bytes == 0)
        {
            return error.InvalidChurnControl;
        }
        offset += event.data.bytes;
        if (event.data.fin) {
            if (offset != out.len) return error.InvalidChurnControl;
            return;
        }
    }
    try receiveFin(session, stream_id, deadline);
}

fn receiveFin(session: anytype, stream_id: u62, deadline: std.Io.Clock.Timestamp) !void {
    var empty: [1]u8 = undefined;
    const event = try session.readStreamIdWithDeadline(stream_id, &empty, deadline);
    if (event != .data or event.data.stream_id != stream_id or
        event.data.bytes != 0 or !event.data.fin)
    {
        return error.InvalidChurnControl;
    }
}

fn decodeResult(
    bytes: *const [churn_protocol.result_len]u8,
) !churn_protocol.Result {
    return churn_protocol.Result.decode(bytes);
}

fn expectedResult(
    config: Config,
    payloads: []const u8,
) churn_protocol.Result {
    var result: churn_protocol.Result = .{
        .streams = @intCast(config.streams),
        .fins = 0,
        .resets = 0,
        .received_bytes = 0,
        .checksum = 0,
        .reset_mask = 0,
        .reset_code_sum = 0,
    };
    for (0..config.streams) |index| {
        const reset = shouldReset(config, index);
        const count = if (reset) config.reset_after_bytes else config.bytes_per_stream;
        result.received_bytes += count;
        for (payloadForConst(payloads, config, index)[0..count]) |byte| {
            result.checksum +%= byte;
        }
        if (reset) {
            result.resets += 1;
            result.markReset(index);
            result.reset_code_sum += config.reset_code + @as(u32, @intCast(index));
        } else result.fins += 1;
    }
    return result;
}

fn shouldReset(config: Config, index: usize) bool {
    return (index + 1) % config.reset_every == 0;
}

fn payloadFor(storage: []u8, config: Config, index: usize) []u8 {
    return storage[index * config.bytes_per_stream ..][0..config.bytes_per_stream];
}

fn payloadForConst(storage: []const u8, config: Config, index: usize) []const u8 {
    return storage[index * config.bytes_per_stream ..][0..config.bytes_per_stream];
}

fn payloadByte(offset: usize, stream_index: usize) u8 {
    return @truncate(offset *% 131 +% stream_index *% 17);
}

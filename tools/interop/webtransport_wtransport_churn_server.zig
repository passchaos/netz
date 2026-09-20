const std = @import("std");
const netz = @import("netz");
const benchmark = @import("webtransport_wtransport_bench.zig");
const churn_protocol = @import("webtransport_churn_protocol.zig");

const ready = "NZWTRDY1";
const sibling_ready = "NZWTSIB1";
const reset_sent = "NZWTRSNT";
const resets_observed = "NZWTRST1";
const fin_sent = "NZWTFSNT";
const ack = "NZWTACK1";
const stream_magic = "NZWTSTRM";
const stream_prelude_len: usize = 12;
const sibling_start = "sibling-before-churn";
const sibling_end = "-after-churn";
const sibling_response = "sibling-survived";
const close_ready = "NZWTCLSR";
const reset_after_bytes: usize = 256;
const reset_every: usize = 2;
const reset_code_base: u32 = 0x4000;

pub fn run(_: std.process.Init, args: []const []const u8) !void {
    if (args.len < 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[0], 10);
    const fault = args[1];
    if (!std.mem.eql(u8, fault, "loss") and
        !std.mem.eql(u8, fault, "reorder"))
    {
        return error.InvalidArgument;
    }
    const config = try benchmark.Config.parse(args[2..]);
    if (config.mode != .stream or
        config.streams > churn_protocol.max_streams or
        config.bytes_per_stream < reset_after_bytes)
    {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const server_cid =
        [_]u8{ 0x6e, 0x7a, 0x77, 0x74, 0x73, 0x00, 0x00, 0x01 };
    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .http3 = .{ .quic = .{
                .max_datagram_size = benchmark.max_datagram_size,
                .max_frames_per_datagram = 256,
                .enable_gso_send = false,
                .enable_gro_receive = false,
            } },
            .max_session_streams = try config.sessionStreams(),
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = try config.transportParameters(),
                .initial_one_rtt_config = try config.oneRttConfig(),
                .max_crypto_buffer = 64 * 1024,
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
                },
            },
            .session = try config.sessionOptions(),
        },
    );
    defer server.deinit();
    std.debug.print("NETZ_CHURN_PORT={d}\n", .{server.address().ip4.port});

    var pending = try server.receiveSessionRequestWithTimeout(config.timeout());
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    if (!std.mem.eql(u8, pending.path(), "/benchmark") or
        !std.mem.eql(
            u8,
            pending.userAgent() orelse return error.UnexpectedHeader,
            "wtransport-benchmark",
        ))
    {
        return error.UnexpectedBenchmarkConnect;
    }
    var session = try pending.accept();
    pending_owned = false;
    defer session.deinit();
    const control = try benchmark.acceptControlServer(&session, config);
    var association_storage: [16]u8 = undefined;
    var association: std.ArrayList(u8) = .initBuffer(&association_storage);
    try netz.webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &association,
        allocator,
        session.sessionId(),
    );
    const association_prefix_len = association.items.len;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = config.timeout(),
        .clock = .awake,
    });
    const sibling = try receivePrefix(
        &session,
        sibling_start,
        .bidirectional,
        deadline,
    );
    try sendExact(&session, control.stream_id, sibling_ready, false, deadline);

    const streams = try allocator.alloc(ReceiveStream, config.streams);
    defer allocator.free(streams);
    for (streams) |*stream| stream.* = .{};
    var seen: churn_protocol.ResetMask = 0;
    var buffer: [16 * 1024]u8 = undefined;
    var discovered: usize = 0;
    var prefixes_complete: usize = 0;
    while (prefixes_complete < streams.len) {
        const event = try session.readStreamWithDeadline(&buffer, deadline);
        if (event != .data) return error.InvalidChurnStream;
        const data = event.data;
        if (data.direction != .unidirectional or data.locally_initiated or
            data.fin or data.bytes == 0)
        {
            return error.InvalidChurnStream;
        }
        var stream = findStream(streams[0..discovered], data.stream_id);
        if (stream == null) {
            if (discovered == streams.len) return error.InvalidChurnStream;
            streams[discovered].stream_id = data.stream_id;
            stream = &streams[discovered];
            discovered += 1;
        }
        const entry = stream.?;
        if (entry.prefix_complete) return error.InvalidChurnStream;
        var consumed: usize = 0;
        if (entry.prelude_bytes < stream_prelude_len) {
            const count = @min(
                data.bytes,
                stream_prelude_len - entry.prelude_bytes,
            );
            @memcpy(
                entry.prelude[entry.prelude_bytes..][0..count],
                buffer[0..count],
            );
            entry.prelude_bytes += count;
            consumed = count;
            if (entry.prelude_bytes == stream_prelude_len) {
                entry.index = try decodePrelude(&entry.prelude, config.streams);
                const bit = @as(churn_protocol.ResetMask, 1) <<
                    @intCast(entry.index);
                if (seen & bit != 0) return error.InvalidChurnStream;
                seen |= bit;
            }
        }
        if (entry.prelude_bytes == stream_prelude_len and consumed < data.bytes) {
            const payload = buffer[consumed..data.bytes];
            if (payload.len > reset_after_bytes - entry.received) {
                return error.InvalidChurnStream;
            }
            try verifyPayload(payload, entry.index, entry.received);
            entry.received += payload.len;
            addChecksum(&entry.checksum, payload);
        }
        if (entry.prelude_bytes == stream_prelude_len and
            entry.received == reset_after_bytes)
        {
            entry.prefix_complete = true;
            prefixes_complete += 1;
        }
    }
    try sendExact(&session, control.stream_id, ready, false, deadline);

    var reset_count: usize = 0;
    for (streams) |*entry| {
        if (!shouldReset(entry.index)) continue;
        while (true) {
            const event = try session.readStreamIdWithDeadline(
                entry.stream_id,
                &buffer,
                deadline,
            );
            switch (event) {
                .reset => |reset| {
                    if (entry.terminal or
                        reset.error_info.application_code !=
                            reset_code_base + @as(u32, @intCast(entry.index)) or
                        reset.final_size != association_prefix_len +
                            stream_prelude_len + entry.received)
                    {
                        return error.InvalidChurnStream;
                    }
                    entry.terminal = true;
                    reset_count += 1;
                    break;
                },
                .data, .stopped => return error.InvalidChurnStream,
            }
        }
    }
    try receiveMarker(&session, control.stream_id, reset_sent, deadline);
    try sendExact(&session, control.stream_id, resets_observed, false, deadline);

    var fin_count: usize = 0;
    for (streams) |*entry| {
        if (shouldReset(entry.index)) continue;
        while (!entry.terminal) {
            const event = try session.readStreamIdWithDeadline(
                entry.stream_id,
                &buffer,
                deadline,
            );
            switch (event) {
                .data => |data| {
                    if (data.direction != .unidirectional or
                        data.locally_initiated or
                        data.bytes > config.bytes_per_stream - entry.received)
                    {
                        return error.InvalidChurnStream;
                    }
                    try verifyPayload(
                        buffer[0..data.bytes],
                        entry.index,
                        entry.received,
                    );
                    entry.received += data.bytes;
                    addChecksum(&entry.checksum, buffer[0..data.bytes]);
                    if (data.fin) {
                        if (entry.received != config.bytes_per_stream) {
                            return error.InvalidChurnStream;
                        }
                        entry.terminal = true;
                        fin_count += 1;
                    }
                },
                .reset, .stopped => return error.InvalidChurnStream,
            }
        }
    }
    try receiveMarker(&session, control.stream_id, fin_sent, deadline);

    var result = churn_protocol.Result{ .streams = @intCast(streams.len) };
    for (streams) |stream| {
        result.received_bytes +%= stream.received;
        result.checksum +%= stream.checksum;
        if (shouldReset(stream.index)) {
            result.resets += 1;
            result.markReset(stream.index);
            result.reset_code_sum += reset_code_base + @as(u32, @intCast(stream.index));
        } else result.fins += 1;
    }
    const encoded = result.encode();
    try sendExact(&session, control.stream_id, &encoded, false, deadline);

    try receiveExactAndFin(&session, sibling, sibling_end, deadline);
    try sendExact(&session, sibling, sibling_response, true, deadline);
    try receiveMarker(&session, control.stream_id, ack, deadline);
    try session.finishStreamWithDeadline(control.stream_id, deadline);
    try receiveExactAndFin(&session, control.stream_id, close_ready, deadline);
    std.debug.print(
        "netz server churn passed: fault={s} fault_scope=wtransport-client-outbound streams={d} fin={d} reset={d} bytes={d} checksum={d} reset_mask=0x{x:0>64} reset_code_sum={d} sibling=true client_io=wtransport-quinn-tokio server_io=zio-std-io\n",
        .{ fault, result.streams, result.fins, result.resets, result.received_bytes, result.checksum, result.reset_mask, result.reset_code_sum },
    );
    try session.closeConnection(0, "churn complete");
}

const ReceiveStream = struct {
    stream_id: u62 = 0,
    index: usize = 0,
    prelude: [stream_prelude_len]u8 = undefined,
    prelude_bytes: usize = 0,
    received: usize = 0,
    checksum: u64 = 0,
    prefix_complete: bool = false,
    terminal: bool = false,
};

fn findStream(streams: []ReceiveStream, id: u62) ?*ReceiveStream {
    for (streams) |*stream| if (stream.stream_id == id) return stream;
    return null;
}

fn decodePrelude(bytes: *const [stream_prelude_len]u8, streams: usize) !usize {
    if (!std.mem.eql(u8, bytes[0..8], stream_magic) or
        bytes[10] != 0 or bytes[11] != 0)
    {
        return error.InvalidChurnStream;
    }
    const index = std.mem.readInt(u16, bytes[8..10], .big);
    if (index >= streams) return error.InvalidChurnStream;
    return index;
}

fn receivePrefix(session: anytype, expected: []const u8, direction: netz.webtransport.StreamDirection, deadline: std.Io.Clock.Timestamp) !u62 {
    var buffer: [sibling_start.len]u8 = undefined;
    var received: usize = 0;
    var stream_id: ?u62 = null;
    while (received < expected.len) {
        const event = if (stream_id) |id|
            try session.readStreamIdWithDeadline(id, buffer[received..], deadline)
        else
            try session.readStreamWithDeadline(buffer[received..], deadline);
        if (event != .data or event.data.direction != direction or
            event.data.locally_initiated or event.data.bytes == 0 or event.data.fin)
        {
            return error.InvalidChurnStream;
        }
        stream_id = stream_id orelse event.data.stream_id;
        if (event.data.stream_id != stream_id.? or
            !std.mem.eql(u8, buffer[received..][0..event.data.bytes], expected[received..][0..event.data.bytes]))
        {
            return error.InvalidChurnStream;
        }
        received += event.data.bytes;
    }
    return stream_id.?;
}

fn receiveExactAndFin(session: anytype, stream_id: u62, expected: []const u8, deadline: std.Io.Clock.Timestamp) !void {
    var buffer: [sibling_start.len]u8 = undefined;
    var received: usize = 0;
    while (received < expected.len) {
        const event = try session.readStreamIdWithDeadline(stream_id, buffer[received..], deadline);
        if (event != .data or event.data.stream_id != stream_id or event.data.bytes == 0 or
            !std.mem.eql(u8, buffer[received..][0..event.data.bytes], expected[received..][0..event.data.bytes]))
        {
            return error.InvalidChurnStream;
        }
        received += event.data.bytes;
        if (event.data.fin) {
            if (received != expected.len) return error.InvalidChurnStream;
            return;
        }
    }
    try receiveFin(session, stream_id, deadline);
}

fn receiveMarker(session: anytype, stream_id: u62, expected: []const u8, deadline: std.Io.Clock.Timestamp) !void {
    var buffer: [ready.len]u8 = undefined;
    if (expected.len != buffer.len) return error.InvalidArgument;
    var received: usize = 0;
    while (received < expected.len) {
        const event = try session.readStreamIdWithDeadline(stream_id, buffer[received..], deadline);
        if (event != .data or event.data.stream_id != stream_id or
            event.data.bytes == 0 or event.data.fin)
        {
            return error.InvalidChurnControl;
        }
        received += event.data.bytes;
    }
    if (!std.mem.eql(u8, &buffer, expected)) return error.InvalidChurnControl;
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

fn sendExact(session: anytype, stream_id: u62, bytes: []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) !void {
    var committed: usize = 0;
    try session.sendStreamWithDeadline(stream_id, bytes, fin, &committed, deadline);
    if (committed != bytes.len) return error.IncompleteTransfer;
}

fn shouldReset(index: usize) bool {
    return (index + 1) % reset_every == 0;
}

fn verifyPayload(bytes: []const u8, stream_index: usize, offset: usize) !void {
    for (bytes, 0..) |byte, index| {
        if (byte != @as(u8, @truncate((offset + index) *% 131 +% stream_index *% 17))) {
            return error.InvalidChurnStream;
        }
    }
}

fn addChecksum(checksum: *u64, bytes: []const u8) void {
    for (bytes) |byte| checksum.* +%= byte;
}

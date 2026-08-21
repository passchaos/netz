//! One-shot QUIC v1 server for process-boundary interop with quic-go.

const std = @import("std");
const netz = @import("netz");

const payloads = [_][]const u8{ "hello", "world" };
const flow_control_payload = [_]u8{'f'} ** 12_288;
const Mode = enum { echo, reset, stop, flow };

fn receiveExpectedStream(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
    stream_id: u64,
    expected: []const u8,
) !void {
    var received: usize = 0;
    while (received < expected.len or
        !connection.receivedStreamComplete(stream_id))
    {
        if (connection.availableReceivedStream(stream_id)) |available| {
            if (available.len != 0) {
                const end = std.math.add(
                    usize,
                    received,
                    available.len,
                ) catch return error.UnexpectedRequest;
                if (end > expected.len or !std.mem.eql(
                    u8,
                    available,
                    expected[received..end],
                )) return error.UnexpectedRequest;
                try connection.releaseReceivedCapacity(
                    stream_id,
                    available.len,
                );
                received = end;
            }
        }
        if (received == expected.len and
            connection.receivedStreamComplete(stream_id))
        {
            break;
        }
        var packet = try connection.receivePacketServicingTimers();
        defer packet.deinit(allocator);
    }
}

fn sendEcho(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    payload: []const u8,
) !void {
    try connection.send(&.{.{ .stream = .{
        .stream_id = stream_id,
        .offset = 0,
        .data = payload,
        .fin = true,
    } }});
}

fn sendStreamFully(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
    stream_id: u64,
    payload: []const u8,
) !void {
    // A STREAM frame must fit the peer's negotiated UDP payload limit. Keep
    // this raw-QUIC fixture deliberately below the IPv6-safe 1200-byte packet
    // size, and make flow-control/congestion progress before retrying a chunk.
    const max_chunk_len: usize = 1024;
    var offset: usize = 0;
    while (offset < payload.len) {
        const end = @min(offset + max_chunk_len, payload.len);
        connection.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .data = payload[offset..end],
            .fin = end == payload.len,
        } }}) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receivePacket(connection, allocator);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailability();
                continue;
            },
            else => return err,
        };
        offset = end;
    }
}

fn receivePacket(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
) !void {
    var packet = try connection.receivePacketServicingTimers();
    defer packet.deinit(allocator);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const mode: Mode = if (args.len == 3)
        std.meta.stringToEnum(Mode, args[2]) orelse return error.InvalidArgument
    else
        .echo;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();

    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .max_datagram_size = 8192 },
    );
    defer endpoint.deinit();
    std.debug.print(
        "netz QUIC interop server listening on {f}\n",
        .{endpoint.address()},
    );

    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var local_transport_parameters =
        netz.quic.practical_transport_parameters;
    if (mode == .flow) {
        local_transport_parameters.initial_max_data = 8 * 1024;
        local_transport_parameters.initial_max_stream_data_bidi_remote =
            2 * 1024;
    }
    var established = try netz.quic.handshake.accept(&endpoint, .{
        .local_connection_id = &server_cid,
        .alpn_protocol = "hq-interop",
        .local_transport_parameters = local_transport_parameters,
        .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        },
        .max_crypto_buffer = 64 * 1024,
        .handshake_recovery = .{
            .initial_pto_ms = 250,
            .max_pto_ms = 2000,
            .max_retries = 4,
            .max_duration_ms = 10_000,
        },
        .initial_one_rtt_config = if (mode == .flow) .{
            // Match the advertised limits so consuming data advances credit
            // in bounded 8 KiB connection / 2 KiB stream windows rather than
            // immediately switching to the normal 64 KiB runtime windows.
            .max_datagram_size = 8192,
            .receive_window = 8 * 1024,
            .max_receive_window = 8 * 1024,
            .stream_receive_window = 2 * 1024,
            .max_stream_receive_window = 2 * 1024,
        } else .{
            .max_datagram_size = 8192,
        },
    });
    defer established.deinit();
    if (!std.mem.eql(u8, established.alpn, "hq-interop")) {
        return error.InvalidAlpn;
    }

    switch (mode) {
        .echo => {
            for (payloads, 0..) |expected, index| {
                const stream_id: u64 = @intCast(index * 4);
                try receiveExpectedStream(
                    &established.connection,
                    allocator,
                    stream_id,
                    expected,
                );
                try sendEcho(
                    &established.connection,
                    stream_id,
                    expected,
                );
            }
        },
        .reset => {
            while (established.connection.streamResetReceived(0) == null) {
                try receivePacket(&established.connection, allocator);
            }
            const reset = established.connection.streamResetReceived(0).?;
            if (reset.application_error_code != 41) {
                return error.UnexpectedResetError;
            }
            try receiveExpectedStream(
                &established.connection,
                allocator,
                4,
                payloads[1],
            );
            try sendEcho(&established.connection, 4, payloads[1]);
        },
        .stop => {
            // quic-go can append probe bytes immediately after "stop" while
            // waiting for STOP_SENDING. Validate only the stable prefix before
            // cancelling its send side; RESET_STREAM supplies the final size.
            while (true) {
                if (established.connection.availableReceivedStream(0)) |available| {
                    const prefix_len = @min(available.len, "stop".len);
                    if (!std.mem.eql(u8, available[0..prefix_len], "stop"[0..prefix_len])) {
                        return error.UnexpectedRequest;
                    }
                    if (available.len >= "stop".len) {
                        try established.connection.releaseReceivedCapacity(
                            0,
                            "stop".len,
                        );
                        break;
                    }
                }
                try receivePacket(&established.connection, allocator);
            }
            try established.connection.sendStopSending(0, 42);
            while (established.connection.streamResetReceived(0) == null) {
                try receivePacket(&established.connection, allocator);
            }
            const reset = established.connection.streamResetReceived(0).?;
            if (reset.application_error_code != 42 or reset.final_size < 4) {
                return error.UnexpectedResetError;
            }
            try receiveExpectedStream(
                &established.connection,
                allocator,
                4,
                payloads[1],
            );
            try sendEcho(&established.connection, 4, payloads[1]);
        },
        .flow => {
            try receiveExpectedStream(
                &established.connection,
                allocator,
                0,
                &flow_control_payload,
            );
            try sendStreamFully(
                &established.connection,
                allocator,
                0,
                &flow_control_payload,
            );
        },
    }

    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    switch (mode) {
        .echo => std.debug.print(
            "netz QUIC server interoperated with quic-go: alpn=hq-interop streams=2 bytes=10\n",
            .{},
        ),
        .reset => std.debug.print(
            "netz QUIC reset server interoperated with quic-go: alpn=hq-interop reset_error=41 echo_stream=4 echo_bytes=5\n",
            .{},
        ),
        .stop => std.debug.print(
            "netz QUIC stop-sending server interoperated with quic-go: alpn=hq-interop stop_error=42 reset_error=42 echo_stream=4 echo_bytes=5\n",
            .{},
        ),
        .flow => std.debug.print(
            "netz QUIC flow-control server interoperated with quic-go: alpn=hq-interop initial_max_data=8192 initial_max_stream_data=2048 stream_bytes=12288 echo_bytes=12288\n",
            .{},
        ),
    }
}

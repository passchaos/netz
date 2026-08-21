//! One-shot QUIC v1 server for process-boundary interop with quic-go.

const std = @import("std");
const netz = @import("netz");

const payloads = [_][]const u8{ "hello", "world" };
const flow_control_payload = [_]u8{'f'} ** 12_288;
const stream_limit_payloads = [_][]const u8{
    "hello",
    "world",
    "again",
    "more",
};
const client_uni_payload = "uni";
const server_uni_payload = "uni-reply";
const migration_initial_payload = "hello";
const nat_rebinding_payload = "rebound";
const migration_payloads = [_][]const u8{ "migrated", "migrated-again" };
const migration_addresses = [_][4]u8{
    .{ 127, 0, 0, 2 },
    .{ 127, 0, 0, 3 },
};
const Mode = enum {
    echo,
    reset,
    stop,
    flow,
    stream_limit,
    uni,
    application_pto,
    initial_pto,
    peer_close,
    migration,
    nat_rebinding,
};

fn receiveExpectedStream(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
    stream_id: u64,
    expected: []const u8,
) !void {
    return receiveExpectedStreamWithOptions(
        connection,
        allocator,
        stream_id,
        expected,
        .{},
    );
}

const ReceiveExpectedStreamOptions = struct {
    service_path_responses: bool = false,
};

fn receiveExpectedStreamWithOptions(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
    stream_id: u64,
    expected: []const u8,
    options: ReceiveExpectedStreamOptions,
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
        if (options.service_path_responses) {
            // quic-go probes its candidate socket before switching application
            // traffic. PATH_RESPONSE must return to that probing source rather
            // than the connection's still-selected handshake path.
            _ = try connection.sendPendingPathResponses();
        }
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

fn expectIpv4Address(
    address: std.Io.net.IpAddress,
    expected: [4]u8,
) !u16 {
    return switch (address) {
        .ip4 => |ip4| if (std.mem.eql(u8, &ip4.bytes, &expected))
            ip4.port
        else
            error.UnexpectedPeerAddress,
        .ip6 => error.UnexpectedPeerAddress,
    };
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
    switch (mode) {
        .flow => {
            local_transport_parameters.initial_max_data = 8 * 1024;
            local_transport_parameters.initial_max_stream_data_bidi_remote =
                2 * 1024;
        },
        .stream_limit => {
            local_transport_parameters.initial_max_streams_bidi = 1;
        },
        else => {},
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

    if (mode == .migration) {
        const original_peer = established.connection.peerAddress();
        const original_port = try expectIpv4Address(
            original_peer,
            .{ 127, 0, 0, 1 },
        );
        // quic-go rotates away from sequence zero after the handshake. Keep
        // one active CID plus one unused CID for each candidate path.
        var migration_cids: [3][8]u8 = undefined;
        var reset_tokens: [3][16]u8 = undefined;
        for (&migration_cids, &reset_tokens) |*migration_cid, *reset_token| {
            try std.Io.randomSecure(io, migration_cid);
            try std.Io.randomSecure(io, reset_token);
            try established.connection.sendNewConnectionId(
                migration_cid,
                reset_token.*,
            );
        }

        // The echo synchronizes after all NEW_CONNECTION_ID frames are sent.
        try receiveExpectedStream(
            &established.connection,
            allocator,
            0,
            migration_initial_payload,
        );
        try sendEcho(
            &established.connection,
            0,
            migration_initial_payload,
        );
        var previous_port = original_port;
        for (migration_payloads, migration_addresses, 0..) |
            payload,
            expected_address,
            index,
        | {
            const stream_id: u64 = @intCast((index + 1) * 4);
            try receiveExpectedStreamWithOptions(
                &established.connection,
                allocator,
                stream_id,
                payload,
                .{ .service_path_responses = true },
            );

            const migrated_port = try expectIpv4Address(
                established.connection.peerAddress(),
                expected_address,
            );
            if (migrated_port == original_port or
                migrated_port == previous_port or
                established.connection.peerAddressValidated())
            {
                return error.MigrationNotObserved;
            }

            // Receiving non-probing traffic selected the new path but did not
            // validate it. Challenge it in the reverse direction and require
            // the authenticated response before returning application data.
            try established.connection.sendPendingPathChallenge();
            while (!established.connection.peerAddressValidated()) {
                try receivePacket(&established.connection, allocator);
            }
            try sendEcho(
                &established.connection,
                stream_id,
                payload,
            );
            previous_port = migrated_port;
        }
        try std.Io.sleep(io, .fromMilliseconds(250), .awake);
        std.debug.print(
            "netz QUIC migration server interoperated with quic-go: alpn=hq-interop path_sequence=127.0.0.1,127.0.0.2,127.0.0.3 source_ports_distinct=true paths_validated=2 echo_streams=4,8 echo_bytes=22\n",
            .{},
        );
        return;
    }

    if (mode == .nat_rebinding) {
        const original_peer = established.connection.peerAddress();
        const original_port = try expectIpv4Address(
            original_peer,
            .{ 127, 0, 0, 1 },
        );
        try receiveExpectedStream(
            &established.connection,
            allocator,
            0,
            migration_initial_payload,
        );
        try sendEcho(
            &established.connection,
            0,
            migration_initial_payload,
        );
        try receiveExpectedStream(
            &established.connection,
            allocator,
            4,
            nat_rebinding_payload,
        );
        const rebound_port = try expectIpv4Address(
            established.connection.peerAddress(),
            .{ 127, 0, 0, 1 },
        );
        if (rebound_port == original_port or
            !established.connection.peerAddressValidated())
        {
            return error.NatRebindingNotObserved;
        }
        // NAT rebinding keeps congestion/validation state and does not queue
        // an active-migration PATH_CHALLENGE. The four dropped client packets
        // force quic-go's PTO retransmission to reveal the new source tuple.
        if (established.connection.pendingPathValidationCount() != 0) {
            return error.UnexpectedPathValidation;
        }
        try sendEcho(
            &established.connection,
            4,
            nat_rebinding_payload,
        );
        try std.Io.sleep(io, .fromMilliseconds(250), .awake);
        std.debug.print(
            "netz QUIC NAT rebinding server interoperated with quic-go: alpn=hq-interop same_ip=true source_port_changed=true dropped_datagrams=4 path_validation_queued=false echo_stream=4 echo_bytes=7\n",
            .{},
        );
        return;
    }

    switch (mode) {
        .echo, .application_pto, .initial_pto, .peer_close => {
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
        .stream_limit => {
            for (stream_limit_payloads, 0..) |expected, index| {
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
                if (!try established.connection
                    .releaseCompletedPeerStream(stream_id))
                {
                    return error.StreamCreditNotReleased;
                }
            }
        },
        .uni => {
            try receiveExpectedStream(
                &established.connection,
                allocator,
                2,
                client_uni_payload,
            );
            const response_stream_id =
                try established.connection.openUnidirectionalStream();
            if (response_stream_id != 3) {
                return error.UnexpectedStreamId;
            }
            try sendEcho(
                &established.connection,
                response_stream_id,
                server_uni_payload,
            );
        },
        .migration => unreachable,
        .nat_rebinding => unreachable,
    }

    if (mode == .peer_close) {
        // Give the peer time to consume both FIN-terminated echoes. The close
        // is intentionally delayed just like the ordinary fixture close so
        // the application-close assertion cannot truncate stream validation.
        try std.Io.sleep(io, .fromMilliseconds(250), .awake);
        try established.connection.closeApplication(58, "netz interop complete");
        std.debug.print(
            "netz QUIC close server interoperated with quic-go: alpn=hq-interop peer_close=58\n",
            .{},
        );
        return;
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
        .stream_limit => std.debug.print(
            "netz QUIC stream-limit server interoperated with quic-go: alpn=hq-interop initial_limit=1 released_stream=12 streams=4 echo_bytes=19\n",
            .{},
        ),
        .uni => std.debug.print(
            "netz QUIC unidirectional server interoperated with quic-go: alpn=hq-interop client_stream=2 server_stream=3 request_bytes=3 reply_bytes=9\n",
            .{},
        ),
        .application_pto => std.debug.print(
            "netz QUIC application PTO server interoperated with quic-go: alpn=hq-interop dropped_datagrams=4 streams=2 bytes=10\n",
            .{},
        ),
        .initial_pto => std.debug.print(
            "netz QUIC Initial PTO server interoperated with quic-go: alpn=hq-interop dropped_datagrams=4 streams=2 bytes=10\n",
            .{},
        ),
        .peer_close => unreachable,
        .migration => unreachable,
        .nat_rebinding => unreachable,
    }
}

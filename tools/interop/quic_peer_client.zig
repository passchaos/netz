//! Certificate-verified QUIC stream interop client for external peer fixtures.
//!
//! The primary matrix lives in the audited local quicz checkout and uses
//! quic-go; the basic stream/close path is also shared with s2n-quic.

const std = @import("std");
const netz = @import("netz");

const payloads = [_][]const u8{ "hello", "world" };
const key_update_payloads = [_][]const u8{
    "before-update",
    "phase-one",
    "phase-two",
};
const Scenario = enum { echo, reset, stop, flow };
const flow_control_payload = [_]u8{'f'} ** 12_288;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or args.len > 6) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }
    var expect_retry = false;
    var expect_key_update = false;
    var peer: enum { quic_go, s2n_quic } = .quic_go;
    var scenario: Scenario = .echo;
    var scenario_set = false;
    var version: netz.quic.Version = .version_1;
    for (args[3..]) |arg| {
        if (std.mem.eql(u8, arg, "--expect-retry")) {
            if (expect_retry) return error.InvalidArgument;
            expect_retry = true;
        } else if (std.mem.eql(u8, arg, "--expect-key-update")) {
            if (expect_key_update) return error.InvalidArgument;
            expect_key_update = true;
        } else if (std.mem.eql(u8, arg, "--version=2")) {
            if (version == .version_2) return error.InvalidArgument;
            version = .version_2;
        } else if (std.mem.eql(u8, arg, "--peer=s2n-quic")) {
            if (peer != .quic_go) return error.InvalidArgument;
            peer = .s2n_quic;
        } else if (std.mem.startsWith(u8, arg, "--scenario=")) {
            if (scenario_set) return error.InvalidArgument;
            scenario_set = true;
            scenario = std.meta.stringToEnum(
                Scenario,
                arg["--scenario=".len..],
            ) orelse return error.InvalidArgument;
        } else {
            return error.InvalidArgument;
        }
    }
    if (expect_retry and expect_key_update) return error.InvalidArgument;
    if (peer == .s2n_quic and
        (expect_retry or expect_key_update or version != .version_1))
    {
        return error.InvalidArgument;
    }
    if (peer == .quic_go and scenario != .echo) {
        return error.InvalidArgument;
    }
    const key_exchange_groups: []const netz.quic.tls_client_hello.NamedGroup =
        if (peer == .s2n_quic)
            &.{.x25519}
        else
            &.{ .x25519_mlkem768, .x25519, .secp256r1 };

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[2],
    );
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };

    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 8192 },
    );
    defer endpoint.deinit();
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);

    var established = try netz.quic.handshake.connect(
        &endpoint,
        .{ .ip4 = .loopback(port) },
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .version = version,
            .available_versions = if (version == .version_2)
                &.{.version_2}
            else
                &.{ .version_1, .version_2 },
            .server_name = "localhost",
            .alpn_protocols = &.{"hq-interop"},
            // s2n-quic 1.85 rejects netz's fragmented post-quantum
            // ClientHello before all CRYPTO ranges arrive. This peer-specific
            // X25519 profile keeps the ClientHello in one Initial datagram and
            // still exercises the standard RFC 9001 handshake path.
            .key_exchange_groups = key_exchange_groups,
            .server_auth = verifier.clientVerifier(),
            .max_crypto_buffer = 64 * 1024,
            .handshake_recovery = .{
                .initial_pto_ms = 250,
                .max_pto_ms = 2000,
                .max_retries = 4,
                .max_duration_ms = 10_000,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 8192,
            },
        },
    );
    defer established.deinit();
    if (!std.mem.eql(u8, established.alpn, "hq-interop")) {
        return error.InvalidAlpn;
    }
    if (established.retry_processed != expect_retry) {
        return error.UnexpectedRetryState;
    }

    if (expect_key_update) {
        for (key_update_payloads, 0..) |payload, index| {
            if (index != 0) {
                try established.connection.initiateKeyUpdate();
                if (established.connection.localOneRttKeyUpdateCount() !=
                    index)
                {
                    return error.UnexpectedKeyUpdate;
                }
            }
            try echoStream(
                &established.connection,
                allocator,
                payload,
            );
            while (index != 0 and
                established.connection.pendingOneRttKeyUpdateAckThreshold() !=
                    null)
            {
                var packet = try established.connection
                    .receivePacketServicingTimers();
                packet.deinit(allocator);
            }
        }
        if (established.connection.localOneRttKeyUpdateCount() != 2 or
            established.connection.peerOneRttKeyUpdateCount() != 2 or
            established.connection.localOneRttKeyPhase() or
            established.connection.peerOneRttKeyPhase())
        {
            return error.UnexpectedKeyUpdate;
        }
    } else if (scenario == .echo) {
        var stream_ids: [payloads.len]u64 = undefined;
        for (payloads, 0..) |payload, index| {
            stream_ids[index] = try established.connection.openStream();
            try established.connection.send(&.{.{ .stream = .{
                .stream_id = stream_ids[index],
                .offset = 0,
                .data = payload,
                .fin = true,
            } }});
        }

        var offsets = [_]usize{0} ** payloads.len;
        var complete = [_]bool{false} ** payloads.len;
        while (!std.mem.allEqual(bool, &complete, true)) {
            var packet = try established.connection
                .receivePacketServicingTimers();
            defer packet.deinit(allocator);
            inline for (stream_ids, payloads, 0..) |stream_id, payload, index| {
                if (established.connection.availableReceivedStream(
                    stream_id,
                )) |available| {
                    if (available.len != 0) {
                        const end = std.math.add(
                            usize,
                            offsets[index],
                            available.len,
                        ) catch return error.UnexpectedEcho;
                        if (end > payload.len or !std.mem.eql(
                            u8,
                            available,
                            payload[offsets[index]..end],
                        )) return error.UnexpectedEcho;
                        try established.connection.releaseReceivedCapacity(
                            stream_id,
                            available.len,
                        );
                        offsets[index] = end;
                    }
                }
                complete[index] = offsets[index] == payload.len and
                    established.connection.receivedStreamComplete(stream_id);
            }
        }
    } else switch (scenario) {
        .reset, .stop => try exerciseCancellation(
            &established.connection,
            allocator,
            scenario,
        ),
        .flow => try exerciseFlowControl(
            &established.connection,
            allocator,
        ),
        .echo => unreachable,
    }

    // Each external fixture closes only after its stream operations complete.
    // Keep pumping QUIC rather than treating echo completion as proof of a
    // clean connection shutdown, and validate its peer application metadata.
    while (established.connection.peerCloseInfo() == null) {
        established.connection.servicePacketServicingTimers() catch |err|
            switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
    }
    const close = established.connection.peerCloseInfo() orelse
        return error.MissingPeerClose;
    switch (close) {
        .application => |application| {
            const expected_reason = switch (peer) {
                .quic_go => "quic-go interop complete",
                // s2n-quic's public close API carries the RFC 9000
                // application code but does not expose a reason phrase.
                .s2n_quic => "",
            };
            if (application.error_code != 57 or
                !std.mem.eql(u8, application.reason_phrase, expected_reason))
            {
                return error.UnexpectedPeerClose;
            }
        },
        .transport => return error.UnexpectedPeerClose,
    }

    if (expect_key_update) {
        std.debug.print(
            "netz QUIC client interoperated with quic-go: verified=true version={d} key_updates=2 peer_key_updates=2 final_phase=0 ack_gates_cleared=true streams=3 bytes=31 peer_close=57\n",
            .{if (version == .version_2) @as(u8, 2) else 1},
        );
    } else if (scenario == .echo) {
        std.debug.print(
            "netz QUIC client interoperated with {s}: verified=true version={d} retry={} alpn=hq-interop streams=2 bytes=10 peer_close=57\n",
            .{
                switch (peer) {
                    .quic_go => "quic-go",
                    .s2n_quic => "s2n-quic",
                },
                if (version == .version_2) @as(u8, 2) else 1,
                expect_retry,
            },
        );
    } else switch (scenario) {
        .reset => std.debug.print(
            "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop reset_error=41 concurrent_sibling=4 echo_bytes=5 peer_close=57\n",
            .{},
        ),
        .stop => std.debug.print(
            "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop stop_error=42 reset_sent=42 concurrent_sibling=4 echo_bytes=5 peer_close=57\n",
            .{},
        ),
        .flow => std.debug.print(
            "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop initial_max_data=8192 initial_max_stream_data=2048 flow_blocked=true stream_bytes=12288 echo_bytes=12288 peer_close=57\n",
            .{},
        ),
        .echo => unreachable,
    }
}

fn exerciseCancellation(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
    scenario: Scenario,
) !void {
    const target_payload = switch (scenario) {
        .reset => "reset",
        .stop => "stop",
        .echo, .flow => unreachable,
    };
    const target_stream_id = try connection.openStream();
    if (target_stream_id != 0) return error.UnexpectedStreamId;
    try connection.send(&.{.{ .stream = .{
        .stream_id = target_stream_id,
        .offset = 0,
        .data = target_payload,
        .fin = scenario == .reset,
    } }});

    // Put the sibling on the wire before waiting for cancellation so its echo
    // proves RESET_STREAM/STOP_SENDING affected only the target stream.
    const sibling_stream_id = try connection.openStream();
    if (sibling_stream_id != 4) return error.UnexpectedStreamId;
    try connection.send(&.{.{ .stream = .{
        .stream_id = sibling_stream_id,
        .offset = 0,
        .data = payloads[1],
        .fin = true,
    } }});

    switch (scenario) {
        .reset => {
            while (connection.streamResetReceived(target_stream_id) == null) {
                try receivePacket(connection, allocator);
            }
            const reset = connection.streamResetReceived(target_stream_id).?;
            if (reset.application_error_code != 41 or reset.final_size != 0) {
                return error.UnexpectedResetError;
            }
        },
        .stop => {
            while (connection.streamStopped(target_stream_id) == null) {
                try receivePacket(connection, allocator);
            }
            if (connection.streamStopped(target_stream_id).?.application_error_code != 42) {
                return error.UnexpectedStopSendingError;
            }
        },
        .echo, .flow => unreachable,
    }
    try receiveExpectedStream(
        connection,
        allocator,
        sibling_stream_id,
        payloads[1],
    );
}

fn exerciseFlowControl(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
) !void {
    const stream_id = try connection.openStream();
    if (stream_id != 0) return error.UnexpectedStreamId;
    const initial_credit = connection.streamSendCredit(stream_id);
    if (initial_credit.connection != 8 * 1024 or
        initial_credit.stream != 2 * 1024)
    {
        return error.UnexpectedFlowControlLimit;
    }
    const max_chunk_len: usize = 1024;
    var offset: usize = 0;
    var flow_blocked = false;
    while (offset < flow_control_payload.len) {
        const end = @min(offset + max_chunk_len, flow_control_payload.len);
        connection.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .data = flow_control_payload[offset..end],
            .fin = end == flow_control_payload.len,
        } }}) catch |err| switch (err) {
            error.FlowControlBlocked => {
                flow_blocked = true;
                try receivePacket(connection, allocator);
                continue;
            },
            error.CongestionLimited => {
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
    if (!flow_blocked) return error.FlowControlNotExercised;
    try receiveExpectedStream(
        connection,
        allocator,
        stream_id,
        &flow_control_payload,
    );
}

fn echoStream(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
    payload: []const u8,
) !void {
    const stream_id = try connection.openStream();
    try connection.send(&.{.{ .stream = .{
        .stream_id = stream_id,
        .offset = 0,
        .data = payload,
        .fin = true,
    } }});
    var received: usize = 0;
    while (received < payload.len or
        !connection.receivedStreamComplete(stream_id))
    {
        if (connection.availableReceivedStream(stream_id)) |available| {
            if (available.len != 0) {
                const end = received + available.len;
                if (end > payload.len or
                    !std.mem.eql(u8, available, payload[received..end]))
                {
                    return error.UnexpectedEcho;
                }
                try connection.releaseReceivedCapacity(
                    stream_id,
                    available.len,
                );
                received = end;
            }
        }
        if (received == payload.len and
            connection.receivedStreamComplete(stream_id))
        {
            return;
        }
        var packet = try connection.receivePacketServicingTimers();
        packet.deinit(allocator);
    }
}

fn receivePacket(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
) !void {
    var packet = try connection.receivePacketServicingTimers();
    packet.deinit(allocator);
}

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
                const end = std.math.add(usize, received, available.len) catch
                    return error.UnexpectedEcho;
                if (end > expected.len or !std.mem.eql(
                    u8,
                    available,
                    expected[received..end],
                )) return error.UnexpectedEcho;
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
            return;
        }
        try receivePacket(connection, allocator);
    }
}

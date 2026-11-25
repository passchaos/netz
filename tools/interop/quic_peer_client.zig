//! Certificate-verified QUIC stream interop client for external peer fixtures.
//!
//! The primary quic-go matrix uses the repository-owned, checksum-locked Go
//! module; the basic stream/close path is also shared with s2n-quic.

const std = @import("std");
const netz = @import("netz");
const exact_certificate = @import("exact_certificate_verifier.zig");
const OneShotReorder = @import("support/one_shot_reorder.zig").State;
const PhasedFault = @import("support/phased_datagram_fault.zig").State;
const s2n_churn = @import("support/s2n_churn.zig");
const native_datagram = @import("support/native_datagram.zig");

const payloads = [_][]const u8{ "hello", "world" };
const key_update_payloads = [_][]const u8{
    "before-update",
    "phase-one",
    "phase-two",
};
const Scenario = enum {
    echo,
    reset,
    stop,
    flow,
    reset_reorder,
    stop_reorder,
    mixed_churn,
    mixed_churn_loss,
    mixed_churn_reorder,
    datagram,
    datagram_loss,
    datagram_reorder,
};
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
    var peer: enum { quic_go, s2n_quic, quinn } = .quic_go;
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
        } else if (std.mem.eql(u8, arg, "--peer=quinn")) {
            if (peer != .quic_go) return error.InvalidArgument;
            peer = .quinn;
        } else if (std.mem.startsWith(u8, arg, "--scenario=")) {
            if (scenario_set) return error.InvalidArgument;
            scenario_set = true;
            const value = arg["--scenario=".len..];
            scenario = if (std.mem.eql(u8, value, "reordered-reset"))
                .reset_reorder
            else if (std.mem.eql(u8, value, "reordered-stop"))
                .stop_reorder
            else if (std.mem.eql(u8, value, "mixed-churn"))
                .mixed_churn
            else if (std.mem.eql(u8, value, "mixed-churn-loss"))
                .mixed_churn_loss
            else if (std.mem.eql(u8, value, "mixed-churn-reorder"))
                .mixed_churn_reorder
            else
                std.meta.stringToEnum(Scenario, value) orelse
                    return error.InvalidArgument;
        } else {
            return error.InvalidArgument;
        }
    }
    if (expect_retry and expect_key_update) return error.InvalidArgument;
    if (peer != .quic_go and
        (expect_key_update or version != .version_1))
    {
        return error.InvalidArgument;
    }
    switch (peer) {
        .quic_go => if (scenario != .echo) return error.InvalidArgument,
        .s2n_quic => if (scenario == .datagram_loss or
            scenario == .datagram_reorder) return error.InvalidArgument,
        .quinn => if ((scenario != .datagram and
            scenario != .datagram_loss and
            scenario != .datagram_reorder) or expect_retry)
        {
            return error.InvalidArgument;
        },
    }
    const key_exchange_groups: []const netz.quic.tls_client_hello.NamedGroup =
        if (peer != .quic_go)
            &.{.x25519}
        else
            &.{ .x25519_mlkem768, .x25519, .secp256r1 };

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    std.debug.print(
        "netz QUIC interop runtime: endpoint_role=client client_io=zio-std-io server_io={s}\n",
        .{switch (peer) {
            .quic_go => "quic-go-netpoll",
            .s2n_quic => "s2n-quic-tokio",
            .quinn => "quinn-tokio-rustls",
        }},
    );

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[2],
    );
    var bundle_verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    var exact_verifier: exact_certificate.Verifier = undefined;
    const server_verifier = if (peer == .quic_go) blk: {
        exact_verifier = try .init(&ca_bundle, now.toSeconds());
        break :blk exact_verifier.clientVerifier();
    } else netz.quic.tls.auth.ClientVerifier.fromTrustVerifier(
        bundle_verifier.clientVerifier(),
    );

    var cancellation_reorder = OneShotReorder{};
    var churn_loss = PhasedFault.init(.loss);
    var churn_reorder = PhasedFault.init(.reorder);
    var datagram_loss = PhasedFault.init(.loss);
    var datagram_reorder = PhasedFault.init(.reorder);
    var endpoint_limits: netz.quic.runtime.Limits = .{
        .max_datagram_size = 8192,
    };
    if (scenario == .reset_reorder or scenario == .stop_reorder) {
        endpoint_limits.send_interceptor = .{
            .context = &cancellation_reorder,
            .should_hold = OneShotReorder.shouldHold,
        };
    } else if (scenario == .mixed_churn_loss) {
        endpoint_limits.send_interceptor = .{
            .context = &churn_loss,
            .should_drop = PhasedFault.shouldDrop,
        };
    } else if (scenario == .mixed_churn_reorder) {
        endpoint_limits.send_interceptor = .{
            .context = &churn_reorder,
            .should_hold = PhasedFault.shouldHold,
        };
    } else if (scenario == .datagram_loss) {
        endpoint_limits.send_interceptor = .{
            .context = &datagram_loss,
            .should_drop = PhasedFault.shouldDrop,
        };
    } else if (scenario == .datagram_reorder) {
        endpoint_limits.send_interceptor = .{
            .context = &datagram_reorder,
            .should_hold = PhasedFault.shouldHold,
        };
    }
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        endpoint_limits,
    );
    defer endpoint.deinit();
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    var local_transport_parameters =
        netz.quic.practical_transport_parameters;
    if (scenario == .datagram or scenario == .datagram_loss or
        scenario == .datagram_reorder)
    {
        local_transport_parameters.max_datagram_frame_size = 64;
    }

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
            .server_auth = server_verifier,
            .local_transport_parameters = local_transport_parameters,
            .max_crypto_buffer = 64 * 1024,
            .handshake_recovery = .{
                .initial_pto_ms = 250,
                .max_pto_ms = 2000,
                .max_retries = 4,
                .max_duration_ms = 10_000,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = if (scenario == .datagram or
                    scenario == .datagram_loss or
                    scenario == .datagram_reorder) 1200 else 8192,
                // The 32-stream churn can receive dense ACK/STREAM batches
                // from s2n-quic; keep the ordinary fixture limit elsewhere.
                .max_frames_per_packet = if (scenario == .mixed_churn or
                    scenario == .mixed_churn_loss or
                    scenario == .mixed_churn_reorder)
                    256
                else
                    16,
                .key_update_profile = if (version == .version_2 and
                    expect_key_update)
                    .quic_go_v0_59
                else
                    .rfc,
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
    var datagram_result: ?native_datagram.Result = null;

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
                payload,
            );
            while (index != 0 and
                established.connection.pendingOneRttKeyUpdateAckThreshold() !=
                    null)
            {
                try established.connection.servicePacketServicingTimers();
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
            try established.connection.servicePacketServicingTimers();
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
        .reset_reorder, .stop_reorder => try exerciseReorderedCancellation(
            &established.connection,
            allocator,
            scenario,
            &cancellation_reorder,
        ),
        .mixed_churn => _ = try s2n_churn.runSender(
            &established.connection,
            .client,
            null,
        ),
        .mixed_churn_loss => _ = try s2n_churn.runSender(
            &established.connection,
            .client,
            &churn_loss,
        ),
        .mixed_churn_reorder => _ = try s2n_churn.runSender(
            &established.connection,
            .client,
            &churn_reorder,
        ),
        .flow => try exerciseFlowControl(
            &established.connection,
            allocator,
        ),
        .datagram, .datagram_loss, .datagram_reorder => datagram_result =
            try native_datagram.run(
                &established.connection,
                .client,
                switch (peer) {
                    .s2n_quic => .s2n,
                    .quinn => .quinn,
                    .quic_go => unreachable,
                },
                switch (scenario) {
                    .datagram_loss => &datagram_loss,
                    .datagram_reorder => &datagram_reorder,
                    else => null,
                },
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
                .quinn => "quinn interop complete",
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
                    .quinn => "Quinn",
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
        .reset_reorder => std.debug.print(
            "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop reset_error=41 held_cancel_datagrams=1 reordered=true sibling_before_cancel=true concurrent_sibling=4 echo_bytes=5 peer_close=57\n",
            .{},
        ),
        .stop_reorder => std.debug.print(
            "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop stop_error=42 reset_sent=42 held_cancel_datagrams=1 reordered=true sibling_before_cancel=true concurrent_sibling=4 echo_bytes=5 peer_close=57\n",
            .{},
        ),
        .mixed_churn => std.debug.print(
            "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop mixed_churn=true streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true peer_close=57\n",
            .{},
        ),
        .mixed_churn_loss => {
            if (churn_loss.injectedCount() != 2) {
                return error.UnexpectedChurnFaultCount;
            }
            std.debug.print(
                "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop mixed_churn=true fault=loss fault_scope=netz-client-outbound streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true reset_faults=1 fin_faults=1 dropped_datagrams=2 peer_close=57\n",
                .{},
            );
        },
        .mixed_churn_reorder => {
            if (churn_reorder.injectedCount() != 2) {
                return error.UnexpectedChurnFaultCount;
            }
            std.debug.print(
                "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop mixed_churn=true fault=reorder fault_scope=netz-client-outbound streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true reset_faults=1 fin_faults=1 reordered_pairs=2 peer_close=57\n",
                .{},
            );
        },
        .datagram => switch (peer) {
            .s2n_quic => std.debug.print(
                "netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes={d} s2n_boundary_bytes={d} oversized_rejected=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=s2n-quic-tokio\n",
                .{
                    datagram_result.?.netz_boundary_bytes,
                    datagram_result.?.peer_boundary_bytes,
                },
            ),
            .quinn => std.debug.print(
                "netz QUIC client interoperated with Quinn: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes={d} quinn_boundary_bytes={d} oversized_rejected=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls\n",
                .{
                    datagram_result.?.netz_boundary_bytes,
                    datagram_result.?.peer_boundary_bytes,
                },
            ),
            .quic_go => unreachable,
        },
        .datagram_loss => std.debug.print(
            "netz QUIC client interoperated with Quinn: verified=true version=1 alpn=hq-interop datagram=true fault=loss fault_scope=netz-client-outbound dropped_datagrams={d} unreliable_not_retransmitted=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls\n",
            .{datagram_result.?.injected_datagrams},
        ),
        .datagram_reorder => std.debug.print(
            "netz QUIC client interoperated with Quinn: verified=true version=1 alpn=hq-interop datagram=true fault=reorder fault_scope=netz-client-outbound reordered_pairs={d} all_datagrams_received=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls\n",
            .{datagram_result.?.injected_datagrams},
        ),
        .echo => unreachable,
    }
}

fn exerciseReorderedCancellation(
    connection: *netz.quic.one_rtt.Connection,
    allocator: std.mem.Allocator,
    scenario: Scenario,
    reorder: *OneShotReorder,
) !void {
    const target_stream_id = try connection.openStream();
    if (target_stream_id != 0) return error.UnexpectedStreamId;
    const target_payload = switch (scenario) {
        .reset_reorder => "reset",
        .stop_reorder => "stop",
        else => unreachable,
    };
    try connection.send(&.{.{ .stream = .{
        .stream_id = target_stream_id,
        .offset = 0,
        .data = target_payload,
    } }});
    if (scenario == .reset_reorder or scenario == .stop_reorder) {
        try receiveExpectedPrefix(
            connection,
            allocator,
            target_stream_id,
            "target",
        );
    }

    const sibling_stream_id = try connection.openStream();
    if (sibling_stream_id != 4) return error.UnexpectedStreamId;
    reorder.arm();
    switch (scenario) {
        .reset_reorder => try connection.resetStream(target_stream_id, 41),
        .stop_reorder => try connection.sendStopSending(target_stream_id, 42),
        else => unreachable,
    }
    try connection.send(&.{.{ .stream = .{
        .stream_id = sibling_stream_id,
        .offset = 0,
        .data = payloads[1],
        .fin = true,
    } }});
    try receiveExpectedStream(
        connection,
        allocator,
        sibling_stream_id,
        payloads[1],
    );
    if (scenario == .stop_reorder) {
        while (connection.streamResetReceived(target_stream_id) == null) {
            try receivePacket(connection);
        }
        const reset = connection.streamResetReceived(target_stream_id).?;
        if (reset.application_error_code != 42 or reset.final_size < 6) {
            return error.UnexpectedResetError;
        }
    }
    if (reorder.heldCount() != 1) {
        return error.CancellationDatagramNotReordered;
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
        .echo,
        .flow,
        .reset_reorder,
        .stop_reorder,
        .mixed_churn,
        .mixed_churn_loss,
        .mixed_churn_reorder,
        .datagram,
        .datagram_loss,
        .datagram_reorder,
        => unreachable,
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
                try receivePacket(connection);
            }
            const reset = connection.streamResetReceived(target_stream_id).?;
            if (reset.application_error_code != 41 or reset.final_size != 0) {
                return error.UnexpectedResetError;
            }
        },
        .stop => {
            while (connection.streamStopped(target_stream_id) == null) {
                try receivePacket(connection);
            }
            if (connection.streamStopped(target_stream_id).?.application_error_code != 42) {
                return error.UnexpectedStopSendingError;
            }
        },
        .echo,
        .flow,
        .reset_reorder,
        .stop_reorder,
        .mixed_churn,
        .mixed_churn_loss,
        .mixed_churn_reorder,
        .datagram,
        .datagram_loss,
        .datagram_reorder,
        => unreachable,
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
                try receivePacket(connection);
                continue;
            },
            error.CongestionLimited => {
                try receivePacket(connection);
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
        try connection.servicePacketServicingTimers();
    }
}

fn receivePacket(connection: *netz.quic.one_rtt.Connection) !void {
    try connection.servicePacketServicingTimers();
}

fn receiveExpectedStream(
    connection: *netz.quic.one_rtt.Connection,
    _: std.mem.Allocator,
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
        try receivePacket(connection);
    }
}

fn receiveExpectedPrefix(
    connection: *netz.quic.one_rtt.Connection,
    _: std.mem.Allocator,
    stream_id: u64,
    expected: []const u8,
) !void {
    while (true) {
        if (connection.availableReceivedStream(stream_id)) |available| {
            const prefix_len = @min(available.len, expected.len);
            if (!std.mem.eql(
                u8,
                available[0..prefix_len],
                expected[0..prefix_len],
            )) return error.UnexpectedEcho;
            if (available.len >= expected.len) {
                try connection.releaseReceivedCapacity(
                    stream_id,
                    expected.len,
                );
                return;
            }
        }
        try receivePacket(connection);
    }
}

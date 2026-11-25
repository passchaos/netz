const std = @import("std");
const netz = @import("netz");
const churn = @import("quic_quic_go_churn.zig");

const ClientOutcome = struct {
    result: churn.Result,
    reset_faults: churn.ProxyStats,
    fin_faults: churn.ProxyStats,
};

pub fn run(_: std.process.Init, args: []const []const u8) !void {
    if (args.len < 3 or !std.Io.Dir.path.isAbsolute(args[1])) {
        return error.InvalidArgument;
    }
    const port = try std.fmt.parseInt(u16, args[0], 10);
    const proxy_control_port = try std.fmt.parseInt(u16, args[2], 10);
    if (port == 0 or proxy_control_port == 0) return error.InvalidArgument;
    const config = try churn.Config.parse(args[3..]);
    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = config.timeout(),
    });
    var proxy = try churn.ProxyControl.connect(io, proxy_control_port, deadline);
    defer proxy.deinit();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(allocator, io, now, args[1]);
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = churn.max_frames,
            .enable_gso_send = false,
            .enable_gro_receive = false,
        },
    );
    defer endpoint.deinit();
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    var established = try netz.quic.handshake.connectWithDeadline(
        &endpoint,
        .{ .ip4 = .loopback(port) },
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .version = .version_1,
            .available_versions = &.{.version_1},
            .server_name = "localhost",
            .alpn_protocols = &.{churn.alpn},
            .server_auth = netz.quic.tls.auth.ClientVerifier.fromTrustVerifier(verifier.clientVerifier()),
            .local_transport_parameters = try config.transportParameters(),
            .max_crypto_buffer = 64 * 1024,
            .initial_one_rtt_config = try config.oneRttConfig(),
        },
        deadline,
    );
    defer established.deinit();
    if (!std.mem.eql(u8, established.alpn, churn.alpn)) return error.InvalidAlpn;
    const connection = &established.connection;
    const control_id = try connection.openStreamWithDeadline(deadline);
    if (control_id != 0) return error.UnexpectedStreamId;
    var control_offset: u64 = 0;
    const encoded_config = config.encode();
    try churn.sendExact(
        connection,
        control_id,
        &control_offset,
        &encoded_config,
        false,
        deadline,
    );
    var marker: [churn.config_ack.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &marker, deadline, false);
    if (!std.mem.eql(u8, &marker, churn.config_ack)) {
        return error.InvalidChurnControl;
    }

    const sibling_id = try connection.openStreamWithDeadline(deadline);
    if (sibling_id != 4) return error.UnexpectedStreamId;
    var sibling_offset: u64 = 0;
    try churn.sendExact(
        connection,
        sibling_id,
        &sibling_offset,
        churn.sibling_start,
        false,
        deadline,
    );
    var sibling_marker: [churn.sibling_ready.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &sibling_marker, deadline, false);
    if (!std.mem.eql(u8, &sibling_marker, churn.sibling_ready)) {
        return error.InvalidChurnControl;
    }

    const outcome = if (config.sender == .client)
        try runSender(
            allocator,
            connection,
            &proxy,
            config,
            control_id,
            &control_offset,
            deadline,
        )
    else
        try runReceiver(
            connection,
            &proxy,
            config,
            control_id,
            &control_offset,
            deadline,
        );

    try churn.sendExact(
        connection,
        sibling_id,
        &sibling_offset,
        churn.sibling_end,
        true,
        deadline,
    );
    var sibling_response: [churn.sibling_response.len]u8 = undefined;
    try churn.receiveExact(
        connection,
        @intCast(sibling_id),
        &sibling_response,
        deadline,
        true,
    );
    if (!std.mem.eql(u8, &sibling_response, churn.sibling_response)) {
        return error.InvalidChurnSibling;
    }
    var empty: [0]u8 = .{};
    try churn.receiveExact(connection, 0, &empty, deadline, true);
    try churn.sendExact(
        connection,
        control_id,
        &control_offset,
        churn.close_ready,
        true,
        deadline,
    );
    try churn.waitForPeerClose(connection, deadline);
    const stopped = try proxy.command("stop", "stopped");
    const total = addStats(outcome.reset_faults, outcome.fin_faults);
    if (!std.meta.eql(stopped, total)) return error.InvalidProxyStats;

    printResult(
        config,
        outcome.result,
        total,
        outcome.reset_faults,
        outcome.fin_faults,
    );
}

fn runSender(
    allocator: std.mem.Allocator,
    connection: *netz.quic.one_rtt.Connection,
    proxy: *churn.ProxyControl,
    config: churn.Config,
    control_id: u64,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !ClientOutcome {
    const stream_ids = try churn.prepareSenderStreams(
        allocator,
        connection,
        config,
        deadline,
    );
    defer allocator.free(stream_ids);
    var marker: [churn.ready.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &marker, deadline, false);
    if (!std.mem.eql(u8, &marker, churn.ready)) return error.InvalidChurnControl;
    _ = try proxy.command("arm-once", "armed");
    try churn.sendResets(connection, config, stream_ids, deadline);
    try churn.sendExact(
        connection,
        control_id,
        control_offset,
        churn.reset_sent,
        false,
        deadline,
    );
    try churn.sendExact(connection, control_id, control_offset, &churn.kick, false, deadline);
    var observed: [churn.resets_observed.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &observed, deadline, false);
    if (!std.mem.eql(u8, &observed, churn.resets_observed)) {
        return error.InvalidChurnControl;
    }
    const reset_total = try proxy.command("disarm", "disarmed");
    _ = try proxy.command("arm-once", "armed");
    try churn.sendFinStreams(connection, config, stream_ids, deadline);
    try churn.sendExact(
        connection,
        control_id,
        control_offset,
        churn.fin_sent,
        false,
        deadline,
    );
    try churn.sendExact(connection, control_id, control_offset, &churn.kick, false, deadline);
    const result = try churn.receiveResult(connection, deadline);
    const expected = churn.expectedResult(config);
    if (!std.meta.eql(result, expected)) return error.InvalidChurnResult;
    const all = try proxy.command("disarm", "disarmed");
    const fin_faults = try all.minus(reset_total);
    try churn.validateFaults(config.fault, reset_total, fin_faults);
    try churn.sendExact(
        connection,
        control_id,
        control_offset,
        churn.result_ack,
        false,
        deadline,
    );
    return .{
        .result = result,
        .reset_faults = reset_total,
        .fin_faults = fin_faults,
    };
}

fn runReceiver(
    connection: *netz.quic.one_rtt.Connection,
    proxy: *churn.ProxyControl,
    config: churn.Config,
    control_id: u64,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !ClientOutcome {
    var prefix_checksums = [_]u64{0} ** churn.max_streams;
    try churn.receivePrefixes(connection, config, &prefix_checksums, deadline);
    _ = try proxy.command("arm-once", "armed");
    try churn.sendExact(
        connection,
        control_id,
        control_offset,
        churn.ready,
        false,
        deadline,
    );
    var result: churn.Result = .{
        .streams = config.streams,
        .fins = 0,
        .resets = 0,
        .received_bytes = 0,
        .checksum = 0,
        .reset_mask = 0,
        .reset_code_sum = 0,
    };
    try churn.receiveResets(connection, config, &result, deadline);
    var reset_marker: [churn.reset_sent.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &reset_marker, deadline, false);
    if (!std.mem.eql(u8, &reset_marker, churn.reset_sent)) {
        return error.InvalidChurnControl;
    }
    var kick: [churn.kick_len]u8 = undefined;
    try churn.receiveExact(connection, 0, &kick, deadline, false);
    if (!std.mem.eql(u8, &kick, &churn.kick)) return error.InvalidChurnControl;
    const reset_total = try proxy.command("disarm", "disarmed");
    _ = try proxy.command("arm-once", "armed");
    try churn.sendExact(
        connection,
        control_id,
        control_offset,
        churn.resets_observed,
        false,
        deadline,
    );
    try churn.receiveFins(
        connection,
        config,
        &prefix_checksums,
        &result,
        deadline,
    );
    var fin_marker: [churn.fin_sent.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &fin_marker, deadline, false);
    if (!std.mem.eql(u8, &fin_marker, churn.fin_sent)) {
        return error.InvalidChurnControl;
    }
    try churn.receiveExact(connection, 0, &kick, deadline, false);
    if (!std.mem.eql(u8, &kick, &churn.kick)) return error.InvalidChurnControl;
    const all = try proxy.command("disarm", "disarmed");
    const fin_faults = try all.minus(reset_total);
    try churn.validateFaults(config.fault, reset_total, fin_faults);
    const expected = churn.expectedResult(config);
    if (!std.meta.eql(result, expected)) return error.InvalidChurnResult;
    const encoded = result.encode();
    try churn.sendExact(
        connection,
        control_id,
        control_offset,
        &encoded,
        false,
        deadline,
    );
    var ack: [churn.result_ack.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &ack, deadline, false);
    if (!std.mem.eql(u8, &ack, churn.result_ack)) {
        return error.InvalidChurnControl;
    }
    return .{
        .result = result,
        .reset_faults = reset_total,
        .fin_faults = fin_faults,
    };
}

fn addStats(a: churn.ProxyStats, b: churn.ProxyStats) churn.ProxyStats {
    return .{
        .considered = a.considered + b.considered,
        .dropped = a.dropped + b.dropped,
        .held = a.held + b.held,
        .reordered = a.reordered + b.reordered,
    };
}

fn printResult(
    config: churn.Config,
    result: churn.Result,
    total: churn.ProxyStats,
    reset_faults: churn.ProxyStats,
    fin_faults: churn.ProxyStats,
) void {
    const counter_reset = if (config.fault == .loss) reset_faults.dropped else reset_faults.reordered;
    const counter_fin = if (config.fault == .loss) fin_faults.dropped else fin_faults.reordered;
    std.debug.print(
        "raw QUIC churn client passed: implementation=netz role_pair=netz-client+quic-go-server " ++
            "client_io=zio-std-io server_io=quic-go-netpoll " ++
            "sender={s} fault={s} fault_scope={s}-outbound streams={d} fin={d} reset={d} " ++
            "bytes={d} checksum={d} reset_mask=0x{x:0>16} reset_code_sum={d} " ++
            "considered={d} dropped={d} held={d} reordered={d} reset_faults={d} " ++
            "fin_faults={d} reset_final_size_verified={s} sibling=true peer-close=true\n",
        .{
            @tagName(config.sender),                                           @tagName(config.fault),
            if (config.sender == .client) "netz-client" else "quic-go-server", result.streams,
            result.fins,                                                       result.resets,
            result.received_bytes,                                             result.checksum,
            result.reset_mask,                                                 result.reset_code_sum,
            total.considered,                                                  total.dropped,
            total.held,                                                        total.reordered,
            counter_reset,                                                     counter_fin,
            if (config.sender == .server) "true" else "false",
        },
    );
}

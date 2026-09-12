const std = @import("std");
const netz = @import("netz");
const churn = @import("quic_quic_go_churn.zig");

pub fn run(_: std.process.Init, args: []const []const u8) !void {
    if (args.len < 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[0], 10);
    const expected_config = try churn.Config.parse(args[1..]);
    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
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
        .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = churn.max_frames,
            .enable_gso_send = false,
            .enable_gro_receive = false,
        },
    );
    defer endpoint.deinit();
    std.debug.print("NETZ_QUIC_CHURN_PORT={d}\n", .{endpoint.address().ip4.port});

    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var established = try netz.quic.handshake.acceptWithTimeout(
        &endpoint,
        .{
            .local_connection_id = &server_cid,
            .version = .version_1,
            .available_versions = &.{.version_1},
            .alpn_protocol = churn.alpn,
            .local_transport_parameters = try expected_config.transportParameters(),
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .max_crypto_buffer = 64 * 1024,
            .initial_one_rtt_config = try expected_config.oneRttConfig(),
        },
        .fromSeconds(50),
    );
    defer established.deinit();
    if (!std.mem.eql(u8, established.alpn, churn.alpn)) return error.InvalidAlpn;
    const connection = &established.connection;
    const initial_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(30),
    });
    const config = try churn.receiveConfig(connection, initial_deadline);
    if (!std.meta.eql(config, expected_config)) return error.InvalidChurnConfig;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = config.timeout(),
    });
    var control_offset: u64 = 0;
    try churn.sendExact(
        connection,
        0,
        &control_offset,
        churn.config_ack,
        false,
        deadline,
    );

    var sibling_start: [churn.sibling_start.len]u8 = undefined;
    try churn.receiveExact(connection, 4, &sibling_start, deadline, false);
    if (!std.mem.eql(u8, &sibling_start, churn.sibling_start)) {
        return error.InvalidChurnSibling;
    }
    try churn.sendExact(
        connection,
        0,
        &control_offset,
        churn.sibling_ready,
        false,
        deadline,
    );

    const result = if (config.sender == .server)
        try runSender(allocator, connection, config, &control_offset, deadline)
    else
        try runReceiver(connection, config, &control_offset, deadline);

    var sibling_end: [churn.sibling_end.len]u8 = undefined;
    try churn.receiveExact(connection, 4, &sibling_end, deadline, true);
    if (!std.mem.eql(u8, &sibling_end, churn.sibling_end)) {
        return error.InvalidChurnSibling;
    }
    var sibling_offset: u64 = 0;
    try churn.sendExact(
        connection,
        4,
        &sibling_offset,
        churn.sibling_response,
        true,
        deadline,
    );
    try churn.sendExact(connection, 0, &control_offset, &.{}, true, deadline);
    var close_marker: [churn.close_ready.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &close_marker, deadline, true);
    if (!std.mem.eql(u8, &close_marker, churn.close_ready)) {
        return error.InvalidChurnControl;
    }
    try connection.closeApplication(0, "churn complete");
    printResult(config, result);
}

fn runSender(
    allocator: std.mem.Allocator,
    connection: *netz.quic.one_rtt.Connection,
    config: churn.Config,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !churn.Result {
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
    try churn.sendResets(connection, config, stream_ids, deadline);
    try churn.sendExact(
        connection,
        0,
        control_offset,
        churn.reset_sent,
        false,
        deadline,
    );
    try churn.sendExact(connection, 0, control_offset, &churn.kick, false, deadline);
    var observed: [churn.resets_observed.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &observed, deadline, false);
    if (!std.mem.eql(u8, &observed, churn.resets_observed)) {
        return error.InvalidChurnControl;
    }
    try churn.sendFinStreams(connection, config, stream_ids, deadline);
    try churn.sendExact(
        connection,
        0,
        control_offset,
        churn.fin_sent,
        false,
        deadline,
    );
    try churn.sendExact(connection, 0, control_offset, &churn.kick, false, deadline);
    const result = try churn.receiveResult(connection, deadline);
    if (!std.meta.eql(result, churn.expectedResult(config))) {
        return error.InvalidChurnResult;
    }
    try churn.sendExact(
        connection,
        0,
        control_offset,
        churn.result_ack,
        false,
        deadline,
    );
    return result;
}

fn runReceiver(
    connection: *netz.quic.one_rtt.Connection,
    config: churn.Config,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !churn.Result {
    var prefix_checksums = [_]u64{0} ** churn.max_streams;
    try churn.receivePrefixes(connection, config, &prefix_checksums, deadline);
    try churn.sendExact(
        connection,
        0,
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
    var marker: [churn.reset_sent.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &marker, deadline, false);
    if (!std.mem.eql(u8, &marker, churn.reset_sent)) {
        return error.InvalidChurnControl;
    }
    var kick: [churn.kick_len]u8 = undefined;
    try churn.receiveExact(connection, 0, &kick, deadline, false);
    if (!std.mem.eql(u8, &kick, &churn.kick)) return error.InvalidChurnControl;
    try churn.sendExact(
        connection,
        0,
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
    try churn.receiveExact(connection, 0, &marker, deadline, false);
    if (!std.mem.eql(u8, &marker, churn.fin_sent)) {
        return error.InvalidChurnControl;
    }
    try churn.receiveExact(connection, 0, &kick, deadline, false);
    if (!std.mem.eql(u8, &kick, &churn.kick)) return error.InvalidChurnControl;
    if (!std.meta.eql(result, churn.expectedResult(config))) {
        return error.InvalidChurnResult;
    }
    const encoded = result.encode();
    try churn.sendExact(connection, 0, control_offset, &encoded, false, deadline);
    var ack: [churn.result_ack.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &ack, deadline, false);
    if (!std.mem.eql(u8, &ack, churn.result_ack)) {
        return error.InvalidChurnControl;
    }
    return result;
}

fn printResult(config: churn.Config, result: churn.Result) void {
    std.debug.print(
        "raw QUIC churn server passed: implementation=netz role_pair=quic-go-client+netz-server " ++
            "sender={s} fault={s} fault_scope={s}-outbound streams={d} fin={d} reset={d} " ++
            "bytes={d} checksum={d} reset_mask=0x{x:0>16} reset_code_sum={d} " ++
            "reset_final_size_verified={s} sibling=true\n",
        .{
            @tagName(config.sender),                                           @tagName(config.fault),
            if (config.sender == .client) "quic-go-client" else "netz-server", result.streams,
            result.fins,                                                       result.resets,
            result.received_bytes,                                             result.checksum,
            result.reset_mask,                                                 result.reset_code_sum,
            if (config.sender == .client) "true" else "false",
        },
    );
}

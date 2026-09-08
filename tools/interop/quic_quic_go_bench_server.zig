const std = @import("std");
const netz = @import("netz");
const benchmark = @import("quic_quic_go_bench.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or !std.mem.eql(u8, args[1], "bench-server")) {
        return error.InvalidArgument;
    }
    const port = try std.fmt.parseInt(u16, args[2], 10);
    var sender: ?benchmark.Sender = null;
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[3..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--sender=")) {
            if (sender != null) return error.InvalidArgument;
            sender = std.meta.stringToEnum(
                benchmark.Sender,
                arg["--sender=".len..],
            ) orelse return error.InvalidArgument;
        } else {
            try config_args.append(std.heap.c_allocator, arg);
        }
    }
    const selected_sender = sender orelse return error.InvalidArgument;
    const expected_config = try benchmark.Config.parse(config_args.items);
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
            .max_frames_per_datagram = benchmark.max_frames,
            .enable_gso_send = false,
            .enable_gro_receive = false,
        },
    );
    defer endpoint.deinit();
    std.debug.print("NETZ_QUIC_BENCH_PORT={d}\n", .{endpoint.address().ip4.port});
    const sender_name = if (selected_sender == .server) "netz" else "quic-go";
    const role_pair = "quic-go-client+netz-server";
    try benchmark.printConfig(sender_name, role_pair, expected_config);

    for (0..try expected_config.rounds()) |round_index| {
        try runRound(
            allocator,
            io,
            &endpoint,
            &certificate_der,
            key_pair,
            expected_config,
            selected_sender,
            @intCast(round_index),
            sender_name,
            role_pair,
        );
    }
}

fn runRound(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: *netz.quic.runtime.Endpoint,
    certificate_der: []const u8,
    key_pair: anytype,
    config: benchmark.Config,
    selected_sender: benchmark.Sender,
    round: u32,
    sender_name: []const u8,
    role_pair: []const u8,
) !void {
    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var established = try netz.quic.handshake.acceptWithTimeout(
        endpoint,
        .{
            .local_connection_id = &server_cid,
            .version = .version_1,
            .available_versions = &.{.version_1},
            .alpn_protocol = benchmark.alpn,
            .local_transport_parameters = try config.transportParameters(),
            .identity = .{
                .certificate_chain = &.{certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .max_crypto_buffer = 64 * 1024,
            .initial_one_rtt_config = try config.oneRttConfig(),
        },
        config.timeout(),
    );
    defer established.deinit();
    if (!std.mem.eql(u8, established.alpn, benchmark.alpn)) {
        return error.InvalidAlpn;
    }
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = config.timeout(),
    });
    const config_record = try benchmark.receiveRecord(
        &established.connection,
        0,
        deadline,
        false,
    );
    try benchmark.validateRecord(
        config_record,
        .config,
        selected_sender,
        round,
        config,
    );
    var control_offset: u64 = 0;
    try benchmark.sendRecord(
        &established.connection,
        0,
        &control_offset,
        benchmark.Record.init(.config_ack, selected_sender, round, config),
        false,
        deadline,
    );
    const result = if (selected_sender == .server)
        try runSender(
            allocator,
            io,
            &established.connection,
            config,
            round,
            &control_offset,
            deadline,
        )
    else
        try runReceiver(
            allocator,
            &established.connection,
            config,
            round,
            &control_offset,
            deadline,
        );
    if (selected_sender == .server and round >= config.warmup) {
        try benchmark.printSample(
            sender_name,
            role_pair,
            config,
            round - config.warmup + 1,
            result.elapsed_ns,
            result.checksum,
        );
    }
    if (selected_sender == .client) {
        try established.connection.closeApplication(0, "benchmark complete");
    } else {
        try waitForClientClose(&established.connection, deadline);
    }
}

const Result = struct { elapsed_ns: u64, checksum: u64 };

fn runSender(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: *netz.quic.one_rtt.Connection,
    config: benchmark.Config,
    round: u32,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !Result {
    var payloads = try benchmark.PayloadSet.init(allocator, config, round);
    defer payloads.deinit(allocator);
    const stream_ids = try benchmark.prepareDataStreams(
        connection,
        config,
        round,
        deadline,
    );
    const ready = try benchmark.receiveRecord(connection, 0, deadline, false);
    try benchmark.validateRecord(ready, .ready, .server, round, config);
    const started = benchmark.nowNs(io);
    try benchmark.sendPayloads(connection, config, &stream_ids, &payloads, deadline);
    const done = try benchmark.receiveRecord(connection, 0, deadline, true);
    try benchmark.validateRecord(done, .done, .server, round, config);
    if (done.received_bytes != try config.totalBytes() or
        done.checksum != payloads.checksum)
    {
        return error.InvalidBenchmarkResult;
    }
    const elapsed = benchmark.nowNs(io) -| started;
    var ack = benchmark.Record.init(.done_ack, .server, round, config);
    ack.received_bytes = done.received_bytes;
    ack.checksum = done.checksum;
    try benchmark.sendRecord(connection, 0, control_offset, ack, true, deadline);
    try benchmark.drainDeliveryRecovery(connection, deadline);
    return .{ .elapsed_ns = elapsed, .checksum = payloads.checksum };
}

fn runReceiver(
    allocator: std.mem.Allocator,
    connection: *netz.quic.one_rtt.Connection,
    config: benchmark.Config,
    round: u32,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !Result {
    const stream_ids = try benchmark.receiveDataPreludes(
        connection,
        config,
        round,
        .client,
        deadline,
    );
    const buffer = try allocator.alloc(u8, config.effectiveChunk());
    defer allocator.free(buffer);
    try benchmark.sendRecord(
        connection,
        0,
        control_offset,
        benchmark.Record.init(.ready, .client, round, config),
        false,
        deadline,
    );
    const result = try benchmark.receivePayloads(
        connection,
        config,
        round,
        &stream_ids,
        buffer,
        deadline,
    );
    var done = benchmark.Record.init(.done, .client, round, config);
    done.received_bytes = result.bytes;
    done.checksum = result.checksum;
    try benchmark.sendRecord(connection, 0, control_offset, done, true, deadline);
    const ack = try benchmark.receiveRecord(connection, 0, deadline, true);
    try benchmark.validateRecord(ack, .done_ack, .client, round, config);
    if (ack.received_bytes != result.bytes or ack.checksum != result.checksum) {
        return error.InvalidBenchmarkResult;
    }
    std.debug.print(
        "protocol=quic-stream role_pair=quic-go-client+netz-server receiver_complete=true round={d} received_bytes={d} checksum={d}\n",
        .{ round, result.bytes, result.checksum },
    );
    return .{ .elapsed_ns = 0, .checksum = result.checksum };
}

fn waitForClientClose(
    connection: *netz.quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) !void {
    while (connection.peerCloseInfo() == null) {
        var packet = connection.receivePacketServicingTimersDeadline(deadline) catch |err|
            switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
        packet.deinit(connection.endpoint.allocator);
    }
    try benchmark.validateBenchmarkClose(connection);
}

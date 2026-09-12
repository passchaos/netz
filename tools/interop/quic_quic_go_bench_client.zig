const std = @import("std");
const netz = @import("netz");
const benchmark = @import("quic_quic_go_bench.zig");
const churn = @import("quic_quic_go_churn_client.zig");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 5 and std.mem.eql(u8, args[1], "churn-client")) {
        return churn.run(init, args[2..]);
    }
    if (args.len < 4 or !std.mem.eql(u8, args[1], "bench-client")) {
        return error.InvalidArgument;
    }
    const port = try std.fmt.parseInt(u16, args[2], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[3])) {
        return error.InvalidArgument;
    }
    var sender: ?benchmark.Sender = null;
    var stats = false;
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[4..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--sender=")) {
            if (sender != null) return error.InvalidArgument;
            sender = std.meta.stringToEnum(
                benchmark.Sender,
                arg["--sender=".len..],
            ) orelse return error.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            stats = true;
        } else {
            try config_args.append(std.heap.c_allocator, arg);
        }
    }
    const selected_sender = sender orelse return error.InvalidArgument;
    const config = try benchmark.Config.parse(config_args.items);
    const role_pair = "netz-client+quic-go-server";
    var counting = CountingAllocator.init(std.heap.c_allocator);
    const allocator = if (stats) counting.allocator() else std.heap.c_allocator;
    defer if (stats) benchmark.printNetzMemory(
        role_pair,
        "client",
        selected_sender,
        config,
        counting.snapshot(),
    );
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(allocator, io, now, args[3]);
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    const sender_name = if (selected_sender == .client) "netz" else "quic-go";
    try benchmark.printConfig(sender_name, role_pair, config);
    for (0..try config.rounds()) |round_index| {
        try runRound(
            allocator,
            io,
            port,
            verifier.clientVerifier(),
            config,
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
    port: u16,
    verifier: netz.quic.tls.auth.ClientVerifier,
    config: benchmark.Config,
    selected_sender: benchmark.Sender,
    round: u32,
    sender_name: []const u8,
    role_pair: []const u8,
) !void {
    var socket_traffic: netz.quic.runtime.SocketTrafficCounters = .{};
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = benchmark.max_frames,
            .enable_gso_send = false,
            .enable_gro_receive = false,
            .socket_traffic_counters = &socket_traffic,
        },
    );
    defer endpoint.deinit();
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    var established = try netz.quic.handshake.connectWithTimeout(
        &endpoint,
        .{ .ip4 = .loopback(port) },
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .version = .version_1,
            .available_versions = &.{.version_1},
            .server_name = "localhost",
            .alpn_protocols = &.{benchmark.alpn},
            .server_auth = verifier,
            .local_transport_parameters = try config.transportParameters(),
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
    const control_id = try established.connection.openStreamWithDeadline(deadline);
    if (control_id != 0) return error.UnexpectedStreamId;
    var control_send_offset: u64 = 0;
    try benchmark.sendRecord(
        &established.connection,
        control_id,
        &control_send_offset,
        benchmark.Record.init(.config, selected_sender, round, config),
        false,
        deadline,
    );
    const config_ack = try benchmark.receiveRecord(
        &established.connection,
        @intCast(control_id),
        deadline,
        false,
    );
    try benchmark.validateRecord(
        config_ack,
        .config_ack,
        selected_sender,
        round,
        config,
    );
    const result = if (selected_sender == .client)
        try runSender(
            allocator,
            io,
            &established.connection,
            config,
            round,
            control_id,
            &control_send_offset,
            deadline,
        )
    else
        try runReceiver(
            allocator,
            &established.connection,
            config,
            round,
            control_id,
            &control_send_offset,
            deadline,
        );
    if (selected_sender == .client and round >= config.warmup) {
        try benchmark.printSample(
            sender_name,
            role_pair,
            config,
            round - config.warmup + 1,
            result.elapsed_ns,
            result.checksum,
        );
    }
    if (selected_sender == .server) {
        try established.connection.closeApplication(0, "benchmark complete");
    } else {
        try waitForServerClose(&established.connection, deadline);
    }
    if (round >= config.warmup) {
        benchmark.printSocketTraffic(
            "netz",
            role_pair,
            "client",
            config,
            round - config.warmup + 1,
            socket_traffic.stats(),
        );
    }
}

const Result = struct { elapsed_ns: u64, checksum: u64 };

fn runSender(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: *netz.quic.one_rtt.Connection,
    config: benchmark.Config,
    round: u32,
    control_id: u64,
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
    const ready = try benchmark.receiveRecord(
        connection,
        @intCast(control_id),
        deadline,
        false,
    );
    try benchmark.validateRecord(ready, .ready, .client, round, config);
    const started = benchmark.nowNs(io);
    try benchmark.sendPayloads(
        connection,
        config,
        &stream_ids,
        &payloads,
        deadline,
    );
    const done = try benchmark.receiveRecord(
        connection,
        @intCast(control_id),
        deadline,
        true,
    );
    try benchmark.validateRecord(done, .done, .client, round, config);
    if (done.received_bytes != try config.totalBytes() or
        done.checksum != payloads.checksum)
    {
        return error.InvalidBenchmarkResult;
    }
    const elapsed = benchmark.nowNs(io) -| started;
    var ack = benchmark.Record.init(.done_ack, .client, round, config);
    ack.received_bytes = done.received_bytes;
    ack.checksum = done.checksum;
    try benchmark.sendRecord(
        connection,
        control_id,
        control_offset,
        ack,
        true,
        deadline,
    );
    try benchmark.drainDeliveryRecovery(connection, deadline);
    return .{ .elapsed_ns = elapsed, .checksum = payloads.checksum };
}

fn runReceiver(
    allocator: std.mem.Allocator,
    connection: *netz.quic.one_rtt.Connection,
    config: benchmark.Config,
    round: u32,
    control_id: u64,
    control_offset: *u64,
    deadline: std.Io.Clock.Timestamp,
) !Result {
    const stream_ids = try benchmark.receiveDataPreludes(
        connection,
        config,
        round,
        .server,
        deadline,
    );
    const buffer = try allocator.alloc(u8, config.effectiveChunk());
    defer allocator.free(buffer);
    try benchmark.sendRecord(
        connection,
        control_id,
        control_offset,
        benchmark.Record.init(.ready, .server, round, config),
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
    var done = benchmark.Record.init(.done, .server, round, config);
    done.received_bytes = result.bytes;
    done.checksum = result.checksum;
    try benchmark.sendRecord(
        connection,
        control_id,
        control_offset,
        done,
        true,
        deadline,
    );
    const ack = try benchmark.receiveRecord(
        connection,
        @intCast(control_id),
        deadline,
        true,
    );
    try benchmark.validateRecord(ack, .done_ack, .server, round, config);
    if (ack.received_bytes != result.bytes or ack.checksum != result.checksum) {
        return error.InvalidBenchmarkResult;
    }
    std.debug.print(
        "protocol=quic-stream role_pair=netz-client+quic-go-server receiver_complete=true round={d} received_bytes={d} checksum={d}\n",
        .{ round, result.bytes, result.checksum },
    );
    return .{ .elapsed_ns = 0, .checksum = result.checksum };
}

fn waitForServerClose(
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

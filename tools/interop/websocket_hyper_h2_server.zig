const std = @import("std");
const netz = @import("netz");
const benchmark = @import("websocket_hyper_h2_bench.zig");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or !std.mem.eql(u8, args[1], "bench-server")) {
        return error.InvalidArgument;
    }
    const port = try std.fmt.parseInt(u16, args[2], 10);
    var stats = false;
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[3..]) |arg| {
        if (std.mem.eql(u8, arg, "--stats") and !stats) {
            stats = true;
        } else {
            try config_args.append(std.heap.c_allocator, arg);
        }
    }
    const expected_config = try benchmark.Config.parse(config_args.items);
    var counting = CountingAllocator.init(std.heap.c_allocator);
    const allocator = if (stats) counting.allocator() else std.heap.c_allocator;
    try runBenchmarkWithAllocator(allocator, port, expected_config);
    if (stats) {
        const snapshot = counting.snapshot();
        if (snapshot.current_bytes != 0) return error.MemoryLeak;
        benchmark.printNetzMemory(
            "hyper-client+netz-server",
            "server",
            expected_config,
            snapshot,
        );
    }
}

fn runBenchmarkWithAllocator(
    allocator: std.mem.Allocator,
    port: u16,
    expected_config: benchmark.Config,
) !void {
    // Keep zio's executor bookkeeping outside the explicit protocol allocator
    // so --stats remains comparable with the historical workload scope.
    var backend = try netz.runtime.Backend.init(std.heap.smp_allocator);
    defer backend.deinit();
    const io = backend.io();
    var server = try netz.http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        expected_config.serverH2Limits(),
    );
    defer server.deinit();
    std.debug.print("NETZ_WEBSOCKET_H2_BENCH_PORT={d}\n", .{server.address().ip4.port});
    var h2 = try server.acceptWithTimeout(expected_config.timeout());
    defer h2.close();
    var pending = try netz.websocket.runtime.H2Server.receiveUpgradeRequestWithTimeout(
        allocator,
        &h2,
        .{
            .protocols = &.{benchmark.protocol},
            .require_subprotocol = true,
            .allowed_origins = &.{benchmark.origin},
            .limits = expected_config.wsLimits(),
        },
        expected_config.timeout(),
    );
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    const config = try benchmark.Config.fromUpgrade(pending);
    if (!std.meta.eql(config, expected_config) or
        !std.mem.eql(u8, pending.target(), benchmark.path) or
        !std.mem.eql(u8, pending.scheme(), "http") or pending.authority() == null or
        !std.mem.eql(u8, pending.authority().?, "localhost"))
    {
        return error.InvalidBenchmarkConfig;
    }
    var ws = try pending.accept();
    pending_owned = false;
    defer ws.close();
    try ws.sendBinary(benchmark.ready);
    benchmark.printConfig("hyper-client+netz-server", config);
    const storage = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(storage);
    var checksum: u64 = 0;
    for (0..try config.rounds()) |round| {
        const message = try ws.receiveMessageIntoWithTimeout(storage, config.timeout());
        if (message.opcode != .binary or message.was_compressed or
            message.payload.len != config.payload_bytes)
        {
            return error.InvalidBenchmarkPayload;
        }
        const value = try benchmark.verifyPayload(message.payload, @intCast(round));
        if (round >= config.warmup) checksum +%= value;
        try ws.sendBinary(message.payload);
    }
    var close = try ws.receiveFrameAutoWithTimeout(config.timeout());
    defer close.deinit(allocator);
    if (close.header.opcode != .close) return error.UnexpectedClose;
    const parsed = (try netz.websocket.parseClosePayload(close.payload)) orelse
        return error.MissingClosePayload;
    if (parsed.code != .normal_closure or !std.mem.eql(u8, parsed.reason, "done")) {
        return error.UnexpectedClose;
    }
    std.debug.print(
        "record=server-complete implementation=netz protocol=websocket-h2 " ++
            "transport=h2c mode=binary-echo role_pair=hyper-client+netz-server " ++
            "endpoint_role=server client_io=hyper-tokio server_io=zio-std-io " ++
            "connection_scope=persistent benchmark_scope=same-application-shape " ++
            "warmup={d} " ++
            "iterations={d} payload_bytes={d} timeout_ms={d} sent_bytes={d} " ++
            "received_bytes={d} checksum={d} server_complete=true\n",
        .{
            config.warmup,
            config.iterations,
            config.payload_bytes,
            config.timeout_ms,
            @as(u64, config.iterations) * config.payload_bytes,
            @as(u64, config.iterations) * config.payload_bytes,
            checksum,
        },
    );
}

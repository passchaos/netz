const std = @import("std");
const netz = @import("netz");
const benchmark = @import("websocket_hyper_h2_bench.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or !std.mem.eql(u8, args[1], "bench-server")) {
        return error.InvalidArgument;
    }
    const port = try std.fmt.parseInt(u16, args[2], 10);
    const expected_config = try benchmark.Config.parse(args[3..]);
    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
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
    errdefer pending.deinit();
    const config = try benchmark.Config.fromUpgrade(pending);
    if (!std.meta.eql(config, expected_config) or
        !std.mem.eql(u8, pending.target(), benchmark.path) or
        !std.mem.eql(u8, pending.scheme(), "http") or pending.authority() == null or
        !std.mem.eql(u8, pending.authority().?, "localhost"))
    {
        return error.InvalidBenchmarkConfig;
    }
    var ws = try pending.accept();
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
        "protocol=websocket-h2 role_pair=hyper-client+netz-server server_complete=true received_bytes={d} checksum={d}\n",
        .{ @as(u64, config.iterations) * config.payload_bytes, checksum },
    );
}

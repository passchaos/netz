const std = @import("std");
const netz = @import("netz");
const config = @import("grpc_shared_bench/options.zig");
const Session = @import("grpc_shared_bench/session.zig").Session;
const Peer = @import("grpc_shared_bench/peer.zig").Peer;
const telemetry = @import("support/counting_allocator.zig");

pub fn main(init: std.process.Init) !void {
    const options = try config.parse(init);
    const backing = std.heap.smp_allocator;
    var counting = telemetry.CountingAllocator.init(backing);
    const allocator = if (options.stats) counting.allocator() else backing;
    const request = try config.message(backing, options.payload_bytes, 'a');
    defer backing.free(request);
    const response = try config.message(backing, options.payload_bytes, 'b');
    defer backing.free(response);
    const latencies = try backing.alloc(u64, options.iterations);
    defer backing.free(latencies);
    var backend = try netz.runtime.Backend.init(backing);
    defer backend.deinit();
    const io = backend.io();
    const limits: netz.http2.runtime.Limits = .{
        .max_body_bytes = std.math.maxInt(usize),
        .initial_window_size = options.stream_window,
        .initial_connection_window_size = options.connection_window,
        .adaptive_window = options.adaptive_window,
        .adaptive_window_max = options.adaptive_window_max,
        .max_frame_size = options.max_frame_size,
    };
    var server = try netz.grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits, 16 * 1024 * 1024);
    defer server.deinit();
    var peer: Peer = .{ .server = &server, .options = options, .request = request, .response = response };
    var server_task = io.async(Peer.run, .{&peer});
    defer _ = server_task.cancel(io) catch {};
    var client = try netz.grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address(), .limits = limits } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var persistent: ?Session = if (options.mode == .persistent) try Session.open(sender, allocator, response) else null;
    defer if (persistent) |*session| session.deinit();
    for (0..options.warmup) |_| try exchange(sender, allocator, request, response, &persistent);
    const before = counting.snapshot();
    const started = now(io);
    for (latencies) |*latency| {
        const begin = now(io);
        try exchange(sender, allocator, request, response, &persistent);
        latency.* = now(io) -| begin;
    }
    const elapsed = now(io) -| started;
    const after = counting.snapshot();
    if (persistent) |*session| try session.finish();
    client.deinit();
    live = false;
    try server_task.await(io);
    if (peer.messages != options.total() or peer.finished_calls != options.calls()) return error.InvalidPeerCompletion;
    std.mem.sort(u64, latencies, {}, std.sort.asc(u64));
    const roundtrips = if (elapsed == 0) 0 else @as(u128, options.iterations) * std.time.ns_per_s / elapsed;
    const logical_bytes = @as(u128, options.iterations) * options.payload_bytes * 2;
    std.debug.print(
        "record=result schema=2 implementation=netz protocol=grpc transport=h2c " ++
            "mode={s} client_api=shared client_io=zio-std-io server_io=zio-std-io " ++
            "connection_scope=persistent connections=1 validation=full-bytes " ++
            "protobuf_scope=preencoded allocation_scope=client+server+protocol stats_enabled={} warmup={d} iterations={d} " ++
            "payload_bytes={d} protobuf_bytes={d} logical_bytes={d} elapsed_ns={d} " ++
            "stream_window={d} connection_window={d} adaptive_window={} adaptive_window_max={d} max_frame_size={d} " ++
            "final_client_stream_window={d} final_server_stream_window={d} " ++
            "ns_per_roundtrip={d} roundtrips_per_second={d} p50_ns={d} p95_ns={d} p99_ns={d} " ++
            "alloc_count={d} allocated_bytes={d} freed_bytes={d} live_bytes={d}\n",
        .{ @tagName(options.mode), options.stats, options.warmup, options.iterations, options.payload_bytes, request.len, logical_bytes, elapsed, options.stream_window, options.connection_window, options.adaptive_window, options.adaptive_window_max, options.max_frame_size, peer.final_client_stream_window, peer.final_server_stream_window, elapsed / options.iterations, roundtrips, percentile(latencies, 50), percentile(latencies, 95), percentile(latencies, 99), after.alloc_count - before.alloc_count, after.total_allocated - before.total_allocated, after.total_freed - before.total_freed, after.current_bytes },
    );
    std.debug.print("record=peer-completion schema=2 implementation=netz protocol=grpc mode={s} request_messages={d} response_messages={d} terminal_calls={d} protobuf_bytes={d} stream_window={d} connection_window={d} adaptive_window={} adaptive_window_max={d} max_frame_size={d} final_client_stream_window={d} final_server_stream_window={d}\n", .{ @tagName(options.mode), peer.messages, peer.messages, peer.finished_calls, request.len, options.stream_window, options.connection_window, options.adaptive_window, options.adaptive_window_max, options.max_frame_size, peer.final_client_stream_window, peer.final_server_stream_window });
}

fn exchange(sender: netz.grpc.SharedChannelSender, allocator: std.mem.Allocator, request: []const u8, response: []const u8, persistent: *?Session) !void {
    if (persistent.*) |*session| return session.exchange(request);
    var session = try Session.open(sender, allocator, response);
    defer session.deinit();
    try session.exchange(request);
    try session.finish();
}

fn now(io: std.Io) u64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

fn percentile(sorted: []const u64, percent: usize) u64 {
    const rank = (@as(u128, sorted.len) * percent + 99) / 100;
    return sorted[@intCast(rank - 1)];
}

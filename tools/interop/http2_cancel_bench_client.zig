//! Netz client for the HTTP/2 cancellation-race benchmark.

const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

const stream_window = 8 * 1024;
const connection_window = 65_535;
const offered_bytes = 128 * 1024;
const sibling_bytes = 16 * 1024;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    const warmup = try std.fmt.parseInt(usize, args[2], 10);
    const iterations = try std.fmt.parseInt(usize, args[3], 10);
    if (port == 0 or iterations == 0) return error.InvalidArgument;

    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = counting.allocator();
    var backend = try netz.runtime.Backend.init(std.heap.smp_allocator);
    defer backend.deinit();
    const io = backend.io();
    var client = try netz.http2.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .max_frame_payload = 16 * 1024,
            .max_body_bytes = 256 * 1024,
            .initial_window_size = stream_window,
            .initial_connection_window_size = connection_window,
            .handshake_timeout = .fromSeconds(5),
        },
    );
    defer client.close();

    for (0..warmup) |_| _ = try exchange(&client, allocator);
    const started = nowNs(io);
    var checksum: usize = 0;
    for (0..iterations) |_| checksum +%= try exchange(&client, allocator);
    const elapsed_ns = nowNs(io) -| started;
    var reuse = try client.request(.{
        .method = "GET",
        .path = "/reuse",
        .scheme = "http",
        .authority = "localhost",
    });
    if (reuse.status != 200 or !std.mem.eql(u8, reuse.body, "reuse-ok")) {
        reuse.deinit(allocator);
        return error.InvalidResponse;
    }
    reuse.deinit(allocator);
    const ns_per_batch = elapsed_ns / iterations;
    const batches_per_second = if (elapsed_ns == 0)
        0
    else
        (@as(u128, iterations) * std.time.ns_per_s) / elapsed_ns;

    std.debug.print(
        "record=result implementation=netz protocol=http2 transport=h2c " ++
            "mode=cancellation-race server_implementation=hyper " ++
            "client_io=zio-std-io server_io=hyper-tokio " ++
            "connection_scope=persistent benchmark_scope=same-server-behavior " ++
            "warmup={d} iterations={d} stream_window=8192 " ++
            "connection_window=65535 offered_bytes=131072 canceled_bytes=8192 " ++
            "sibling_bytes=16384 completed_batches={d} reuse_requests=1 " ++
            "cancellation_observation=server-body-drop-gated-sibling " ++
            "sibling_concurrent=true " ++
            "elapsed_ns={d} ns_per_batch={d} batches_per_s={d} " ++
            "checksum={d} complete=true\n",
        .{ warmup, iterations, iterations, elapsed_ns, ns_per_batch, batches_per_second, checksum },
    );
    const snapshot = counting.snapshot();
    snapshot.print();
    std.debug.print(
        "record=memory implementation=netz protocol=http2 transport=h2c " ++
            "mode=cancellation-race server_implementation=hyper " ++
            "client_io=zio-std-io server_io=hyper-tokio " ++
            "memory_scope=client-process-through-reuse allocator_scope=netz-explicit " ++
            "alloc_count={d} free_count={d} resize_count={d} remap_count={d} " ++
            "total_allocated_bytes={d} total_freed_bytes={d} live_bytes={d} " ++
            "peak_live_bytes={d} complete=true\n",
        .{
            snapshot.alloc_count,
            snapshot.free_count,
            snapshot.resize_count,
            snapshot.remap_count,
            snapshot.total_allocated,
            snapshot.total_freed,
            snapshot.current_bytes,
            snapshot.peak_bytes,
        },
    );
}

fn exchange(
    client: *netz.http2.runtime.Connection,
    allocator: std.mem.Allocator,
) !usize {
    var cancel = try client.startRequest(.{
        .method = "GET",
        .path = "/cancel",
        .scheme = "http",
        .authority = "localhost",
        .body_length = 0,
    });
    defer cancel.deinit();
    try cancel.finish();
    var sibling = try client.startRequest(.{
        .method = "GET",
        .path = "/sibling",
        .scheme = "http",
        .authority = "localhost",
        .body_length = 0,
    });
    defer sibling.deinit();
    try sibling.finish();

    var canceled: CancelContext = .{};
    const result = cancel.readResponseStreamingWithHead(
        &canceled,
        beginCancel,
        consumeCancel,
    );
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit(allocator);
        return error.ExpectedCancellation;
    } else |err| if (err != error.CancelResponse) return err;
    if (!canceled.valid_head or canceled.body_bytes != stream_window) {
        return error.InvalidResponse;
    }

    var response = try sibling.readResponse();
    defer response.deinit(allocator);
    if (response.status != 200 or response.body.len != sibling_bytes or
        !allBytesEqual(response.body, 's'))
    {
        return error.InvalidResponse;
    }
    return canceled.body_bytes + response.body.len;
}

const CancelContext = struct {
    valid_head: bool = false,
    body_bytes: usize = 0,
};

fn beginCancel(context: *CancelContext, head: netz.http2.runtime.StreamingResponseHead) !void {
    context.valid_head = head.status == 200 and
        headerEquals(head.headers, "content-length", "131072");
}

fn consumeCancel(context: *CancelContext, data: []const u8) !void {
    if (!allBytesEqual(data, 'c')) return error.InvalidResponse;
    context.body_bytes += data.len;
    if (context.body_bytes >= stream_window) return error.CancelResponse;
}

fn headerEquals(
    headers: []const netz.http2.Hpack.HeaderField,
    name: []const u8,
    value: []const u8,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name))
            return std.mem.eql(u8, header.value, value);
    }
    return false;
}

fn allBytesEqual(bytes: []const u8, expected: u8) bool {
    for (bytes) |byte| if (byte != expected) return false;
    return true;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

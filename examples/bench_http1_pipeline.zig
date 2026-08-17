const std = @import("std");
const netz = @import("netz");

const pipelined_requests: usize = 16;
const warmup_iterations: usize = 200;
const iterations: usize = 2_000;
const request =
    "GET / HTTP/1.1\r\n" ++
    "Host: localhost\r\n" ++
    "\r\n";
const response_body = "Hello, World!";
// Hyper's HTTP/1 server automatically adds a 29-byte IMF-fixdate. Keep the
// exact 89-byte response wire size in this same-shape benchmark rather than
// giving netz a smaller 52-byte response workload.
const response_date = "Mon, 17 Aug 2026 00:00:00 GMT";
const response_headers = [_]netz.http1.Header{.{
    .name = "date",
    .value = response_date,
}};
const response_bytes: usize =
    "HTTP/1.1 200 OK\r\n".len +
    "Content-Length: 13\r\n".len +
    "date: ".len +
    response_date.len +
    "\r\n".len +
    "\r\n".len +
    response_body.len;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http1.runtime.Server,
        failed: *std.atomic.Value(bool),
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
                shared.failed.store(true, .release);
            };
        }

        fn runFallible(
            server_ptr: *netz.http1.runtime.Server,
        ) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var responses: [pipelined_requests]netz.http1.runtime.ResponseOptions = undefined;
            var heads: [pipelined_requests]netz.http1.RequestHead = undefined;
            var headers: [pipelined_requests * 8]netz.http1.Header = undefined;
            var bodies: [pipelined_requests][]const u8 = undefined;
            for (0..warmup_iterations + iterations) |_| {
                const consumed = try connection.readRequestBatchInto(
                    &heads,
                    &headers,
                    &bodies,
                    .{ .max_headers = 8 },
                );
                for (&responses, heads, bodies) |
                    *response_options,
                    head,
                    body,
                | {
                    if (body.len != 0) return error.UnexpectedRequestBody;
                    response_options.* = .{
                        .headers = &response_headers,
                        .body = response_body,
                        .request_method = head.method,
                    };
                }
                try connection.writeResponses(&responses);
                try connection.consumeRequestBatch(consumed);
            }
        }
    };

    var failed = std.atomic.Value(bool).init(false);
    var shared = Shared{ .server = &server, .failed = &failed };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    const batch = request ** pipelined_requests;
    var receive_buffer: [8192]u8 = undefined;
    const response_bytes_per_iteration = response_bytes *
        pipelined_requests;
    for (0..warmup_iterations) |_| {
        _ = try exchangeBatch(
            io,
            client,
            batch,
            response_bytes_per_iteration,
            &receive_buffer,
            &failed,
            &shared.err,
        );
    }

    const started = nowNs(io);
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        checksum +%= try exchangeBatch(
            io,
            client,
            batch,
            response_bytes_per_iteration,
            &receive_buffer,
            &failed,
            &shared.err,
        );
    }
    const elapsed = nowNs(io) -| started;

    thread.join();
    if (shared.err) |err| return err;
    const request_count = iterations * pipelined_requests;
    const requests_per_second = if (elapsed == 0)
        0
    else
        (@as(u64, request_count) *| std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\HTTP/1 pipeline runtime benchmark
        \\  pipeline depth: {d}
        \\  warmup iterations: {d}
        \\  iterations: {d}
        \\  requests: {d}
        \\  ns/request: {d}
        \\  requests/s: {d}
        \\  checksum: {d}
        \\
    , .{
        pipelined_requests,
        warmup_iterations,
        iterations,
        request_count,
        elapsed / request_count,
        requests_per_second,
        checksum,
    });
}

fn exchangeBatch(
    io: std.Io,
    stream: std.Io.net.Stream,
    request_batch: []const u8,
    expected_response_bytes: usize,
    receive_buffer: []u8,
    failed: *std.atomic.Value(bool),
    server_err: *const ?anyerror,
) !usize {
    try writeAll(io, stream, request_batch);
    var received: usize = 0;
    while (received < expected_response_bytes) {
        if (failed.load(.acquire)) {
            return server_err.* orelse error.ServerFailed;
        }
        const count = try readSome(io, stream, receive_buffer);
        if (count == 0) return error.ConnectionClosed;
        received += count;
    }
    if (received != expected_response_bytes) {
        return error.UnexpectedResponseLength;
    }
    return received;
}

fn readSome(
    io: std.Io,
    stream: std.Io.net.Stream,
    buffer: []u8,
) std.Io.net.Stream.Reader.Error!usize {
    var buffers = [_][]u8{buffer};
    return io.vtable.netRead(
        io.userdata,
        stream.socket.handle,
        &buffers,
    );
}

fn writeAll(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) std.Io.net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        written += count;
    }
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

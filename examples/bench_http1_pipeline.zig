const std = @import("std");
const netz = @import("netz");

const pipelined_requests: usize = 16;
const default_warmup_iterations: usize = 200;
const default_iterations: usize = 2_000;
const request =
    "GET / HTTP/1.1\r\n" ++
    "Host: localhost\r\n" ++
    "\r\n";
const default_response_body_bytes: usize = "Hello, World!".len;
const large_response_body_bytes: usize = 64 * 1024;
pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const config = parseConfig(init) catch
        return error.InvalidArgument;
    const response_body_bytes = config.response_body_bytes;
    const response_body = try allocator.alloc(u8, response_body_bytes);
    defer allocator.free(response_body);
    @memset(response_body, 'x');
    var content_length_buffer: [32]u8 = undefined;
    const content_length = try std.fmt.bufPrint(
        &content_length_buffer,
        "{}",
        .{response_body_bytes},
    );
    const response_bytes: usize =
        "HTTP/1.1 200 OK\r\n".len +
        "Content-Length: \r\n".len +
        content_length.len +
        "Date: ".len +
        29 +
        "\r\n".len +
        "\r\n".len +
        response_body.len;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = 0,
            .write_strategy = config.write_strategy,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http1.runtime.Server,
        failed: *std.atomic.Value(bool),
        response_body: []const u8,
        total_batches: usize,
        served_requests: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
                shared.failed.store(true, .release);
            };
        }

        fn runFallible(
            shared: *@This(),
        ) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var responses: [pipelined_requests]netz.http1.runtime.ResponseOptions = undefined;
            var heads: [pipelined_requests]netz.http1.RequestHead = undefined;
            var headers: [pipelined_requests * 8]netz.http1.Header = undefined;
            var bodies: [pipelined_requests][]const u8 = undefined;
            for (0..shared.total_batches) |_| {
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
                        .body = shared.response_body,
                        .request_method = head.method,
                    };
                }
                try connection.writeResponses(&responses);
                try connection.consumeRequestBatch(consumed);
                shared.served_requests += heads.len;
            }
        }
    };

    var failed = std.atomic.Value(bool).init(false);
    var shared = Shared{
        .server = &server,
        .failed = &failed,
        .response_body = response_body,
        .total_batches = config.warmup_iterations + config.iterations,
    };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    const batch = request ** pipelined_requests;
    var receive_buffer: [8192]u8 = undefined;
    const response_bytes_per_iteration = response_bytes *
        pipelined_requests;
    for (0..config.warmup_iterations) |_| {
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
    for (0..config.iterations) |_| {
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

    server_task.await(io);
    if (shared.err) |err| return err;
    const request_count = config.iterations * pipelined_requests;
    const expected_served_requests =
        (config.warmup_iterations + config.iterations) * pipelined_requests;
    if (shared.served_requests != expected_served_requests) {
        return error.UnexpectedServerRequestCount;
    }
    const requests_per_second = if (elapsed == 0)
        0
    else
        (@as(u64, request_count) *| std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\HTTP/1 pipeline runtime benchmark
        \\  io backend: zio-std-io
        \\  pipeline depth: {d}
        \\  warmup iterations: {d}
        \\  iterations: {d}
        \\  response body bytes: {d}
        \\  write strategy: {s}
        \\  requests: {d}
        \\  ns/request: {d}
        \\  requests/s: {d}
        \\  checksum: {d}
        \\
    , .{
        pipelined_requests,
        config.warmup_iterations,
        config.iterations,
        response_body_bytes,
        @tagName(config.write_strategy),
        request_count,
        elapsed / request_count,
        requests_per_second,
        checksum,
    });
    std.debug.print(
        "record=config implementation=netz protocol=http1 transport=tcp " ++
            "workload=pipeline benchmark_scope=same-application-shape " ++
            "client_io=zio-std-io server_io=zio-std-io " ++
            "connection_scope=persistent pipeline_depth={d} warmup={d} " ++
            "iterations={d} request_wire_bytes={d} " ++
            "response_wire_bytes={d} pipeline_flush=true " ++
            "write_strategy={s}\n",
        .{
            pipelined_requests,
            config.warmup_iterations,
            config.iterations,
            request.len,
            response_bytes,
            @tagName(config.write_strategy),
        },
    );
    std.debug.print(
        "record=result implementation=netz protocol=http1 transport=tcp " ++
            "workload=pipeline benchmark_scope=same-application-shape " ++
            "client_io=zio-std-io server_io=zio-std-io " ++
            "connection_scope=persistent pipeline_depth={d} warmup={d} " ++
            "iterations={d} requests={d} received_bytes={d} " ++
            "server_requests={d} elapsed_ns={d} ns_per_request={d} " ++
            "requests_per_s={d} complete=true\n",
        .{
            pipelined_requests,
            config.warmup_iterations,
            config.iterations,
            request_count,
            checksum,
            expected_served_requests,
            elapsed,
            elapsed / request_count,
            requests_per_second,
        },
    );
}

const Config = struct {
    response_body_bytes: usize = default_response_body_bytes,
    write_strategy: netz.http1.runtime.WriteStrategy = .auto,
    warmup_iterations: usize = default_warmup_iterations,
    iterations: usize = default_iterations,
};

fn parseConfig(init: std.process.Init) !Config {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var config: Config = .{};
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--large-body")) {
            config.response_body_bytes = large_response_body_bytes;
        } else if (std.mem.startsWith(u8, arg, "--body-bytes=")) {
            config.response_body_bytes = try std.fmt.parseInt(
                usize,
                arg["--body-bytes=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--write-strategy=")) {
            config.write_strategy = std.meta.stringToEnum(
                netz.http1.runtime.WriteStrategy,
                arg["--write-strategy=".len..],
            ) orelse return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            config.warmup_iterations = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            config.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else return error.InvalidArgument;
    }
    if (config.response_body_bytes == 0 or config.iterations == 0) {
        return error.InvalidArgument;
    }
    return config;
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

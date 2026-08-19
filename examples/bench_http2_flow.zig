const std = @import("std");
const netz = @import("netz");

const default_parallel: usize = 10;
const default_body_bytes: usize = 1024 * 1024;
const default_stream_window: u32 = 8 * 1024;
const default_connection_window: u32 = 65_535;
const default_warmups: usize = 5;
const default_iterations: usize = 20;
const application_chunk_size: usize = 16 * 1024;
const response_headers = [_]netz.http2.Hpack.HeaderField{.{
    .name = "date",
    .value = "Mon, 17 Aug 2026 00:00:00 GMT",
}};

const Options = struct {
    parallel: usize = default_parallel,
    body_bytes: usize = default_body_bytes,
    stream_window: u32 = default_stream_window,
    connection_window: u32 = default_connection_window,
    warmups: usize = default_warmups,
    iterations: usize = default_iterations,
    priority: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const options = try parseOptions(init);
    if (options.parallel == 0 or options.body_bytes == 0 or
        options.stream_window == 0 or
        options.connection_window < 65_535 or
        options.iterations == 0)
    {
        return error.InvalidArguments;
    }

    const allocator = std.heap.smp_allocator;
    const response_body = try allocator.alloc(u8, options.body_bytes);
    defer allocator.free(response_body);
    @memset(response_body, 'x');

    const limits: netz.http2.runtime.Limits = .{
        .max_body_bytes = options.body_bytes,
        .initial_window_size = options.stream_window,
        .initial_connection_window_size = options.connection_window,
        .no_rfc7540_priorities = options.priority,
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try netz.http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http2.runtime.Server,
        options: Options,
        response_body: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();

            const stream_ids = try shared.server.allocator.alloc(
                u31,
                shared.options.parallel,
            );
            defer shared.server.allocator.free(stream_ids);
            const responses = try shared.server.allocator.alloc(
                netz.http2.runtime.ResponseOptions,
                shared.options.parallel,
            );
            defer shared.server.allocator.free(responses);
            @memset(responses, .{
                .headers = &response_headers,
                .body = shared.response_body,
            });

            const total = shared.options.warmups +
                shared.options.iterations;
            for (0..total) |_| {
                var requests_initialized: usize = 0;
                const requests = try shared.server.allocator.alloc(
                    netz.http2.runtime.OwnedRequest,
                    shared.options.parallel,
                );
                defer {
                    for (requests[0..requests_initialized]) |*request| {
                        request.deinit(shared.server.allocator);
                    }
                    shared.server.allocator.free(requests);
                }
                for (requests, stream_ids) |*request, *stream_id| {
                    request.* = try connection.readRequest();
                    requests_initialized += 1;
                    stream_id.* = request.stream_id;
                }
                try connection.writeResponseBodyBatch(
                    stream_ids,
                    responses,
                    application_chunk_size,
                );
            }
        }
    };
    var shared = Shared{
        .server = &server,
        .options = options,
        .response_body = response_body,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const authority = try std.fmt.allocPrint(
        allocator,
        "127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(authority);
    const requests = try allocator.alloc(
        netz.http2.runtime.RequestOptions,
        options.parallel,
    );
    defer allocator.free(requests);
    for (requests, 0..) |*request, index| {
        request.* = .{
            .path = "/flow",
            .scheme = "http",
            .authority = authority,
            .priority = if (!options.priority)
                null
            else if (index == 0)
                .{ .urgency = 0 }
            else if (index < @max(options.parallel / 2, 2))
                .{ .urgency = 2, .incremental = true }
            else
                .{ .urgency = 5, .incremental = true },
        };
    }
    const responses = try allocator.alloc(
        netz.http2.runtime.StreamingResponse,
        options.parallel,
    );
    defer allocator.free(responses);
    const body_bytes = try allocator.alloc(usize, options.parallel);
    defer allocator.free(body_bytes);

    var checksum: usize = 0;
    for (0..options.warmups) |_| {
        checksum +%= try exchange(
            &client,
            requests,
            responses,
            body_bytes,
            allocator,
            options.body_bytes,
        );
    }
    const started = nowNs(io);
    for (0..options.iterations) |_| {
        checksum +%= try exchange(
            &client,
            requests,
            responses,
            body_bytes,
            allocator,
            options.body_bytes,
        );
    }
    const elapsed = nowNs(io) -| started;

    thread.join();
    if (shared.err) |err| return err;
    const wire_body_bytes = @as(u64, options.body_bytes) *
        options.parallel * options.iterations;
    const mebibytes_per_second = if (elapsed == 0)
        0
    else
        (wire_body_bytes * std.time.ns_per_s) /
            (elapsed * 1024 * 1024);
    std.debug.print(
        \\HTTP/2 flow-controlled response benchmark
        \\  parallel streams: {d}
        \\  response bytes/stream: {d}
        \\  initial stream window: {d}
        \\  initial connection window: {d}
        \\  scheduler: {s}
        \\  warmup iterations: {d}
        \\  iterations: {d}
        \\  ns/batch: {d}
        \\  body MiB/s: {d}
        \\  checksum: {d}
        \\
    , .{
        options.parallel,
        options.body_bytes,
        options.stream_window,
        options.connection_window,
        if (options.priority) "RFC 9218" else "round-robin",
        options.warmups,
        options.iterations,
        elapsed / options.iterations,
        mebibytes_per_second,
        checksum,
    });
}

fn exchange(
    client: *netz.http2.runtime.Connection,
    requests: []const netz.http2.runtime.RequestOptions,
    responses: []netz.http2.runtime.StreamingResponse,
    body_bytes: []usize,
    allocator: std.mem.Allocator,
    expected_body_bytes: usize,
) !usize {
    @memset(body_bytes, 0);
    try client.requestBatchStreamingInto(
        requests,
        responses,
        body_bytes,
        struct {
            fn consume(
                counts: []usize,
                index: usize,
                data: []const u8,
            ) !void {
                counts[index] += data.len;
            }
        }.consume,
    );
    defer for (responses) |*response| response.deinit(allocator);

    var total: usize = 0;
    for (responses, body_bytes) |response, streamed| {
        if (response.status != 200 or
            response.body_bytes != expected_body_bytes or
            streamed != expected_body_bytes)
        {
            return error.UnexpectedResponse;
        }
        total += streamed;
    }
    return total;
}

fn parseOptions(init: std.process.Init) !Options {
    var options: Options = .{};
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args[1..]) |argument| {
        if (std.mem.startsWith(u8, argument, "--parallel=")) {
            options.parallel = try std.fmt.parseInt(
                usize,
                argument["--parallel=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, argument, "--body-bytes=")) {
            options.body_bytes = try std.fmt.parseInt(
                usize,
                argument["--body-bytes=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, argument, "--stream-window=")) {
            options.stream_window = try std.fmt.parseInt(
                u32,
                argument["--stream-window=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, argument, "--connection-window=")) {
            options.connection_window = try std.fmt.parseInt(
                u32,
                argument["--connection-window=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, argument, "--warmup=")) {
            options.warmups = try std.fmt.parseInt(
                usize,
                argument["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, argument, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                argument["--iterations=".len..],
                10,
            );
        } else if (std.mem.eql(u8, argument, "--priority")) {
            options.priority = true;
        } else {
            return error.InvalidArguments;
        }
    }
    return options;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

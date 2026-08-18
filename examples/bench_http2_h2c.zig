const std = @import("std");
const netz = @import("netz");

const warmup_iterations: usize = 1_000;
const iterations: usize = 2_000;
// Hyper's server inserts Date and then references it from the HPACK dynamic
// table. Supplying the same-length field makes steady-state responses 11 wire
// bytes in both benchmarks instead of netz's otherwise smaller 10-byte frame.
const response_headers = [_]netz.http2.Hpack.HeaderField{.{
    .name = "date",
    .value = "Mon, 17 Aug 2026 00:00:00 GMT",
}};
const request_body = "ssssssssss";
const request_body_100kb = "x" ** (100 * 1024);
const parallel_chunk = "x" ** (10 * 1024);
const parallel_chunk_count: usize = 100;
const parallel_body = parallel_chunk ** parallel_chunk_count;
const h2_window: u32 = std.math.maxInt(i31);
const limits: netz.http2.runtime.Limits = .{
    .max_body_bytes = parallel_body.len,
    .initial_window_size = h2_window,
    .initial_connection_window_size = h2_window,
};

const Scenario = struct {
    name: []const u8,
    request: netz.http2.runtime.RequestOptions,
    parallel: usize = 1,
    warmups: usize = warmup_iterations,
    measured: usize = iterations,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const ScenarioServer = struct {
                body: []const u8,
                parallel: usize,
                warmups: usize = warmup_iterations,
                measured: usize = iterations,
                streaming: bool = false,
            };
            const scenarios = [_]ScenarioServer{
                .{ .body = "", .parallel = 1 },
                .{ .body = request_body, .parallel = 1 },
                .{
                    .body = request_body_100kb,
                    .parallel = 1,
                    .warmups = 100,
                    .streaming = true,
                },
                .{ .body = "", .parallel = 10 },
                .{
                    .body = parallel_body,
                    .parallel = 10,
                    .warmups = 5,
                    .measured = 20,
                },
            };
            for (scenarios) |scenario| {
                var connection = try shared.server.accept();
                defer connection.close();
                const scenario_iterations =
                    scenario.warmups + scenario.measured;
                if (scenario.parallel == 1) {
                    for (0..scenario_iterations) |_| {
                        const stream_id = if (scenario.streaming) stream: {
                            var body_bytes: usize = 0;
                            var request = try connection.readRequestStreaming(
                                &body_bytes,
                                struct {
                                    fn consume(
                                        count: *usize,
                                        data: []const u8,
                                    ) !void {
                                        count.* += data.len;
                                    }
                                }.consume,
                            );
                            defer request.deinit(shared.server.allocator);
                            if (body_bytes != scenario.body.len or
                                request.body_bytes != scenario.body.len)
                            {
                                return error.UnexpectedRequestBody;
                            }
                            break :stream request.stream_id;
                        } else stream: {
                            var request = try connection.readRequest();
                            defer request.deinit(shared.server.allocator);
                            if (!std.mem.eql(
                                u8,
                                request.body,
                                scenario.body,
                            )) {
                                return error.UnexpectedRequestBody;
                            }
                            break :stream request.stream_id;
                        };
                        try connection.writeResponse(stream_id, .{
                            .headers = &response_headers,
                        });
                    }
                } else {
                    var stream_ids: [10]u31 = undefined;
                    const responses = [_]netz.http2.runtime.ResponseOptions{
                        .{ .headers = &response_headers },
                    } ** 10;
                    for (0..scenario_iterations) |_| {
                        if (scenario.body.len == 0) {
                            var requests: [10]netz.http2.runtime.OwnedRequest =
                                undefined;
                            var initialized: usize = 0;
                            defer for (requests[0..initialized]) |*request| {
                                request.deinit(shared.server.allocator);
                            };
                            for (&requests, &stream_ids) |
                                *request,
                                *stream_id,
                            | {
                                request.* = try connection.readRequest();
                                initialized += 1;
                                stream_id.* = request.stream_id;
                            }
                        } else {
                            var requests: [10]netz.http2.runtime.StreamingRequest = undefined;
                            var initialized = false;
                            defer if (initialized) for (&requests) |*request| {
                                request.deinit(shared.server.allocator);
                            };
                            var body_bytes: usize = 0;
                            try connection.readRequestBatchStreamingInto(
                                &requests,
                                &body_bytes,
                                struct {
                                    fn consume(
                                        total: *usize,
                                        _: u31,
                                        data: []const u8,
                                    ) !void {
                                        total.* += data.len;
                                    }
                                }.consume,
                            );
                            initialized = true;
                            for (&requests, &stream_ids) |
                                *request,
                                *stream_id,
                            | {
                                stream_id.* = request.stream_id;
                                if (request.body_bytes != scenario.body.len) {
                                    return error.UnexpectedRequestBody;
                                }
                            }
                            if (body_bytes !=
                                scenario.body.len * scenario.parallel)
                            {
                                return error.UnexpectedRequestBody;
                            }
                        }
                        try connection.writeResponseBatch(
                            &stream_ids,
                            &responses,
                        );
                    }
                }
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const authority = try std.fmt.allocPrint(
        allocator,
        "127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(authority);
    const scenarios = [_]Scenario{
        .{
            .name = "http2_consecutive_x1_empty",
            .request = .{
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
            },
        },
        .{
            .name = "http2_consecutive_x1_req_10b",
            .request = .{
                .method = "POST",
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
                .body = request_body,
            },
        },
        .{
            .name = "http2_consecutive_x1_req_100kb",
            .request = .{
                .method = "POST",
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
                .body = request_body_100kb,
            },
            .warmups = 100,
        },
        .{
            .name = "http2_parallel_x10_empty",
            .request = .{
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
            },
            .parallel = 10,
        },
        .{
            .name = "http2_parallel_x10_req_10kb_100_chunks_max_window",
            .request = .{
                .method = "POST",
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
                .body = parallel_body,
            },
            .parallel = 10,
            .warmups = 5,
            .measured = 20,
        },
    };
    for (scenarios) |scenario| {
        var client = try netz.http2.runtime.Client.connect(
            allocator,
            io,
            server.address(),
            limits,
        );
        defer client.close();

        var requests: [10]netz.http2.runtime.RequestOptions = undefined;
        @memset(requests[0..scenario.parallel], scenario.request);
        var responses: [10]netz.http2.runtime.OwnedResponse = undefined;
        for (0..scenario.warmups) |_| {
            try exchangeScenario(
                &client,
                requests[0..scenario.parallel],
                responses[0..scenario.parallel],
                allocator,
            );
        }

        const start = nowNs(io);
        var status_total: usize = 0;
        for (0..scenario.measured) |_| {
            try exchangeScenario(
                &client,
                requests[0..scenario.parallel],
                responses[0..scenario.parallel],
                allocator,
            );
            status_total += 200 * scenario.parallel;
        }
        const elapsed = nowNs(io) -| start;
        const requests_per_second = if (elapsed == 0)
            0
        else
            (@as(u64, scenario.measured) *| std.time.ns_per_s) / elapsed;

        std.debug.print(
            \\HTTP/2 h2c runtime benchmark
            \\  shape: Hyper {s}
            \\  parallel requests: {d}
            \\  warmup iterations: {d}
            \\  iterations: {d}
            \\  status total: {d}
            \\  ns/op: {d}
            \\  ns/request: {d}
            \\  requests/s: {d}
            \\
        , .{
            scenario.name,
            scenario.parallel,
            scenario.warmups,
            scenario.measured,
            status_total,
            elapsed / scenario.measured,
            elapsed / (scenario.measured * scenario.parallel),
            requests_per_second * scenario.parallel,
        });
    }

    thread.join();
    if (shared.err) |err| return err;
}

fn validateResponse(response: netz.http2.runtime.OwnedResponse) !void {
    if (response.status != 200 or response.body.len != 0) {
        return error.UnexpectedResponse;
    }
}

fn exchangeScenario(
    client: *netz.http2.runtime.Connection,
    requests: []const netz.http2.runtime.RequestOptions,
    responses: []netz.http2.runtime.OwnedResponse,
    allocator: std.mem.Allocator,
) !void {
    if (requests.len == 1) {
        responses[0] = try client.request(requests[0]);
    } else if (requests[0].body.len != 0) {
        try client.requestBodyBatchInto(
            requests,
            parallel_chunk.len,
            responses,
        );
    } else {
        try client.requestBatchInto(requests, responses);
    }
    defer for (responses) |*response| response.deinit(allocator);
    for (responses) |response| try validateResponse(response);
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

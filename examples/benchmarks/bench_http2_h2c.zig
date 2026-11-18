const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support").counting_allocator
    .CountingAllocator;

const warmup_iterations: usize = 1_000;
const iterations: usize = 2_000;
const request_body = "ssssssssss";
const request_body_100kb = "x" ** (100 * 1024);
const parallel_chunk = "x" ** (10 * 1024);
const parallel_chunk_count: usize = 100;
const parallel_body = parallel_chunk ** parallel_chunk_count;
const response_body_1mb = "x" ** (1024 * 1024);
const response_frame_chunk: usize = 16 * 1024;
const h2_window: u32 = std.math.maxInt(i31);
const limits: netz.http2.runtime.Limits = .{
    .max_body_bytes = @max(parallel_body.len, response_body_1mb.len),
    .initial_window_size = h2_window,
    .initial_connection_window_size = h2_window,
};

const ScenarioId = enum {
    http2_consecutive_x1_empty,
    http2_shared_consecutive_x1_empty,
    http2_consecutive_x1_req_10b,
    http2_consecutive_x1_res_10b,
    http2_consecutive_x1_req_100kb,
    http2_parallel_x10_empty,
    http2_parallel_x10_req_10kb_100_chunks_max_window,
    http2_parallel_x10_res_1mb,
    http2_parallel_x10_duplex_1mb_aggregate,
    http2_parallel_x10_duplex_1mb_streaming,
};

/// The 1-MiB response and duplex self-benchmarks currently deadlock in the
/// in-process single-executor harness. Keep them selectable with --scenario
/// while the flow-control issue is investigated, but do not hang the default
/// benchmark step.
fn largeScenario(id: ScenarioId) bool {
    return switch (id) {
        .http2_parallel_x10_res_1mb,
        .http2_parallel_x10_duplex_1mb_aggregate,
        .http2_parallel_x10_duplex_1mb_streaming,
        => true,
        else => false,
    };
}

const Options = struct {
    scenario: ?ScenarioId = null,
    stats: bool = false,
};

const Scenario = struct {
    id: ScenarioId,
    request: netz.http2.runtime.RequestOptions,
    response_body: []const u8 = "",
    streaming_response: bool = false,
    parallel: usize = 1,
    warmups: usize = warmup_iterations,
    measured: usize = iterations,
    shared_sender: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const options = try parseOptions(init, std.heap.smp_allocator);
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = if (options.stats)
        counting.allocator()
    else
        std.heap.smp_allocator;

    var backend = try netz.runtime.Backend.init(std.heap.smp_allocator);
    defer backend.deinit();
    const io = backend.io();

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
        scenario: ?ScenarioId,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                std.debug.print("bench server error: {s}\n", .{@errorName(err)});
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const ScenarioServer = struct {
                id: ScenarioId,
                request_body: []const u8,
                response_body: []const u8 = "",
                parallel: usize,
                warmups: usize = warmup_iterations,
                measured: usize = iterations,
                streaming: bool = false,
            };
            const scenarios = [_]ScenarioServer{
                .{ .id = .http2_consecutive_x1_empty, .request_body = "", .parallel = 1 },
                .{ .id = .http2_shared_consecutive_x1_empty, .request_body = "", .parallel = 1 },
                .{ .id = .http2_consecutive_x1_req_10b, .request_body = request_body, .parallel = 1 },
                .{
                    .id = .http2_consecutive_x1_req_100kb,
                    .request_body = request_body_100kb,
                    .parallel = 1,
                    .warmups = 100,
                    .streaming = true,
                },
                .{
                    .id = .http2_consecutive_x1_res_10b,
                    .request_body = "",
                    .response_body = request_body,
                    .parallel = 1,
                },
                .{ .id = .http2_parallel_x10_empty, .request_body = "", .parallel = 10 },
                .{
                    .id = .http2_parallel_x10_req_10kb_100_chunks_max_window,
                    .request_body = parallel_body,
                    .parallel = 10,
                    .warmups = 5,
                    .measured = 20,
                },
                .{
                    .id = .http2_parallel_x10_res_1mb,
                    .request_body = "",
                    .response_body = response_body_1mb,
                    .parallel = 10,
                    .warmups = 5,
                    .measured = 20,
                },
                .{
                    .id = .http2_parallel_x10_duplex_1mb_aggregate,
                    .request_body = response_body_1mb,
                    .response_body = response_body_1mb,
                    .parallel = 10,
                    .warmups = 2,
                    .measured = 5,
                },
                .{
                    .id = .http2_parallel_x10_duplex_1mb_streaming,
                    .request_body = response_body_1mb,
                    .response_body = response_body_1mb,
                    .parallel = 10,
                    .warmups = 2,
                    .measured = 5,
                },
            };
            for (scenarios) |scenario| {
                if (shared.scenario != null and
                    scenario.id != shared.scenario.?) continue;
                if (shared.scenario == null and
                    largeScenario(scenario.id)) continue;
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
                            if (body_bytes != scenario.request_body.len or
                                request.body_bytes !=
                                    scenario.request_body.len)
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
                                scenario.request_body,
                            )) {
                                return error.UnexpectedRequestBody;
                            }
                            break :stream request.stream_id;
                        };
                        try connection.writeResponse(stream_id, .{
                            .body = scenario.response_body,
                        });
                    }
                } else {
                    var stream_ids: [10]u31 = undefined;
                    var responses: [10]netz.http2.runtime.ResponseOptions =
                        undefined;
                    @memset(&responses, .{
                        .body = scenario.response_body,
                    });
                    for (0..scenario_iterations) |_| {
                        if (scenario.request_body.len == 0) {
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
                            connection.readRequestBatchStreamingInto(
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
                            ) catch |err| {
                                std.debug.print(
                                    "bench server batch read error: {s}\n",
                                    .{@errorName(err)},
                                );
                                return err;
                            };
                            initialized = true;
                            for (&requests, &stream_ids) |
                                *request,
                                *stream_id,
                            | {
                                stream_id.* = request.stream_id;
                                if (request.body_bytes !=
                                    scenario.request_body.len)
                                {
                                    return error.UnexpectedRequestBody;
                                }
                            }
                            if (body_bytes !=
                                scenario.request_body.len * scenario.parallel)
                            {
                                return error.UnexpectedRequestBody;
                            }
                        }
                        if (scenario.response_body.len == 0) {
                            try connection.writeResponseBatch(
                                &stream_ids,
                                &responses,
                            );
                        } else {
                            // Hyper's h2 scheduler splits Full at the default
                            // 16-KiB DATA limit and requeues the stream after
                            // each frame. Use that as the round-robin
                            // contribution to preserve the same frame order.
                            try connection.writeResponseBodyBatch(
                                &stream_ids,
                                &responses,
                                response_frame_chunk,
                            );
                        }
                    }
                }
            }
        }
    };

    var shared = Shared{
        .server = &server,
        .scenario = options.scenario,
    };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    const authority = try std.fmt.allocPrint(
        allocator,
        "127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(authority);
    const scenarios = [_]Scenario{
        .{
            .id = .http2_consecutive_x1_empty,
            .request = .{
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
            },
        },
        .{
            .id = .http2_shared_consecutive_x1_empty,
            .request = .{
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
            },
            .shared_sender = true,
        },
        .{
            .id = .http2_consecutive_x1_req_10b,
            .request = .{
                .method = "POST",
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
                .body = request_body,
            },
        },
        .{
            .id = .http2_consecutive_x1_req_100kb,
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
            .id = .http2_consecutive_x1_res_10b,
            .request = .{
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
            },
            .response_body = request_body,
        },
        .{
            .id = .http2_parallel_x10_empty,
            .request = .{
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
            },
            .parallel = 10,
        },
        .{
            .id = .http2_parallel_x10_req_10kb_100_chunks_max_window,
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
        .{
            .id = .http2_parallel_x10_res_1mb,
            .request = .{
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
            },
            .response_body = response_body_1mb,
            .streaming_response = true,
            .parallel = 10,
            .warmups = 5,
            .measured = 20,
        },
        .{
            .id = .http2_parallel_x10_duplex_1mb_aggregate,
            .request = .{
                .method = "POST",
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
                .body = response_body_1mb,
            },
            .response_body = response_body_1mb,
            .parallel = 10,
            .warmups = 2,
            .measured = 5,
        },
        .{
            .id = .http2_parallel_x10_duplex_1mb_streaming,
            .request = .{
                .method = "POST",
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
                .body = response_body_1mb,
            },
            .response_body = response_body_1mb,
            .streaming_response = true,
            .parallel = 10,
            .warmups = 2,
            .measured = 5,
        },
    };
    for (scenarios) |scenario| {
        if (options.scenario != null and
            scenario.id != options.scenario.?) continue;
        if (options.scenario == null and
            largeScenario(scenario.id)) continue;
        if (scenario.shared_sender) {
            try benchmarkSharedScenario(
                allocator,
                io,
                server.address(),
                scenario,
                &counting,
                options.stats,
            );
            continue;
        }
        var client = try netz.http2.runtime.Client.connect(
            allocator,
            io,
            server.address(),
            limits,
        );
        defer client.close();

        var requests: [10]netz.http2.runtime.RequestOptions = undefined;
        @memset(requests[0..scenario.parallel], scenario.request);
        for (0..scenario.warmups) |_| {
            try exchangeScenario(
                &client,
                requests[0..scenario.parallel],
                allocator,
                scenario.response_body.len,
                scenario.streaming_response,
            );
        }

        const allocations_before = counting.snapshot();
        const start = nowNs(io);
        var status_total: usize = 0;
        for (0..scenario.measured) |_| {
            try exchangeScenario(
                &client,
                requests[0..scenario.parallel],
                allocator,
                scenario.response_body.len,
                scenario.streaming_response,
            );
            status_total += 200 * scenario.parallel;
        }
        const elapsed = nowNs(io) -| start;
        const allocations_after = counting.snapshot();
        const requests_per_second = if (elapsed == 0)
            0
        else
            (@as(u64, scenario.measured) *| std.time.ns_per_s) / elapsed;

        std.debug.print(
            \\HTTP/2 h2c runtime benchmark
            \\  io backend: zio-std-io
            \\  scenario: {s}
            \\  parallel requests: {d}
            \\  warmup iterations: {d}
            \\  iterations: {d}
            \\  status total: {d}
            \\  ns/op: {d}
            \\  ns/request: {d}
            \\  requests/s: {d}
            \\
        , .{
            @tagName(scenario.id),
            scenario.parallel,
            scenario.warmups,
            scenario.measured,
            status_total,
            elapsed / scenario.measured,
            elapsed / (scenario.measured * scenario.parallel),
            requests_per_second * scenario.parallel,
        });
        if (options.stats) {
            printAllocationDelta(allocations_before, allocations_after);
        }
    }

    server_task.await(io);
    if (shared.err) |err| return err;
}

fn benchmarkSharedScenario(
    allocator: std.mem.Allocator,
    io: std.Io,
    address: std.Io.net.IpAddress,
    scenario: Scenario,
    counting: *CountingAllocator,
    print_stats: bool,
) !void {
    var pool = try netz.http2.client_pool.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
        .limits = limits,
    });
    defer pool.deinit();
    var dispatcher = try netz.http2.client_pool.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 1, .max_batch_requests = 1 },
    );
    defer dispatcher.deinit();
    var driver = try std.Io.concurrent(
        io,
        netz.http2.client_pool.SharedDispatcher.run,
        .{&dispatcher},
    );
    defer _ = driver.cancel(io) catch {};
    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/hello",
        .{address.ip4.port},
    );
    defer allocator.free(uri);
    const sender = dispatcher.sender();

    for (0..scenario.warmups) |_| {
        var response = try sender.request(uri, scenario.request);
        defer response.deinit(allocator);
        if (response.status != 200 or response.body.len != 0) {
            return error.UnexpectedResponse;
        }
    }

    const allocations_before = counting.snapshot();
    const start = nowNs(io);
    var status_total: usize = 0;
    for (0..scenario.measured) |_| {
        var response = try sender.request(uri, scenario.request);
        defer response.deinit(allocator);
        if (response.status != 200 or response.body.len != 0) {
            return error.UnexpectedResponse;
        }
        status_total += response.status;
    }
    const elapsed = nowNs(io) -| start;
    const allocations_after = counting.snapshot();
    dispatcher.close();
    try driver.await(io);

    const requests_per_second = if (elapsed == 0)
        0
    else
        (@as(u64, scenario.measured) *| std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\HTTP/2 SharedSender h2c runtime benchmark
        \\  io backend: zio-std-io
        \\  scenario: {s}
        \\  parallel requests: 1
        \\  warmup iterations: {d}
        \\  iterations: {d}
        \\  status total: {d}
        \\  ns/op: {d}
        \\  ns/request: {d}
        \\  requests/s: {d}
        \\
    , .{
        @tagName(scenario.id),
        scenario.warmups,
        scenario.measured,
        status_total,
        elapsed / scenario.measured,
        elapsed / scenario.measured,
        requests_per_second,
    });
    if (print_stats) {
        printAllocationDelta(allocations_before, allocations_after);
    }
}

fn parseOptions(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !Options {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--stats")) {
            options.stats = true;
        } else if (std.mem.startsWith(u8, arg, "--scenario=")) {
            options.scenario = std.meta.stringToEnum(
                ScenarioId,
                arg["--scenario=".len..],
            ) orelse return error.InvalidArgument;
        } else return error.InvalidArgument;
    }
    return options;
}

fn printAllocationDelta(
    before: @import("support").counting_allocator.Snapshot,
    after: @import("support").counting_allocator.Snapshot,
) void {
    std.debug.print(
        \\  measured allocator calls: {d}
        \\  measured frees: {d}
        \\  measured resize/remap: {d}/{d}
        \\  measured allocated bytes: {d}
        \\  live bytes after measurement: {d}
        \\  peak live bytes: {d}
        \\  measured allocation buckets:
    ++ "\n", .{
        after.alloc_count - before.alloc_count,
        after.free_count - before.free_count,
        after.resize_count - before.resize_count,
        after.remap_count - before.remap_count,
        after.total_allocated - before.total_allocated,
        after.current_bytes,
        after.peak_bytes,
    });
    for (@import("support").counting_allocator.bucket_labels, 0..) |label, index| {
        std.debug.print(
            "    {s}: count={d}, bytes={d}\n",
            .{
                label,
                after.alloc_buckets[index] - before.alloc_buckets[index],
                after.alloc_bucket_bytes[index] -
                    before.alloc_bucket_bytes[index],
            },
        );
    }
    std.debug.print("  measured exact allocation sizes:\n", .{});
    for (after.exact_sizes[0..after.exact_size_len]) |entry| {
        var before_count: usize = 0;
        for (before.exact_sizes[0..before.exact_size_len]) |old_entry| {
            if (old_entry.size != entry.size) continue;
            before_count = old_entry.count;
            break;
        }
        if (entry.count <= before_count) continue;
        std.debug.print(
            "    {d} bytes: {d}\n",
            .{ entry.size, entry.count - before_count },
        );
    }
}

fn validateResponse(response: netz.http2.runtime.OwnedResponse) !void {
    if (response.status != 200 or response.body.len != 0) {
        return error.UnexpectedResponse;
    }
}

fn exchangeScenario(
    client: *netz.http2.runtime.Connection,
    requests: []const netz.http2.runtime.RequestOptions,
    allocator: std.mem.Allocator,
    response_body_len: usize,
    streaming_response: bool,
) !void {
    if (streaming_response) {
        var responses: [10]netz.http2.runtime.StreamingResponse = undefined;
        var body_bytes = [_]usize{0} ** 10;
        const consume = struct {
            fn consume(
                counts: *[10]usize,
                request_index: usize,
                data: []const u8,
            ) !void {
                counts[request_index] += data.len;
            }
        }.consume;
        if (requests[0].body.len == 0) {
            try client.requestBatchStreamingInto(
                requests,
                responses[0..requests.len],
                &body_bytes,
                consume,
            );
        } else {
            client.requestBodyBatchStreamingInto(
                requests,
                parallel_chunk.len,
                responses[0..requests.len],
                &body_bytes,
                consume,
            ) catch |err| {
                std.debug.print(
                    "bench client batch error: {s}\n",
                    .{@errorName(err)},
                );
                return err;
            };
        }
        defer for (responses[0..requests.len]) |*response| {
            response.deinit(allocator);
        };
        for (
            responses[0..requests.len],
            body_bytes[0..requests.len],
        ) |response, streamed_bytes| {
            if (response.status != 200 or
                response.body_bytes != response_body_len or
                streamed_bytes != response_body_len)
            {
                return error.UnexpectedResponse;
            }
        }
        return;
    }

    var responses: [10]netz.http2.runtime.OwnedResponse = undefined;
    const output = responses[0..requests.len];
    if (requests.len == 1) {
        output[0] = try client.request(requests[0]);
    } else if (requests[0].body.len != 0) {
        try client.requestBodyBatchInto(
            requests,
            parallel_chunk.len,
            output,
        );
    } else {
        try client.requestBatchInto(requests, output);
    }
    defer for (output) |*response| response.deinit(allocator);
    for (output) |response| {
        if (response.status != 200 or
            response.body.len != response_body_len)
        {
            return error.UnexpectedResponse;
        }
    }
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

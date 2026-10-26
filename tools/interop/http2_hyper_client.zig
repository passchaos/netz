//! One-shot netz HTTP/2 client for process-boundary interoperability with the
//! audited local Hyper server.

const std = @import("std");
const netz = @import("netz");

const constrained_stream_window = 8 * 1024;
const cancel_response_bytes = 128 * 1024;
const sibling_response_bytes = 16 * 1024;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const pool_mode = std.mem.eql(u8, args[args.len - 1], "--pool");
    const redirect_mode = std.mem.eql(
        u8,
        args[args.len - 1],
        "--redirect",
    );
    if (pool_mode and redirect_mode) return error.InvalidArgument;
    const effective_len = args.len - @intFromBool(pool_mode or redirect_mode);
    if (effective_len != 2 and effective_len != 3) {
        return error.InvalidArgument;
    }
    const tls_enabled = effective_len == 3;
    if (tls_enabled and !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = 256 * 1024,
        .initial_window_size = constrained_stream_window,
        .initial_connection_window_size = 65_535,
        .handshake_timeout = .fromSeconds(5),
    };
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (tls_enabled) {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            args[2],
        );
    }
    if (pool_mode) {
        return runPoolInterop(
            allocator,
            io,
            port,
            tls_enabled,
            &ca_bundle,
            &ca_lock,
            limits,
        );
    }
    if (redirect_mode) {
        return runRedirectInterop(
            allocator,
            io,
            port,
            tls_enabled,
            &ca_bundle,
            &ca_lock,
            limits,
        );
    }
    var connection = if (tls_enabled)
        try netz.http2.runtime.Client.connectTlsHost(
            allocator,
            io,
            "localhost",
            port,
            limits,
            .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        )
    else
        try netz.http2.runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    defer connection.close();

    var response = try connection.request(.{
        .method = "POST",
        .path = "/interop?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-netz-request",
            .value = "request-header",
        }},
        .body = "request-body",
        .trailers = &.{.{
            .name = "x-netz-trailer",
            .value = "request-trailer",
        }},
    });
    defer response.deinit(allocator);

    if (response.status != 201 or
        !std.mem.eql(u8, response.body, "hyper-response") or
        !headerEquals(
            response.headers,
            "x-hyper-response",
            "response-header",
        ) or
        !headerEquals(
            response.trailers,
            "x-hyper-trailer",
            "response-trailer",
        ))
    {
        return error.InvalidResponse;
    }
    if (tls_enabled) {
        const updates = connection.keyUpdateCounts() orelse
            return error.MissingKeyUpdate;
        if (updates.received != 1 or updates.sent != 1 or
            updates.awaiting_peer_response)
        {
            return error.InvalidKeyUpdateCount;
        }
        std.debug.print(
            "netz HTTP/2 client interoperated with rustls KeyUpdate: received=1 sent=1 next_request=true\n",
            .{},
        );
    }

    std.debug.print(
        "netz HTTP/2 client interoperated with Hyper: transport={s} alpn={s} status=201 body=14 trailers=1\n",
        .{ if (tls_enabled) "tls" else "h2c", if (tls_enabled) "h2" else "n/a" },
    );

    // Hyper's connection driver owns the PING/PONG path independently of a
    // request body. Waiting through an idle interval proves the public netz
    // keep-alive scheduler interoperates with that implementation; the
    // following request proves the same connection remains application-usable.
    var keep_alive = try netz.http2.runtime.KeepAlive.init(.{
        .interval = .fromMilliseconds(25),
        .timeout = .fromSeconds(1),
        .while_idle = true,
    });
    if (try keep_alive.run(&connection) != .acknowledged or
        keep_alive.next_payload != 1)
    {
        return error.InvalidResponse;
    }
    var after_keep_alive = try connection.request(.{
        .method = "GET",
        .path = "/after-keep-alive?from=netz",
        .scheme = "http",
        .authority = "localhost",
    });
    defer after_keep_alive.deinit(allocator);
    if (after_keep_alive.status != 200 or
        !std.mem.eql(u8, after_keep_alive.body, "hyper-still-alive"))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/2 keep-alive interoperated with Hyper: transport={s} ack=true next_request=true\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );

    // Open both requests before reading either response. Hyper deliberately
    // withholds the sibling until it observes cancellation of the large body,
    // so completing it proves that only the target stream was retired.
    const request_deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
    var cancel_request = try connection.startRequestWithDeadline(.{
        .method = "GET",
        .path = "/cancel?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .body_length = 0,
    }, request_deadline);
    defer cancel_request.deinit();
    try cancel_request.finishWithDeadline(request_deadline);

    var sibling_request = try connection.startRequestWithDeadline(.{
        .method = "GET",
        .path = "/sibling?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .body_length = 0,
    }, request_deadline);
    defer sibling_request.deinit();
    try sibling_request.finishWithDeadline(request_deadline);

    var cancellation: CancelContext = .{};
    const cancel_result = cancel_request.readResponseStreamingWithHead(
        &cancellation,
        beginCancelResponse,
        cancelResponseBody,
    );
    if (cancel_result) |response_value| {
        var unexpected = response_value;
        unexpected.deinit(allocator);
        return error.ExpectedCancellation;
    } else |err| if (err != error.CancelResponse) {
        return err;
    }
    if (!cancellation.valid_head or
        cancellation.body_bytes != constrained_stream_window or
        cancellation.body_bytes >= cancel_response_bytes)
    {
        return error.InvalidResponse;
    }

    var sibling = try sibling_request.readResponse();
    defer sibling.deinit(allocator);
    if (sibling.status != 200 or
        sibling.body.len != sibling_response_bytes or
        !allBytesEqual(sibling.body, 's') or
        !headerEquals(sibling.headers, "x-hyper-sibling", "after-cancel"))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/2 client canceled flow-blocked Hyper stream and completed concurrent sibling: transport={s} rst=CANCEL window={} received={} sibling={}\n",
        .{ if (tls_enabled) "tls" else "h2c", constrained_stream_window, cancellation.body_bytes, sibling.body.len },
    );

    // Hyper begins graceful shutdown while stream 9 is active. Netz processes
    // the initial GOAWAY/PING synchronization and narrower final GOAWAY while
    // still completing that accepted stream, then rejects stream 11 locally.
    var graceful = try connection.startRequest(.{
        .method = "GET",
        .path = "/graceful?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .body_length = 0,
    });
    defer graceful.deinit();
    try graceful.finish();
    var graceful_response = try graceful.readResponse();
    defer graceful_response.deinit(allocator);
    if (graceful_response.status != 200 or
        !std.mem.eql(u8, graceful_response.body, "hyper-drained"))
    {
        return error.InvalidResponse;
    }
    try std.testing.expectError(
        error.ConnectionGoAway,
        connection.request(.{
            .method = "GET",
            .path = "/after-goaway",
            .scheme = "http",
            .authority = "localhost",
        }),
    );
    std.debug.print(
        "netz HTTP/2 client drained Hyper GOAWAY: transport={s} active_stream=9 new_request_refused=true client_io=zio-std-io server_io=hyper-tokio\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

fn runRedirectInterop(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    tls_enabled: bool,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: *std.Io.RwLock,
    limits: netz.http2.runtime.Limits,
) !void {
    const scheme = if (tls_enabled) "https" else "http";
    const uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/redirect-start?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(uri);
    var result = try netz.http2.runtime.Client
        .requestUriFollowingRedirectsDetailedWithTimeout(
        allocator,
        io,
        uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer hyper-h2-redirect" },
                .{ .name = "content-type", .value = "text/plain" },
            },
            .body = "redirect-body",
        },
        limits,
        .{ .tls = .{ .ca_bundle = if (tls_enabled) .{
            .bundle = ca_bundle,
            .lock = ca_lock,
        } else null } },
        .fromSeconds(5),
    );
    defer result.deinit();
    if (result.response.status != 200 or
        !std.mem.eql(
            u8,
            result.response.body,
            "hyper-h2-redirected",
        ) or result.redirect_count != 1)
    {
        return error.InvalidRedirectResponse;
    }
    std.debug.print(
        "netz HTTP/2 client followed Hyper redirect: transport={s} status=200 redirects=1 method=POST->GET credentials=same-origin\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

fn runPoolInterop(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    tls_enabled: bool,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: *std.Io.RwLock,
    limits: netz.http2.runtime.Limits,
) !void {
    var pool = try netz.http2.client_pool.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
        .limits = limits,
        .tls = .{ .ca_bundle = if (tls_enabled) .{
            .bundle = ca_bundle,
            .lock = ca_lock,
        } else null },
    });
    defer pool.deinit();
    const scheme = if (tls_enabled) "https" else "http";
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/pool-one?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://LOCALHOST:{d}/pool-two?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(second_uri);

    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit(allocator);
    const batch_one_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/pool-batch-one?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(batch_one_uri);
    const batch_two_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://LOCALHOST:{d}/pool-batch-two?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(batch_two_uri);
    const batch_three_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/pool-batch-three?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(batch_three_uri);
    const batch_requests = [_]netz.http2.client_pool.UriBatchRequest{
        .{ .uri = batch_one_uri },
        .{ .uri = batch_two_uri },
        .{ .uri = batch_three_uri },
    };
    var batch_responses: [batch_requests.len]netz.http2.runtime.OwnedResponse =
        undefined;
    try pool.requestUriBatchWithTimeout(
        &batch_requests,
        &batch_responses,
        .fromSeconds(5),
    );
    defer for (&batch_responses) |*response| response.deinit(allocator);
    var dispatcher = try netz.http2.client_pool.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 8, .max_batch_requests = 8 },
    );
    defer dispatcher.deinit();
    const SharedProducer = struct {
        sender: netz.http2.client_pool.SharedSender,
        uri: []const u8,
        request: netz.http2.runtime.RequestOptions,
        deadline: std.Io.Clock.Timestamp,
        response: ?netz.http2.runtime.OwnedResponse = null,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.response = self.sender.requestWithDeadline(
                self.uri,
                self.request,
                self.deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    const SharedStreamingProducer = struct {
        sender: netz.http2.client_pool.SharedSender,
        uri: []const u8,
        request: netz.http2.runtime.RequestOptions,
        deadline: std.Io.Clock.Timestamp,
        expected_path: []const u8,
        expected_byte: u8,
        saw_head: bool = false,
        body_bytes: usize = 0,
        response: ?netz.http2.runtime.StreamingResponse = null,
        err: ?anyerror = null,

        fn begin(
            self: *@This(),
            head: netz.http2.runtime.StreamingResponseHead,
        ) !void {
            if (head.status != 200 or
                !headerEquals(head.headers, "x-path", self.expected_path) or
                !headerEquals(head.headers, "content-length", "65536"))
            {
                return error.InvalidResponse;
            }
            self.saw_head = true;
        }

        fn consume(self: *@This(), data: []const u8) !void {
            if (!self.saw_head or !allBytesEqual(data, self.expected_byte)) {
                return error.InvalidResponse;
            }
            self.body_bytes += data.len;
        }

        fn run(self: *@This()) void {
            self.response = self.sender.requestStreamingWithHeadAndDeadline(
                self.uri,
                self.request,
                self.deadline,
                self,
                begin,
                consume,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    const shared_one_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/pool-shared-one?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(shared_one_uri);
    const shared_two_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://LOCALHOST:{d}/pool-shared-two?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(shared_two_uri);
    const shared_three_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/pool-shared-three?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(shared_three_uri);
    const sender = dispatcher.sender();
    const shared_deadlines = [_]std.Io.Clock.Timestamp{
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
        .fromNow(io, .{ .raw = .fromSeconds(6), .clock = .awake }),
        .fromNow(io, .{ .raw = .fromSeconds(7), .clock = .awake }),
    };
    var producers = [_]SharedProducer{
        .{
            .sender = sender.clone(),
            .uri = shared_one_uri,
            .deadline = shared_deadlines[0],
            .request = .{
                .method = "POST",
                .body = "shared-body-one",
                .trailers = &.{.{
                    .name = "x-shared-request-finished",
                    .value = "one",
                }},
            },
        },
        .{
            .sender = sender.clone(),
            .uri = shared_two_uri,
            .deadline = shared_deadlines[1],
            .request = .{
                .method = "POST",
                .body = "shared-body-two",
                .trailers = &.{.{
                    .name = "x-shared-request-finished",
                    .value = "two",
                }},
            },
        },
        .{
            .sender = sender.clone(),
            .uri = shared_three_uri,
            .deadline = shared_deadlines[2],
            .request = .{
                .method = "POST",
                .body = "shared-body-three",
                .trailers = &.{.{
                    .name = "x-shared-request-finished",
                    .value = "three",
                }},
            },
        },
    };
    var producer_threads: [producers.len]std.Thread = undefined;
    for (&producer_threads, &producers) |*thread, *producer| {
        thread.* = try std.Thread.spawn(.{}, SharedProducer.run, .{producer});
    }
    var queued_attempts: usize = 0;
    while (dispatcher.queuedCount() != producers.len and
        queued_attempts < 500) : (queued_attempts += 1)
    {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    if (dispatcher.queuedCount() != producers.len) return error.Timeout;
    var driver = try std.Io.concurrent(
        io,
        netz.http2.client_pool.SharedDispatcher.run,
        .{&dispatcher},
    );
    const ProducerJoiner = struct {
        dispatcher: *netz.http2.client_pool.SharedDispatcher,
        threads: []std.Thread,

        fn run(self: *@This()) void {
            for (self.threads) |*thread| thread.join();
            self.dispatcher.close();
        }
    };
    var producer_joiner = ProducerJoiner{
        .dispatcher = &dispatcher,
        .threads = &producer_threads,
    };
    const producer_join_thread = try std.Thread.spawn(
        .{},
        ProducerJoiner.run,
        .{&producer_joiner},
    );
    var driver_err: ?anyerror = null;
    driver.await(io) catch |err| {
        driver_err = err;
    };
    producer_join_thread.join();
    if (driver_err) |err| return err;
    const shared_expected = [_][]const u8{
        "pool-shared-one",
        "pool-shared-two",
        "pool-shared-three",
    };
    for (&producers, shared_expected) |*producer, expected| {
        if (producer.err) |err| return err;
        if (!std.mem.eql(u8, producer.response.?.body, expected)) {
            return error.InvalidResponse;
        }
    }
    defer for (&producers) |*producer| {
        if (producer.response) |*response| response.deinit(allocator);
    };
    const shared_stats = dispatcher.stats();
    if (shared_stats.batches != 1 or
        shared_stats.coalesced_requests != producers.len)
    {
        return error.InvalidResponse;
    }

    var streaming_dispatcher =
        try netz.http2.client_pool.SharedDispatcher.init(
            allocator,
            io,
            &pool,
            .{ .max_queued_requests = 8, .max_batch_requests = 8 },
        );
    defer streaming_dispatcher.deinit();
    const streaming_uris = [_][]u8{
        try std.fmt.allocPrint(
            allocator,
            "{s}://localhost:{d}/pool-shared-stream-one?from=netz",
            .{ scheme, port },
        ),
        try std.fmt.allocPrint(
            allocator,
            "{s}://LOCALHOST:{d}/pool-shared-stream-two?from=netz",
            .{ scheme, port },
        ),
        try std.fmt.allocPrint(
            allocator,
            "{s}://localhost:{d}/pool-shared-stream-three?from=netz",
            .{ scheme, port },
        ),
    };
    defer for (streaming_uris) |uri| allocator.free(uri);
    const streaming_paths = [_][]const u8{
        "/pool-shared-stream-one?from=netz",
        "/pool-shared-stream-two?from=netz",
        "/pool-shared-stream-three?from=netz",
    };
    const streaming_bodies = [_][]const u8{
        "stream-request-one",
        "stream-request-two",
        "stream-request-three",
    };
    const streaming_trailers = [_][]const u8{ "one", "two", "three" };
    const streaming_bytes = [_]u8{ 'a', 'b', 'c' };
    const streaming_sender = streaming_dispatcher.sender();
    var streaming_request_trailer_fields: [streaming_uris.len][1]netz.http2.Hpack.HeaderField = undefined;
    var streaming_producers: [streaming_uris.len]SharedStreamingProducer =
        undefined;
    for (
        &streaming_producers,
        streaming_uris,
        streaming_paths,
        streaming_bodies,
        streaming_trailers,
        streaming_bytes,
        0..,
    ) |
        *producer,
        uri,
        path,
        body,
        trailer,
        expected_byte,
        index,
    | {
        streaming_request_trailer_fields[index][0] = .{
            .name = "x-shared-request-finished",
            .value = trailer,
        };
        producer.* = .{
            .sender = streaming_sender.clone(),
            .uri = uri,
            .request = .{
                .method = "POST",
                .body = body,
                .trailers = &streaming_request_trailer_fields[index],
            },
            .deadline = .fromNow(io, .{
                .raw = .fromSeconds(@intCast(5 + index)),
                .clock = .awake,
            }),
            .expected_path = path,
            .expected_byte = expected_byte,
        };
    }
    var streaming_threads: [streaming_producers.len]std.Thread = undefined;
    for (&streaming_threads, &streaming_producers) |*thread, *producer| {
        thread.* = try std.Thread.spawn(
            .{},
            SharedStreamingProducer.run,
            .{producer},
        );
    }
    queued_attempts = 0;
    while (streaming_dispatcher.queuedCount() != streaming_producers.len and
        queued_attempts < 500) : (queued_attempts += 1)
    {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    if (streaming_dispatcher.queuedCount() != streaming_producers.len) {
        return error.Timeout;
    }
    var streaming_driver = try std.Io.concurrent(
        io,
        netz.http2.client_pool.SharedDispatcher.run,
        .{&streaming_dispatcher},
    );
    var streaming_joiner = ProducerJoiner{
        .dispatcher = &streaming_dispatcher,
        .threads = &streaming_threads,
    };
    const streaming_join_thread = try std.Thread.spawn(
        .{},
        ProducerJoiner.run,
        .{&streaming_joiner},
    );
    driver_err = null;
    streaming_driver.await(io) catch |err| {
        driver_err = err;
    };
    streaming_join_thread.join();
    if (driver_err) |err| return err;
    for (
        &streaming_producers,
        streaming_trailers,
    ) |*producer, expected_trailer| {
        if (producer.err) |err| return err;
        const response = &producer.response.?;
        if (!producer.saw_head or producer.body_bytes != 64 * 1024 or
            response.body_bytes != 64 * 1024 or
            !headerEquals(
                response.trailers,
                "x-shared-response-finished",
                expected_trailer,
            ))
        {
            return error.InvalidResponse;
        }
    }
    defer for (&streaming_producers) |*producer| {
        if (producer.response) |*response| response.deinit(allocator);
    };
    const streaming_stats = streaming_dispatcher.stats();
    if (streaming_stats.batches != 1 or
        streaming_stats.coalesced_requests != streaming_producers.len)
    {
        return error.InvalidResponse;
    }

    var cancel_dispatcher = try netz.http2.client_pool.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 4, .max_batch_requests = 4 },
    );
    defer cancel_dispatcher.deinit();
    const active_cancel_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/pool-shared-active-cancel?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(active_cancel_uri);
    const active_sibling_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://LOCALHOST:{d}/pool-shared-active-sibling?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(active_sibling_uri);
    const cancel_sender = cancel_dispatcher.sender();
    const cancel_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    var cancel_producers = [_]SharedProducer{
        .{
            .sender = cancel_sender.clone(),
            .uri = active_cancel_uri,
            .deadline = cancel_deadline,
            .request = .{},
        },
        .{
            .sender = cancel_sender.clone(),
            .uri = active_sibling_uri,
            .deadline = cancel_deadline,
            .request = .{},
        },
    };
    var cancel_future = try std.Io.concurrent(
        io,
        SharedProducer.run,
        .{&cancel_producers[0]},
    );
    queued_attempts = 0;
    while (cancel_dispatcher.queuedCount() != 1 and
        queued_attempts < 500) : (queued_attempts += 1)
    {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    if (cancel_dispatcher.queuedCount() != 1) return error.Timeout;
    var sibling_future = try std.Io.concurrent(
        io,
        SharedProducer.run,
        .{&cancel_producers[1]},
    );
    queued_attempts = 0;
    while (cancel_dispatcher.queuedCount() != cancel_producers.len and
        queued_attempts < 500) : (queued_attempts += 1)
    {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    if (cancel_dispatcher.queuedCount() != cancel_producers.len) {
        return error.Timeout;
    }
    var cancel_driver = try std.Io.concurrent(
        io,
        netz.http2.client_pool.SharedDispatcher.run,
        .{&cancel_dispatcher},
    );
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    const cancel_started = std.Io.Clock.awake.now(io);
    cancel_future.cancel(io);
    const cancel_elapsed = cancel_started.durationTo(
        std.Io.Clock.awake.now(io),
    );
    const active_cancel_err = cancel_producers[0].err orelse
        return error.InvalidResponse;
    if (cancel_elapsed.nanoseconds >=
        std.Io.Duration.fromSeconds(2).nanoseconds or
        active_cancel_err != error.Canceled or
        cancel_producers[0].response != null)
    {
        return error.InvalidResponse;
    }
    sibling_future.await(io);
    if (cancel_producers[1].err) |err| return err;
    if (!std.mem.eql(
        u8,
        cancel_producers[1].response.?.body,
        "active-sibling-finished",
    )) {
        return error.InvalidResponse;
    }
    defer if (cancel_producers[1].response) |*response| {
        response.deinit(allocator);
    };
    cancel_dispatcher.close();
    try cancel_driver.await(io);
    const cancel_stats = cancel_dispatcher.stats();
    if (cancel_stats.batches != 1 or
        cancel_stats.coalesced_requests != cancel_producers.len)
    {
        return error.InvalidResponse;
    }
    const redirect_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/pool-redirect-start?from=netz",
        .{ scheme, port },
    );
    defer allocator.free(redirect_uri);
    var redirected = try pool.requestUriFollowingRedirectsDetailedWithTimeout(
        redirect_uri,
        .{
            .method = "POST",
            .headers = &.{.{
                .name = "authorization",
                .value = "Bearer h2-pool-redirect",
            }},
            .body = "pool-body",
        },
        .{},
        .fromSeconds(5),
    );
    defer redirected.deinit();
    if (first.status != 200 or second.status != 200 or
        !std.mem.eql(u8, first.body, "pool-one") or
        !std.mem.eql(u8, second.body, "pool-two") or
        !std.mem.eql(u8, batch_responses[0].body, "pool-batch-one") or
        !std.mem.eql(u8, batch_responses[1].body, "pool-batch-two") or
        !std.mem.eql(u8, batch_responses[2].body, "pool-batch-three") or
        !std.mem.eql(u8, redirected.response.body, "pool-redirected") or
        redirected.redirect_count != 1 or
        pool.idleCount() != 1 or pool.connectionCount() != 1)
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/2 pool multiplexed Hyper batch, aggregate/streaming shared senders, active cancellation, and redirect: transport={s} requests=15 batch=3 shared=8 streamed_bytes=196608 active_cancel=1 redirects=1 idle=1 total=1 client_io=zio-std-io server_io=hyper-tokio\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

const CancelContext = struct {
    valid_head: bool = false,
    body_bytes: usize = 0,
};

fn beginCancelResponse(
    context: *CancelContext,
    head: netz.http2.runtime.StreamingResponseHead,
) !void {
    context.valid_head = head.status == 200 and
        headerEquals(
            head.headers,
            "content-length",
            "131072",
        ) and
        headerEquals(
            head.headers,
            "x-hyper-cancel-body",
            "131072",
        );
}

fn cancelResponseBody(
    context: *CancelContext,
    data: []const u8,
) error{ CancelResponse, InvalidResponse }!void {
    if (!allBytesEqual(data, 'h')) return error.InvalidResponse;
    context.body_bytes += data.len;
    // The advertised stream window is now fully consumed. Returning an error
    // makes the runtime restore the charged connection credit and emit the
    // target stream's RST_STREAM(CANCEL) before reading the sibling response.
    if (context.body_bytes >= constrained_stream_window) {
        return error.CancelResponse;
    }
}

fn allBytesEqual(bytes: []const u8, expected: u8) bool {
    for (bytes) |byte| if (byte != expected) return false;
    return true;
}

fn headerEquals(
    headers: []const netz.http2.Hpack.HeaderField,
    name: []const u8,
    value: []const u8,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) {
            return std.mem.eql(u8, header.value, value);
        }
    }
    return false;
}

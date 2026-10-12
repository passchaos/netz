//! One-shot netz HTTP/3 server for process-boundary interoperability with a
//! certificate-verifying quic-go client.

const std = @import("std");
const netz = @import("netz");
const benchmark = @import("http3_quic_go_bench.zig");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

const cancellation_response_size = 128 * 1024;
const stream_receive_window = 8 * 1024;
const connection_receive_window = 24 * 1024;
const read_before_cancel = 12 * 1024;
const cancellation_prefix = "n" ** read_before_cancel;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 3 and std.mem.eql(u8, args[1], "bench-server")) {
        return runBenchmark(init, args[2..]);
    }
    if (args.len < 2 or args.len > 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    var version: netz.quic.Version = .version_1;
    var version_set = false;
    var informational = false;
    var handler_supervisor = false;
    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "--version=2") and !version_set) {
            version = .version_2;
            version_set = true;
        } else if (std.mem.eql(u8, arg, "--informational") and
            !informational)
        {
            informational = true;
        } else if (std.mem.eql(u8, arg, "--handler-supervisor") and
            !handler_supervisor)
        {
            handler_supervisor = true;
        } else {
            return error.InvalidArgument;
        }
    }
    if (informational and handler_supervisor) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var local_transport_parameters = netz.quic.practical_transport_parameters;
    local_transport_parameters.initial_max_data = connection_receive_window;
    local_transport_parameters.initial_max_stream_data_bidi_remote =
        stream_receive_window;

    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .version = version,
                .available_versions = if (version == .version_2)
                    &.{.version_2}
                else
                    &.{ .version_1, .version_2 },
                .local_transport_parameters = local_transport_parameters,
                .initial_one_rtt_config = .{
                    .receive_window = connection_receive_window,
                    .max_receive_window = connection_receive_window,
                    .stream_receive_window = stream_receive_window,
                    .max_stream_receive_window = stream_receive_window,
                    .max_datagram_size = 4096,
                },
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 1200,
            },
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz HTTP/3 quic-go interop server listening on {f}\n",
        .{server.address()},
    );

    if (handler_supervisor) {
        var endpoint = try netz.http3.runtime.EndpointServer.init(&server, .{
            .max_pending_handshakes = 2,
            .max_connections = 2,
            .inbox_capacity = 8,
        });
        defer endpoint.deinit();
        const Context = struct {
            const headers = [_]netz.http3.Qpack.HeaderField{.{
                .name = "x-netz-handler",
                .value = "concurrent",
            }};
            const trailers = [_]netz.http3.Qpack.HeaderField{.{
                .name = "x-netz-handler",
                .value = "complete",
            }};

            io: std.Io,
            entered: std.atomic.Value(usize) = .init(0),
            both_entered: std.Io.Event = .unset,

            fn handle(
                self: *@This(),
                request: *const netz.http3.runtime.OwnedEndpointRequest,
            ) netz.http3.runtime.Error!netz.http3.Response {
                if (!std.mem.eql(u8, request.method, "POST") or
                    request.body.len == 0)
                {
                    return error.InvalidHeader;
                }
                if (self.entered.fetchAdd(1, .acq_rel) + 1 == 2) {
                    self.both_entered.set(self.io);
                }
                self.both_entered.waitTimeout(self.io, .{
                    .duration = .{
                        .clock = .awake,
                        .raw = .fromSeconds(5),
                    },
                }) catch return error.InvalidHeader;
                return .{
                    .status = 200,
                    .headers = &headers,
                    .body = request.body,
                    .trailers = &trailers,
                };
            }
        };
        var context = Context{ .io = io };
        var shutdown: std.Io.Event = .unset;
        try endpoint.serveHandlersUntil(
            Context,
            &context,
            Context.handle,
            .{
                .shutdown = &shutdown,
                .supported_versions = if (version == .version_2)
                    &.{netz.quic.Version.version_2.wireValue()}
                else
                    &.{netz.quic.Version.version_1.wireValue()},
                .max_handler_tasks = 2,
                .max_pending_requests = 4,
                .max_request_body_bytes = 4096,
                .stop_after_responses = 2,
                .poll_interval = .{
                    .clock = .awake,
                    .raw = .fromMilliseconds(1),
                },
                .error_policy = .stop,
            },
        );
        try std.Io.sleep(io, .fromMilliseconds(250), .awake);
        std.debug.print(
            "netz HTTP/3 endpoint handler supervisor served quic-go: version={d} connections=2 handlers=2 concurrent=true bodies=2 trailers=2 server_io=zio-std-io\n",
            .{if (version == .version_2) @as(u8, 2) else 1},
        );
        return;
    }

    var session = try server.accept();
    defer session.deinit();
    try session.sendOrigins(&.{"https://localhost"});
    if (informational) {
        var request = try session.receiveRequest();
        defer request.deinit(allocator);
        if (!std.mem.eql(
            u8,
            request.request.path,
            "/informational?from=quic-go",
        )) {
            return error.InvalidRequest;
        }
        try session.sendResponseWithInformational(
            request.stream_id,
            &.{
                .{
                    .status = 103,
                    .headers = &.{.{
                        .name = "link",
                        .value = "</netz.css>",
                    }},
                },
                .{
                    .status = 102,
                    .headers = &.{.{
                        .name = "x-progress",
                        .value = "half",
                    }},
                },
            },
            .{
                .status = 200,
                .headers = &.{.{
                    .name = "x-netz-final",
                    .value = "yes",
                }},
                .body = "final",
            },
        );
        try std.Io.sleep(io, .fromMilliseconds(250), .awake);
        std.debug.print(
            "netz HTTP/3 server sent informational responses to quic-go: version={d} origin=true statuses=103,102 final=200 body=5\n",
            .{if (version == .version_2) @as(u8, 2) else 1},
        );
        return;
    }

    var canceled = try session.receiveRequest();
    defer canceled.deinit(allocator);
    if (canceled.stream_id != 0 or
        !std.mem.eql(u8, canceled.request.method, "GET") or
        !std.mem.eql(
            u8,
            canceled.request.path,
            "/cancel-response?from=quic-go",
        ) or
        canceled.request.body.len != 0)
    {
        return error.InvalidRequest;
    }
    try session.startResponse(canceled.stream_id, .{
        .status = 200,
        .headers = &.{.{
            .name = "x-netz-cancel",
            .value = "large-response-started",
        }},
    }, cancellation_response_size);

    // The response head lets quic-go start stream 4, but no cancellation body
    // is sent until that sibling is already present on this same session.
    var request = try session.receiveRequest();
    defer request.deinit(allocator);
    if (request.stream_id != 4 or
        !std.mem.eql(u8, request.request.method, "POST") or
        !std.mem.eql(u8, request.request.path, "/interop?from=quic-go") or
        !std.mem.eql(u8, request.request.scheme, "https") or
        request.request.authority == null or
        !std.mem.eql(u8, request.request.authority.?, "localhost") or
        !std.mem.eql(u8, request.request.body, "quic-go-request") or
        !headerEquals(
            request.request.headers,
            "x-quic-go-request",
            "request-header",
        ) or
        !headerEquals(
            request.request.trailers,
            "x-quic-go-trailer",
            "request-trailer",
        ))
    {
        return error.InvalidRequest;
    }
    try session.sendResponseBodyPaced(
        canceled.stream_id,
        cancellation_prefix,
        false,
    );
    const cancellation = try session.receivePeerResponseCancellation(
        canceled.stream_id,
    );
    if (cancellation.application_error_code !=
        netz.http3.ApplicationErrorCode.request_cancelled)
    {
        return error.UnexpectedCancellationCode;
    }

    try session.startResponse(request.stream_id, .{
        .status = 201,
        .headers = &.{.{
            .name = "x-netz-response",
            .value = "response-header",
        }},
    }, "netz-response".len);
    try session.sendResponseBodyPaced(
        request.stream_id,
        "netz-",
        false,
    );
    try session.sendResponseBodyPaced(
        request.stream_id,
        "response",
        false,
    );
    try session.finishResponseTrailersPaced(request.stream_id, &.{.{
        .name = "x-netz-trailer",
        .value = "response-trailer",
    }});
    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    std.debug.print(
        "netz HTTP/3 server interoperated with quic-go: version={d} origin=true cancel=H3_REQUEST_CANCELLED concurrent_sibling=true connection_reused=true stream_window={d} read_before_cancel={d} large_response={d} request_body=15 request_trailers=1 response_body=13 response_trailers=1\n",
        .{
            if (version == .version_2) @as(u8, 2) else 1,
            stream_receive_window,
            read_before_cancel,
            cancellation_response_size,
        },
    );
}

const BenchmarkRequest = struct {
    stream_id: u62,
    close: bool,
    ready: bool = false,
    round: u32 = 0,
    bytes: usize = 0,
    checksum: u64 = 0,
};

fn runBenchmark(_: std.process.Init, args: []const []const u8) !void {
    if (args.len == 0) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[0], 10);
    var stats = false;
    var role_pair: []const u8 = "quic-go-client+netz-server";
    var role_pair_set = false;
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--stats") and !stats) {
            stats = true;
        } else if (std.mem.startsWith(u8, arg, "--role-pair=") and
            !role_pair_set)
        {
            role_pair = arg["--role-pair=".len..];
            role_pair_set = true;
        } else {
            try config_args.append(std.heap.c_allocator, arg);
        }
    }
    if (!std.mem.eql(u8, role_pair, "quic-go-client+netz-server") and
        !std.mem.eql(u8, role_pair, "netz-client+netz-server"))
    {
        return error.InvalidArgument;
    }
    const config = try benchmark.Config.parse(config_args.items);
    if (stats and (config.capture or config.socket_traffic)) {
        return error.InvalidArgument;
    }
    var counting = CountingAllocator.init(std.heap.c_allocator);
    const allocator = if (stats) counting.allocator() else std.heap.c_allocator;
    defer if (stats) benchmark.printNetzMemory(
        role_pair,
        "server",
        config,
        counting.snapshot(),
    );
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var socket_traffic: netz.quic.runtime.SocketTrafficCounters = .{};

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = benchmark.max_frames,
            .enable_gso_send = false,
            .enable_gro_receive = false,
            .socket_traffic_counters = if (config.socket_traffic)
                &socket_traffic
            else
                null,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .version = config.version,
                .available_versions = if (config.version == .version_2)
                    &.{.version_2}
                else
                    &.{.version_1},
                .local_transport_parameters = try config.transportParameters(),
                .initial_one_rtt_config = try config.oneRttConfig(),
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .max_crypto_buffer = 64 * 1024,
            },
            .session = try config.sessionOptions(),
        },
    );
    defer server.deinit();
    std.debug.print("NETZ_HTTP3_BENCH_PORT={d}\n", .{server.address().ip4.port});
    try benchmark.printConfig(
        "netz",
        role_pair,
        "server",
        config,
    );
    var payloads = try benchmark.PayloadSet.init(allocator, config);
    defer payloads.deinit(allocator);
    const read_buffer = try allocator.alloc(u8, config.effectiveChunk());
    defer allocator.free(read_buffer);

    for (0..try config.rounds()) |round_index| {
        var session = try server.acceptWithTimeout(config.timeout());
        defer session.deinit();
        const ready = try receiveBenchmarkRequest(
            allocator,
            &session,
            config,
            0,
            read_buffer,
        );
        if (!ready.ready) return error.InvalidRequest;
        try session.sendResponsePacedWithTimeout(ready.stream_id, .{
            .status = 200,
            .headers = &.{.{ .name = "x-netz-bench-ready", .value = "ok" }},
        }, config.timeout());
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = config.timeout(),
            .clock = .awake,
        });
        var stream_ids = [_]u62{std.math.maxInt(u62)} ** benchmark.max_streams;
        try receiveBenchmarkRequests(
            allocator,
            &session,
            config,
            @intCast(round_index),
            &payloads,
            &stream_ids,
            read_buffer,
            deadline,
        );
        switch (config.mode) {
            .upload => for (stream_ids[0..config.streams], 0..) |stream_id, index| {
                try sendBenchmarkResponse(
                    &session,
                    config,
                    stream_id,
                    @intCast(round_index),
                    index,
                    payloads.checksums[index],
                    &.{},
                    deadline,
                );
            },
            .download => {
                var responses: [benchmark.max_streams]netz.http3.runtime.ResponseBody = undefined;
                for (stream_ids[0..config.streams], 0..) |stream_id, index| {
                    try startBenchmarkResponse(
                        &session,
                        config,
                        stream_id,
                        @intCast(round_index),
                        index,
                        payloads.checksums[index],
                        payloads.streams[index].len,
                        deadline,
                    );
                    responses[index] = .{
                        .stream_id = stream_id,
                        .data = payloads.streams[index],
                    };
                }
                var committed_bytes = [_]usize{0} ** benchmark.max_streams;
                try session.sendResponseBodiesPacedWithDeadline(
                    responses[0..config.streams],
                    committed_bytes[0..config.streams],
                    deadline,
                );
                for (committed_bytes[0..config.streams], payloads.streams[0..config.streams]) |committed, payload| {
                    if (committed != payload.len) {
                        return error.IncompleteBenchmarkSend;
                    }
                }
            },
        }
        try session.waitForRecoveryIdleWithDeadline(deadline);
        if (round_index >= config.warmup) {
            benchmark.printServerComplete(
                "netz",
                role_pair,
                config,
                @intCast(round_index - config.warmup + 1),
                payloads.aggregate_checksum,
            );
        }
        const close = try receiveBenchmarkRequest(
            allocator,
            &session,
            config,
            @intCast(round_index),
            read_buffer,
        );
        if (!close.close or close.ready or close.round != round_index) {
            return error.InvalidRequest;
        }
        try session.sendResponsePacedWithTimeout(close.stream_id, .{
            .status = 200,
            .headers = &.{.{ .name = "x-netz-bench-close", .value = "ok" }},
        }, config.timeout());
    }
    if (config.socket_traffic) {
        benchmark.printSocketTraffic(
            "netz",
            role_pair,
            "server",
            config,
            socket_traffic.stats(),
        );
    }
}

const BenchmarkStreamState = struct {
    stream_id: ?u62 = null,
    head_seen: bool = false,
    finished: bool = false,
    bytes: usize = 0,
    checksum: u64 = 0,
};

fn receiveBenchmarkRequests(
    allocator: std.mem.Allocator,
    session: *netz.http3.runtime.HandshakeServerSession,
    config: benchmark.Config,
    expected_round: u32,
    payloads: *const benchmark.PayloadSet,
    stream_ids: *[benchmark.max_streams]u62,
    read_buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var states = [_]BenchmarkStreamState{.{}} ** benchmark.max_streams;
    var complete: usize = 0;
    while (complete < config.streams) {
        var event = try session.receiveRequestEventWithDeadline(deadline);
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.InvalidRequest,
            .message => |message| switch (message.value) {
                .head => |head| switch (head) {
                    .request => |request| {
                        const index = try validateBenchmarkRequestHead(
                            request,
                            config,
                            expected_round,
                        );
                        if (states[index].head_seen or
                            benchmark.streamIndexForId(
                                stream_ids[0..config.streams],
                                message.stream_id,
                            ) != null)
                        {
                            return error.InvalidRequest;
                        }
                        states[index].stream_id = message.stream_id;
                        states[index].head_seen = true;
                        stream_ids[index] = message.stream_id;
                    },
                    .response => return error.InvalidRequest,
                },
                .data_available => {
                    const index = benchmark.streamIndexForId(
                        stream_ids[0..config.streams],
                        message.stream_id,
                    ) orelse return error.InvalidRequest;
                    const state = &states[index];
                    if (!state.head_seen or state.finished or
                        config.mode != .upload)
                    {
                        return error.InvalidRequest;
                    }
                    const count = try session.readRequestData(
                        message.stream_id,
                        read_buffer,
                    );
                    if (state.bytes + count > config.body_bytes) {
                        return error.InvalidRequest;
                    }
                    try benchmark.verifyStreamPayload(
                        read_buffer[0..count],
                        index,
                        state.bytes,
                        &state.checksum,
                    );
                    state.bytes += count;
                },
                .finished => {
                    const index = benchmark.streamIndexForId(
                        stream_ids[0..config.streams],
                        message.stream_id,
                    ) orelse return error.InvalidRequest;
                    const state = &states[index];
                    const expected_bytes: usize = if (config.mode == .upload)
                        @intCast(config.body_bytes)
                    else
                        0;
                    const expected_checksum = if (config.mode == .upload)
                        payloads.checksums[index]
                    else
                        0;
                    if (!state.head_seen or state.finished or
                        state.bytes != expected_bytes or
                        state.checksum != expected_checksum)
                    {
                        return error.InvalidRequest;
                    }
                    state.finished = true;
                    complete += 1;
                },
                .trailers, .push_promise => return error.InvalidRequest,
            },
        }
    }
}

fn receiveBenchmarkRequest(
    allocator: std.mem.Allocator,
    session: *netz.http3.runtime.HandshakeServerSession,
    config: benchmark.Config,
    expected_round: u32,
    buffer: []u8,
) !BenchmarkRequest {
    var result = BenchmarkRequest{ .stream_id = 0, .close = false };
    var head_seen = false;
    var finished = false;
    while (!finished) {
        var event = try session.receiveRequestEventWithTimeout(config.timeout());
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.InvalidRequest,
            .message => |message| switch (message.value) {
                .head => |head| switch (head) {
                    .request => |request| {
                        if (head_seen) return error.InvalidRequest;
                        result.stream_id = message.stream_id;
                        result.close = std.mem.eql(
                            u8,
                            request.path,
                            "/benchmark/close",
                        );
                        result.ready = std.mem.eql(
                            u8,
                            request.path,
                            "/benchmark/ready",
                        );
                        if (result.close or result.ready) {
                            if (!std.mem.eql(u8, request.method, "GET") or
                                !std.mem.eql(u8, request.scheme, "https") or
                                request.authority == null or
                                !std.mem.eql(
                                    u8,
                                    request.authority.?,
                                    "localhost",
                                ) or
                                request.content_length != null)
                            {
                                return error.InvalidRequest;
                            }
                            if (result.close) {
                                result.round = std.math.cast(
                                    u32,
                                    try benchmark.parseHeaderInt(
                                        request.headers,
                                        "x-netz-bench-round",
                                    ),
                                ) orelse return error.InvalidRequest;
                            }
                        } else {
                            const method = if (config.mode == .upload)
                                "POST"
                            else
                                "GET";
                            const path = if (config.mode == .upload)
                                "/benchmark/upload"
                            else
                                "/benchmark/download";
                            if (!std.mem.eql(u8, request.method, method) or
                                !std.mem.eql(u8, request.path, path) or
                                !std.mem.eql(
                                    u8,
                                    benchmark.header(
                                        request.headers,
                                        "x-netz-bench-mode",
                                    ) orelse return error.InvalidRequest,
                                    config.mode.name(),
                                ) or
                                try benchmark.parseHeaderInt(
                                    request.headers,
                                    "x-netz-bench-round",
                                ) != expected_round or
                                try benchmark.parseHeaderInt(
                                    request.headers,
                                    "x-netz-bench-bytes",
                                ) != config.body_bytes or
                                try benchmark.parseHeaderInt(
                                    request.headers,
                                    "x-netz-bench-chunk",
                                ) != config.chunk_bytes or
                                try benchmark.parseHeaderInt(
                                    request.headers,
                                    "x-netz-bench-window",
                                ) != config.stream_window or
                                (config.mode == .upload and
                                    request.content_length != config.body_bytes) or
                                (config.mode == .download and
                                    request.content_length != null))
                            {
                                return error.InvalidRequest;
                            }
                            result.round = expected_round;
                        }
                        head_seen = true;
                    },
                    .response => return error.InvalidRequest,
                },
                .data_available => {
                    if (!head_seen or result.close or result.ready or
                        config.mode != .upload)
                    {
                        return error.InvalidRequest;
                    }
                    const count = try session.readRequestData(
                        message.stream_id,
                        buffer,
                    );
                    if (result.bytes + count > config.body_bytes) {
                        return error.InvalidRequest;
                    }
                    try benchmark.verifyPayload(
                        buffer[0..count],
                        result.bytes,
                        &result.checksum,
                    );
                    result.bytes += count;
                },
                .finished => {
                    if (!head_seen or message.stream_id != result.stream_id) {
                        return error.InvalidRequest;
                    }
                    finished = true;
                },
                .trailers, .push_promise => return error.InvalidRequest,
            },
        }
    }
    return result;
}

fn sendBenchmarkResponse(
    session: *netz.http3.runtime.HandshakeServerSession,
    config: benchmark.Config,
    stream_id: u62,
    round: u32,
    stream_index: usize,
    checksum: u64,
    body: []const u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    try startBenchmarkResponse(
        session,
        config,
        stream_id,
        round,
        stream_index,
        checksum,
        body.len,
        deadline,
    );
    if (body.len == 0) return;
    var offset: usize = 0;
    while (offset < body.len) {
        const end = @min(body.len, offset + config.effectiveChunk());
        const chunk = [_]netz.http3.runtime.BodyChunk{.{
            .stream_id = stream_id,
            .data = body[offset..end],
            .fin = end == body.len,
        }};
        var committed: usize = 0;
        try session.sendResponseBodyBatchPacedWithDeadline(
            &chunk,
            &committed,
            deadline,
        );
        if (committed != 1) return error.IncompleteBenchmarkSend;
        offset = end;
    }
}

fn startBenchmarkResponse(
    session: *netz.http3.runtime.HandshakeServerSession,
    config: benchmark.Config,
    stream_id: u62,
    round: u32,
    stream_index: usize,
    checksum: u64,
    body_len: usize,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var round_buffer: [10]u8 = undefined;
    var index_buffer: [5]u8 = undefined;
    var bytes_buffer: [20]u8 = undefined;
    var checksum_buffer: [20]u8 = undefined;
    var streams_buffer: [5]u8 = undefined;
    const headers = [_]netz.http3.Qpack.HeaderField{
        .{ .name = "x-netz-bench-round", .value = try std.fmt.bufPrint(&round_buffer, "{d}", .{round}) },
        .{ .name = "x-netz-bench-stream-index", .value = try std.fmt.bufPrint(&index_buffer, "{d}", .{stream_index}) },
        .{ .name = "x-netz-bench-streams", .value = try std.fmt.bufPrint(&streams_buffer, "{d}", .{config.streams}) },
        .{ .name = "x-netz-bench-bytes", .value = try std.fmt.bufPrint(&bytes_buffer, "{d}", .{config.body_bytes}) },
        .{ .name = "x-netz-bench-checksum", .value = try std.fmt.bufPrint(&checksum_buffer, "{d}", .{checksum}) },
    };
    if (body_len == 0) {
        try session.sendResponsePacedWithDeadline(
            stream_id,
            .{ .status = 200, .headers = &headers },
            deadline,
        );
        return;
    }
    try session.startResponse(
        stream_id,
        .{ .status = 200, .headers = &headers },
        body_len,
    );
}

fn validateBenchmarkRequestHead(
    request: netz.http3.DecodedRequestHead,
    config: benchmark.Config,
    expected_round: u32,
) !usize {
    const method = if (config.mode == .upload) "POST" else "GET";
    const path = if (config.mode == .upload) "/benchmark/upload" else "/benchmark/download";
    const index = std.math.cast(usize, try benchmark.parseHeaderInt(
        request.headers,
        "x-netz-bench-stream-index",
    )) orelse return error.InvalidRequest;
    if (index >= config.streams or !std.mem.eql(u8, request.method, method) or
        !std.mem.eql(u8, request.path, path) or
        !std.mem.eql(u8, request.scheme, "https") or request.authority == null or
        !std.mem.eql(u8, request.authority.?, "localhost") or
        !std.mem.eql(u8, benchmark.header(request.headers, "x-netz-bench-mode") orelse return error.InvalidRequest, config.mode.name()) or
        try benchmark.parseHeaderInt(request.headers, "x-netz-bench-round") != expected_round or
        try benchmark.parseHeaderInt(request.headers, "x-netz-bench-streams") != config.streams or
        try benchmark.parseHeaderInt(request.headers, "x-netz-bench-bytes") != config.body_bytes or
        try benchmark.parseHeaderInt(request.headers, "x-netz-bench-chunk") != config.chunk_bytes or
        try benchmark.parseHeaderInt(request.headers, "x-netz-bench-window") != config.stream_window)
    {
        return error.InvalidRequest;
    }
    if (config.mode == .upload) {
        if (request.content_length != config.body_bytes) {
            return error.InvalidRequest;
        }
    } else if (request.content_length != null) {
        return error.InvalidRequest;
    }
    return index;
}

fn headerEquals(
    headers: []const netz.http3.Qpack.HeaderField,
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

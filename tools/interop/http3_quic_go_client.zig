//! Certificate-verified HTTP/3 client for process-boundary interoperability
//! with the independently implemented, repository-pinned quic-go fixture.

const std = @import("std");
const netz = @import("netz");
const benchmark = @import("http3_quic_go_bench.zig");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

const cancellation_response_size = 128 * 1024;
const stream_receive_window = 8 * 1024;
const connection_receive_window = 24 * 1024;
const read_before_cancel = 12 * 1024;
const BenchmarkResult = struct { elapsed_ns: u64, checksum: u64 };

const CancellationLoss = struct {
    armed: bool = false,
    sends_after_arm: usize = 0,
    dropped: usize = 0,

    fn arm(self: *CancellationLoss) void {
        self.armed = true;
    }

    fn shouldDrop(context: *anyopaque, _: []const u8) bool {
        const self: *CancellationLoss = @ptrCast(@alignCast(context));
        if (!self.armed) return false;
        self.sends_after_arm += 1;
        // HandshakeClient.cancelRequest writes RESET_STREAM first and
        // STOP_SENDING second. Losing only the latter forces QUIC recovery to
        // retransmit the response-direction cancellation while leaving the
        // request-direction reset independently observable on the wire.
        if (self.sends_after_arm != 2) return false;
        self.dropped += 1;
        return true;
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 4 and std.mem.eql(u8, args[1], "bench-client")) {
        return runBenchmark(init, args[2..]);
    }
    if (args.len < 3 or args.len > 5) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }
    var version: netz.quic.Version = .version_1;
    var version_set = false;
    var informational = false;
    var redirect = false;
    for (args[3..]) |arg| {
        if (std.mem.eql(u8, arg, "--version=2") and !version_set) {
            version = .version_2;
            version_set = true;
        } else if (std.mem.eql(u8, arg, "--informational") and
            !informational)
        {
            informational = true;
        } else if (std.mem.eql(u8, arg, "--redirect") and !redirect) {
            redirect = true;
        } else {
            return error.InvalidArgument;
        }
    }
    if (informational and redirect) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[2],
    );
    var bundle_verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    const server_verifier = bundle_verifier.clientVerifier();
    if (redirect) {
        try runRedirect(
            allocator,
            io,
            port,
            version,
            server_verifier,
        );
        return;
    }

    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    var local_transport_parameters = netz.quic.practical_transport_parameters;
    local_transport_parameters.initial_max_data = connection_receive_window;
    local_transport_parameters.initial_max_stream_data_bidi_local =
        stream_receive_window;
    local_transport_parameters.initial_max_stream_data_bidi_remote =
        stream_receive_window;
    var cancellation_loss = CancellationLoss{};
    var client = try netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
            .send_interceptor = .{
                .context = &cancellation_loss,
                .should_drop = CancellationLoss.shouldDrop,
            },
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .version = version,
                .available_versions = if (version == .version_2)
                    &.{.version_2}
                else
                    &.{ .version_1, .version_2 },
                .server_name = "localhost",
                .server_auth = server_verifier,
                .max_crypto_buffer = 64 * 1024,
                .local_transport_parameters = local_transport_parameters,
                .initial_one_rtt_config = .{
                    // Keep auto-tuning from hiding whether cancellation can
                    // unblock a response larger than the negotiated window.
                    .receive_window = connection_receive_window,
                    .max_receive_window = connection_receive_window,
                    .stream_receive_window = stream_receive_window,
                    .max_stream_receive_window = stream_receive_window,
                    .max_datagram_size = 4096,
                },
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 1200,
            },
        },
    );
    defer client.deinit();
    if (informational) {
        try runInformational(allocator, &client, version);
        return;
    }

    const canceled_stream_id = try client.startRequest(.{
        .method = "GET",
        .path = "/cancel?from=netz",
        .scheme = "https",
        .authority = "localhost",
    }, 0);

    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/interop?from=netz",
        .scheme = "https",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-netz-request",
            .value = "request-header",
        }},
    }, "netz-request".len);
    try client.sendRequestBodyPaced(stream_id, "netz-", false);
    try client.sendRequestBodyPaced(stream_id, "request", false);
    try client.finishRequestTrailersPaced(stream_id, &.{.{
        .name = "x-netz-trailer",
        .value = "request-trailer",
    }});

    var canceled_bytes: usize = 0;
    var cancellation_sent = false;
    var sibling_head = false;
    var sibling_trailer = false;
    var sibling_finished = false;
    var sibling_body: std.ArrayList(u8) = .empty;
    defer sibling_body.deinit(allocator);
    var read_buffer: [2048]u8 = undefined;
    while (!sibling_finished) {
        var event = try client.receiveNextResponseEvent();
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.UnexpectedResponseReset,
            .message => |message| {
                if (message.stream_id != canceled_stream_id and
                    message.stream_id != stream_id)
                {
                    return error.UnexpectedStream;
                }
                switch (message.value) {
                    .head => |head| {
                        if (head != .response) return error.InvalidResponse;
                        if (message.stream_id == canceled_stream_id) {
                            if (head.response.status != 200 or
                                head.response.content_length !=
                                    cancellation_response_size or
                                !headerEquals(
                                    head.response.headers,
                                    "x-quic-go-cancel",
                                    "large-response-started",
                                ))
                            {
                                return error.InvalidResponse;
                            }
                        } else {
                            if (head.response.status != 201 or
                                !headerEquals(
                                    head.response.headers,
                                    "x-quic-go-response",
                                    "response-header",
                                ))
                            {
                                return error.InvalidResponse;
                            }
                            sibling_head = true;
                        }
                    },
                    .data_available => {
                        const read = try client.readResponseData(
                            message.stream_id,
                            &read_buffer,
                        );
                        if (message.stream_id == canceled_stream_id) {
                            for (read_buffer[0..read]) |byte| {
                                if (byte != 'q') {
                                    return error.InvalidResponse;
                                }
                            }
                            canceled_bytes += read;
                            if (canceled_bytes >= read_before_cancel) {
                                cancellation_loss.arm();
                                try client.cancelRequest(
                                    canceled_stream_id,
                                    netz.http3.ApplicationErrorCode
                                        .request_cancelled,
                                );
                                cancellation_sent = true;
                            }
                        } else {
                            try sibling_body.appendSlice(
                                allocator,
                                read_buffer[0..read],
                            );
                        }
                    },
                    .trailers => |trailers| {
                        if (message.stream_id != stream_id or
                            !headerEquals(
                                trailers.fields,
                                "x-quic-go-trailer",
                                "response-trailer",
                            ))
                        {
                            return error.InvalidResponse;
                        }
                        sibling_trailer = true;
                    },
                    .finished => {
                        if (message.stream_id != stream_id) {
                            return error.InvalidResponse;
                        }
                        sibling_finished = true;
                    },
                    .push_promise => return error.InvalidResponse,
                }
            },
        }
    }
    if (!cancellation_sent or cancellation_loss.dropped != 1 or
        canceled_bytes < read_before_cancel or
        !sibling_head or !sibling_trailer or
        !std.mem.eql(u8, sibling_body.items, "quic-go-response"))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/3 client interoperated with quic-go: version={d} cancel=H3_REQUEST_CANCELLED dropped_stop_sending=1 concurrent_sibling=true stream_window={d} read_before_cancel>={d} large_response={d} request_body=12 request_trailers=1 response_body=16 response_trailers=1\n",
        .{
            if (version == .version_2) @as(u8, 2) else 1,
            stream_receive_window,
            read_before_cancel,
            cancellation_response_size,
        },
    );
}

fn runBenchmark(_: std.process.Init, args: []const []const u8) !void {
    if (args.len < 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[0], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[1])) {
        return error.InvalidArgument;
    }
    var stats = false;
    var role_pair: []const u8 = "netz-client+quic-go-server";
    var role_pair_set = false;
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[2..]) |arg| {
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
    if (!std.mem.eql(u8, role_pair, "netz-client+quic-go-server") and
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
        "client",
        config,
        counting.snapshot(),
    );
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var socket_traffic: netz.quic.runtime.SocketTrafficCounters = .{};
    var transport_stats: benchmark.TransportStats = .{};

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(allocator, io, now, args[1]);
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    try benchmark.printConfig(
        "netz",
        role_pair,
        "client",
        config,
    );

    var payloads = try benchmark.PayloadSet.init(allocator, config);
    defer payloads.deinit(allocator);
    const expected_checksum = payloads.aggregate_checksum;
    const rounds = try config.rounds();
    for (0..rounds) |round_index| {
        const round: u32 = @intCast(round_index);
        var original_dcid: [8]u8 = undefined;
        var client_cid: [8]u8 = undefined;
        try std.Io.randomSecure(io, &original_dcid);
        try std.Io.randomSecure(io, &client_cid);
        var client = try connectBenchmarkClient(
            allocator,
            io,
            port,
            verifier.clientVerifier(),
            config,
            &original_dcid,
            &client_cid,
            if (config.socket_traffic) &socket_traffic else null,
        );
        const result = blk: {
            defer client.deinit();
            try benchmarkReady(allocator, &client, config);
            const measured = switch (config.mode) {
                .upload => try runBenchmarkUpload(
                    allocator,
                    io,
                    &client,
                    config,
                    round,
                    &payloads,
                    expected_checksum,
                ),
                .download => try runBenchmarkDownload(
                    allocator,
                    io,
                    &client,
                    config,
                    round,
                    expected_checksum,
                ),
            };
            try benchmarkClose(allocator, &client, config, round);
            if (config.socket_traffic) {
                transport_stats.add(client.established.connection.stats());
            }
            break :blk measured;
        };
        if (round >= config.warmup) {
            benchmark.printSample(
                benchmark.senderImplementation(role_pair, config),
                role_pair,
                "client",
                config,
                round - config.warmup + 1,
                result.elapsed_ns,
                result.checksum,
            );
        }
    }
    if (config.socket_traffic) {
        benchmark.printSocketTraffic(
            "netz",
            role_pair,
            "client",
            config,
            socket_traffic.stats(),
        );
        benchmark.printTransportStats(
            role_pair,
            "client",
            config,
            transport_stats,
        );
    }
}

fn benchmarkClose(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    config: benchmark.Config,
    round: u32,
) !void {
    var round_buffer: [10]u8 = undefined;
    var response = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/benchmark/close",
        .scheme = "https",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-netz-bench-round",
            .value = try std.fmt.bufPrint(&round_buffer, "{d}", .{round}),
        }},
    }, config.timeout());
    defer response.deinit(allocator);
    if (response.response.status != 200 or
        response.response.body.len != 0 or response.response.trailers.len != 0 or
        !std.mem.eql(
            u8,
            benchmark.header(response.response.headers, "x-netz-bench-close") orelse
                return error.InvalidResponse,
            "ok",
        ))
    {
        return error.InvalidResponse;
    }
}

fn connectBenchmarkClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    verifier: netz.quic.tls.auth.ClientVerifier,
    config: benchmark.Config,
    original_dcid: []const u8,
    client_cid: []const u8,
    socket_traffic: ?*netz.quic.runtime.SocketTrafficCounters,
) !netz.http3.runtime.HandshakeClient {
    return netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = benchmark.max_frames,
            .enable_gso_send = false,
            .enable_gro_receive = false,
            .socket_traffic_counters = socket_traffic,
        } },
        .{
            .connect_timeout = config.timeout(),
            .handshake = .{
                .original_destination_connection_id = original_dcid,
                .local_connection_id = client_cid,
                .version = config.version,
                .available_versions = if (config.version == .version_2)
                    &.{.version_2}
                else
                    &.{.version_1},
                .server_name = "localhost",
                .server_auth = verifier,
                .local_transport_parameters = try config.transportParameters(),
                .initial_one_rtt_config = try config.oneRttConfig(),
                .max_crypto_buffer = 64 * 1024,
            },
            .session = try config.sessionOptions(),
        },
    );
}

fn benchmarkReady(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    config: benchmark.Config,
) !void {
    var ready = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/benchmark/ready",
        .scheme = "https",
        .authority = "localhost",
    }, config.timeout());
    defer ready.deinit(allocator);
    if (ready.response.status != 200 or
        ready.response.body.len != 0 or
        ready.response.trailers.len != 0 or
        !std.mem.eql(
            u8,
            benchmark.header(ready.response.headers, "x-netz-bench-ready") orelse
                return error.InvalidResponse,
            "ok",
        ))
    {
        return error.InvalidResponse;
    }
}

fn benchmarkHeaders(
    config: benchmark.Config,
    round: u32,
    stream_index: usize,
    round_buffer: *[10]u8,
    index_buffer: *[5]u8,
    streams_buffer: *[5]u8,
    bytes_buffer: *[20]u8,
    chunk_buffer: *[10]u8,
    window_buffer: *[20]u8,
) ![7]netz.http3.Qpack.HeaderField {
    const round_text = try std.fmt.bufPrint(round_buffer, "{d}", .{round});
    const index_text = try std.fmt.bufPrint(index_buffer, "{d}", .{stream_index});
    const bytes_text = try std.fmt.bufPrint(bytes_buffer, "{d}", .{config.body_bytes});
    const chunk_text = try std.fmt.bufPrint(chunk_buffer, "{d}", .{config.chunk_bytes});
    const window_text = try std.fmt.bufPrint(window_buffer, "{d}", .{config.stream_window});
    const streams_text = try std.fmt.bufPrint(streams_buffer, "{d}", .{config.streams});
    return .{
        .{ .name = "x-netz-bench-mode", .value = config.mode.name() },
        .{ .name = "x-netz-bench-round", .value = round_text },
        .{ .name = "x-netz-bench-stream-index", .value = index_text },
        .{ .name = "x-netz-bench-streams", .value = streams_text },
        .{ .name = "x-netz-bench-bytes", .value = bytes_text },
        .{ .name = "x-netz-bench-chunk", .value = chunk_text },
        .{ .name = "x-netz-bench-window", .value = window_text },
    };
}

fn runBenchmarkUpload(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netz.http3.runtime.HandshakeClient,
    config: benchmark.Config,
    round: u32,
    payloads: *const benchmark.PayloadSet,
    expected_checksum: u64,
) !BenchmarkResult {
    const deadline = deadlineFor(io, config);
    const started = benchmark.nowNs(io);
    var stream_ids: [benchmark.max_streams]u62 = undefined;
    for (0..config.streams) |index| {
        var round_buffer: [10]u8 = undefined;
        var index_buffer: [5]u8 = undefined;
        var streams_buffer: [5]u8 = undefined;
        var bytes_buffer: [20]u8 = undefined;
        var chunk_buffer: [10]u8 = undefined;
        var window_buffer: [20]u8 = undefined;
        const headers = try benchmarkHeaders(config, round, index, &round_buffer, &index_buffer, &streams_buffer, &bytes_buffer, &chunk_buffer, &window_buffer);
        stream_ids[index] = try client.startRequest(.{
            .method = "POST",
            .path = "/benchmark/upload",
            .scheme = "https",
            .authority = "localhost",
            .headers = &headers,
        }, @intCast(config.body_bytes));
    }
    var offsets = [_]usize{0} ** benchmark.max_streams;
    var chunks: [benchmark.max_streams]netz.http3.runtime.BodyChunk = undefined;
    while (offsets[0] < config.body_bytes) {
        for (stream_ids[0..config.streams], 0..) |stream_id, index| {
            const end = @min(payloads.streams[index].len, offsets[index] + config.effectiveChunk());
            chunks[index] = .{
                .stream_id = stream_id,
                .data = payloads.streams[index][offsets[index]..end],
                .fin = end == payloads.streams[index].len,
            };
        }
        var committed: usize = 0;
        try client.sendRequestBodyBatchPacedWithDeadline(
            chunks[0..config.streams],
            &committed,
            deadline,
        );
        if (committed != config.streams) return error.IncompleteBenchmarkSend;
        for (0..config.streams) |index| offsets[index] += chunks[index].data.len;
    }
    try receiveBenchmarkResponses(
        allocator,
        client,
        config,
        round,
        stream_ids[0..config.streams],
        payloads,
        false,
        deadline,
    );
    return .{
        .elapsed_ns = benchmark.nowNs(io) -| started,
        .checksum = expected_checksum,
    };
}

fn runBenchmarkDownload(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netz.http3.runtime.HandshakeClient,
    config: benchmark.Config,
    round: u32,
    expected_checksum: u64,
) !BenchmarkResult {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = config.timeout(),
        .clock = .awake,
    });
    const started = benchmark.nowNs(io);
    var stream_ids: [benchmark.max_streams]u62 = undefined;
    for (0..config.streams) |index| {
        var round_buffer: [10]u8 = undefined;
        var index_buffer: [5]u8 = undefined;
        var streams_buffer: [5]u8 = undefined;
        var bytes_buffer: [20]u8 = undefined;
        var chunk_buffer: [10]u8 = undefined;
        var window_buffer: [20]u8 = undefined;
        const headers = try benchmarkHeaders(config, round, index, &round_buffer, &index_buffer, &streams_buffer, &bytes_buffer, &chunk_buffer, &window_buffer);
        stream_ids[index] = try client.sendRequest(.{
            .method = "GET",
            .path = "/benchmark/download",
            .scheme = "https",
            .authority = "localhost",
            .headers = &headers,
        });
    }
    var payloads = try benchmark.PayloadSet.init(allocator, config);
    defer payloads.deinit(allocator);
    try receiveBenchmarkResponses(
        allocator,
        client,
        config,
        round,
        stream_ids[0..config.streams],
        &payloads,
        true,
        deadline,
    );
    return .{
        .elapsed_ns = benchmark.nowNs(io) -| started,
        .checksum = expected_checksum,
    };
}

fn deadlineFor(io: std.Io, config: benchmark.Config) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = config.timeout(), .clock = .awake });
}

fn receiveBenchmarkResponses(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    config: benchmark.Config,
    round: u32,
    stream_ids: []const u62,
    payloads: *const benchmark.PayloadSet,
    expect_body: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var seen = [_]bool{false} ** benchmark.max_streams;
    var complete: usize = 0;
    while (complete < config.streams) {
        var event = try client.receiveNextResponseWithDeadline(deadline);
        defer event.deinit(allocator);
        const response = switch (event) {
            .reset => return error.UnexpectedResponseReset,
            .response => |value| value,
        };
        const index = benchmark.streamIndexForId(stream_ids, response.stream_id) orelse
            return error.UnexpectedResponseStream;
        if (seen[index] or response.value.response.status != 200 or
            response.value.response.trailers.len != 0 or
            try benchmark.parseHeaderInt(response.value.response.headers, "x-netz-bench-round") != round or
            try benchmark.parseHeaderInt(response.value.response.headers, "x-netz-bench-stream-index") != index or
            try benchmark.parseHeaderInt(response.value.response.headers, "x-netz-bench-streams") != config.streams or
            try benchmark.parseHeaderInt(response.value.response.headers, "x-netz-bench-bytes") != config.body_bytes or
            try benchmark.parseHeaderInt(response.value.response.headers, "x-netz-bench-checksum") != payloads.checksums[index])
        {
            return error.InvalidResponse;
        }
        if (expect_body) {
            if (!std.mem.eql(u8, response.value.response.body, payloads.streams[index])) {
                return error.InvalidResponseBody;
            }
        } else if (response.value.response.body.len != 0) {
            return error.InvalidResponseBody;
        }
        seen[index] = true;
        complete += 1;
    }
}

fn runRedirect(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    version: netz.quic.Version,
    server_verifier: netz.quic.tls.auth.ClientVerifier,
) !void {
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    const uri_text = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/redirect-start?from=netz",
        .{port},
    );
    defer allocator.free(uri_text);
    var result = try netz.http3.runtime.HandshakeClient
        .requestUriFollowingRedirectsDetailedWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        try std.Uri.parse(uri_text),
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer quic-go-redirect" },
                .{ .name = "content-type", .value = "text/plain" },
            },
            .body = "redirect-body",
        },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .version = version,
            .available_versions = if (version == .version_2)
                &.{.version_2}
            else
                &.{ .version_1, .version_2 },
            .server_name = "localhost",
            .server_auth = server_verifier,
            .max_crypto_buffer = 64 * 1024,
        } },
        .{},
        .fromSeconds(10),
    );
    defer result.deinit();
    if (result.response.response.status != 200 or
        !std.mem.eql(
            u8,
            result.response.response.body,
            "quic-go-redirected",
        ) or result.redirect_count != 1)
    {
        return error.InvalidRedirectResponse;
    }
    std.debug.print(
        "netz HTTP/3 client followed quic-go redirect: version={d} status=200 redirects=1 method=POST->GET credentials=same-origin connections=2\n",
        .{if (version == .version_2) @as(u8, 2) else 1},
    );
}

fn runInformational(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    version: netz.quic.Version,
) !void {
    const State = struct {
        statuses: [2]u16 = undefined,
        headers_valid: bool = true,
        count: usize = 0,

        fn observe(
            context_ptr: *anyopaque,
            head: netz.http3.InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            if (self.count >= self.statuses.len) {
                self.headers_valid = false;
                return;
            }
            const valid = switch (head.status) {
                103 => headerEquals(head.headers, "link", "</quic-go.css>"),
                102 => headerEquals(head.headers, "x-progress", "half"),
                else => false,
            };
            self.headers_valid = self.headers_valid and valid;
            self.statuses[self.count] = head.status;
            self.count += 1;
        }
    };
    var state: State = .{};
    var response = try client.requestWithInformational(.{
        .method = "GET",
        .path = "/informational?from=netz",
        .scheme = "https",
        .authority = "localhost",
    }, .{
        .context = &state,
        .on_response = State.observe,
    });
    defer response.deinit(allocator);
    if (state.count != 2 or !state.headers_valid or
        !std.mem.eql(u16, &state.statuses, &.{ 103, 102 }) or
        response.response.status != 200 or
        !headerEquals(
            response.response.headers,
            "x-quic-go-final",
            "yes",
        ) or
        !std.mem.eql(u8, response.response.body, "final"))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/3 client observed quic-go informational responses: version={d} statuses=103,102 final=200 body=5\n",
        .{if (version == .version_2) @as(u8, 2) else 1},
    );
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

//! Certificate-verified HTTP/3 client for process-boundary interoperability
//! with the quic-go fixture maintained in the audited local quicz checkout.

const std = @import("std");
const netz = @import("netz");
const benchmark = @import("http3_quic_go_bench.zig");

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
    for (args[3..]) |arg| {
        if (std.mem.eql(u8, arg, "--version=2") and !version_set) {
            version = .version_2;
            version_set = true;
        } else if (std.mem.eql(u8, arg, "--informational") and
            !informational)
        {
            informational = true;
        } else {
            return error.InvalidArgument;
        }
    }

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[2],
    );
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };

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
                .server_auth = verifier.clientVerifier(),
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
    const config = try benchmark.Config.parse(args[2..]);
    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(allocator, io, now, args[1]);
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    try benchmark.printConfig(
        if (config.mode == .upload) "netz" else "quic-go",
        "netz-client+quic-go-server",
        config,
    );

    const payload = try allocator.alloc(u8, @intCast(config.body_bytes));
    defer allocator.free(payload);
    const expected_checksum = benchmark.fillPayload(payload);
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
                    payload,
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
            try std.Io.sleep(io, .fromMilliseconds(100), .awake);
            break :blk measured;
        };
        if (round >= config.warmup) {
            benchmark.printSample(
                if (config.mode == .upload) "netz" else "quic-go",
                "netz-client+quic-go-server",
                config,
                round - config.warmup + 1,
                result.elapsed_ns,
                result.checksum,
            );
        }
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
        } },
        .{
            .connect_timeout = config.timeout(),
            .handshake = .{
                .original_destination_connection_id = original_dcid,
                .local_connection_id = client_cid,
                .version = .version_1,
                .available_versions = &.{.version_1},
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
    round_buffer: *[10]u8,
    bytes_buffer: *[20]u8,
    chunk_buffer: *[10]u8,
    window_buffer: *[20]u8,
) ![5]netz.http3.Qpack.HeaderField {
    const round_text = try std.fmt.bufPrint(round_buffer, "{d}", .{round});
    const bytes_text = try std.fmt.bufPrint(bytes_buffer, "{d}", .{config.body_bytes});
    const chunk_text = try std.fmt.bufPrint(chunk_buffer, "{d}", .{config.chunk_bytes});
    const window_text = try std.fmt.bufPrint(window_buffer, "{d}", .{config.stream_window});
    return .{
        .{ .name = "x-netz-bench-mode", .value = config.mode.name() },
        .{ .name = "x-netz-bench-round", .value = round_text },
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
    payload: []const u8,
    expected_checksum: u64,
) !BenchmarkResult {
    var round_buffer: [10]u8 = undefined;
    var bytes_buffer: [20]u8 = undefined;
    var chunk_buffer: [10]u8 = undefined;
    var window_buffer: [20]u8 = undefined;
    const headers = try benchmarkHeaders(
        config,
        round,
        &round_buffer,
        &bytes_buffer,
        &chunk_buffer,
        &window_buffer,
    );
    const started = benchmark.nowNs(io);
    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/benchmark/upload",
        .scheme = "https",
        .authority = "localhost",
        .headers = &headers,
    }, payload.len);
    var offset: usize = 0;
    while (offset < payload.len) {
        const end = @min(payload.len, offset + config.effectiveChunk());
        try client.sendRequestBodyPaced(
            stream_id,
            payload[offset..end],
            end == payload.len,
        );
        offset = end;
    }
    var response = try client.receiveResponseWithTimeout(
        stream_id,
        config.timeout(),
    );
    defer response.deinit(allocator);
    if (response.response.status != 200 or
        response.response.body.len != 0 or
        response.response.trailers.len != 0 or
        try benchmark.parseHeaderInt(
            response.response.headers,
            "x-netz-bench-round",
        ) != round or
        try benchmark.parseHeaderInt(
            response.response.headers,
            "x-netz-bench-bytes",
        ) != config.body_bytes or
        try benchmark.parseHeaderInt(
            response.response.headers,
            "x-netz-bench-checksum",
        ) != expected_checksum)
    {
        return error.InvalidResponse;
    }
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
    var round_buffer: [10]u8 = undefined;
    var bytes_buffer: [20]u8 = undefined;
    var chunk_buffer: [10]u8 = undefined;
    var window_buffer: [20]u8 = undefined;
    const headers = try benchmarkHeaders(config, round, &round_buffer, &bytes_buffer, &chunk_buffer, &window_buffer);
    const buffer = try allocator.alloc(u8, config.effectiveChunk());
    defer allocator.free(buffer);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = config.timeout(),
        .clock = .awake,
    });
    const started = benchmark.nowNs(io);
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/benchmark/download",
        .scheme = "https",
        .authority = "localhost",
        .headers = &headers,
    });
    var received: usize = 0;
    var checksum: u64 = 0;
    var head_seen = false;
    var finished = false;
    while (!finished) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            deadline,
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| switch (head) {
                .response => |response| {
                    if (head_seen) return error.DuplicateResponseHead;
                    if (response.status != 200) return error.InvalidResponseStatus;
                    if (response.content_length != config.body_bytes) {
                        return error.InvalidResponseLength;
                    }
                    if (try benchmark.parseHeaderInt(response.headers, "x-netz-bench-round") != round) {
                        return error.InvalidResponseRound;
                    }
                    if (try benchmark.parseHeaderInt(response.headers, "x-netz-bench-bytes") != config.body_bytes) {
                        return error.InvalidResponseBytes;
                    }
                    if (try benchmark.parseHeaderInt(response.headers, "x-netz-bench-checksum") != expected_checksum) {
                        return error.InvalidResponseChecksum;
                    }
                    head_seen = true;
                },
                .request => return error.InvalidResponse,
            },
            .data_available => {
                const count = try client.readResponseData(stream_id, buffer);
                if (received + count > config.body_bytes) {
                    return error.ResponseBodyTooLarge;
                }
                try benchmark.verifyPayload(buffer[0..count], received, &checksum);
                received += count;
            },
            .finished => finished = true,
            .trailers => return error.UnexpectedResponseTrailers,
            .push_promise => return error.UnexpectedPushPromise,
        }
    }
    if (!head_seen or received != config.body_bytes or checksum != expected_checksum) {
        return error.InvalidResponseBody;
    }
    return .{
        .elapsed_ns = benchmark.nowNs(io) -| started,
        .checksum = checksum,
    };
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

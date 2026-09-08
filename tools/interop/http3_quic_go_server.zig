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
    for (args[2..]) |arg| {
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
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--stats") and !stats) {
            stats = true;
        } else {
            try config_args.append(std.heap.c_allocator, arg);
        }
    }
    const config = try benchmark.Config.parse(config_args.items);
    const role_pair = "quic-go-client+netz-server";
    var counting = CountingAllocator.init(std.heap.c_allocator);
    const allocator = if (stats) counting.allocator() else std.heap.c_allocator;
    defer if (stats) benchmark.printNetzMemory(
        role_pair,
        "server",
        config,
        counting.snapshot(),
    );
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

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
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .version = .version_1,
                .available_versions = &.{.version_1},
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
        if (config.mode == .upload) "quic-go" else "netz",
        role_pair,
        config,
    );
    const payload = try allocator.alloc(u8, @intCast(config.body_bytes));
    defer allocator.free(payload);
    const expected_checksum = benchmark.fillPayload(payload);
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
        const request = try receiveBenchmarkRequest(
            allocator,
            &session,
            config,
            @intCast(round_index),
            read_buffer,
        );
        if (request.close or request.ready) return error.InvalidRequest;
        switch (config.mode) {
            .upload => {
                if (request.bytes != config.body_bytes or request.checksum != expected_checksum) {
                    return error.InvalidRequest;
                }
                try sendBenchmarkResponse(&session, config, request.stream_id, request.round, expected_checksum, &.{});
            },
            .download => try sendBenchmarkResponse(&session, config, request.stream_id, request.round, expected_checksum, payload),
        }
        try session.waitForRecoveryIdleWithTimeout(config.timeout());
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
    checksum: u64,
    body: []const u8,
) !void {
    var round_buffer: [10]u8 = undefined;
    var bytes_buffer: [20]u8 = undefined;
    var checksum_buffer: [20]u8 = undefined;
    const headers = [_]netz.http3.Qpack.HeaderField{
        .{ .name = "x-netz-bench-round", .value = try std.fmt.bufPrint(&round_buffer, "{d}", .{round}) },
        .{ .name = "x-netz-bench-bytes", .value = try std.fmt.bufPrint(&bytes_buffer, "{d}", .{config.body_bytes}) },
        .{ .name = "x-netz-bench-checksum", .value = try std.fmt.bufPrint(&checksum_buffer, "{d}", .{checksum}) },
    };
    if (body.len == 0) {
        try session.sendResponsePacedWithTimeout(
            stream_id,
            .{ .status = 200, .headers = &headers },
            config.timeout(),
        );
        return;
    }
    try session.startResponse(
        stream_id,
        .{ .status = 200, .headers = &headers },
        body.len,
    );
    var offset: usize = 0;
    while (offset < body.len) {
        const end = @min(body.len, offset + config.effectiveChunk());
        try session.sendResponseBodyPaced(
            stream_id,
            body[offset..end],
            end == body.len,
        );
        offset = end;
    }
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

const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 1;
const default_body_bytes: usize = 64 * 1024;
const default_max_stream_frame_data: usize = 1024;
const min_stream_buffer: usize = 2 * 1024 * 1024;
const default_streams: usize = 1;
const max_streams: usize = 128;
const default_round_robin_chunk_bytes: usize = 64 * 1024;
const single_stream_round_robin_chunk_bytes: usize = 8 * 1024;
const benchmark_min_flow_control_bytes: u64 = 256 * 1024 * 1024;
// ACK every four ack-eliciting packets. The previous threshold of 16 allowed
// loopback's small receive queue to accumulate enough outstanding packets that
// one drop caused a larger recovery burst; four is the best stable point in
// the 2/4/8/16/32 same-host scan.
const benchmark_ack_eliciting_threshold: u64 = 4;
const benchmark_max_ack_delay_us: u64 = 25_000;
const single_stream_one_rtt_datagram_size: usize = 8192;
const single_stream_paced_body_chunk_bytes: usize = 7200;
// Keep multi-stream packetization conservative: 8192 improves the 4-stream
// upload benchmark over 4096 on loopback while avoiding the instability seen
// with larger 12000-byte datagrams.
const multi_stream_one_rtt_datagram_size: usize = 8192;
const multi_stream_paced_body_chunk_bytes: usize = 3000;
// ACK-driven loss repair removed the old false 3200-byte stability ceiling.
// The larger packet wins on quicz-shaped 64 MiB runs, while 3000 bytes remains
// more stable for shorter transfers. Keep the benchmark default adaptive
// rather than regressing one shape to optimize another.
const large_multi_stream_body_bytes: usize = 64 * 1024 * 1024;
const large_multi_stream_paced_body_chunk_bytes: usize = 6000;
const upload_trace_initial_window: usize = 256 * 1024;

const Mode = enum {
    upload,
    download,
};

pub fn main(init: std.process.Init) !void {
    var stats_allocator = CountingAllocator.init(std.heap.smp_allocator);
    const args_allocator = std.heap.smp_allocator;
    const config = try parseArgs(init, args_allocator);
    const allocator = if (config.stats)
        stats_allocator.allocator()
    else
        std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const transfer_body = try allocator.alloc(u8, config.body_bytes);
    defer allocator.free(transfer_body);
    @memset(transfer_body, 'x');

    const throughput_samples = try allocator.alloc(f64, config.iterations);
    defer allocator.free(throughput_samples);
    const started = nowNs(io);
    var status_total: usize = 0;
    var bytes_total: usize = 0;
    for (0..config.iterations) |iteration| {
        const iteration_started = nowNs(io);
        const result = try runIteration(
            allocator,
            io,
            config,
            transfer_body,
            iteration,
        );
        const iteration_elapsed = nowNs(io) -| iteration_started;
        throughput_samples[iteration] = mibPerSecond(config.body_bytes, iteration_elapsed);
        if (config.verbose) {
            std.debug.print(
                "  [iter {d}] {d:.2} MiB/s\n",
                .{ iteration, throughput_samples[iteration] },
            );
        }
        status_total += result.status_total;
        bytes_total += result.bytes_total;
    }
    const elapsed = nowNs(io) -| started;

    const bytes_per_second: u128 = if (elapsed == 0) 0 else (@as(u128, bytes_total) * std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\HTTP/3 real-handshake transfer benchmark
        \\  mode: {s}
        \\  streams: {d}
        \\  body batch: {}
        \\  1-RTT datagram bytes: {d}
        \\  paced body chunk bytes: {d}
        \\  server ACK-eliciting threshold: {d}
        \\  iterations: {d}
        \\  body bytes/iteration: {d}
        \\  total body bytes: {d}
        \\  status total: {d}
        \\  ns/iteration: {d}
        \\  bytes/s: {d}
        \\  MiB/s: {d}
        \\
    , .{ @tagName(config.mode), config.streams, config.enable_body_batch, transferOneRttDatagramSize(config), transferPacedBodyChunkBytes(config), config.ack_eliciting_threshold, config.iterations, config.body_bytes, bytes_total, status_total, if (config.iterations == 0) 0 else elapsed / config.iterations, bytes_per_second, bytes_per_second / (1024 * 1024) });
    const summary = summarizeThroughput(throughput_samples);
    std.debug.print(
        "  mean MiB/s: {d:.2}\n" ++
            "  stddev MiB/s: {d:.2}\n" ++
            "  stddev percent: {d:.2}\n",
        .{ summary.mean, summary.stddev, if (summary.mean == 0) 0 else summary.stddev * 100.0 / summary.mean },
    );
    if (config.stats) stats_allocator.print();
}

const ThroughputSummary = struct {
    mean: f64,
    stddev: f64,
};

fn mibPerSecond(bytes: usize, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    const mib = @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
    return mib / seconds;
}

fn summarizeThroughput(samples: []const f64) ThroughputSummary {
    if (samples.len == 0) return .{ .mean = 0, .stddev = 0 };
    var mean: f64 = 0;
    for (samples) |sample| mean += sample;
    mean /= @as(f64, @floatFromInt(samples.len));
    var variance: f64 = 0;
    for (samples) |sample| {
        const delta = sample - mean;
        variance += delta * delta;
    }
    variance /= @as(f64, @floatFromInt(samples.len));
    return .{ .mean = mean, .stddev = @sqrt(variance) };
}

const IterationResult = struct {
    status_total: usize,
    bytes_total: usize,
};

fn traceIteration(config: Config, iteration: usize, message: []const u8) void {
    if (config.trace_iteration) {
        std.debug.print("  [iter {d}] {s}\n", .{ iteration, message });
    }
}

fn shouldTraceUploadSendCall(
    config: Config,
    offset: usize,
    end: usize,
    stream_len: usize,
    next_progress_trace: usize,
) bool {
    if (!config.trace_iteration) return false;

    // Progress checkpoints print only after a send returns. Trace the early
    // calls and every checkpoint boundary before entering the blocking paced
    // send as well, so a timeout shows the exact stream/offset that stopped
    // making forward progress without flooding long successful transfers.
    return offset < upload_trace_initial_window or
        end >= next_progress_trace or
        end == stream_len;
}

fn runIteration(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    transfer_body: []const u8,
    iteration: usize,
) !IterationResult {
    const endpoint_datagram_size = transferEndpointDatagramSize(config);
    const one_rtt_datagram_size = transferOneRttDatagramSize(config);
    const paced_body_chunk_bytes = transferPacedBodyChunkBytes(config);
    const round_robin_chunk_bytes = transferRoundRobinChunkBytes(config);
    const stream_buffer = transferStreamBufferBytes(config);
    const transport_parameters = transferTransportParameters(config);
    const enable_data_prefix_fast_path = config.streams == 1;
    const enable_hystart = config.enable_hystart orelse (config.streams != 1);
    const enable_pacing = config.enable_pacing;

    traceIteration(config, iteration, "bind server");
    var server_cid = [_]u8{ 0x44, 0x45, 0x46, 0x47 };
    server_cid[0] +%= @truncate(iteration);
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = endpoint_datagram_size, .max_frames_per_datagram = 32 } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = transport_parameters,
                .initial_one_rtt_config = .{ .max_datagram_size = one_rtt_datagram_size, .enable_hystart = enable_hystart, .enable_pacing = enable_pacing },
                .random = [_]u8{0x31} ** 32,
                .x25519_secret_key = [_]u8{0x32} ** 32,
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = stream_buffer,
                .max_stream_frame_data = config.max_stream_frame_data,
                .paced_body_chunk_bytes = paced_body_chunk_bytes,
                .enable_data_prefix_fast_path = enable_data_prefix_fast_path,
                .max_concurrent_request_streams = max_streams,
            },
        },
    );
    defer server.deinit();
    traceIteration(config, iteration, "server bound");

    const Shared = struct {
        server: *netz.http3.runtime.HandshakeServer,
        body_bytes: usize,
        streams: usize,
        round_robin_chunk_bytes: usize,
        mode: Mode,
        body: []const u8,
        trace: bool,
        iteration: usize,
        ack_eliciting_threshold: u64,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                if (shared.trace) {
                    std.debug.print("  [iter {d}] server error: {}\n", .{ shared.iteration, err });
                }
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            session.established.connection.configureAckPolicy(
                shared.ack_eliciting_threshold,
                benchmark_max_ack_delay_us,
                netz.quic.packet_space.default_packet_threshold,
            );
            switch (shared.mode) {
                .upload => {
                    if (shared.trace) std.debug.print("  [iter {d}] server upload start\n", .{shared.iteration});
                    try serveUpload(
                        &session,
                        shared.body_bytes,
                        shared.streams,
                        shared.trace,
                        shared.iteration,
                    );
                    if (shared.trace) std.debug.print("  [iter {d}] server upload done\n", .{shared.iteration});
                },
                .download => try serveDownload(
                    &session,
                    shared.body_bytes,
                    shared.streams,
                    shared.round_robin_chunk_bytes,
                    shared.body,
                ),
            }
        }
    };

    var shared = Shared{
        .server = &server,
        .body_bytes = config.body_bytes,
        .streams = config.streams,
        .round_robin_chunk_bytes = round_robin_chunk_bytes,
        .mode = config.mode,
        .body = transfer_body,
        .trace = config.trace_iteration,
        .iteration = iteration,
        .ack_eliciting_threshold = config.ack_eliciting_threshold,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    traceIteration(config, iteration, "server thread spawned");

    var original_dcid: [8]u8 = undefined;
    var local_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &local_cid);

    traceIteration(config, iteration, "connect start");
    var client = try netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{ .max_datagram_size = endpoint_datagram_size, .max_frames_per_datagram = 32 } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &local_cid,
                .server_name = "localhost",
                .local_transport_parameters = transport_parameters,
                .initial_one_rtt_config = .{ .max_datagram_size = one_rtt_datagram_size, .enable_hystart = enable_hystart, .enable_pacing = enable_pacing },
                .max_crypto_buffer = 64 * 1024,
                .handshake_recovery = .{ .initial_pto_ms = 250, .max_pto_ms = 2000, .max_retries = 4, .max_duration_ms = 10_000 },
            },
            .session = .{
                .max_stream_buffer = stream_buffer,
                .max_stream_frame_data = config.max_stream_frame_data,
                .paced_body_chunk_bytes = paced_body_chunk_bytes,
                .enable_data_prefix_fast_path = enable_data_prefix_fast_path,
                .max_concurrent_request_streams = max_streams,
            },
        },
    );
    defer client.deinit();
    traceIteration(config, iteration, "connect done");

    var result: IterationResult = .{ .status_total = 0, .bytes_total = 0 };
    switch (config.mode) {
        .upload => {
            result.status_total += try runUploadClient(
                allocator,
                &client,
                config,
                iteration,
                transfer_body,
            );
            result.bytes_total += config.body_bytes;
        },
        .download => {
            const download = try runDownloadClient(
                allocator,
                &client,
                config.body_bytes,
                config.streams,
                round_robin_chunk_bytes,
            );
            result.status_total += download.status;
            result.bytes_total += download.bytes;
        },
    }
    traceIteration(config, iteration, "transfer done");

    thread.join();
    traceIteration(config, iteration, "server thread joined");
    if (shared.err) |err| return err;
    return result;
}

fn serveUpload(
    session: *netz.http3.runtime.HandshakeServerSession,
    body_bytes: usize,
    streams: usize,
    trace: bool,
    iteration: usize,
) !void {
    const allocator = session.established.connection.endpoint.allocator;
    const stream_ids = try receiveUploadBodies(
        allocator,
        session,
        body_bytes,
        streams,
        trace,
        iteration,
    );
    defer allocator.free(stream_ids);
    for (stream_ids) |stream_id| {
        try session.sendResponse(stream_id, .{
            .status = 200,
            .headers = &.{.{ .name = "server", .value = "netz-transfer-bench" }},
            .body = "ok",
        });
    }
}

fn receiveUploadBodies(
    allocator: std.mem.Allocator,
    session: *netz.http3.runtime.HandshakeServerSession,
    body_bytes: usize,
    streams: usize,
    trace: bool,
    iteration: usize,
) ![]u62 {
    const stream_ids = try allocator.alloc(u62, streams);
    errdefer allocator.free(stream_ids);
    const expected = try allocator.alloc(usize, streams);
    defer allocator.free(expected);
    const read = try allocator.alloc(usize, streams);
    defer allocator.free(read);
    const finished = try allocator.alloc(bool, streams);
    defer allocator.free(finished);
    @memset(expected, 0);
    @memset(read, 0);
    @memset(finished, false);

    var seen_count: usize = 0;
    var finished_count: usize = 0;
    var total_expected: usize = 0;
    var total_read: usize = 0;
    while (finished_count < streams) {
        var event = try session.receiveRequestEvent();
        defer event.deinit(session.established.connection.endpoint.allocator);
        if (event != .message) return error.InvalidFrame;
        const message = &event.message;
        switch (message.value) {
            .head => |head| {
                if (head != .request) return error.InvalidFrame;
                if (findStreamIndex(stream_ids[0..seen_count], message.stream_id) != null) {
                    return error.InvalidFrame;
                }
                if (seen_count == streams) return error.InvalidFrame;
                const content_length = head.request.content_length orelse
                    return error.InvalidFrame;
                stream_ids[seen_count] = message.stream_id;
                expected[seen_count] = content_length;
                total_expected += content_length;
                if (total_expected > body_bytes) return error.InvalidFrame;
                if (trace) {
                    std.debug.print(
                        "  [iter {d}] server upload head stream_id={d} index={d} length={d}\n",
                        .{ iteration, message.stream_id, seen_count, content_length },
                    );
                }
                seen_count += 1;
            },
            .data_available => {
                const index = findStreamIndex(stream_ids[0..seen_count], message.stream_id) orelse
                    return error.InvalidFrame;
                const skipped = try session.skipRequestData(message.stream_id);
                read[index] += skipped;
                total_read += skipped;
                if (read[index] > expected[index] or total_read > body_bytes) {
                    return error.InvalidFrame;
                }
                if (trace and
                    (read[index] == expected[index] or
                        read[index] % (256 * 1024) == 0))
                {
                    std.debug.print(
                        "  [iter {d}] server upload data stream={d} read={d}/{d} total={d}/{d}\n",
                        .{ iteration, index, read[index], expected[index], total_read, body_bytes },
                    );
                }
            },
            .finished => {
                const index = findStreamIndex(stream_ids[0..seen_count], message.stream_id) orelse
                    return error.InvalidFrame;
                if (finished[index] or read[index] != expected[index]) {
                    return error.InvalidFrame;
                }
                finished[index] = true;
                finished_count += 1;
                if (trace) {
                    std.debug.print(
                        "  [iter {d}] server upload finished stream={d} count={d}/{d}\n",
                        .{ iteration, index, finished_count, streams },
                    );
                }
            },
            .push_promise, .trailers => return error.InvalidFrame,
        }
    }
    if (seen_count != streams or total_expected != body_bytes or total_read != body_bytes) {
        return error.InvalidFrame;
    }
    return stream_ids;
}

fn serveDownload(
    session: *netz.http3.runtime.HandshakeServerSession,
    body_bytes: usize,
    streams: usize,
    round_robin_chunk_bytes: usize,
    body: []const u8,
) !void {
    const allocator = session.established.connection.endpoint.allocator;
    const stream_ids = try allocator.alloc(u62, streams);
    defer allocator.free(stream_ids);
    for (0..streams) |index| {
        var request = try session.receiveRequest();
        defer request.deinit(session.established.connection.endpoint.allocator);
        if (!std.mem.eql(u8, request.request.path, "/bench-transfer")) {
            return error.InvalidFrame;
        }
        if (request.request.body.len != 0) return error.InvalidFrame;
        stream_ids[index] = request.stream_id;
    }
    for (stream_ids, 0..) |stream_id, index| {
        try session.startResponse(
            stream_id,
            .{
                .status = 200,
                .headers = &.{.{ .name = "server", .value = "netz-transfer-bench" }},
            },
            transferBytesForStream(body_bytes, streams, index),
        );
    }
    try sendDownloadBodies(session, stream_ids, body_bytes, streams, round_robin_chunk_bytes, body);
}

fn sendDownloadBodies(
    session: *netz.http3.runtime.HandshakeServerSession,
    stream_ids: []const u62,
    body_bytes: usize,
    streams: usize,
    round_robin_chunk_bytes: usize,
    body: []const u8,
) !void {
    const allocator = session.established.connection.endpoint.allocator;
    const sent = try allocator.alloc(usize, streams);
    defer allocator.free(sent);
    @memset(sent, 0);
    var finished_count: usize = 0;
    while (finished_count < streams) {
        for (stream_ids, 0..) |stream_id, index| {
            const stream_len = transferBytesForStream(body_bytes, streams, index);
            if (sent[index] == stream_len) continue;
            const count = @min(round_robin_chunk_bytes, stream_len - sent[index]);
            const end = sent[index] + count;
            try session.sendResponseBodyPaced(
                stream_id,
                body[0..count],
                end == stream_len,
            );
            // The benchmark runs both endpoints in one process. A tiny sleep
            // between response chunks gives the client thread time to drain
            // loopback UDP, avoiding artificial drops that do not represent an
            // event-loop driven server.
            try std.Io.sleep(
                session.established.connection.endpoint.io,
                .fromNanoseconds(50_000),
                .awake,
            );
            sent[index] = end;
            if (end == stream_len) finished_count += 1;
        }
    }
}

fn runUploadClient(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    config: Config,
    iteration: usize,
    body: []const u8,
) !usize {
    const body_bytes = config.body_bytes;
    const streams = config.streams;
    const round_robin_chunk_bytes = transferRoundRobinChunkBytes(config);
    traceIteration(config, iteration, "upload open streams");
    const stream_ids = try allocator.alloc(u62, streams);
    defer allocator.free(stream_ids);
    for (stream_ids, 0..) |*stream_id, index| {
        stream_id.* = try client.startRequest(.{
            .method = "POST",
            .path = "/bench-transfer",
            .scheme = "https",
            .authority = "localhost",
        }, transferBytesForStream(body_bytes, streams, index));
    }
    traceIteration(config, iteration, "upload send bodies start");
    try sendUploadBodies(client, stream_ids, body_bytes, streams, round_robin_chunk_bytes, body, config, iteration);
    traceIteration(config, iteration, "upload send bodies done");

    var status_total: usize = 0;
    var received: usize = 0;
    traceIteration(config, iteration, "upload receive responses start");
    while (received < streams) {
        var event = try client.receiveNextResponse();
        defer event.deinit(allocator);
        switch (event) {
            .response => |response| {
                if (response.value.response.status != 200) {
                    return error.InvalidFrame;
                }
                status_total += response.value.response.status;
                received += 1;
            },
            .reset => return error.InvalidFrame,
        }
    }
    traceIteration(config, iteration, "upload receive responses done");
    return status_total;
}

fn sendUploadBodies(
    client: *netz.http3.runtime.HandshakeClient,
    stream_ids: []const u62,
    body_bytes: usize,
    streams: usize,
    round_robin_chunk_bytes: usize,
    body: []const u8,
    config: Config,
    iteration: usize,
) !void {
    const allocator = client.allocator;
    const sent = try allocator.alloc(usize, streams);
    defer allocator.free(sent);
    const round_targets = try allocator.alloc(usize, streams);
    defer allocator.free(round_targets);
    const trace_round = try allocator.alloc(bool, streams);
    defer allocator.free(trace_round);
    const completed = try allocator.alloc(bool, streams);
    defer allocator.free(completed);
    const chunks = try allocator.alloc(
        netz.http3.runtime.BodyChunk,
        streams,
    );
    defer allocator.free(chunks);
    var next_trace: ?[]usize = null;
    defer if (next_trace) |trace| allocator.free(trace);
    @memset(sent, 0);
    @memset(completed, false);
    const per_stream_trace_step = @max(@as(usize, 1), body_bytes / streams / 4);
    if (config.trace_iteration) {
        next_trace = try allocator.alloc(usize, streams);
        @memset(next_trace.?, per_stream_trace_step);
    }
    var finished_count: usize = 0;
    const paced_chunk_bytes = transferPacedBodyChunkBytes(config);
    while (finished_count < streams) {
        var round_pending = false;
        for (stream_ids, 0..) |stream_id, index| {
            _ = stream_id;
            if (completed[index]) continue;
            const stream_len = transferBytesForStream(body_bytes, streams, index);
            if (sent[index] == stream_len) {
                round_targets[index] = stream_len;
                trace_round[index] = false;
                continue;
            }
            round_targets[index] = @min(
                stream_len,
                sent[index] + round_robin_chunk_bytes,
            );
            trace_round[index] = if (next_trace) |trace|
                shouldTraceUploadSendCall(
                    config,
                    sent[index],
                    round_targets[index],
                    stream_len,
                    trace[index],
                )
            else
                false;
            if (trace_round[index]) {
                std.debug.print(
                    "  [iter {d}] upload stream {d} send call {d}+{d}/{d} fin={}\n",
                    .{
                        iteration,
                        index,
                        sent[index],
                        round_targets[index] - sent[index],
                        stream_len,
                        round_targets[index] == stream_len,
                    },
                );
            }
            round_pending = true;
        }

        while (round_pending) {
            var chunk_count: usize = 0;
            round_pending = false;
            for (stream_ids, 0..) |stream_id, index| {
                if (sent[index] == round_targets[index]) continue;
                const count = @min(
                    paced_chunk_bytes,
                    round_targets[index] - sent[index],
                );
                const end = sent[index] + count;
                chunks[chunk_count] = .{
                    .stream_id = stream_id,
                    .data = body[0..count],
                    .fin = end ==
                        transferBytesForStream(body_bytes, streams, index),
                };
                chunk_count += 1;
                round_pending = true;
            }
            if (chunk_count == 0) break;
            if (config.enable_body_batch) {
                try client.sendRequestBodyBatchPaced(chunks[0..chunk_count]);
            } else {
                for (chunks[0..chunk_count]) |chunk| {
                    try client.sendRequestBodyPaced(
                        chunk.stream_id,
                        chunk.data,
                        chunk.fin,
                    );
                }
            }
            for (chunks[0..chunk_count]) |chunk| {
                const index = findStreamIndex(
                    stream_ids,
                    chunk.stream_id,
                ) orelse return error.InvalidFrame;
                sent[index] += chunk.data.len;
            }
        }

        for (stream_ids, 0..) |_, index| {
            const stream_len = transferBytesForStream(
                body_bytes,
                streams,
                index,
            );
            if (trace_round[index]) {
                std.debug.print(
                    "  [iter {d}] upload stream {d} send call done {d}/{d}\n",
                    .{ iteration, index, sent[index], stream_len },
                );
            }
            if (next_trace) |trace| {
                if (sent[index] >= trace[index] or
                    sent[index] == stream_len)
                {
                    std.debug.print(
                        "  [iter {d}] upload stream {d} sent {d}/{d}\n",
                        .{ iteration, index, sent[index], stream_len },
                    );
                    while (trace[index] <= sent[index]) {
                        trace[index] += per_stream_trace_step;
                    }
                }
            }
            if (!completed[index] and sent[index] == stream_len) {
                completed[index] = true;
                finished_count += 1;
            }
        }
    }
}

const DownloadResult = struct {
    status: usize,
    bytes: usize,
};

fn runDownloadClient(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    body_bytes: usize,
    streams: usize,
    round_robin_chunk_bytes: usize,
) !DownloadResult {
    _ = round_robin_chunk_bytes;
    const stream_ids = try allocator.alloc(u62, streams);
    defer allocator.free(stream_ids);
    for (stream_ids) |*stream_id| {
        stream_id.* = try client.sendRequest(.{
            .method = "GET",
            .path = "/bench-transfer",
            .scheme = "https",
            .authority = "localhost",
        });
    }
    return receiveDownloadBodies(allocator, client, stream_ids, body_bytes, streams);
}

fn receiveDownloadBodies(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    stream_ids: []const u62,
    body_bytes: usize,
    streams: usize,
) !DownloadResult {
    const expected = try allocator.alloc(usize, streams);
    defer allocator.free(expected);
    const read = try allocator.alloc(usize, streams);
    defer allocator.free(read);
    const saw_head = try allocator.alloc(bool, streams);
    defer allocator.free(saw_head);
    const finished = try allocator.alloc(bool, streams);
    defer allocator.free(finished);
    for (expected, 0..) |*value, index| value.* = transferBytesForStream(body_bytes, streams, index);
    @memset(read, 0);
    @memset(saw_head, false);
    @memset(finished, false);

    var status_total: usize = 0;
    var total_read: usize = 0;
    var finished_count: usize = 0;
    while (finished_count < streams) {
        var event = try client.receiveNextResponseEvent();
        defer event.deinit(allocator);
        switch (event) {
            .message => |message| {
                const index = findStreamIndex(stream_ids, message.stream_id) orelse
                    return error.InvalidFrame;
                switch (message.value) {
                    .head => |head| {
                        if (head != .response) return error.InvalidFrame;
                        if (head.response.status != 200) return error.InvalidFrame;
                        if (head.response.content_length != expected[index]) {
                            return error.InvalidFrame;
                        }
                        if (saw_head[index]) return error.InvalidFrame;
                        saw_head[index] = true;
                        status_total += head.response.status;
                    },
                    .data_available => {
                        if (!saw_head[index]) return error.InvalidFrame;
                        const skipped = try client.skipResponseData(message.stream_id);
                        read[index] += skipped;
                        total_read += skipped;
                        if (read[index] > expected[index] or total_read > body_bytes) {
                            return error.InvalidFrame;
                        }
                    },
                    .finished => {
                        if (!saw_head[index] or finished[index] or read[index] != expected[index]) {
                            return error.InvalidFrame;
                        }
                        finished[index] = true;
                        finished_count += 1;
                    },
                    .push_promise, .trailers => return error.InvalidFrame,
                }
            },
            .reset => return error.InvalidFrame,
        }
    }
    if (total_read != body_bytes) return error.InvalidFrame;
    return .{ .status = status_total, .bytes = total_read };
}

fn transferBytesForStream(total: usize, streams: usize, index: usize) usize {
    const base = total / streams;
    const remainder = total % streams;
    return base + if (index < remainder) @as(usize, 1) else @as(usize, 0);
}

fn findStreamIndex(stream_ids: []const u62, stream_id: u62) ?usize {
    for (stream_ids, 0..) |candidate, index| {
        if (candidate == stream_id) return index;
    }
    return null;
}

fn transferEndpointDatagramSize(config: Config) usize {
    return config.one_rtt_datagram_size orelse
        if (config.streams == 1) single_stream_one_rtt_datagram_size else multi_stream_one_rtt_datagram_size;
}

fn transferOneRttDatagramSize(config: Config) usize {
    return config.one_rtt_datagram_size orelse
        if (config.streams == 1) single_stream_one_rtt_datagram_size else multi_stream_one_rtt_datagram_size;
}

fn transferPacedBodyChunkBytes(config: Config) usize {
    return config.paced_body_chunk_bytes orelse
        if (config.streams == 1)
            single_stream_paced_body_chunk_bytes
        else if (config.body_bytes >= large_multi_stream_body_bytes)
            large_multi_stream_paced_body_chunk_bytes
        else
            multi_stream_paced_body_chunk_bytes;
}

fn transferRoundRobinChunkBytes(config: Config) usize {
    return config.round_robin_chunk_bytes orelse
        if (config.streams == 1) single_stream_round_robin_chunk_bytes else default_round_robin_chunk_bytes;
}

fn transferStreamBufferBytes(config: Config) usize {
    const max_per_stream = transferBytesForStream(config.body_bytes, config.streams, 0);
    const frame_slack = @max(config.max_stream_frame_data, 64 * 1024);
    const desired = max_per_stream +| frame_slack;
    return @max(min_stream_buffer, desired);
}

fn transferTransportParameters(config: Config) netz.quic.TransportParameters {
    var params = netz.quic.practical_transport_parameters;
    const flow_control_bytes = transferFlowControlBytes(config);
    // The throughput benchmark should measure packetization, congestion, and
    // HTTP/3 body movement, not repeated small-window MAX_DATA turnarounds.
    // quicz's comparable benchmarks advertise 256MiB receive windows; keep the
    // same floor here while scaling above it for larger local experiments.
    params.initial_max_data = flow_control_bytes;
    params.initial_max_stream_data_bidi_local = flow_control_bytes;
    params.initial_max_stream_data_bidi_remote = flow_control_bytes;
    params.initial_max_stream_data_uni = flow_control_bytes;
    params.initial_max_streams_bidi = max_streams;
    params.initial_max_streams_uni = max_streams;
    return params;
}

fn transferFlowControlBytes(config: Config) u64 {
    const body_bytes = std.math.cast(u64, config.body_bytes) orelse
        netz.quic.varint.max_value;
    const slack = @max(@as(u64, 1024 * 1024), body_bytes / 8);
    const desired = body_bytes +| slack;
    return @min(
        @max(benchmark_min_flow_control_bytes, desired),
        netz.quic.varint.max_value,
    );
}

const CountingAllocator = struct {
    backing: std.mem.Allocator,
    current_bytes: usize = 0,
    peak_bytes: usize = 0,
    total_allocated: usize = 0,
    total_freed: usize = 0,
    alloc_count: usize = 0,
    free_count: usize = 0,
    resize_count: usize = 0,
    remap_count: usize = 0,
    alloc_buckets: [bucket_count]usize = .{0} ** bucket_count,
    alloc_bucket_bytes: [bucket_count]usize = .{0} ** bucket_count,

    const bucket_count = 7;
    const bucket_labels = [_][]const u8{ "<=64", "<=256", "<=1K", "<=4K", "<=16K", "<=64K", ">64K" };

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn init(backing: std.mem.Allocator) CountingAllocator {
        return .{ .backing = backing };
    }

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.backing.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.alloc_count += 1;
        self.recordAllocBucket(len);
        self.total_allocated += len;
        self.current_bytes += len;
        self.peak_bytes = @max(self.peak_bytes, self.current_bytes);
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.backing.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.resize_count += 1;
        self.recordResize(memory.len, new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.backing.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.remap_count += 1;
        self.recordResize(memory.len, new_len);
        return ptr;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.free_count += 1;
        self.total_freed += memory.len;
        self.current_bytes -|= memory.len;
        self.backing.rawFree(memory, alignment, ret_addr);
    }

    fn recordAllocBucket(self: *CountingAllocator, len: usize) void {
        const index = bucketIndex(len);
        self.alloc_buckets[index] += 1;
        self.alloc_bucket_bytes[index] += len;
    }

    fn bucketIndex(len: usize) usize {
        if (len <= 64) return 0;
        if (len <= 256) return 1;
        if (len <= 1024) return 2;
        if (len <= 4096) return 3;
        if (len <= 16 * 1024) return 4;
        if (len <= 64 * 1024) return 5;
        return 6;
    }

    fn recordResize(self: *CountingAllocator, old_len: usize, new_len: usize) void {
        if (new_len > old_len) {
            const delta = new_len - old_len;
            self.total_allocated += delta;
            self.current_bytes += delta;
            self.peak_bytes = @max(self.peak_bytes, self.current_bytes);
        } else {
            const delta = old_len - new_len;
            self.total_freed += delta;
            self.current_bytes -|= delta;
        }
    }

    fn print(self: CountingAllocator) void {
        std.debug.print(
            "allocator stats\n" ++
                "  alloc count: {d}\n" ++
                "  free count: {d}\n" ++
                "  resize count: {d}\n" ++
                "  remap count: {d}\n" ++
                "  total allocated bytes: {d}\n" ++
                "  total freed bytes: {d}\n" ++
                "  live bytes: {d}\n" ++
                "  peak live bytes: {d}\n",
            .{ self.alloc_count, self.free_count, self.resize_count, self.remap_count, self.total_allocated, self.total_freed, self.current_bytes, self.peak_bytes },
        );
        std.debug.print("  allocation buckets:\n", .{});
        for (bucket_labels, 0..) |label, index| {
            std.debug.print(
                "    {s}: count={d}, bytes={d}\n",
                .{ label, self.alloc_buckets[index], self.alloc_bucket_bytes[index] },
            );
        }
    }
};

const Config = struct {
    iterations: usize = default_iterations,
    body_bytes: usize = default_body_bytes,
    max_stream_frame_data: usize = default_max_stream_frame_data,
    streams: usize = default_streams,
    round_robin_chunk_bytes: ?usize = null,
    one_rtt_datagram_size: ?usize = null,
    paced_body_chunk_bytes: ?usize = null,
    mode: Mode = .upload,
    stats: bool = false,
    verbose: bool = false,
    trace_iteration: bool = false,
    enable_hystart: ?bool = null,
    enable_pacing: bool = true,
    // This host's small sysctl-capped UDP receive queue makes four-packet GSO
    // bursts slower than sequential submissions. Keep the batch mode opt-in so
    // capable hosts can measure it without regressing the portable baseline.
    enable_body_batch: bool = false,
    ack_eliciting_threshold: u64 = benchmark_ack_eliciting_threshold,
};

fn parseArgs(init: std.process.Init, allocator: std.mem.Allocator) !Config {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();
    var config: Config = .{};
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--iterations=")) {
            config.iterations = try parsePositiveUsize(arg["--iterations=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--body-bytes=")) {
            config.body_bytes = try parsePositiveUsize(arg["--body-bytes=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--max-stream-frame-data=")) {
            config.max_stream_frame_data = try parsePositiveUsize(arg["--max-stream-frame-data=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--round-robin-chunk-bytes=")) {
            config.round_robin_chunk_bytes = try parsePositiveUsize(arg["--round-robin-chunk-bytes=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--one-rtt-datagram-size=")) {
            config.one_rtt_datagram_size = try parsePositiveUsize(arg["--one-rtt-datagram-size=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--paced-body-chunk-bytes=")) {
            config.paced_body_chunk_bytes = try parsePositiveUsize(arg["--paced-body-chunk-bytes=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--ack-eliciting-threshold=")) {
            config.ack_eliciting_threshold = try std.fmt.parseInt(
                u64,
                arg["--ack-eliciting-threshold=".len..],
                10,
            );
            if (config.ack_eliciting_threshold == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(u8, arg, "--streams=")) {
            config.streams = try parsePositiveUsize(arg["--streams=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--mode=")) {
            config.mode = try parseMode(arg["--mode=".len..]);
        } else if (std.mem.eql(u8, arg, "--stats")) {
            config.stats = true;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else if (std.mem.eql(u8, arg, "--trace-iteration")) {
            config.trace_iteration = true;
        } else if (std.mem.eql(u8, arg, "--disable-hystart")) {
            config.enable_hystart = false;
        } else if (std.mem.eql(u8, arg, "--enable-hystart")) {
            config.enable_hystart = true;
        } else if (std.mem.eql(u8, arg, "--disable-pacing")) {
            config.enable_pacing = false;
        } else if (std.mem.eql(u8, arg, "--enable-body-batch")) {
            config.enable_body_batch = true;
        } else {
            return error.InvalidArgument;
        }
    }
    if (config.streams > max_streams or config.streams > config.body_bytes) {
        return error.InvalidArgument;
    }
    return config;
}

fn parseMode(raw: []const u8) !Mode {
    if (std.mem.eql(u8, raw, "upload")) return .upload;
    if (std.mem.eql(u8, raw, "download")) return .download;
    return error.InvalidArgument;
}

fn parsePositiveUsize(raw: []const u8) !usize {
    const value = try std.fmt.parseInt(usize, raw, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

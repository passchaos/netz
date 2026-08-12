const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 1;
const default_body_bytes: usize = 64 * 1024;
const default_max_stream_frame_data: usize = 1024;
const default_max_stream_buffer: usize = 64 * 1024;
const default_streams: usize = 1;
const max_streams: usize = 128;
const default_round_robin_chunk_bytes: usize = 64 * 1024;
const default_endpoint_datagram_size: usize = 4096;
const single_stream_one_rtt_datagram_size: usize = 8192;
const single_stream_paced_body_chunk_bytes: usize = 7200;
const multi_stream_one_rtt_datagram_size: usize = 4096;
const multi_stream_paced_body_chunk_bytes: usize = 2800;

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

    const endpoint_datagram_size = transferEndpointDatagramSize(config.streams);
    const one_rtt_datagram_size = transferOneRttDatagramSize(config.streams);
    const paced_body_chunk_bytes = transferPacedBodyChunkBytes(config.streams);

    const server_cid = [_]u8{ 0x44, 0x45, 0x46, 0x47 };
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = endpoint_datagram_size, .max_frames_per_datagram = 32 } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{ .max_datagram_size = one_rtt_datagram_size },
                .random = [_]u8{0x31} ** 32,
                .x25519_secret_key = [_]u8{0x32} ** 32,
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = default_max_stream_buffer,
                .max_stream_frame_data = config.max_stream_frame_data,
                .paced_body_chunk_bytes = paced_body_chunk_bytes,
                .max_concurrent_request_streams = max_streams,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http3.runtime.HandshakeServer,
        iterations: usize,
        body_bytes: usize,
        streams: usize,
        round_robin_chunk_bytes: usize,
        mode: Mode,
        body: []const u8,
        err: ?anyerror = null,
        handled: usize = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            while (shared.handled < shared.iterations) : (shared.handled += 1) {
                var session = try shared.server.accept();
                defer session.deinit();
                switch (shared.mode) {
                    .upload => try serveUpload(
                        &session,
                        shared.body_bytes,
                        shared.streams,
                    ),
                    .download => try serveDownload(
                        &session,
                        shared.body_bytes,
                        shared.streams,
                        shared.round_robin_chunk_bytes,
                        shared.body,
                    ),
                }
            }
        }
    };

    var shared = Shared{
        .server = &server,
        .iterations = config.iterations,
        .body_bytes = config.body_bytes,
        .streams = config.streams,
        .round_robin_chunk_bytes = config.round_robin_chunk_bytes,
        .mode = config.mode,
        .body = transfer_body,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const started = nowNs(io);
    var status_total: usize = 0;
    var bytes_total: usize = 0;
    for (0..config.iterations) |_| {
        var original_dcid: [8]u8 = undefined;
        var local_cid: [8]u8 = undefined;
        try std.Io.randomSecure(io, &original_dcid);
        try std.Io.randomSecure(io, &local_cid);

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
                    .initial_one_rtt_config = .{ .max_datagram_size = one_rtt_datagram_size },
                    .max_crypto_buffer = 64 * 1024,
                    .handshake_recovery = .{ .initial_pto_ms = 250, .max_pto_ms = 2000, .max_retries = 4, .max_duration_ms = 10_000 },
                },
                .session = .{
                    .max_stream_buffer = default_max_stream_buffer,
                    .max_stream_frame_data = config.max_stream_frame_data,
                    .paced_body_chunk_bytes = paced_body_chunk_bytes,
                    .max_concurrent_request_streams = max_streams,
                },
            },
        );
        defer client.deinit();

        switch (config.mode) {
            .upload => {
                status_total += try runUploadClient(
                    allocator,
                    &client,
                    config.body_bytes,
                    config.streams,
                    config.round_robin_chunk_bytes,
                    transfer_body,
                );
                bytes_total += config.body_bytes;
            },
            .download => {
                const result = try runDownloadClient(
                    allocator,
                    &client,
                    config.body_bytes,
                    config.streams,
                    config.round_robin_chunk_bytes,
                );
                status_total += result.status;
                bytes_total += result.bytes;
            },
        }
    }
    const elapsed = nowNs(io) -| started;
    thread.join();
    if (shared.err) |err| return err;

    const bytes_per_second: u128 = if (elapsed == 0) 0 else (@as(u128, bytes_total) * std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\HTTP/3 real-handshake transfer benchmark
        \\  mode: {s}
        \\  streams: {d}
        \\  iterations: {d}
        \\  body bytes/iteration: {d}
        \\  total body bytes: {d}
        \\  status total: {d}
        \\  ns/iteration: {d}
        \\  bytes/s: {d}
        \\  MiB/s: {d}
        \\
    , .{ @tagName(config.mode), config.streams, config.iterations, config.body_bytes, bytes_total, status_total, if (config.iterations == 0) 0 else elapsed / config.iterations, bytes_per_second, bytes_per_second / (1024 * 1024) });
    if (config.stats) stats_allocator.print();
}

fn serveUpload(
    session: *netz.http3.runtime.HandshakeServerSession,
    body_bytes: usize,
    streams: usize,
) !void {
    const allocator = session.established.connection.endpoint.allocator;
    const stream_ids = try receiveUploadBodies(
        allocator,
        session,
        body_bytes,
        streams,
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
            },
            .finished => {
                const index = findStreamIndex(stream_ids[0..seen_count], message.stream_id) orelse
                    return error.InvalidFrame;
                if (finished[index] or read[index] != expected[index]) {
                    return error.InvalidFrame;
                }
                finished[index] = true;
                finished_count += 1;
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
            sent[index] = end;
            if (end == stream_len) finished_count += 1;
        }
    }
}

fn runUploadClient(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    body_bytes: usize,
    streams: usize,
    round_robin_chunk_bytes: usize,
    body: []const u8,
) !usize {
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
    try sendUploadBodies(client, stream_ids, body_bytes, streams, round_robin_chunk_bytes, body);

    var status_total: usize = 0;
    var received: usize = 0;
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
    return status_total;
}

fn sendUploadBodies(
    client: *netz.http3.runtime.HandshakeClient,
    stream_ids: []const u62,
    body_bytes: usize,
    streams: usize,
    round_robin_chunk_bytes: usize,
    body: []const u8,
) !void {
    const allocator = client.allocator;
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
            try client.sendRequestBodyPaced(
                stream_id,
                body[0..count],
                end == stream_len,
            );
            sent[index] = end;
            if (end == stream_len) finished_count += 1;
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

fn transferEndpointDatagramSize(streams: usize) usize {
    return if (streams == 1) single_stream_one_rtt_datagram_size else default_endpoint_datagram_size;
}

fn transferOneRttDatagramSize(streams: usize) usize {
    return if (streams == 1) single_stream_one_rtt_datagram_size else default_endpoint_datagram_size;
}

fn transferPacedBodyChunkBytes(streams: usize) usize {
    return if (streams == 1) single_stream_paced_body_chunk_bytes else multi_stream_paced_body_chunk_bytes;
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
    round_robin_chunk_bytes: usize = default_round_robin_chunk_bytes,
    mode: Mode = .upload,
    stats: bool = false,
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
        } else if (std.mem.startsWith(u8, arg, "--streams=")) {
            config.streams = try parsePositiveUsize(arg["--streams=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--mode=")) {
            config.mode = try parseMode(arg["--mode=".len..]);
        } else if (std.mem.eql(u8, arg, "--stats")) {
            config.stats = true;
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

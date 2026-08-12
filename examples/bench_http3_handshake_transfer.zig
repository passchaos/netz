const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 1;
const default_body_bytes: usize = 64 * 1024;
const default_max_stream_frame_data: usize = 1024;
const default_max_stream_buffer: usize = 64 * 1024;

const Mode = enum {
    upload,
    download,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const config = try parseArgs(init, allocator);

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const transfer_body = try allocator.alloc(u8, config.body_bytes);
    defer allocator.free(transfer_body);
    @memset(transfer_body, 'x');

    const server_cid = [_]u8{ 0x44, 0x45, 0x46, 0x47 };
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 32 } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x31} ** 32,
                .x25519_secret_key = [_]u8{0x32} ** 32,
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = default_max_stream_buffer,
                .max_stream_frame_data = config.max_stream_frame_data,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http3.runtime.HandshakeServer,
        iterations: usize,
        body_bytes: usize,
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
                    .upload => try serveUpload(&session, shared.body_bytes),
                    .download => try serveDownload(
                        &session,
                        shared.body_bytes,
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
            .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 32 } },
            .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &local_cid,
                    .server_name = "localhost",
                    .max_crypto_buffer = 64 * 1024,
                    .handshake_recovery = .{ .initial_pto_ms = 250, .max_pto_ms = 2000, .max_retries = 4, .max_duration_ms = 10_000 },
                },
                .session = .{
                    .max_stream_buffer = default_max_stream_buffer,
                    .max_stream_frame_data = config.max_stream_frame_data,
                },
            },
        );
        defer client.deinit();

        switch (config.mode) {
            .upload => {
                const stream_id = try client.startRequest(.{
                    .method = "POST",
                    .path = "/bench-transfer",
                    .scheme = "https",
                    .authority = "localhost",
                }, config.body_bytes);
                try client.sendRequestBodyPaced(stream_id, transfer_body, true);
                var response = try client.receiveResponse(stream_id);
                defer response.deinit(allocator);
                if (response.response.status != 200) return error.InvalidFrame;
                status_total += response.response.status;
                bytes_total += config.body_bytes;
            },
            .download => {
                const stream_id = try client.sendRequest(.{
                    .method = "GET",
                    .path = "/bench-transfer",
                    .scheme = "https",
                    .authority = "localhost",
                });
                const result = try receiveDownloadBody(
                    allocator,
                    &client,
                    stream_id,
                    config.body_bytes,
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
        \\  iterations: {d}
        \\  body bytes/iteration: {d}
        \\  total body bytes: {d}
        \\  status total: {d}
        \\  ns/iteration: {d}
        \\  bytes/s: {d}
        \\  MiB/s: {d}
        \\
    , .{ @tagName(config.mode), config.iterations, config.body_bytes, bytes_total, status_total, if (config.iterations == 0) 0 else elapsed / config.iterations, bytes_per_second, bytes_per_second / (1024 * 1024) });
}

fn serveUpload(
    session: *netz.http3.runtime.HandshakeServerSession,
    body_bytes: usize,
) !void {
    const stream_id = try receiveUploadBody(session, body_bytes);
    try session.sendResponse(stream_id, .{
        .status = 200,
        .headers = &.{.{ .name = "server", .value = "netz-transfer-bench" }},
        .body = "ok",
    });
}

fn receiveUploadBody(
    session: *netz.http3.runtime.HandshakeServerSession,
    body_bytes: usize,
) !u62 {
    var saw_head = false;
    var saw_finished = false;
    var stream_id: ?u62 = null;
    var body_read: usize = 0;
    while (!saw_finished) {
        var event = try session.receiveRequestEvent();
        defer event.deinit(session.established.connection.endpoint.allocator);
        if (event != .message) return error.InvalidFrame;
        const message = &event.message;
        if (stream_id) |expected| {
            if (message.stream_id != expected) return error.InvalidFrame;
        } else {
            stream_id = message.stream_id;
        }
        switch (message.value) {
            .head => |head| {
                if (head != .request) return error.InvalidFrame;
                if (head.request.content_length != body_bytes) {
                    return error.InvalidFrame;
                }
                saw_head = true;
            },
            .data_available => {
                if (!saw_head) return error.InvalidFrame;
                const skipped = try session.skipRequestData(message.stream_id);
                body_read += skipped;
                if (body_read > body_bytes) return error.InvalidFrame;
            },
            .finished => {
                if (!saw_head or body_read != body_bytes) {
                    return error.InvalidFrame;
                }
                saw_finished = true;
            },
            .push_promise, .trailers => return error.InvalidFrame,
        }
    }
    return stream_id orelse error.InvalidFrame;
}

fn serveDownload(
    session: *netz.http3.runtime.HandshakeServerSession,
    body_bytes: usize,
    body: []const u8,
) !void {
    var request = try session.receiveRequest();
    defer request.deinit(session.established.connection.endpoint.allocator);
    if (!std.mem.eql(u8, request.request.path, "/bench-transfer")) {
        return error.InvalidFrame;
    }
    if (request.request.body.len != 0) return error.InvalidFrame;
    try session.startResponse(
        request.stream_id,
        .{
            .status = 200,
            .headers = &.{.{ .name = "server", .value = "netz-transfer-bench" }},
        },
        body_bytes,
    );
    try sendDownloadBody(session, request.stream_id, body);
}

fn sendDownloadBody(
    session: *netz.http3.runtime.HandshakeServerSession,
    stream_id: u62,
    body: []const u8,
) !void {
    try session.sendResponseBodyPaced(stream_id, body, true);
}

const DownloadResult = struct {
    status: usize,
    bytes: usize,
};

fn receiveDownloadBody(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    stream_id: u62,
    body_bytes: usize,
) !DownloadResult {
    var saw_head = false;
    var saw_finished = false;
    var status: usize = 0;
    var body_read: usize = 0;
    while (!saw_finished) {
        const event = (try client.receiveResponseEvent(stream_id)) orelse continue;
        var owned_event = event;
        defer owned_event.deinit(allocator);
        switch (owned_event) {
            .head => |head| {
                if (head != .response) return error.InvalidFrame;
                if (head.response.status != 200) return error.InvalidFrame;
                if (head.response.content_length != body_bytes) {
                    return error.InvalidFrame;
                }
                status = head.response.status;
                saw_head = true;
            },
            .data_available => {
                if (!saw_head) return error.InvalidFrame;
                const skipped = try client.skipResponseData(stream_id);
                body_read += skipped;
                if (body_read > body_bytes) return error.InvalidFrame;
            },
            .finished => {
                if (!saw_head or body_read != body_bytes) {
                    return error.InvalidFrame;
                }
                saw_finished = true;
            },
            .push_promise, .trailers => return error.InvalidFrame,
        }
    }
    return .{ .status = status, .bytes = body_read };
}

const Config = struct {
    iterations: usize = default_iterations,
    body_bytes: usize = default_body_bytes,
    max_stream_frame_data: usize = default_max_stream_frame_data,
    mode: Mode = .upload,
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
        } else if (std.mem.startsWith(u8, arg, "--mode=")) {
            config.mode = try parseMode(arg["--mode=".len..]);
        } else {
            return error.InvalidArgument;
        }
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

const std = @import("std");
const netz = @import("netz");

const default_body_bytes: usize = 1024 * 1024;
const default_chunk_bytes: usize = 16 * 1024;
const default_warmup_iterations: usize = 20;
const default_iterations: usize = 100;
const response_date = "Mon, 17 Aug 2026 00:00:00 GMT";
const response_headers = [_]netz.http1.Header{.{
    .name = "date",
    .value = response_date,
}};

const Mode = enum {
    fixed,
    chunked,
};

const Options = struct {
    mode: Mode = .fixed,
    body_bytes: usize = default_body_bytes,
    chunk_bytes: usize = default_chunk_bytes,
    warmup_iterations: usize = default_warmup_iterations,
    iterations: usize = default_iterations,
};

pub fn main(init: std.process.Init) !void {
    const options = try parseOptions(init);
    if (options.body_bytes == 0 or options.chunk_bytes == 0 or
        options.body_bytes % options.chunk_bytes != 0)
    {
        return error.InvalidArguments;
    }
    const allocator = std.heap.smp_allocator;
    const payload = try allocator.alloc(u8, options.body_bytes);
    defer allocator.free(payload);
    @memset(payload, 'x');
    const chunks = try chunkSlices(
        allocator,
        payload,
        options.chunk_bytes,
    );
    defer allocator.free(chunks);

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = options.body_bytes,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http1.runtime.Server,
        options: Options,
        payload: []const u8,
        chunks: []const []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const Context = struct {
                bytes: usize = 0,
                checksum: u64 = 0,

                fn consume(self: *@This(), data: []const u8) !void {
                    self.bytes += data.len;
                    if (data.len != 0) {
                        self.checksum +%= data[0];
                        self.checksum +%= data[data.len - 1];
                    }
                }
            };
            const total = shared.options.warmup_iterations +
                shared.options.iterations;
            for (0..total) |_| {
                var context: Context = .{};
                var request = try connection.readRequestStreaming(
                    &context,
                    Context.consume,
                );
                defer request.deinit(shared.server.allocator);
                if (request.body_bytes != shared.options.body_bytes or
                    context.bytes != shared.options.body_bytes)
                {
                    return error.UnexpectedRequestBody;
                }
                std.mem.doNotOptimizeAway(context.checksum);
                var response = try connection.startResponse(.{
                    .headers = &response_headers,
                    .body_length = if (shared.options.mode == .fixed)
                        shared.options.body_bytes
                    else
                        null,
                    .request_method = request.method,
                });
                defer response.deinit();
                if (shared.options.mode == .fixed) {
                    try response.write(shared.payload);
                } else {
                    try response.writeChunks(shared.chunks);
                }
                try response.finish();
            }
        }
    };
    var shared = Shared{
        .server = &server,
        .options = options,
        .payload = payload,
        .chunks = chunks,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.http1.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = options.body_bytes,
        },
    );
    defer client.close();

    const Context = struct {
        bytes: usize = 0,
        checksum: u64 = 0,

        fn consume(self: *@This(), data: []const u8) !void {
            self.bytes += data.len;
            if (data.len != 0) {
                self.checksum +%= data[0];
                self.checksum +%= data[data.len - 1];
            }
        }
    };
    var checksum: u64 = 0;
    for (0..options.warmup_iterations) |_| {
        checksum +%= try exchange(
            &client,
            options,
            payload,
            chunks,
            Context,
        );
    }

    const started = nowNs(io);
    for (0..options.iterations) |_| {
        checksum +%= try exchange(
            &client,
            options,
            payload,
            chunks,
            Context,
        );
    }
    const elapsed = nowNs(io) -| started;

    server_thread.join();
    if (shared.err) |err| return err;
    const wire_body_bytes = @as(u64, options.body_bytes) * 2 *
        options.iterations;
    const mebibytes_per_second = if (elapsed == 0)
        0
    else
        (wire_body_bytes * std.time.ns_per_s) /
            (elapsed * 1024 * 1024);
    std.debug.print(
        \\HTTP/1 streaming body benchmark
        \\  mode: {s}
        \\  body bytes/direction: {d}
        \\  chunk bytes: {d}
        \\  warmup iterations: {d}
        \\  iterations: {d}
        \\  ns/round-trip: {d}
        \\  aggregate body MiB/s: {d}
        \\  checksum: {d}
        \\
    , .{
        @tagName(options.mode),
        options.body_bytes,
        options.chunk_bytes,
        options.warmup_iterations,
        options.iterations,
        elapsed / options.iterations,
        mebibytes_per_second,
        checksum,
    });
}

fn exchange(
    client: *netz.http1.runtime.Client,
    options: Options,
    payload: []const u8,
    chunks: []const []const u8,
    comptime Context: type,
) !u64 {
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/body",
        .host = "localhost",
        .body_length = if (options.mode == .fixed)
            options.body_bytes
        else
            null,
    });
    defer writer.deinit();
    if (options.mode == .fixed) {
        try writer.write(payload);
    } else {
        try writer.writeChunks(chunks);
    }
    try writer.finish();

    var context: Context = .{};
    var response = try writer.readResponseStreaming(
        &context,
        Context.consume,
    );
    defer response.deinit(client.allocator);
    if (response.body_bytes != options.body_bytes or
        context.bytes != options.body_bytes)
    {
        return error.UnexpectedResponseBody;
    }
    return context.checksum;
}

fn chunkSlices(
    allocator: std.mem.Allocator,
    payload: []const u8,
    chunk_bytes: usize,
) ![][]const u8 {
    const count = payload.len / chunk_bytes;
    const chunks = try allocator.alloc([]const u8, count);
    for (chunks, 0..) |*chunk, index| {
        const start = index * chunk_bytes;
        chunk.* = payload[start..][0..chunk_bytes];
    }
    return chunks;
}

fn parseOptions(init: std.process.Init) !Options {
    var options: Options = .{};
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--mode=fixed")) {
            options.mode = .fixed;
        } else if (std.mem.eql(u8, arg, "--mode=chunked")) {
            options.mode = .chunked;
        } else if (std.mem.startsWith(u8, arg, "--body-bytes=")) {
            options.body_bytes = try std.fmt.parseInt(
                usize,
                arg["--body-bytes=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--chunk-bytes=")) {
            options.chunk_bytes = try std.fmt.parseInt(
                usize,
                arg["--chunk-bytes=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup_iterations = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else {
            return error.InvalidArguments;
        }
    }
    if (options.iterations == 0) return error.InvalidArguments;
    return options;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

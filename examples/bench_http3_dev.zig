const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 1000;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const iterations = try parseIterations(init, allocator);

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.http3.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 256,
    });
    defer server.deinit();

    const Shared = struct {
        server: *netz.http3.runtime.Server,
        iterations: usize,
        err: ?anyerror = null,
        handled: usize = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            while (shared.handled < shared.iterations) : (shared.handled += 1) {
                var request = try shared.server.receiveRequest();
                defer request.deinit(shared.server.quic_server.endpoint.allocator);
                try shared.server.sendResponse(request.from, request.stream_id, .{
                    .status = 200,
                    .body = "h3 bench pong",
                });
            }
        }
    };

    var shared = Shared{ .server = &server, .iterations = iterations };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.http3.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 256,
    });
    defer client.deinit();

    const start = nowNs(io);
    var status_total: usize = 0;
    for (0..iterations) |_| {
        var response = try client.request(.{
            .method = "GET",
            .path = "/bench",
            .authority = "localhost",
        });
        defer response.deinit(allocator);
        status_total += response.response.status;
    }
    const elapsed = nowNs(io) -| start;
    const requests_per_second = if (elapsed == 0)
        0
    else
        (@as(u64, iterations) *| std.time.ns_per_s) / elapsed;

    thread.join();
    if (shared.err) |err| return err;

    std.debug.print(
        \\HTTP/3 dev runtime benchmark
        \\  iterations: {d}
        \\  status total: {d}
        \\  ns/op: {d}
        \\  requests/s: {d}
        \\
    , .{
        iterations,
        status_total,
        elapsed / iterations,
        requests_per_second,
    });
}

fn parseIterations(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !usize {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var iterations = default_iterations;
    while (args.next()) |arg| {
        if (!std.mem.startsWith(u8, arg, "--iterations=")) {
            return error.InvalidArgument;
        }
        iterations = try std.fmt.parseInt(
            usize,
            arg["--iterations=".len..],
            10,
        );
        if (iterations == 0) return error.InvalidArgument;
    }
    return iterations;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

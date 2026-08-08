const std = @import("std");
const netz = @import("netz");

const iterations: usize = 1000;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
        err: ?anyerror = null,
        handled: usize = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            while (shared.handled < iterations) : (shared.handled += 1) {
                var request = try shared.server.receiveRequest();
                defer request.deinit(shared.server.quic_server.endpoint.allocator);
                try shared.server.sendResponse(request.from, request.stream_id, .{
                    .status = 200,
                    .body = "h3 bench pong",
                });
            }
        }
    };

    var shared = Shared{ .server = &server };
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

    thread.join();
    if (shared.err) |err| return err;

    std.debug.print(
        \\HTTP/3 dev runtime benchmark
        \\  iterations: {d}
        \\  status total: {d}
        \\  ns/op: {d}
        \\
    , .{
        iterations,
        status_total,
        elapsed / iterations,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

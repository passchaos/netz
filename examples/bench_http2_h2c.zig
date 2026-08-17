const std = @import("std");
const netz = @import("netz");

const warmup_iterations: usize = 200;
const iterations: usize = 2_000;
// Hyper's server inserts Date and then references it from the HPACK dynamic
// table. Supplying the same-length field makes steady-state responses 11 wire
// bytes in both benchmarks instead of netz's otherwise smaller 10-byte frame.
const response_headers = [_]netz.http2.Hpack.HeaderField{.{
    .name = "date",
    .value = "Mon, 17 Aug 2026 00:00:00 GMT",
}};
const request_body = "ssssssssss";

const Scenario = struct {
    name: []const u8,
    request: netz.http2.runtime.RequestOptions,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http2.runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const scenario_iterations = warmup_iterations + iterations;
            for ([_][]const u8{ "", request_body }) |expected_body| {
                var connection = try shared.server.accept();
                defer connection.close();
                for (0..scenario_iterations) |_| {
                    var request = try connection.readRequest();
                    defer request.deinit(shared.server.allocator);
                    if (!std.mem.eql(u8, request.body, expected_body)) {
                        return error.UnexpectedRequestBody;
                    }
                    try connection.writeResponse(request.stream_id, .{
                        .headers = &response_headers,
                    });
                }
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const authority = try std.fmt.allocPrint(
        allocator,
        "127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(authority);
    const scenarios = [_]Scenario{
        .{
            .name = "http2_consecutive_x1_empty",
            .request = .{
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
            },
        },
        .{
            .name = "http2_consecutive_x1_req_10b",
            .request = .{
                .method = "POST",
                .path = "/hello",
                .scheme = "http",
                .authority = authority,
                .body = request_body,
            },
        },
    };
    for (scenarios) |scenario| {
        var client = try netz.http2.runtime.Client.connect(
            allocator,
            io,
            server.address(),
            .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        );
        defer client.close();

        for (0..warmup_iterations) |_| {
            var response = try client.request(scenario.request);
            try validateResponse(response);
            response.deinit(allocator);
        }

        const start = nowNs(io);
        var status_total: usize = 0;
        for (0..iterations) |_| {
            var response = try client.request(scenario.request);
            try validateResponse(response);
            status_total += response.status;
            response.deinit(allocator);
        }
        const elapsed = nowNs(io) -| start;
        const requests_per_second = if (elapsed == 0)
            0
        else
            (@as(u64, iterations) *| std.time.ns_per_s) / elapsed;

        std.debug.print(
            \\HTTP/2 h2c runtime benchmark
            \\  shape: Hyper {s}
            \\  warmup iterations: {d}
            \\  iterations: {d}
            \\  status total: {d}
            \\  ns/op: {d}
            \\  requests/s: {d}
            \\
        , .{
            scenario.name,
            warmup_iterations,
            iterations,
            status_total,
            elapsed / iterations,
            requests_per_second,
        });
    }

    thread.join();
    if (shared.err) |err| return err;
}

fn validateResponse(response: netz.http2.runtime.OwnedResponse) !void {
    if (response.status != 200 or response.body.len != 0) {
        return error.UnexpectedResponse;
    }
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

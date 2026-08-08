const std = @import("std");
const netz = @import("netz");

const iterations: usize = 100_000;
const raw_request =
    "POST /bench?mode=parse HTTP/1.1\r\n" ++
    "Host: example.com\r\n" ++
    "User-Agent: netz-bench/1\r\n" ++
    "Accept: */*\r\n" ++
    "Content-Type: text/plain\r\n" ++
    "Content-Length: 11\r\n" ++
    "Connection: keep-alive\r\n" ++
    "\r\n" ++
    "hello world" ++
    "GET /next HTTP/1.1\r\n" ++
    "Host: example.com\r\n" ++
    "\r\n";

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var headers: [32]netz.http1.Header = undefined;

    const borrowed_start = nowNs(io);
    var borrowed_total: usize = 0;
    for (0..iterations) |_| {
        const head = try netz.http1.parseRequestHead(raw_request, &headers, .{});
        borrowed_total += (try head.messageLength()).?;
    }
    const borrowed_ns = nowNs(io) -| borrowed_start;

    const owned_start = nowNs(io);
    var owned_total: usize = 0;
    for (0..iterations) |_| {
        var request = try netz.http1.parseRequest(allocator, raw_request, .{});
        owned_total += request.consumed;
        request.deinit(allocator);
    }
    const owned_ns = nowNs(io) -| owned_start;
    const speedup_x100 = ratioTimes100(owned_ns, borrowed_ns);

    std.debug.print(
        \\HTTP/1 parse benchmark
        \\  iterations: {d}
        \\  borrowed total: {d}, ns/op: {d}
        \\  owned total: {d}, ns/op: {d}
        \\  borrowed speedup: {d}.{d:0>2}x
        \\
    , .{
        iterations,
        borrowed_total,
        borrowed_ns / iterations,
        owned_total,
        owned_ns / iterations,
        speedup_x100 / 100,
        speedup_x100 % 100,
    });
}

fn ratioTimes100(numerator: u64, denominator: u64) u64 {
    if (denominator == 0) return 0;
    return (numerator *| 100) / denominator;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 100_000;
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
const raw_absolute_request =
    "POST http://example.com/bench?mode=parse HTTP/1.1\r\n" ++
    raw_request["POST /bench?mode=parse HTTP/1.1\r\n".len..];

const Scenario = enum { all, borrowed, owned, owned_checked };
const TargetForm = enum { origin, absolute };

const Options = struct {
    scenario: Scenario = .all,
    target_form: TargetForm = .origin,
    iterations: usize = default_iterations,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const request_bytes = switch (options.target_form) {
        .origin => raw_request,
        .absolute => raw_absolute_request,
    };

    var headers: [32]netz.http1.Header = undefined;
    var borrowed_total: usize = 0;
    var borrowed_ns: u64 = 0;
    if (options.scenario == .all or options.scenario == .borrowed) {
        const started = nowNs(io);
        for (0..options.iterations) |_| {
            const head = try netz.http1.parseRequestHead(
                request_bytes,
                &headers,
                .{},
            );
            borrowed_total += (try head.messageLength()).?;
        }
        borrowed_ns = nowNs(io) -| started;
    }

    var owned_total: usize = 0;
    var owned_ns: u64 = 0;
    if (options.scenario == .all or options.scenario == .owned) {
        const started = nowNs(io);
        for (0..options.iterations) |_| {
            var request = try netz.http1.parseRequest(
                allocator,
                request_bytes,
                .{},
            );
            owned_total += request.consumed;
            request.deinit(allocator);
        }
        owned_ns = nowNs(io) -| started;
    }

    var owned_checked_total: usize = 0;
    var owned_checked_ns: u64 = 0;
    if (options.scenario == .all or options.scenario == .owned_checked) {
        const started = nowNs(io);
        for (0..options.iterations) |_| {
            var request = try netz.http1.parseRequest(
                allocator,
                request_bytes,
                .{},
            );
            try netz.http1.validateRequestHost(request);
            owned_checked_total += request.consumed;
            request.deinit(allocator);
        }
        owned_checked_ns = nowNs(io) -| started;
    }

    std.debug.print(
        "HTTP/1 parse benchmark\n  io backend: zio-std-io\n" ++
            "  target form: {s}\n" ++
            "  iterations: {d}\n",
        .{ @tagName(options.target_form), options.iterations },
    );
    if (options.scenario == .all or options.scenario == .borrowed) {
        std.debug.print(
            "  borrowed total: {d}, ns/op: {d}\n",
            .{ borrowed_total, borrowed_ns / options.iterations },
        );
    }
    if (options.scenario == .all or options.scenario == .owned) {
        std.debug.print(
            "  owned total: {d}, ns/op: {d}\n",
            .{ owned_total, owned_ns / options.iterations },
        );
    }
    if (options.scenario == .all or options.scenario == .owned_checked) {
        std.debug.print(
            "  owned+host total: {d}, ns/op: {d}\n",
            .{ owned_checked_total, owned_checked_ns / options.iterations },
        );
    }
    if (options.scenario == .all) {
        const speedup_x100 = ratioTimes100(
            owned_checked_ns,
            borrowed_ns,
        );
        std.debug.print(
            "  strict borrowed speedup: {d}.{d:0>2}x\n",
            .{ speedup_x100 / 100, speedup_x100 % 100 },
        );
    }
}

fn parseOptions(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !Options {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--scenario=")) {
            options.scenario = std.meta.stringToEnum(
                Scenario,
                arg["--scenario=".len..],
            ) orelse return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--target-form=")) {
            options.target_form = std.meta.stringToEnum(
                TargetForm,
                arg["--target-form=".len..],
            ) orelse return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
            if (options.iterations == 0) return error.InvalidArgument;
        } else {
            return error.InvalidArgument;
        }
    }
    return options;
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

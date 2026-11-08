const std = @import("std");
const sampling = @import("support/bench_sampling.zig");
const netz = @import("netz");

const default_iterations: usize = 1_000_000;
const payload_len: usize = 256;
const capsules_per_buffer: usize = 8;

const Options = struct {
    iterations: usize = default_iterations,
    samples: usize = 10,
    warmup: usize = 1,
    baseline_path: ?[]const u8 = null,
    update_baseline: bool = false,
    max_regression_ratio: f64 = 1.05,
    warn_only: bool = false,
};

const SingleParseContext = struct {
    capsule: []const u8,
    iterations: usize,
};

const IteratorContext = struct {
    stream: []const u8,
    iterations: usize,
};

const WriteContext = struct {
    payload: []const u8,
    iterations: usize,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @truncate(index);
    }

    const encoded_len = try netz.http3.capsule.encodedLen(
        netz.http3.capsule.CapsuleType.datagram,
        payload.len,
    );
    var encoded: [payload_len + 8]u8 = undefined;
    const capsule = try netz.http3.capsule.writeDatagramInto(&encoded, &payload);

    var stream_buf: [capsules_per_buffer * (payload_len + 8)]u8 = undefined;
    var stream_len: usize = 0;
    for (0..capsules_per_buffer) |_| {
        std.mem.copyForwards(u8, stream_buf[stream_len..][0..capsule.len], capsule);
        stream_len += capsule.len;
    }
    const stream = stream_buf[0..stream_len];

    var parse = try sampling.run(
        allocator,
        io,
        .{
            .iterations = options.iterations,
            .samples = options.samples,
            .warmup = options.warmup,
        },
        SingleParseContext{
            .capsule = capsule,
            .iterations = options.iterations,
        },
        singleParseWork,
    );
    defer parse.deinit(allocator);

    var iterator = try sampling.run(
        allocator,
        io,
        .{
            .iterations = options.iterations,
            .samples = options.samples,
            .warmup = options.warmup,
        },
        IteratorContext{
            .stream = stream,
            .iterations = options.iterations,
        },
        iteratorWork,
    );
    defer iterator.deinit(allocator);

    var write = try sampling.run(
        allocator,
        io,
        .{
            .iterations = options.iterations,
            .samples = options.samples,
            .warmup = options.warmup,
        },
        WriteContext{
            .payload = &payload,
            .iterations = options.iterations,
        },
        writeIntoWork,
    );
    defer write.deinit(allocator);

    std.debug.print(
        \\HTTP/3 Capsule Protocol benchmark
        \\  io backend: zio-std-io
        \\  iterations: {d}, payload bytes: {d}, encoded bytes: {d}
        \\  samples: {d}, warmup: {d}
        \\  parse single capsule:   {d} ns/op
        \\  iterate {d} capsules:    {d} ns/buffer, {d} ns/capsule
        \\  caller-buffer encode:   {d} ns/op
        \\  checksum: {d}
        \\
    , .{
        options.iterations,
        payload.len,
        encoded_len,
        options.samples,
        options.warmup,
        sampling.nsPerOp(parse, options.iterations),
        capsules_per_buffer,
        sampling.nsPerOp(iterator, options.iterations),
        sampling.nsPerOp(iterator, options.iterations * capsules_per_buffer),
        sampling.nsPerOp(write, options.iterations),
        parse.last_result +% iterator.last_result +% write.last_result,
    });
    sampling.printDistribution("parse", parse);
    sampling.printDistribution("iterate", iterator);
    sampling.printDistribution("encode", write);
    if (options.baseline_path) |path| {
        const entries = [_]sampling.BaselineEntry{
            .{ .name = "bench-http3-capsule/parse", .stats = parse },
            .{ .name = "bench-http3-capsule/iterate", .stats = iterator },
            .{ .name = "bench-http3-capsule/encode", .stats = write },
        };
        try sampling.checkBaselines(allocator, io, &entries, .{
            .path = path,
            .max_regression_ratio = options.max_regression_ratio,
            .update = options.update_baseline,
            .warn_only = options.warn_only,
        });
    }
}

fn singleParseWork(
    context: SingleParseContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var checksum: u64 = 0;
    for (0..context.iterations) |_| {
        std.mem.doNotOptimizeAway(context.capsule.ptr);
        const parsed = try netz.http3.capsule.parse(context.capsule);
        std.mem.doNotOptimizeAway(parsed.consumed);
        checksum +%= parsed.consumed;
        checksum +%= parsed.capsule.value[0];
        checksum +%= parsed.capsule.value[parsed.capsule.value.len - 1];
    }
    return checksum;
}

fn iteratorWork(
    context: IteratorContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var checksum: u64 = 0;
    for (0..context.iterations) |_| {
        std.mem.doNotOptimizeAway(context.stream.ptr);
        var iter = netz.http3.capsule.Iterator.init(context.stream);
        while (try iter.next()) |capsule| {
            std.mem.doNotOptimizeAway(capsule.value.ptr);
            checksum +%= capsule.value.len;
            checksum +%= capsule.value[0];
        }
        checksum +%= iter.remaining();
    }
    return checksum;
}

fn writeIntoWork(
    context: WriteContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var encoded: [payload_len + 8]u8 = undefined;
    var checksum: u64 = 0;
    for (0..context.iterations) |_| {
        std.mem.doNotOptimizeAway(context.payload.ptr);
        const written = try netz.http3.capsule.writeDatagramInto(
            &encoded,
            context.payload,
        );
        std.mem.doNotOptimizeAway(&encoded);
        checksum +%= written.len;
        checksum +%= written[0];
    }
    return checksum;
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
        if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
            if (options.iterations == 0) return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--samples=")) {
            options.samples = try std.fmt.parseInt(
                usize,
                arg["--samples=".len..],
                10,
            );
            if (options.samples == 0) return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--baseline=")) {
            options.baseline_path = arg["--baseline=".len..];
            if (options.baseline_path.?.len == 0) return error.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--update-baseline")) {
            options.update_baseline = true;
        } else if (std.mem.eql(u8, arg, "--warn-only")) {
            options.warn_only = true;
        } else if (std.mem.startsWith(u8, arg, "--max-regression-ratio=")) {
            options.max_regression_ratio = try std.fmt.parseFloat(
                f64,
                arg["--max-regression-ratio=".len..],
            );
            if (!std.math.isFinite(options.max_regression_ratio) or
                options.max_regression_ratio <= 0)
            {
                return error.InvalidArgument;
            }
        } else {
            return error.InvalidArgument;
        }
    }
    if (options.update_baseline and options.baseline_path == null) {
        return error.InvalidArgument;
    }
    return options;
}

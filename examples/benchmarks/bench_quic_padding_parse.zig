const std = @import("std");
const sampling = @import("support").bench_sampling;
const netz = @import("netz");

const default_iterations: usize = 1_000_000;
const padding_len: usize = 1200;

const Options = struct {
    iterations: usize = default_iterations,
    samples: usize = 10,
    warmup: usize = 1,
    baseline_path: ?[]const u8 = null,
    update_baseline: bool = false,
    max_regression_ratio: f64 = 1.05,
    warn_only: bool = false,
};

const PaddingOnlyContext = struct {
    payload: []const u8,
    iterations: usize,
};

const PaddingThenPingContext = struct {
    payload: []const u8,
    iterations: usize,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var payload: [padding_len + 1]u8 = .{0} ** (padding_len + 1);
    payload[payload.len - 1] = @intFromEnum(netz.quic.FrameType.ping);

    var padding_only = try sampling.run(
        allocator,
        io,
        .{
            .iterations = options.iterations,
            .samples = options.samples,
            .warmup = options.warmup,
        },
        PaddingOnlyContext{
            .payload = payload[0..padding_len],
            .iterations = options.iterations,
        },
        paddingOnlyWork,
    );
    defer padding_only.deinit(allocator);

    var padding_then_ping = try sampling.run(
        allocator,
        io,
        .{
            .iterations = options.iterations,
            .samples = options.samples,
            .warmup = options.warmup,
        },
        PaddingThenPingContext{
            .payload = &payload,
            .iterations = options.iterations,
        },
        paddingThenPingWork,
    );
    defer padding_then_ping.deinit(allocator);

    const checksum = padding_only.last_result +% padding_then_ping.last_result;

    std.debug.print(
        \\QUIC PADDING parse benchmark
        \\  io backend: zio-std-io
        \\  iterations: {d}, padding bytes: {d}
        \\  samples: {d}, warmup: {d}
        \\  padding-only payload:  {d} ns/op
        \\  padding before PING:   {d} ns/op
        \\  checksum: {d}
        \\
    , .{
        options.iterations,
        padding_len,
        options.samples,
        options.warmup,
        sampling.nsPerOp(padding_only, options.iterations),
        sampling.nsPerOp(padding_then_ping, options.iterations),
        checksum,
    });
    sampling.printDistribution("padding-only", padding_only);
    sampling.printDistribution("padding+ping", padding_then_ping);
    if (options.baseline_path) |path| {
        const entries = [_]sampling.BaselineEntry{
            .{
                .name = "bench-quic-padding-parse/padding-only",
                .stats = padding_only,
            },
            .{
                .name = "bench-quic-padding-parse/padding-then-ping",
                .stats = padding_then_ping,
            },
        };
        try sampling.checkBaselines(allocator, io, &entries, .{
            .path = path,
            .max_regression_ratio = options.max_regression_ratio,
            .update = options.update_baseline,
            .warn_only = options.warn_only,
        });
    }
}

fn paddingOnlyWork(
    context: PaddingOnlyContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var checksum: u64 = 0;
    for (0..context.iterations) |_| {
        const parsed = try netz.quic.parseFrame(context.payload);
        checksum +%= parsed.consumed;
        checksum +%= parsed.frame.padding.len;
    }
    return checksum;
}

fn paddingThenPingWork(
    context: PaddingThenPingContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var checksum: u64 = 0;
    for (0..context.iterations) |_| {
        const parsed = try netz.quic.parseFrame(context.payload);
        checksum +%= parsed.consumed;
        checksum +%= parsed.frame.padding.len;
        const ping = try netz.quic.parseFrame(context.payload[parsed.consumed..]);
        checksum +%= @intFromEnum(std.meta.activeTag(ping.frame));
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

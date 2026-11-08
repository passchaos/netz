const std = @import("std");
const sampling = @import("support/bench_sampling.zig");
const netz = @import("netz");

const default_iterations: usize = 100_000;
const default_churn_iterations: usize = 50_000;

const headers = [_]netz.http2.Hpack.HeaderField{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "example.com" },
    .{ .name = ":path", .value = "/assets/app.js" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "user-agent", .value = "netz-hpack-bench/1" },
    .{ .name = "cache-control", .value = "no-cache" },
};

const Options = struct {
    iterations: usize = default_iterations,
    churn_iterations: usize = default_churn_iterations,
    samples: usize = 10,
    warmup: usize = 1,
    baseline_path: ?[]const u8 = null,
    update_baseline: bool = false,
    max_regression_ratio: f64 = 1.05,
    warn_only: bool = false,
};

const EncodeContext = struct {
    encoder: *netz.http2.Hpack.Encoder,
    block: *std.ArrayList(u8),
    fields: []const netz.http2.Hpack.HeaderField,
    iterations: usize,
};

const DecodeContext = struct {
    decoder: *netz.http2.Hpack.Decoder,
    block: []const u8,
    iterations: usize,
};

const DecodeIntoContext = struct {
    decoder: *netz.http2.Hpack.Decoder,
    block: []const u8,
    storage: []netz.http2.Hpack.HeaderField,
    iterations: usize,
};

const DecodeOwnedContext = struct {
    decoder: *netz.http2.Hpack.Decoder,
    block: []const u8,
    max_fields: usize,
    iterations: usize,
};

const RoundtripContext = struct {
    encoder: *netz.http2.Hpack.Encoder,
    decoder: *netz.http2.Hpack.Decoder,
    block: *std.ArrayList(u8),
    fields: []const netz.http2.Hpack.HeaderField,
    iterations: usize,
};

const StatelessContext = struct {
    block: *std.ArrayList(u8),
    fields: []const netz.http2.Hpack.HeaderField,
    iterations: usize,
};

const ChurnContext = struct {
    names: [][24]u8,
    values: [][24]u8,
    iterations: usize,
    maintain_lookup_indexes: bool,
};

const ValidateContext = struct {
    fields: []const netz.http2.Hpack.HeaderField,
    iterations: usize,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var stateful_encoder = netz.http2.Hpack.Encoder{};
    defer stateful_encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);

    var encode_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.iterations),
        EncodeContext{
            .encoder = &stateful_encoder,
            .block = &block,
            .fields = &headers,
            .iterations = options.iterations,
        },
        encodeWork,
    );
    defer encode_run.deinit(allocator);

    var decode_block: std.ArrayList(u8) = .empty;
    defer decode_block.deinit(allocator);
    var decode_encoder = netz.http2.Hpack.Encoder{};
    defer decode_encoder.deinit(allocator);
    try decode_encoder.encodeBlock(&decode_block, allocator, &headers);

    var stateful_decoder = netz.http2.Hpack.Decoder{};
    defer stateful_decoder.deinit(allocator);
    var decode_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.iterations),
        DecodeContext{
            .decoder = &stateful_decoder,
            .block = decode_block.items,
            .iterations = options.iterations,
        },
        decodeWork,
    );
    defer decode_run.deinit(allocator);

    var decode_into_decoder = netz.http2.Hpack.Decoder{};
    defer decode_into_decoder.deinit(allocator);
    var decode_storage: [headers.len]netz.http2.Hpack.HeaderField = undefined;
    var decode_into_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.iterations),
        DecodeIntoContext{
            .decoder = &decode_into_decoder,
            .block = decode_block.items,
            .storage = &decode_storage,
            .iterations = options.iterations,
        },
        decodeIntoWork,
    );
    defer decode_into_run.deinit(allocator);

    var decode_owned_decoder = netz.http2.Hpack.Decoder{};
    defer decode_owned_decoder.deinit(allocator);
    var decode_owned_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.iterations),
        DecodeOwnedContext{
            .decoder = &decode_owned_decoder,
            .block = decode_block.items,
            .max_fields = headers.len,
            .iterations = options.iterations,
        },
        decodeOwnedWork,
    );
    defer decode_owned_run.deinit(allocator);

    var roundtrip_encoder = netz.http2.Hpack.Encoder{};
    defer roundtrip_encoder.deinit(allocator);
    var roundtrip_decoder = netz.http2.Hpack.Decoder{};
    defer roundtrip_decoder.deinit(allocator);
    var roundtrip_block: std.ArrayList(u8) = .empty;
    defer roundtrip_block.deinit(allocator);
    var stateful_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.iterations),
        RoundtripContext{
            .encoder = &roundtrip_encoder,
            .decoder = &roundtrip_decoder,
            .block = &roundtrip_block,
            .fields = &headers,
            .iterations = options.iterations,
        },
        statefulRoundtripWork,
    );
    defer stateful_run.deinit(allocator);

    var stateless_block: std.ArrayList(u8) = .empty;
    defer stateless_block.deinit(allocator);
    var stateless_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.iterations),
        StatelessContext{
            .block = &stateless_block,
            .fields = &headers,
            .iterations = options.iterations,
        },
        statelessRoundtripWork,
    );
    defer stateless_run.deinit(allocator);

    const churn_names = try allocator.alloc([24]u8, options.churn_iterations);
    defer allocator.free(churn_names);
    const churn_values = try allocator.alloc([24]u8, options.churn_iterations);
    defer allocator.free(churn_values);

    var encoder_churn_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.churn_iterations),
        ChurnContext{
            .names = churn_names,
            .values = churn_values,
            .iterations = options.churn_iterations,
            .maintain_lookup_indexes = true,
        },
        churnWork,
    );
    defer encoder_churn_run.deinit(allocator);

    var decoder_churn_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.churn_iterations),
        ChurnContext{
            .names = churn_names,
            .values = churn_values,
            .iterations = options.churn_iterations,
            .maintain_lookup_indexes = false,
        },
        churnWork,
    );
    defer decoder_churn_run.deinit(allocator);

    var validate_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, options.iterations),
        ValidateContext{
            .fields = &headers,
            .iterations = options.iterations,
        },
        validateWork,
    );
    defer validate_run.deinit(allocator);

    const speedup_x100 = sampling.ratioTimes100(
        stateless_run.distribution.median,
        stateful_run.distribution.median,
    );

    std.debug.print(
        \\HTTP/2 HPACK benchmark
        \\  io backend: zio-std-io
        \\  iterations: {d}
        \\  samples: {d}, warmup: {d}
        \\  stateful encode-only total bytes: {d}, ns/op: {d}
        \\  stateful decode-only fields: {d}, ns/op: {d}
        \\  stateful decode-into fields: {d}, ns/op: {d}
        \\  stateful decode-owned fields: {d}, ns/op: {d}
        \\  stateful total bytes: {d}, ns/op: {d}
        \\  stateless total bytes: {d}, ns/op: {d}
        \\  stateful speedup: {d}.{d:0>2}x
        \\  encoder table churn iterations: {d}, ns/insert: {d}
        \\  decoder table churn iterations: {d}, ns/insert: {d}
        \\  request header validation: ns/block: {d}
        \\
    , .{
        options.iterations,
        options.samples,
        options.warmup,
        encode_run.last_result,
        sampling.nsPerOp(encode_run, options.iterations),
        decode_run.last_result,
        sampling.nsPerOp(decode_run, options.iterations),
        decode_into_run.last_result,
        sampling.nsPerOp(decode_into_run, options.iterations),
        decode_owned_run.last_result,
        sampling.nsPerOp(decode_owned_run, options.iterations),
        stateful_run.last_result,
        sampling.nsPerOp(stateful_run, options.iterations),
        stateless_run.last_result,
        sampling.nsPerOp(stateless_run, options.iterations),
        speedup_x100 / 100,
        speedup_x100 % 100,
        options.churn_iterations,
        sampling.nsPerOp(encoder_churn_run, options.churn_iterations),
        options.churn_iterations,
        sampling.nsPerOp(decoder_churn_run, options.churn_iterations),
        sampling.nsPerOp(validate_run, options.iterations),
    });
    sampling.printDistribution("encode", encode_run);
    sampling.printDistribution("decode", decode_run);
    sampling.printDistribution("decode-into", decode_into_run);
    sampling.printDistribution("decode-owned", decode_owned_run);
    sampling.printDistribution("stateful-roundtrip", stateful_run);
    sampling.printDistribution("stateless-roundtrip", stateless_run);
    sampling.printDistribution("encoder-churn", encoder_churn_run);
    sampling.printDistribution("decoder-churn", decoder_churn_run);
    sampling.printDistribution("header-validation", validate_run);

    if (options.baseline_path) |path| {
        const entries = [_]sampling.BaselineEntry{
            .{ .name = "bench-http2-hpack/encode", .stats = encode_run },
            .{ .name = "bench-http2-hpack/decode", .stats = decode_run },
            .{ .name = "bench-http2-hpack/decode-into", .stats = decode_into_run },
            .{ .name = "bench-http2-hpack/decode-owned", .stats = decode_owned_run },
            .{ .name = "bench-http2-hpack/stateful-roundtrip", .stats = stateful_run },
            .{ .name = "bench-http2-hpack/stateless-roundtrip", .stats = stateless_run },
            .{ .name = "bench-http2-hpack/encoder-churn", .stats = encoder_churn_run },
            .{ .name = "bench-http2-hpack/decoder-churn", .stats = decoder_churn_run },
            .{ .name = "bench-http2-hpack/header-validation", .stats = validate_run },
        };
        try sampling.checkBaselines(allocator, io, &entries, .{
            .path = path,
            .max_regression_ratio = options.max_regression_ratio,
            .update = options.update_baseline,
            .warn_only = options.warn_only,
        });
    }
}

fn samplingOptions(options: Options, iterations: usize) sampling.Options {
    return .{
        .iterations = iterations,
        .samples = options.samples,
        .warmup = options.warmup,
    };
}

fn encodeWork(
    context: EncodeContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        context.block.clearRetainingCapacity();
        try context.encoder.encodeBlock(
            context.block,
            allocator,
            context.fields,
        );
        total += context.block.items.len;
    }
    return total;
}

fn decodeWork(
    context: DecodeContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        const decoded = try context.decoder.decodeBlock(
            allocator,
            context.block,
        );
        total += decoded.len;
        netz.http2.Hpack.freeDecodedFields(allocator, decoded);
    }
    return total;
}

fn decodeIntoWork(
    context: DecodeIntoContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        const decoded = try context.decoder.decodeBlockInto(
            allocator,
            context.block,
            context.storage,
        );
        total += decoded.len;
        netz.http2.Hpack.freeDecodedFieldStorages(allocator, decoded);
    }
    return total;
}

fn decodeOwnedWork(
    context: DecodeOwnedContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        const decoded = try context.decoder.decodeBlockOwnedWithLimit(
            allocator,
            context.block,
            context.max_fields,
            std.math.maxInt(usize),
        );
        total += decoded.len;
        netz.http2.Hpack.freeOwnedFields(allocator, decoded);
    }
    return total;
}

fn statefulRoundtripWork(
    context: RoundtripContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        context.block.clearRetainingCapacity();
        try context.encoder.encodeBlock(
            context.block,
            allocator,
            context.fields,
        );
        total += context.block.items.len;
        const decoded = try context.decoder.decodeBlock(
            allocator,
            context.block.items,
        );
        netz.http2.Hpack.freeDecodedFields(allocator, decoded);
    }
    return total;
}

fn statelessRoundtripWork(
    context: StatelessContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        context.block.clearRetainingCapacity();
        try netz.http2.Hpack.encodeLiteralBlock(
            context.block,
            allocator,
            context.fields,
        );
        total += context.block.items.len;
        const decoded = try netz.http2.Hpack.decodeLiteralBlock(
            allocator,
            context.block.items,
        );
        netz.http2.Hpack.freeDecodedFields(allocator, decoded);
    }
    return total;
}

fn churnWork(
    context: ChurnContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var table = netz.http2.Hpack.DynamicTable{
        .maintain_lookup_indexes = context.maintain_lookup_indexes,
    };
    defer table.deinit(allocator);
    table.setLimit(allocator, 4096);
    for (0..context.iterations) |index| {
        const name = try std.fmt.bufPrint(
            &context.names[index],
            "x-hpack-churn-{d:0>5}",
            .{index},
        );
        const value = try std.fmt.bufPrint(
            &context.values[index],
            "value-{d:0>8}",
            .{index},
        );
        try table.add(allocator, name, value);
    }
    return @intCast(table.used);
}

fn validateWork(
    context: ValidateContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        try netz.http2.runtime.validateHeaderBlock(
            context.fields,
            .request,
        );
        total +%= context.fields.len;
    }
    return total;
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
        } else if (std.mem.startsWith(u8, arg, "--churn-iterations=")) {
            options.churn_iterations = try std.fmt.parseInt(
                usize,
                arg["--churn-iterations=".len..],
                10,
            );
            if (options.churn_iterations == 0) return error.InvalidArgument;
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

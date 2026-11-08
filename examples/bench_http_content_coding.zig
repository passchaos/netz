const std = @import("std");
const sampling = @import("support/bench_sampling.zig");
const netz = @import("netz");

const payload_len: usize = 4096;
const default_iterations: usize = 200_000;

const Options = struct {
    iterations: usize = default_iterations,
    samples: usize = 10,
    warmup: usize = 1,
    baseline_path: ?[]const u8 = null,
    update_baseline: bool = false,
    max_regression_ratio: f64 = 1.05,
    warn_only: bool = false,
};

const DecodeContext = struct {
    chain: netz.http.content_coding.Chain,
    encoded: []const u8,
    output: []u8,
    iterations: usize,
};

const StreamContext = struct {
    decoder: *netz.http.content_coding.StreamDecoder,
    encoded: []const u8,
    output: []u8,
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
        byte.* = "content-encoding=bounded;cache=vort;"[
            index % "content-encoding=bounded;cache=vort;".len
        ];
    }
    var encoded = try netz.grpc.compressMessageAlloc(
        allocator,
        .gzip,
        &payload,
        1,
    );
    defer encoded.deinit(allocator);
    if (!encoded.compressed) return error.CompressionNotUseful;

    const chain = try netz.http.content_coding.parse("gzip");
    var output: [payload_len]u8 = undefined;
    _ = try chain.decodeInto(encoded.bytes, &output, &.{});

    var decode_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options),
        DecodeContext{
            .chain = chain,
            .encoded = encoded.bytes,
            .output = &output,
            .iterations = options.iterations,
        },
        decodeWork,
    );
    defer decode_run.deinit(allocator);

    var stream_decoder = try chain.streamDecoder(allocator, .{
        .max_encoded_bytes = encoded.bytes.len,
        .max_decoded_bytes = payload.len,
    });
    defer stream_decoder.deinit();
    _ = try decodeStreaming(&stream_decoder, encoded.bytes, &output);

    var stream_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options),
        StreamContext{
            .decoder = &stream_decoder,
            .encoded = encoded.bytes,
            .output = &output,
            .iterations = options.iterations,
        },
        streamWork,
    );
    defer stream_run.deinit(allocator);

    std.debug.print(
        \\HTTP content-coding benchmark
        \\  io backend: zio-std-io
        \\  coding: gzip, iterations: {d}
        \\  samples: {d}, warmup: {d}
        \\  payload: {d} bytes, encoded: {d} bytes
        \\  caller-buffer decode: {d} ns/representation
        \\  incremental decode: {d} ns/representation
        \\  incremental decoder state: {d} bytes
        \\  checksum: {d}
        \\
    , .{
        options.iterations,
        options.samples,
        options.warmup,
        payload.len,
        encoded.bytes.len,
        sampling.nsPerOp(decode_run, options.iterations),
        sampling.nsPerOp(stream_run, options.iterations),
        @sizeOf(netz.http.content_coding.StreamDecoder),
        decode_run.last_result +% stream_run.last_result,
    });
    sampling.printDistribution("caller-buffer", decode_run);
    sampling.printDistribution("incremental", stream_run);

    if (options.baseline_path) |path| {
        const entries = [_]sampling.BaselineEntry{
            .{
                .name = "bench-http-content-coding/decode",
                .stats = decode_run,
            },
            .{
                .name = "bench-http-content-coding/incremental",
                .stats = stream_run,
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

fn samplingOptions(options: Options) sampling.Options {
    return .{
        .iterations = options.iterations,
        .samples = options.samples,
        .warmup = options.warmup,
    };
}

fn decodeWork(
    context: DecodeContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var checksum: u64 = 0;
    for (0..context.iterations) |iteration| {
        const decoded = try context.chain.decodeInto(
            context.encoded,
            context.output,
            &.{},
        );
        checksum +%= decoded[iteration % decoded.len];
    }
    return checksum;
}

fn streamWork(
    context: StreamContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var checksum: u64 = 0;
    for (0..context.iterations) |iteration| {
        const decoded = try decodeStreaming(
            context.decoder,
            context.encoded,
            context.output,
        );
        checksum +%= decoded[iteration % decoded.len];
    }
    return checksum;
}

fn decodeStreaming(
    decoder: *netz.http.content_coding.StreamDecoder,
    input: []const u8,
    output: []u8,
) ![]u8 {
    decoder.reset();
    var input_offset: usize = 0;
    var output_offset: usize = 0;
    while (input_offset < input.len) {
        const result = try decoder.step(
            input[input_offset..],
            output[output_offset..],
        );
        input_offset += result.input_read;
        output_offset += result.output_written;
        if (result.status == .done) break;
        if (result.input_read == 0 and result.output_written == 0) {
            return error.NoProgress;
        }
    }
    while (!decoder.finished()) {
        const result = try decoder.finish(output[output_offset..]);
        output_offset += result.output_written;
        if (result.status == .done) break;
        if (result.output_written == 0) return error.NoProgress;
    }
    return output[0..output_offset];
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

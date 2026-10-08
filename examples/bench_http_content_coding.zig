const std = @import("std");
const netz = @import("netz");

const payload_len: usize = 4096;
const default_iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const iterations = try parseIterations(init, allocator);
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

    const started = nowNs(io);
    var checksum: u64 = 0;
    for (0..iterations) |iteration| {
        const decoded = try chain.decodeInto(
            encoded.bytes,
            &output,
            &.{},
        );
        checksum +%= decoded[iteration % decoded.len];
    }
    const elapsed = nowNs(io) -| started;

    std.debug.print(
        \\HTTP content-coding benchmark
        \\  io backend: zio-std-io
        \\  coding: gzip, iterations: {d}
        \\  payload: {d} bytes, encoded: {d} bytes
        \\  caller-buffer decode: {d} ns/representation
        \\  checksum: {d}
        \\
    , .{
        iterations,
        payload.len,
        encoded.bytes.len,
        elapsed / iterations,
        checksum,
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

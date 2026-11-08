const std = @import("std");
const sampling = @import("support/bench_sampling.zig");
const netz = @import("netz");

const table_entries: usize = 512;
const fields_per_block: usize = 32;
const large_fields_per_block: usize = 512;
const default_iterations: usize = 100_000;

const Scenario = enum { all, encode, large, churn, decode };

const Options = struct {
    scenario: Scenario = .all,
    iterations: usize = default_iterations,
    samples: usize = 10,
    warmup: usize = 1,
    baseline_path: ?[]const u8 = null,
    update_baseline: bool = false,
    max_regression_ratio: f64 = 1.05,
    warn_only: bool = false,
};

const EncodeContext = struct {
    table: netz.http3.Qpack.DynamicTable,
    fields: []const netz.http3.Qpack.HeaderField,
    encoded: *std.ArrayList(u8),
    references: *std.ArrayList(u64),
    iterations: usize,
};

const DecodeContext = struct {
    table: netz.http3.Qpack.DynamicTable,
    encoded: []const u8,
    iterations: usize,
};

const ChurnContext = struct {
    iterations: usize,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var table = netz.http3.Qpack.DynamicTable.init(allocator, 64 * 1024);
    defer table.deinit();
    try table.setCapacity(64 * 1024);

    var names: [table_entries][24]u8 = undefined;
    var values: [table_entries][24]u8 = undefined;
    var name_slices: [table_entries][]const u8 = undefined;
    var value_slices: [table_entries][]const u8 = undefined;
    for (0..table_entries) |index| {
        name_slices[index] = try std.fmt.bufPrint(
            &names[index],
            "x-qpack-field-{d:0>4}",
            .{index},
        );
        value_slices[index] = try std.fmt.bufPrint(
            &values[index],
            "value-{d:0>8}",
            .{index},
        );
        _ = try table.insert(name_slices[index], value_slices[index]);
    }

    var fields: [fields_per_block]netz.http3.Qpack.HeaderField = undefined;
    for (&fields, 0..) |*field, index| {
        // Mix newest and old entries so a benchmark cannot accidentally hide
        // full-table scan cost behind only recent matches.
        const table_index = if ((index & 1) == 0)
            table_entries - 1 - index
        else
            index;
        field.* = .{
            .name = name_slices[table_index],
            .value = value_slices[table_index],
        };
    }

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var references: std.ArrayList(u64) = .empty;
    defer references.deinit(allocator);

    var encoded_len: usize = 0;
    var references_len: usize = 0;
    if (options.scenario == .all or
        options.scenario == .encode or
        options.scenario == .decode)
    {
        // Warm allocator capacities before timing the lookup and
        // representation work. The production encoder also retains both
        // buffers across sections.
        try netz.http3.Qpack.encodeDynamicBlockKnownReceived(
            &encoded,
            allocator,
            &fields,
            table,
            table.insert_count,
            &references,
        );
        encoded_len = encoded.items.len;
        references_len = references.items.len;
    }

    var encode_run: ?sampling.Stats = null;
    defer if (encode_run) |*run| run.deinit(allocator);
    if (options.scenario == .all or options.scenario == .encode) {
        encode_run = try sampling.run(
            allocator,
            io,
            samplingOptions(options),
            EncodeContext{
                .table = table,
                .fields = &fields,
                .encoded = &encoded,
                .references = &references,
                .iterations = options.iterations,
            },
            encodeWork,
        );
    }

    var large_run: ?sampling.Stats = null;
    defer if (large_run) |*run| run.deinit(allocator);
    if (options.scenario == .all or options.scenario == .large) {
        var large_fields: [large_fields_per_block]netz.http3.Qpack.HeaderField =
            undefined;
        for (&large_fields, 0..) |*field, index| {
            field.* = .{
                .name = name_slices[index],
                .value = value_slices[index],
            };
        }
        var large_encoded: std.ArrayList(u8) = .empty;
        defer large_encoded.deinit(allocator);
        var large_references: std.ArrayList(u64) = .empty;
        defer large_references.deinit(allocator);
        large_run = try sampling.run(
            allocator,
            io,
            samplingOptions(options),
            EncodeContext{
                .table = table,
                .fields = &large_fields,
                .encoded = &large_encoded,
                .references = &large_references,
                .iterations = options.iterations,
            },
            encodeWork,
        );
    }

    var churn_run: ?sampling.Stats = null;
    defer if (churn_run) |*run| run.deinit(allocator);
    if (options.scenario == .all or options.scenario == .churn) {
        churn_run = try sampling.run(
            allocator,
            io,
            samplingOptions(options),
            ChurnContext{ .iterations = options.iterations },
            churnWork,
        );
    }

    var decode_run: ?sampling.Stats = null;
    defer if (decode_run) |*run| run.deinit(allocator);
    if (options.scenario == .all or options.scenario == .decode) {
        decode_run = try sampling.run(
            allocator,
            io,
            samplingOptions(options),
            DecodeContext{
                .table = table,
                .encoded = encoded.items,
                .iterations = options.iterations,
            },
            decodeWork,
        );
    }

    std.debug.print(
        "HTTP/3 QPACK dynamic benchmark\n  io backend: zio-std-io\n  iterations: {d}, table entries: {d}\n  samples: {d}, warmup: {d}\n",
        .{ options.iterations, table.entryCount(), options.samples, options.warmup },
    );
    if (encode_run) |run| {
        std.debug.print("  {d}-field encode: {d} bytes, {d} references, {d} ns/block, {d} ns/field\n", .{
            fields_per_block,
            encoded_len,
            references_len,
            sampling.nsPerOp(run, options.iterations),
            sampling.nsPerOp(run, options.iterations * fields_per_block),
        });
        sampling.printDistribution("encode", run);
    }
    if (large_run) |run| {
        std.debug.print("  512-reference encode: {d} ns/block, {d} ns/field\n", .{
            sampling.nsPerOp(run, options.iterations),
            sampling.nsPerOp(run, options.iterations * large_fields_per_block),
        });
        sampling.printDistribution("large", run);
    }
    if (churn_run) |run| {
        std.debug.print(
            "  dynamic table churn: {d} ns/insert\n",
            .{sampling.nsPerOp(run, options.iterations)},
        );
        sampling.printDistribution("churn", run);
    }
    if (decode_run) |run| {
        std.debug.print(
            "  owned dynamic decode: {d} ns/block\n",
            .{sampling.nsPerOp(run, options.iterations)},
        );
        sampling.printDistribution("decode", run);
    }
    std.debug.print(
        \\  checksum: {d}
        \\
    , .{if (encode_run) |run| run.last_result else 0});

    if (options.baseline_path) |path| {
        var entries: [4]sampling.BaselineEntry = undefined;
        var count: usize = 0;
        if (encode_run) |run| {
            entries[count] = .{
                .name = "bench-http3-qpack/encode",
                .stats = run,
            };
            count += 1;
        }
        if (large_run) |run| {
            entries[count] = .{
                .name = "bench-http3-qpack/large",
                .stats = run,
            };
            count += 1;
        }
        if (churn_run) |run| {
            entries[count] = .{
                .name = "bench-http3-qpack/churn",
                .stats = run,
            };
            count += 1;
        }
        if (decode_run) |run| {
            entries[count] = .{
                .name = "bench-http3-qpack/decode",
                .stats = run,
            };
            count += 1;
        }
        try sampling.checkBaselines(allocator, io, entries[0..count], .{
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

fn encodeWork(
    context: EncodeContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        context.encoded.clearRetainingCapacity();
        context.references.clearRetainingCapacity();
        try netz.http3.Qpack.encodeDynamicBlockKnownReceived(
            context.encoded,
            allocator,
            context.fields,
            context.table,
            context.table.insert_count,
            context.references,
        );
        total +|= context.encoded.items.len;
        total +|= context.references.items.len;
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
        var decoded = try netz.http3.Qpack.decodeDynamicBlockOwnedWithLimit(
            allocator,
            context.encoded,
            context.table,
            64 * 1024,
        );
        std.mem.doNotOptimizeAway(decoded.fields.ptr);
        std.mem.doNotOptimizeAway(decoded.fields.len);
        total += decoded.fields.len;
        netz.http3.Qpack.freeDynamicBlock(allocator, &decoded);
    }
    return total;
}

fn churnWork(
    context: ChurnContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var table = netz.http3.Qpack.DynamicTable.init(allocator, 4096);
    defer table.deinit();
    try table.setCapacity(4096);
    var name_buf: [32]u8 = undefined;
    var value_buf: [32]u8 = undefined;
    for (0..context.iterations) |index| {
        const name = try std.fmt.bufPrint(
            &name_buf,
            "x-qpack-churn-{d:0>5}",
            .{index},
        );
        const value = try std.fmt.bufPrint(
            &value_buf,
            "value-{d:0>8}",
            .{index},
        );
        _ = try table.insert(name, value);
    }
    return @intCast(table.entryCount());
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
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
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

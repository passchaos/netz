const std = @import("std");
const netz = @import("netz");

const table_entries: usize = 512;
const fields_per_block: usize = 32;
const large_fields_per_block: usize = 512;
const default_iterations: usize = 100_000;

const Scenario = enum { all, encode, large, churn, decode };

const Options = struct {
    scenario: Scenario = .all,
    iterations: usize = default_iterations,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

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

    var encoded_total: usize = 0;
    var reference_total: usize = 0;
    var encoded_len: usize = 0;
    var references_len: usize = 0;
    var encode_ns: u64 = 0;
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
        if (options.scenario == .all or options.scenario == .encode) {
            const started = nowNs(io);
            for (0..options.iterations) |_| {
                encoded.clearRetainingCapacity();
                references.clearRetainingCapacity();
                try netz.http3.Qpack.encodeDynamicBlockKnownReceived(
                    &encoded,
                    allocator,
                    &fields,
                    table,
                    table.insert_count,
                    &references,
                );
                encoded_total +|= encoded.items.len;
                reference_total +|= references.items.len;
            }
            encode_ns = nowNs(io) -| started;
        }
    }
    const large_ns = if (options.scenario == .all or options.scenario == .large)
        try measureLargeReferenceBlock(
            allocator,
            io,
            table,
            &name_slices,
            &value_slices,
            options.iterations,
        )
    else
        0;
    const churn_ns = if (options.scenario == .all or options.scenario == .churn)
        try measureDynamicTableChurn(allocator, io, options.iterations)
    else
        0;
    const decode_ns = if (options.scenario == .all or options.scenario == .decode)
        try measureOwnedDecode(
            allocator,
            io,
            table,
            encoded.items,
            options.iterations,
        )
    else
        0;

    std.debug.print(
        "HTTP/3 QPACK dynamic benchmark\n  iterations: {d}, table entries: {d}\n",
        .{ options.iterations, table.entryCount() },
    );
    if (options.scenario == .all or options.scenario == .encode) {
        std.debug.print("  {d}-field encode: {d} bytes, {d} references, {d} ns/block, {d} ns/field\n", .{
            fields_per_block,
            encoded_len,
            references_len,
            encode_ns / options.iterations,
            encode_ns / (options.iterations * fields_per_block),
        });
    }
    if (options.scenario == .all or options.scenario == .large) {
        std.debug.print("  512-reference encode: {d} ns/block, {d} ns/field\n", .{
            large_ns / options.iterations,
            large_ns / (options.iterations * large_fields_per_block),
        });
    }
    if (options.scenario == .all or options.scenario == .churn) {
        std.debug.print(
            "  dynamic table churn: {d} ns/insert\n",
            .{churn_ns / options.iterations},
        );
    }
    if (options.scenario == .all or options.scenario == .decode) {
        std.debug.print(
            "  owned dynamic decode: {d} ns/block\n",
            .{decode_ns / options.iterations},
        );
    }
    std.debug.print(
        \\  checksum: {d}
        \\
    , .{encoded_total +| reference_total});
}

fn measureOwnedDecode(
    allocator: std.mem.Allocator,
    io: std.Io,
    table: netz.http3.Qpack.DynamicTable,
    encoded: []const u8,
    iteration_count: usize,
) !u64 {
    const started = nowNs(io);
    for (0..iteration_count) |_| {
        var decoded = try netz.http3.Qpack.decodeDynamicBlockOwnedWithLimit(
            allocator,
            encoded,
            table,
            64 * 1024,
        );
        netz.http3.Qpack.freeDynamicBlock(allocator, &decoded);
    }
    return nowNs(io) -| started;
}

fn measureLargeReferenceBlock(
    allocator: std.mem.Allocator,
    io: std.Io,
    table: netz.http3.Qpack.DynamicTable,
    names: []const []const u8,
    values: []const []const u8,
    iteration_count: usize,
) !u64 {
    var fields: [large_fields_per_block]netz.http3.Qpack.HeaderField =
        undefined;
    for (&fields, 0..) |*field, index| {
        field.* = .{
            .name = names[index],
            .value = values[index],
        };
    }
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var references: std.ArrayList(u64) = .empty;
    defer references.deinit(allocator);
    try netz.http3.Qpack.encodeDynamicBlockKnownReceived(
        &encoded,
        allocator,
        &fields,
        table,
        table.insert_count,
        &references,
    );
    const started = nowNs(io);
    for (0..iteration_count) |_| {
        encoded.clearRetainingCapacity();
        references.clearRetainingCapacity();
        try netz.http3.Qpack.encodeDynamicBlockKnownReceived(
            &encoded,
            allocator,
            &fields,
            table,
            table.insert_count,
            &references,
        );
    }
    std.mem.doNotOptimizeAway(encoded.items.ptr);
    return nowNs(io) -| started;
}

fn measureDynamicTableChurn(
    allocator: std.mem.Allocator,
    io: std.Io,
    iteration_count: usize,
) !u64 {
    var table = netz.http3.Qpack.DynamicTable.init(allocator, 4096);
    defer table.deinit();
    try table.setCapacity(4096);
    var name_buf: [32]u8 = undefined;
    var value_buf: [32]u8 = undefined;
    const started = nowNs(io);
    for (0..iteration_count) |index| {
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
    return nowNs(io) -| started;
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
        } else {
            return error.InvalidArgument;
        }
    }
    return options;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

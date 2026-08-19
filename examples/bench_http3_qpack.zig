const std = @import("std");
const netz = @import("netz");

const table_entries: usize = 512;
const fields_per_block: usize = 32;
const iterations: usize = 100_000;
const churn_iterations: usize = 100_000;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
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

    // Warm allocator capacities before timing the lookup and representation
    // work. The production encoder also retains both buffers across sections.
    try netz.http3.Qpack.encodeDynamicBlockKnownReceived(
        &encoded,
        allocator,
        &fields,
        table,
        table.insert_count,
        &references,
    );
    const encoded_len = encoded.items.len;
    const references_len = references.items.len;

    var encoded_total: usize = 0;
    var reference_total: usize = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
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
    const elapsed = nowNs(io) -| started;
    const churn_ns = try measureDynamicTableChurn(allocator, io);

    std.debug.print(
        \\HTTP/3 QPACK dynamic encode benchmark
        \\  iterations: {d}, table entries: {d}, fields/block: {d}
        \\  encoded bytes/block: {d}, references/block: {d}
        \\  ns/block: {d}, ns/field: {d}
        \\  dynamic table churn: {d} ns/insert
        \\  checksum: {d}
        \\
    , .{
        iterations,
        table.entryCount(),
        fields_per_block,
        encoded_len,
        references_len,
        elapsed / iterations,
        elapsed / (iterations * fields_per_block),
        churn_ns / churn_iterations,
        encoded_total +| reference_total,
    });
}

fn measureDynamicTableChurn(
    allocator: std.mem.Allocator,
    io: std.Io,
) !u64 {
    var table = netz.http3.Qpack.DynamicTable.init(allocator, 4096);
    defer table.deinit();
    try table.setCapacity(4096);
    var name_buf: [32]u8 = undefined;
    var value_buf: [32]u8 = undefined;
    const started = nowNs(io);
    for (0..churn_iterations) |index| {
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

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

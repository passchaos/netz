const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 2_000_000;
const minimum_scan_iterations: usize = 20_000;
const scan_entry_budget: usize = 64_000_000;
const connection_counts = [_]usize{ 1, 16, 128, 1024 };

pub fn main(init: std.process.Init) !void {
    const iterations = try parseIterations(init);
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    std.debug.print(
        \\QUIC endpoint timer scheduler scaling benchmark
        \\  fast-path iterations: {d}
        \\  bounded due capacity: 32 (one due entry at array tail)
        \\  times are integer hundredths of a nanosecond per operation
        \\  remove measurements include one remove + rearm cycle
        \\
    , .{iterations});
    std.debug.print(
        \\connections  non-earliest update  repeated earliest  advance earliest  new earliest  postpone earliest  remove non-earliest  remove earliest  earliestDeadline  bounded due
        \\
    , .{});

    for (connection_counts) |connection_count| {
        const scan_iterations = iterationsForScan(
            iterations,
            connection_count,
        );
        const non_earliest = try benchmarkNonEarliestUpdate(
            allocator,
            io,
            connection_count,
            iterations,
        );
        const repeated_earliest = try benchmarkRepeatedEarliest(
            allocator,
            io,
            connection_count,
            scan_iterations,
        );
        const advanced_earliest = try benchmarkAdvancedEarliest(
            allocator,
            io,
            connection_count,
            iterations,
        );
        const new_earliest = try benchmarkNewEarliest(
            allocator,
            io,
            connection_count,
            iterations,
        );
        const postponed_earliest = try benchmarkPostponedEarliest(
            allocator,
            io,
            connection_count,
            scan_iterations,
        );
        const removed_non_earliest = try benchmarkRemovedNonEarliest(
            allocator,
            io,
            connection_count,
            iterations,
        );
        const removed_earliest = try benchmarkRemovedEarliest(
            allocator,
            io,
            connection_count,
            scan_iterations,
        );
        const earliest_deadline = try benchmarkEarliestDeadline(
            allocator,
            io,
            connection_count,
            iterations,
        );
        const bounded_due = try benchmarkBoundedDue(
            allocator,
            io,
            connection_count,
            scan_iterations,
        );

        std.debug.print("{d: >11}", .{connection_count});
        printHundredths(non_earliest);
        printHundredths(repeated_earliest);
        printHundredths(advanced_earliest);
        printHundredths(new_earliest);
        printHundredths(postponed_earliest);
        printHundredths(removed_non_earliest);
        printHundredths(removed_earliest);
        printHundredths(earliest_deadline);
        printHundredths(bounded_due);
        std.debug.print("  (scan iterations: {d})\n", .{scan_iterations});
    }
}

fn benchmarkAdvancedEarliest(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = netz.quic.endpoint_timers.EndpointTimers.init(allocator);
    defer timers.deinit();
    try timers.ensureCapacity(connection_count);
    for (0..connection_count) |connection_id| {
        try timers.update(connection_id, timer(std.math.maxInt(u64)));
    }

    const started = nowNs(io);
    for (0..iterations) |iteration| {
        try timers.update(0, timer(std.math.maxInt(u64) - iteration - 1));
    }
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(timers.earliestDeadline());
    return hundredthsPerOperation(elapsed, iterations);
}

fn benchmarkNewEarliest(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = netz.quic.endpoint_timers.EndpointTimers.init(allocator);
    defer timers.deinit();
    try timers.ensureCapacity(connection_count);
    for (0..connection_count) |connection_id| {
        try timers.update(connection_id, timer(std.math.maxInt(u64)));
    }

    const started = nowNs(io);
    for (0..iterations) |iteration| {
        const connection_id = (iteration + 1) % connection_count;
        try timers.update(
            connection_id,
            timer(std.math.maxInt(u64) - iteration - 1),
        );
    }
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(timers.earliestDeadline());
    return hundredthsPerOperation(elapsed, iterations);
}

fn benchmarkNonEarliestUpdate(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = try initializedTimers(allocator, connection_count);
    defer timers.deinit();
    const target = connection_count - 1;

    const started = nowNs(io);
    for (0..iterations) |iteration| {
        try timers.update(target, timer(
            connection_count + 1 + (iteration & 1),
        ));
    }
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(timers.earliestDeadline());
    return hundredthsPerOperation(elapsed, iterations);
}

fn benchmarkRepeatedEarliest(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = try initializedTimers(allocator, connection_count);
    defer timers.deinit();

    const started = nowNs(io);
    for (0..iterations) |_| try timers.update(0, timer(0));
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(timers.earliestDeadline());
    return hundredthsPerOperation(elapsed, iterations);
}

fn benchmarkPostponedEarliest(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = try initializedTimers(allocator, connection_count);
    defer timers.deinit();

    const started = nowNs(io);
    for (0..iterations) |iteration| {
        try timers.update(
            iteration % connection_count,
            timer(connection_count + iteration),
        );
    }
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(timers.earliestDeadline());
    return hundredthsPerOperation(elapsed, iterations);
}

fn benchmarkRemovedEarliest(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = try initializedTimers(allocator, connection_count);
    defer timers.deinit();

    const started = nowNs(io);
    for (0..iterations) |iteration| {
        const connection_id = iteration % connection_count;
        if (!timers.disarmConnection(connection_id)) {
            return error.InvalidBenchmarkResult;
        }
        try timers.update(
            connection_id,
            timer(connection_count + iteration),
        );
    }
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(timers.earliestDeadline());
    return hundredthsPerOperation(elapsed, iterations);
}

fn benchmarkRemovedNonEarliest(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = try initializedTimers(allocator, connection_count);
    defer timers.deinit();
    const connection_id = connection_count - 1;

    const started = nowNs(io);
    for (0..iterations) |_| {
        if (!timers.disarmConnection(connection_id)) {
            return error.InvalidBenchmarkResult;
        }
        try timers.update(connection_id, timer(connection_count));
    }
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(timers.earliestDeadline());
    return hundredthsPerOperation(elapsed, iterations);
}

fn benchmarkEarliestDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = try initializedTimers(allocator, connection_count);
    defer timers.deinit();
    var checksum: u64 = 0;

    const started = nowNs(io);
    for (0..iterations) |_| {
        const earliest = timers.earliestDeadline() orelse
            return error.InvalidBenchmarkResult;
        checksum +%= earliest.connection_id;
        std.mem.doNotOptimizeAway(earliest);
    }
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(checksum);
    return hundredthsPerOperation(elapsed, iterations);
}

fn benchmarkBoundedDue(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    iterations: usize,
) !u64 {
    var timers = netz.quic.endpoint_timers.EndpointTimers.init(allocator);
    defer timers.deinit();
    try timers.ensureCapacity(connection_count);
    for (0..connection_count) |connection_id| {
        const deadline: usize = if (connection_id + 1 == connection_count)
            0
        else
            1;
        try timers.update(connection_id, timer(deadline));
    }
    var output: [32]u64 = undefined;
    var checksum: usize = 0;

    const started = nowNs(io);
    for (0..iterations) |_| {
        const due = timers.dueConnectionIdsInto(0, &output);
        if (due != 1) return error.InvalidBenchmarkResult;
        checksum +%= due;
        std.mem.doNotOptimizeAway(output[0]);
    }
    const elapsed = nowNs(io) -| started;
    std.mem.doNotOptimizeAway(checksum);
    return hundredthsPerOperation(elapsed, iterations);
}

fn initializedTimers(
    allocator: std.mem.Allocator,
    connection_count: usize,
) !netz.quic.endpoint_timers.EndpointTimers {
    var timers = netz.quic.endpoint_timers.EndpointTimers.init(allocator);
    errdefer timers.deinit();
    try timers.ensureCapacity(connection_count);
    for (0..connection_count) |connection_id| {
        try timers.update(connection_id, timer(connection_id));
    }
    return timers;
}

fn timer(deadline: anytype) netz.quic.one_rtt.TimerDeadline {
    return .{
        .kind = .idle_timeout,
        .deadline_ns = @intCast(deadline),
    };
}

fn iterationsForScan(iterations: usize, connection_count: usize) usize {
    const budgeted = scan_entry_budget / connection_count;
    return @min(iterations, @max(minimum_scan_iterations, budgeted));
}

fn hundredthsPerOperation(elapsed_ns: u64, iterations: usize) u64 {
    return elapsed_ns * 100 / iterations;
}

fn printHundredths(value: u64) void {
    std.debug.print("  {d: >7}.{d:0>2} ns", .{ value / 100, value % 100 });
}

fn parseIterations(init: std.process.Init) !usize {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 1) return default_iterations;
    if (args.len != 2 or !std.mem.startsWith(u8, args[1], "--iterations=")) {
        return error.InvalidArgument;
    }
    const value = try std.fmt.parseInt(
        usize,
        args[1]["--iterations=".len..],
        10,
    );
    if (value < minimum_scan_iterations or value > 10_000_000) {
        return error.InvalidArgument;
    }
    return value;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

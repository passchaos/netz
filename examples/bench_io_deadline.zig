const std = @import("std");
const netz = @import("netz");

const max_samples: usize = 9;
const payload = "deadline-io";

const Options = struct {
    samples: usize = 5,
    warmup: usize = 2_000,
    iterations: usize = 50_000,
};

const Sample = struct {
    ready_untimed: u64,
    ready_timed: u64,
    parked_untimed: u64,
    parked_timed: u64,
};

const Results = struct {
    ready_untimed: [max_samples]u64 = undefined,
    ready_timed: [max_samples]u64 = undefined,
    parked_untimed: [max_samples]u64 = undefined,
    parked_timed: [max_samples]u64 = undefined,
    count: usize = 0,

    fn append(self: *Results, sample: Sample) void {
        self.ready_untimed[self.count] = sample.ready_untimed;
        self.ready_timed[self.count] = sample.ready_timed;
        self.parked_untimed[self.count] = sample.parked_untimed;
        self.parked_timed[self.count] = sample.parked_timed;
        self.count += 1;
    }

    fn medians(self: *Results) Sample {
        std.mem.sort(u64, self.ready_untimed[0..self.count], {}, std.sort.asc(u64));
        std.mem.sort(u64, self.ready_timed[0..self.count], {}, std.sort.asc(u64));
        std.mem.sort(u64, self.parked_untimed[0..self.count], {}, std.sort.asc(u64));
        std.mem.sort(u64, self.parked_timed[0..self.count], {}, std.sort.asc(u64));
        const middle = self.count / 2;
        return .{
            .ready_untimed = self.ready_untimed[middle],
            .ready_timed = self.ready_timed[middle],
            .parked_untimed = self.parked_untimed[middle],
            .parked_timed = self.parked_timed[middle],
        };
    }
};

pub fn main(init: std.process.Init) !void {
    const options = try parseOptions(init);
    var backend = try netz.runtime.Backend.init(std.heap.smp_allocator);
    defer backend.deinit();
    const io = backend.io();

    var future = try std.Io.concurrent(
        io,
        benchmark,
        .{ io, options },
    );
    var results = try future.await(io);
    const medians = results.medians();
    std.debug.print(
        "zio deadline I/O benchmark: io_backend=zio-std-io " ++
            "samples={d} warmup={d} iterations={d}\n",
        .{ options.samples, options.warmup, options.iterations },
    );
    printResult("ready_untimed", medians.ready_untimed, options.iterations);
    printResult("ready_timed", medians.ready_timed, options.iterations);
    printResult("parked_untimed", medians.parked_untimed, options.iterations);
    printResult("parked_timed", medians.parked_timed, options.iterations);
    const ready_ratio = ratioTimes100(
        medians.ready_timed,
        medians.ready_untimed,
    );
    const parked_ratio = ratioTimes100(
        medians.parked_timed,
        medians.parked_untimed,
    );
    std.debug.print(
        "timed/untimed ratio: ready={d}.{d:0>2}x parked={d}.{d:0>2}x\n",
        .{
            ready_ratio / 100,
            ready_ratio % 100,
            parked_ratio / 100,
            parked_ratio % 100,
        },
    );
}

fn benchmark(io: std.Io, options: Options) !Results {
    var results = Results{};
    for (0..options.samples) |sample_index| {
        var sample: Sample = undefined;
        if ((sample_index & 1) == 0) {
            sample.ready_untimed = try measureReady(io, options, false);
            sample.ready_timed = try measureReady(io, options, true);
            sample.parked_untimed = try measureParked(io, options, false);
            sample.parked_timed = try measureParked(io, options, true);
        } else {
            sample.parked_timed = try measureParked(io, options, true);
            sample.parked_untimed = try measureParked(io, options, false);
            sample.ready_timed = try measureReady(io, options, true);
            sample.ready_untimed = try measureReady(io, options, false);
        }
        results.append(sample);
    }
    return results;
}

fn measureReady(io: std.Io, options: Options, timed: bool) !u64 {
    var sender = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram },
    );
    defer sender.close(io);
    var receiver = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram },
    );
    defer receiver.close(io);

    for (0..options.warmup) |_| {
        try sender.send(io, &receiver.address, payload);
        try receiveOne(io, &receiver, timed);
    }
    const started = nowNs(io);
    for (0..options.iterations) |_| {
        try sender.send(io, &receiver.address, payload);
        try receiveOne(io, &receiver, timed);
    }
    return nowNs(io) -| started;
}

fn measureParked(io: std.Io, options: Options, timed: bool) !u64 {
    var sender = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram },
    );
    defer sender.close(io);
    var receiver = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram },
    );
    defer receiver.close(io);

    var token_storage: [1]u8 = undefined;
    var tokens: std.Io.Queue(u8) = .init(&token_storage);
    const total = options.warmup + options.iterations;
    const Producer = struct {
        fn run(
            queue: *std.Io.Queue(u8),
            producer_io: std.Io,
            socket: *std.Io.net.Socket,
            destination: *const std.Io.net.IpAddress,
            count: usize,
        ) !void {
            for (0..count) |_| {
                _ = try queue.getOne(producer_io);
                try socket.send(producer_io, destination, payload);
            }
        }
    };
    var producer = try std.Io.concurrent(
        io,
        Producer.run,
        .{ &tokens, io, &sender, &receiver.address, total },
    );
    var producer_active = true;
    defer if (producer_active) producer.cancel(io) catch {};

    for (0..options.warmup) |_| {
        try tokens.putOne(io, 1);
        try receiveOne(io, &receiver, timed);
    }
    const started = nowNs(io);
    for (0..options.iterations) |_| {
        try tokens.putOne(io, 1);
        try receiveOne(io, &receiver, timed);
    }
    const elapsed = nowNs(io) -| started;
    try producer.await(io);
    producer_active = false;
    return elapsed;
}

fn receiveOne(
    io: std.Io,
    receiver: *std.Io.net.Socket,
    timed: bool,
) !void {
    var message: std.Io.net.IncomingMessage = .init;
    var storage: [64]u8 = undefined;
    const operation: std.Io.Operation = .{ .net_receive = .{
        .socket_handle = receiver.handle,
        .message_buffer = (&message)[0..1],
        .data_buffer = &storage,
        .flags = .{},
    } };
    const result = if (timed)
        try io.operateTimeout(operation, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } })
    else
        try io.operate(operation);
    const receive_error, const count = result.net_receive;
    if (receive_error) |err| return err;
    if (count != 1 or !std.mem.eql(u8, payload, message.data)) {
        return error.UnexpectedPayload;
    }
}

fn printResult(name: []const u8, elapsed: u64, iterations: usize) void {
    const hundredths = elapsed * 100 / iterations;
    std.debug.print(
        "{s}: total_ns={d} ns/op={d}.{d:0>2}\n",
        .{ name, elapsed, hundredths / 100, hundredths % 100 },
    );
}

fn ratioTimes100(numerator: u64, denominator: u64) u64 {
    if (denominator == 0) return std.math.maxInt(u64);
    return numerator * 100 / denominator;
}

fn parseOptions(init: std.process.Init) !Options {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var options: Options = .{};
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--samples=")) {
            options.samples = try std.fmt.parseInt(
                usize,
                arg["--samples=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else {
            return error.InvalidArgument;
        }
    }
    if (options.samples == 0 or options.samples > max_samples or
        (options.samples & 1) == 0 or options.warmup == 0 or
        options.iterations < 100 or options.iterations > 10_000_000)
    {
        return error.InvalidArgument;
    }
    return options;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

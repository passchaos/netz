const std = @import("std");
const mqtt = @import("netz").mqtt;

pub const Options = struct {
    protocol: mqtt.ProtocolVersion = .v5,
    qos: mqtt.QoS = .at_least_once,
    topic_alias: bool = true,
    payload_bytes: usize = 512,
    warmup: usize = 100,
    iterations: usize = 5000,

    pub fn total(self: Options) usize {
        return self.warmup + self.iterations;
    }
};

pub fn parse(init: std.process.Init) !Options {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, std.heap.smp_allocator);
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--no-topic-alias")) {
            options.topic_alias = false;
        } else if (std.mem.startsWith(u8, arg, "--payload=")) {
            options.payload_bytes = try std.fmt.parseInt(usize, arg["--payload=".len..], 10);
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup = try std.fmt.parseInt(usize, arg["--warmup=".len..], 10);
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(usize, arg["--iterations=".len..], 10);
        } else if (std.mem.eql(u8, arg, "--qos=1")) {
            options.qos = .at_least_once;
        } else if (std.mem.eql(u8, arg, "--qos=2")) {
            options.qos = .exactly_once;
        } else if (std.mem.eql(u8, arg, "--protocol=4")) {
            options.protocol = .v3_1_1;
        } else if (std.mem.eql(u8, arg, "--protocol=5")) {
            options.protocol = .v5;
        } else return error.InvalidArgument;
    }
    if (options.iterations == 0 or options.payload_bytes > 4 * 1024 * 1024) return error.InvalidArgument;
    _ = std.math.add(usize, options.warmup, options.iterations) catch return error.InvalidArgument;
    return options;
}

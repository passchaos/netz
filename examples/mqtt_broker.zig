const std = @import("std");
const netz = @import("netz");

const Config = struct {
    bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(1883) },
    connections: usize = 16,
    max_queued_deliveries: usize = 1024,
    max_outgoing_inflight: u16 = 64,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const config = try parseArgs(init, allocator);
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try netz.mqtt.broker.Broker.listen(
        allocator,
        io,
        config.bind,
        .{
            .limits = .{
                .max_connections = config.connections,
                .max_queued_deliveries_per_connection = config.max_queued_deliveries,
            },
            .accept = .{
                .max_outgoing_inflight = config.max_outgoing_inflight,
            },
        },
    );
    defer broker.deinit();

    std.debug.print(
        "netz MQTT 3.1.1/5 broker listening on {f} for {d} clients\n",
        .{ broker.address(), config.connections },
    );
    try broker.serve(config.connections);
}

fn parseArgs(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !Config {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();

    var config: Config = .{};
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--bind=")) {
            config.bind = try std.Io.net.IpAddress.parseLiteral(
                arg["--bind=".len..],
            );
            if (config.bind.getPort() == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--connections=",
        )) {
            config.connections = try parsePositiveUsize(
                arg["--connections=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--max-queued-deliveries=",
        )) {
            config.max_queued_deliveries = try parsePositiveUsize(
                arg["--max-queued-deliveries=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--max-outgoing-inflight=",
        )) {
            config.max_outgoing_inflight = try std.fmt.parseInt(
                u16,
                arg["--max-outgoing-inflight=".len..],
                10,
            );
            if (config.max_outgoing_inflight == 0) {
                return error.InvalidArgument;
            }
        } else {
            return error.InvalidArgument;
        }
    }
    return config;
}

fn parsePositiveUsize(raw: []const u8) !usize {
    const value = try std.fmt.parseInt(usize, raw, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

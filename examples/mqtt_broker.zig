const std = @import("std");
const netz = @import("netz");

const Config = struct {
    bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(1883) },
    connections: usize = 16,
    max_queued_deliveries: usize = 1024,
    max_outgoing_inflight: u16 = 64,
    persistence_path: ?[]const u8 = null,
    restore: bool = true,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const config = try parseArgs(init);
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
    if (config.persistence_path) |path| {
        if (config.restore) {
            broker.restoreSnapshot(std.Io.Dir.cwd(), path) catch |err| {
                if (err != error.SnapshotNotFound) return err;
            };
        }
    }

    std.debug.print(
        "netz MQTT 3.1.1/5 broker listening on {f} for {d} clients\n",
        .{ broker.address(), config.connections },
    );
    try broker.serve(config.connections);
    if (config.persistence_path) |path| {
        try broker.saveSnapshot(std.Io.Dir.cwd(), path);
    }
}

fn parseArgs(
    init: std.process.Init,
) !Config {
    var config: Config = .{};
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args[1..]) |arg| {
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
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--persistence=",
        )) {
            const path = arg["--persistence=".len..];
            if (path.len == 0) return error.InvalidArgument;
            config.persistence_path = path;
        } else if (std.mem.eql(u8, arg, "--no-restore")) {
            config.restore = false;
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

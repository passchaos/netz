const std = @import("std");
const netz = @import("netz");

const Config = struct {
    bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(1883) },
    connections: usize = 16,
    max_queued_deliveries: usize = 1024,
    max_outgoing_inflight: u16 = 64,
    max_packet_size: usize = 16 * 1024 * 1024,
    maximum_qos: ?netz.mqtt.QoS = null,
    retain_available: bool = true,
    topic_alias_maximum: u16 = 16,
    server_keep_alive_seconds: ?u16 = null,
    wildcard_subscription_available: bool = true,
    subscription_identifier_available: bool = true,
    shared_subscription_available: bool = true,
    persistence_path: ?[]const u8 = null,
    restore: bool = true,
    ignore_connection_errors: bool = false,
};

pub fn main(init: std.process.Init) !void {
    // This long-lived broker repeatedly transfers small packet/session
    // allocations between I/O workers. The SMP allocator's per-thread caches
    // retain a separate working set for every connection task; libc's shared
    // arenas keep the same workload throughput while materially reducing RSS.
    // Library users still choose the allocator passed to Broker.listen.
    const allocator = std.heap.c_allocator;
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
                .runtime = .{ .max_packet_size = config.max_packet_size },
            },
            .accept = .{
                .max_outgoing_inflight = config.max_outgoing_inflight,
                .maximum_qos = config.maximum_qos,
                .retain_available = config.retain_available,
                .topic_alias_maximum = config.topic_alias_maximum,
                .server_keep_alive_seconds = config.server_keep_alive_seconds,
                .wildcard_subscription_available = config.wildcard_subscription_available,
                .subscription_identifier_available = config.subscription_identifier_available,
                .shared_subscription_available = config.shared_subscription_available,
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
    if (config.ignore_connection_errors) {
        // Conformance/fuzz harnesses deliberately open malformed connections.
        // Serve one finite slot at a time so an expected protocol rejection
        // does not terminate the process before later valid-vector probes.
        for (0..config.connections) |_| {
            broker.serve(1) catch {};
        }
    } else {
        try broker.serve(config.connections);
    }
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
            "--max-packet-size=",
        )) {
            config.max_packet_size = try parsePositiveUsize(
                arg["--max-packet-size=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--maximum-qos=",
        )) {
            config.maximum_qos = switch (try std.fmt.parseInt(
                u2,
                arg["--maximum-qos=".len..],
                10,
            )) {
                0 => .at_most_once,
                1 => .at_least_once,
                2 => .exactly_once,
                else => return error.InvalidArgument,
            };
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--topic-alias-maximum=",
        )) {
            config.topic_alias_maximum = try std.fmt.parseInt(
                u16,
                arg["--topic-alias-maximum=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--server-keep-alive=",
        )) {
            config.server_keep_alive_seconds = try std.fmt.parseInt(
                u16,
                arg["--server-keep-alive=".len..],
                10,
            );
        } else if (std.mem.eql(u8, arg, "--no-retain")) {
            config.retain_available = false;
        } else if (std.mem.eql(
            u8,
            arg,
            "--no-wildcard-subscriptions",
        )) {
            config.wildcard_subscription_available = false;
        } else if (std.mem.eql(
            u8,
            arg,
            "--no-subscription-identifiers",
        )) {
            config.subscription_identifier_available = false;
        } else if (std.mem.eql(
            u8,
            arg,
            "--no-shared-subscriptions",
        )) {
            config.shared_subscription_available = false;
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
        } else if (std.mem.eql(u8, arg, "--ignore-connection-errors")) {
            config.ignore_connection_errors = true;
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

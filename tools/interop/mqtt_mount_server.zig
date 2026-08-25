//! Finite two-listener broker for Mosquitto mount-point interoperability.

const std = @import("std");
const netz = @import("netz");

const max_packet_size: usize = 4096;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArguments;
    const global_port = try std.fmt.parseInt(u16, args[1], 10);
    const mounted_port = try std.fmt.parseInt(u16, args[2], 10);
    if (global_port == 0 or mounted_port == 0 or
        global_port == mounted_port)
    {
        return error.InvalidArguments;
    }

    const allocator = init.gpa;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try netz.mqtt.broker.Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = max_packet_size },
        },
    });
    defer broker.deinit();
    var global_server = try netz.mqtt.runtime.Server.listen(
        allocator,
        io,
        try std.Io.net.IpAddress.parse("127.0.0.1", global_port),
        .{ .max_packet_size = max_packet_size },
    );
    defer global_server.deinit();
    var mounted_server = try netz.mqtt.runtime.Server.listen(
        allocator,
        io,
        try std.Io.net.IpAddress.parse("127.0.0.1", mounted_port),
        .{ .max_packet_size = max_packet_size },
    );
    defer mounted_server.deinit();

    const listeners = [_]netz.mqtt.broker.Listener{
        .{
            .source = global_server.pendingSource(),
            .connection_count = 1,
        },
        .{
            .source = mounted_server.pendingSource(),
            .namespace = try netz.mqtt.listener_namespace.Namespace.init(
                "mount/",
            ),
            .connection_count = 2,
        },
    };
    std.debug.print(
        "netz MQTT mount interop server listening on {d} and {d}\n",
        .{ global_port, mounted_port },
    );
    try broker.serveListeners(&listeners);
}

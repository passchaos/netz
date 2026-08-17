const std = @import("std");
const netz = @import("netz");

const warmup_iterations: usize = 100;
const iterations: usize = 2000;
const payload_bytes: usize = 1024;
const max_packet_size: usize = 4096;

pub fn main(_: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.mqtt.websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{ .max_packet_size = max_packet_size },
            .max_head_bytes = max_packet_size,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.mqtt.websocket_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(
            server_ptr: *netz.mqtt.websocket_runtime.Server,
        ) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 1,
            });
            defer accepted.deinit(server_ptr.allocator);
            for (0..warmup_iterations + iterations) |_| {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(server_ptr.allocator);
                if (publish.publish.qos != .at_least_once or
                    publish.publish.payload.len != payload_bytes)
                {
                    return error.InvalidBenchmarkPacket;
                }
                try accepted.connection.writePubAck(
                    publish.publish.packet_id.?,
                    0,
                );
            }
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.mqtt.websocket_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-ws-benchmark",
                .limits = .{ .max_packet_size = max_packet_size },
                .max_outgoing_inflight = 1,
            },
            .host = "127.0.0.1",
            .target = "/mqtt",
            .max_head_bytes = max_packet_size,
        },
    );
    defer client.close();

    var payload: [payload_bytes]u8 align(64) = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @truncate(index *% 17);
    }
    for (0..warmup_iterations) |_| {
        try client.publish(
            "bench/mqtt/websocket",
            &payload,
            .{ .qos = .at_least_once },
        );
    }

    const started = nowNs(io);
    for (0..iterations) |_| {
        try client.publish(
            "bench/mqtt/websocket",
            &payload,
            .{ .qos = .at_least_once },
        );
    }
    const elapsed = nowNs(io) -| started;
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;

    const operations_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, iterations) * std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\MQTT-over-WebSocket QoS 1 benchmark
        \\  warmup publishes: {d}
        \\  measured publishes: {d}
        \\  payload bytes: {d}
        \\  ns/publish+PUBACK: {d}
        \\  operations/s: {d}
        \\
    , .{
        warmup_iterations,
        iterations,
        payload_bytes,
        elapsed / iterations,
        operations_per_second,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

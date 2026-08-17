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

    var server = try netz.mqtt.testing.tls13_server.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.mqtt.testing.tls13_server.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var tls = try shared.server.accept();
            defer tls.deinit();
            var input: [max_packet_size]u8 = undefined;
            var output: std.ArrayList(u8) = .empty;
            defer output.deinit(shared.server.allocator);

            const connect_bytes = try tls.readApplication(&input);
            var connect = try netz.mqtt.Connect.parse(
                shared.server.allocator,
                connect_bytes,
            );
            defer connect.deinit(shared.server.allocator);
            try netz.mqtt.ConnAck.write(
                &output,
                shared.server.allocator,
                .v5,
                false,
                0,
                &.{},
            );
            try tls.writeApplication(output.items);

            for (0..warmup_iterations + iterations) |_| {
                const publish_bytes = try tls.readApplication(&input);
                var publish = try netz.mqtt.Publish.parse(
                    shared.server.allocator,
                    .v5,
                    publish_bytes,
                );
                defer publish.deinit(shared.server.allocator);
                if (publish.qos != .at_least_once or
                    publish.payload.len != payload_bytes)
                {
                    return error.InvalidBenchmarkPacket;
                }
                output.clearRetainingCapacity();
                try netz.mqtt.AckPacket.write(
                    &output,
                    shared.server.allocator,
                    .v5,
                    .puback,
                    publish.packet_id.?,
                    0,
                    &.{},
                );
                try tls.writeApplication(output.items);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        Shared.run,
        .{&shared},
    );
    var server_joined = false;
    defer if (!server_joined) server_thread.join();

    var client = try netz.mqtt.tls_runtime.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-tls-benchmark",
                .limits = .{ .max_packet_size = max_packet_size },
                .max_outgoing_inflight = 1,
            },
            // The test suite separately validates a pinned CA and hostname.
            // This benchmark isolates steady-state encrypted MQTT transport.
            .tls = .{ .verify_host = false },
        },
    );
    defer client.close();

    var payload: [payload_bytes]u8 align(64) = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @truncate(index *% 17);
    }
    for (0..warmup_iterations) |_| {
        try client.publish(
            "bench/mqtt/tls",
            &payload,
            .{ .qos = .at_least_once },
        );
    }
    const started = nowNs(io);
    for (0..iterations) |_| {
        try client.publish(
            "bench/mqtt/tls",
            &payload,
            .{ .qos = .at_least_once },
        );
    }
    const elapsed = nowNs(io) -| started;

    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
    const operations_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, iterations) * std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\MQTT-over-TLS QoS 1 benchmark
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

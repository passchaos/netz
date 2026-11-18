const std = @import("std");
const netz = @import("netz");

const warmup_iterations: usize = 100;
const iterations: usize = 2000;
const payload_bytes: usize = 1024;
const max_packet_size: usize = 4096;

pub fn main(_: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var certificate_der: [
        netz.tls.testing.certificate_der_len
    ]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair =
        try netz.tls.testing.serverKeyPair();
    var server = try netz.mqtt.tls_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{
                    .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    },
                },
            },
            .limits = .{ .max_packet_size = max_packet_size },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.mqtt.tls_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept(.{
                .protocol = .v5,
            });
            defer accepted.deinit(shared.server.allocator);

            for (0..warmup_iterations + iterations) |_| {
                var publish =
                    try accepted.connection.readPublish();
                defer publish.deinit(shared.server.allocator);
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
        }
    };
    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

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

    server_task.await(io);
    if (shared.err) |err| return err;
    const operations_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, iterations) * std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\MQTT-over-TLS QoS 1 benchmark
        \\  io backend: zio-std-io
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
    std.debug.print(
        "record=result implementation=netz protocol=mqtt5 transport=tls " ++
            "mode=qos1-publish-puback role_pair=netz-self " ++
            "client_io=zio-std-io server_io=zio-std-io " ++
            "connection_scope=persistent warmup={d} iterations={d} " ++
            "payload_bytes={d} elapsed_ns={d} ns_per_operation={d} " ++
            "operations_per_s={d} complete=true\n",
        .{
            warmup_iterations,
            iterations,
            payload_bytes,
            elapsed,
            elapsed / iterations,
            operations_per_second,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

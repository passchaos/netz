const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support").counting_allocator
    .CountingAllocator;

const default_publishers: usize = 4;
const default_subscribers: usize = 4;
const default_warmup_messages: usize = 100;
const default_messages: usize = 10_000;
const default_payload_bytes: usize = 256;
const max_clients: usize = 256;
const topic = "bench/fanout/value";

const Config = struct {
    address: std.Io.net.IpAddress = .{ .ip4 = .loopback(1883) },
    publishers: usize = default_publishers,
    subscribers: usize = default_subscribers,
    warmup_messages: usize = default_warmup_messages,
    messages: usize = default_messages,
    payload_bytes: usize = default_payload_bytes,
    qos: netz.mqtt.QoS = .at_least_once,
    overlapping_subscriptions: usize = 1,
    publisher_window: usize = 1,
    server_queue_capacity: usize = 0,
    session_expiry_seconds: u32 = 0,
    server_implementation: []const u8 = "external",
    server_io: []const u8 = "external-unspecified",
    server_tcp_nodelay: []const u8 = "unspecified",
};

const Worker = struct {
    client: *netz.mqtt.runtime.Connection,
    allocator: std.mem.Allocator,
    io: std.Io,
    warmup_messages: usize,
    measured_messages: usize,
    payload_bytes: usize,
    qos: netz.mqtt.QoS,
    inflight_limit: usize,
    ready: *std.atomic.Value(usize),
    warmup_complete: *std.atomic.Value(usize),
    failed: *std.atomic.Value(bool),
    all_ready: *std.Io.Event,
    begin: *std.Io.Event,
    all_warm: *std.Io.Event,
    measured_start: *std.Io.Event,
    err: *?anyerror,
    finished_ns: *u64,
    checksum: *u64,
    subscriber_count: usize,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err.* = err;
            self.failed.store(true, .release);
            self.all_ready.set(self.io);
            self.begin.set(self.io);
            self.all_warm.set(self.io);
            self.measured_start.set(self.io);
        };
    }

    fn runFallible(self: *@This()) !void {
        var qos2_pending: std.ArrayList(u16) = .empty;
        defer qos2_pending.deinit(self.allocator);
        if (self.qos == .exactly_once) {
            try qos2_pending.ensureTotalCapacityPrecise(
                self.allocator,
                @min(
                    @max(self.warmup_messages, self.measured_messages),
                    self.inflight_limit,
                ),
            );
        }
        const previously_ready = self.ready.fetchAdd(1, .acq_rel);
        if (previously_ready + 1 == self.subscriber_count) {
            self.all_ready.set(self.io);
        }
        self.begin.waitUncancelable(self.io);

        var checksum: u64 = 0;
        try self.consume(self.warmup_messages, &checksum, &qos2_pending);
        const previously_warm = self.warmup_complete.fetchAdd(1, .acq_rel);
        if (previously_warm + 1 == self.subscriber_count) {
            self.all_warm.set(self.io);
        }
        self.measured_start.waitUncancelable(self.io);
        try self.consume(self.measured_messages, &checksum, &qos2_pending);
        self.checksum.* = checksum;
        self.finished_ns.* = nowNs(self.io);
    }

    fn consume(
        self: *@This(),
        message_count: usize,
        checksum: *u64,
        qos2_pending: *std.ArrayList(u16),
    ) !void {
        if (self.qos == .exactly_once) {
            return self.consumeQoS2(message_count, checksum, qos2_pending);
        }
        for (0..message_count) |_| {
            var delivery = try self.client.readPublish();
            defer delivery.deinit(self.allocator);
            if (delivery.publish.qos != self.qos or
                delivery.publish.payload.len != self.payload_bytes)
            {
                return error.InvalidBenchmarkPacket;
            }
            checksum.* +%= delivery.publish.payload[0];
            checksum.* +%= delivery.publish.payload[
                delivery.publish.payload.len - 1
            ];
            try self.client.writePubAck(delivery.publish.packet_id.?, 0);
        }
    }

    fn consumeQoS2(
        self: *@This(),
        message_count: usize,
        checksum: *u64,
        pending: *std.ArrayList(u16),
    ) !void {
        pending.clearRetainingCapacity();
        var received: usize = 0;
        var completed: usize = 0;
        while (completed < message_count) {
            var event = try self.client.readClientPacketEvent();
            defer event.deinit(self.allocator);
            switch (event) {
                .publish => |delivery| {
                    if (received == message_count or
                        delivery.publish.qos != .exactly_once or
                        delivery.publish.payload.len != self.payload_bytes)
                    {
                        return error.InvalidQoS2Delivery;
                    }
                    const packet_id = delivery.publish.packet_id.?;
                    if (std.mem.indexOfScalar(
                        u16,
                        pending.items,
                        packet_id,
                    ) != null) return error.DuplicateQoS2Delivery;
                    pending.appendAssumeCapacity(packet_id);
                    checksum.* +%= delivery.publish.payload[0];
                    checksum.* +%= delivery.publish.payload[
                        delivery.publish.payload.len - 1
                    ];
                    try self.client.writePubRec(packet_id, 0);
                    received += 1;
                },
                .pubrel => |pubrel| {
                    const index = std.mem.indexOfScalar(
                        u16,
                        pending.items,
                        pubrel.ack.packet_id,
                    ) orelse return error.UnexpectedPubRel;
                    if (!pubrel.ack.accepted()) {
                        return error.RefusedPubRel;
                    }
                    try self.client.writePubComp(pubrel.ack.packet_id, 0);
                    _ = pending.swapRemove(index);
                    completed += 1;
                },
                else => return error.UnexpectedSubscriberPacket,
            }
        }
        if (received != message_count or pending.items.len != 0) {
            return error.IncompleteQoS2Delivery;
        }
    }
};

pub fn main(init: std.process.Init) !void {
    var stats_allocator = CountingAllocator.init(std.heap.smp_allocator);
    const config = try parseArgs(init, std.heap.smp_allocator);
    const allocator = stats_allocator.allocator();
    var backend = try netz.runtime.Backend.init(std.heap.smp_allocator);
    defer backend.deinit();
    const io = backend.io();

    const subscribers = try allocator.alloc(
        netz.mqtt.runtime.Connection,
        config.subscribers,
    );
    defer allocator.free(subscribers);
    var subscribers_connected: usize = 0;
    defer for (subscribers[0..subscribers_connected]) |*client| {
        client.close();
    };

    for (subscribers, 0..) |*subscriber, index| {
        var id_buffer: [64]u8 = undefined;
        const client_id = try std.fmt.bufPrint(
            &id_buffer,
            "netz-load-subscriber-{d}",
            .{index},
        );
        subscriber.* = try connect(
            allocator,
            io,
            config.address,
            client_id,
            config.publisher_window,
            config.session_expiry_seconds,
        );
        subscribers_connected += 1;
        for (0..config.overlapping_subscriptions) |overlap| {
            var filter_buffer: [64]u8 = undefined;
            const filter = overlapFilter(overlap, &filter_buffer);
            var suback = try subscriber.subscribe(
                &.{.{
                    .topic_filter = filter,
                    .qos = config.qos,
                }},
                .{},
            );
            defer suback.deinit(allocator);
            if (suback.suback.reason_codes.len != 1 or
                suback.suback.reason_codes[0] !=
                    @intFromEnum(config.qos))
            {
                return error.SubscriptionRefused;
            }
        }
    }

    const publishers = try allocator.alloc(
        netz.mqtt.runtime.Connection,
        config.publishers,
    );
    defer allocator.free(publishers);
    var publishers_connected: usize = 0;
    defer for (publishers[0..publishers_connected]) |*client| {
        client.close();
    };
    for (publishers, 0..) |*publisher, index| {
        var id_buffer: [64]u8 = undefined;
        const client_id = try std.fmt.bufPrint(
            &id_buffer,
            "netz-load-publisher-{d}",
            .{index},
        );
        publisher.* = try connect(
            allocator,
            io,
            config.address,
            client_id,
            config.publisher_window,
            config.session_expiry_seconds,
        );
        publishers_connected += 1;
    }
    const latency_samples = try allocator.alloc(u64, config.messages);
    defer allocator.free(latency_samples);

    var ready = std.atomic.Value(usize).init(0);
    var warmup_complete = std.atomic.Value(usize).init(0);
    var failed = std.atomic.Value(bool).init(false);
    var all_ready: std.Io.Event = .unset;
    var begin: std.Io.Event = .unset;
    var all_warm: std.Io.Event = .unset;
    var measured_start: std.Io.Event = .unset;
    const errors = try allocator.alloc(?anyerror, config.subscribers);
    defer allocator.free(errors);
    @memset(errors, null);
    const finished_ns = try allocator.alloc(u64, config.subscribers);
    defer allocator.free(finished_ns);
    @memset(finished_ns, 0);
    const checksums = try allocator.alloc(u64, config.subscribers);
    defer allocator.free(checksums);
    @memset(checksums, 0);
    var workers: std.Io.Group = .init;
    defer workers.cancel(io);
    const contexts = try allocator.alloc(Worker, config.subscribers);
    defer allocator.free(contexts);

    for (0..config.subscribers) |index| {
        contexts[index] = .{
            .client = &subscribers[index],
            .allocator = allocator,
            .io = io,
            .warmup_messages = config.warmup_messages,
            .measured_messages = config.messages,
            .payload_bytes = config.payload_bytes,
            .qos = config.qos,
            .inflight_limit = config.publisher_window,
            .ready = &ready,
            .warmup_complete = &warmup_complete,
            .failed = &failed,
            .all_ready = &all_ready,
            .begin = &begin,
            .all_warm = &all_warm,
            .measured_start = &measured_start,
            .err = &errors[index],
            .finished_ns = &finished_ns[index],
            .checksum = &checksums[index],
            .subscriber_count = config.subscribers,
        };
        workers.async(io, Worker.run, .{&contexts[index]});
    }

    all_ready.waitUncancelable(io);
    if (failed.load(.acquire)) return firstWorkerError(errors);
    begin.set(io);

    const payload = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| {
        byte.* = @truncate(index *% 17 +% 3);
    }

    try publishWindowed(
        publishers,
        topic,
        payload,
        config.warmup_messages,
        config.publisher_window,
        config.qos,
        io,
        allocator,
        null,
    );

    all_warm.waitUncancelable(io);
    if (failed.load(.acquire)) return firstWorkerError(errors);
    const started_ns = nowNs(io);
    measured_start.set(io);
    try publishWindowed(
        publishers,
        topic,
        payload,
        config.messages,
        config.publisher_window,
        config.qos,
        io,
        allocator,
        latency_samples,
    );
    try workers.await(io);
    for (errors) |maybe_err| {
        if (maybe_err) |err| return err;
    }

    var finished_ns_max = started_ns;
    var checksum: u64 = 0;
    for (finished_ns, checksums) |finished, worker_checksum| {
        finished_ns_max = @max(finished_ns_max, finished);
        checksum +%= worker_checksum;
    }
    const elapsed_ns = finished_ns_max -| started_ns;
    const measured_deliveries = std.math.mul(
        usize,
        config.messages,
        config.subscribers,
    ) catch return error.InvalidArgument;
    const publishes_per_second = ratePerSecond(
        config.messages,
        elapsed_ns,
    );
    const deliveries_per_second = ratePerSecond(
        measured_deliveries,
        elapsed_ns,
    );
    std.mem.sort(u64, latency_samples, {}, lessThanU64);
    const latency_p50 = percentile(latency_samples, 50, 100);
    const latency_p99 = percentile(latency_samples, 99, 100);
    const latency_p999 = percentile(latency_samples, 999, 1000);

    // DISCONNECT is sent only after all worker readers have drained the wire,
    // making this driver suitable for finite netz broker runs as well as
    // long-lived rumqttd and Mosquitto processes.
    for (subscribers) |*subscriber| try subscriber.disconnect(0);
    for (publishers) |*publisher| try publisher.disconnect(0);

    std.debug.print(
        \\MQTT 5 TCP broker fanout workload
        \\  client io backend: zio-std-io
        \\  endpoint: {f}
        \\  publishers: {d}
        \\  subscribers: {d}
        \\  overlapping subscriptions/client: {d}
        \\  publisher window: {d}
        \\  delivery QoS: {d}
        \\  server queue capacity: {d}
        \\  session expiry seconds: {d}
        \\  warmup publishes: {d}
        \\  measured publishes: {d}
        \\  measured deliveries: {d}
        \\  payload bytes: {d}
        \\  elapsed ns: {d}
        \\  publishes/s: {d}
        \\  deliveries/s: {d}
        \\  publish completion p50 ns: {d}
        \\  publish completion p99 ns: {d}
        \\  publish completion p99.9 ns: {d}
        \\  client allocation calls: {d}
        \\  client cumulative allocated bytes: {d}
        \\  client peak live bytes: {d}
        \\  checksum: {d}
        \\
    , .{
        config.address,
        config.publishers,
        config.subscribers,
        config.overlapping_subscriptions,
        config.publisher_window,
        @intFromEnum(config.qos),
        config.server_queue_capacity,
        config.session_expiry_seconds,
        config.warmup_messages,
        config.messages,
        measured_deliveries,
        config.payload_bytes,
        elapsed_ns,
        publishes_per_second,
        deliveries_per_second,
        latency_p50,
        latency_p99,
        latency_p999,
        stats_allocator.snapshot().alloc_count,
        stats_allocator.snapshot().total_allocated,
        stats_allocator.snapshot().peak_bytes,
        checksum,
    });
    std.debug.print(
        "record=result implementation=netz protocol=mqtt5 transport=tcp " ++
            "mode=qos{d}-fanout role_pair=netz-client+{s}-server " ++
            "client_io=zio-std-io server_io={s} " ++
            "benchmark_scope=same-client-workload timing_usable=true " ++
            "client_tcp_nodelay=true server_tcp_nodelay={s} " ++
            "connection_scope=persistent publishers={d} subscribers={d} " ++
            "overlapping_subscriptions={d} publisher_window={d} " ++
            "server_queue_capacity={d} " ++
            "session_expiry_seconds={d} warmup={d} publishes={d} " ++
            "deliveries={d} payload_bytes={d} elapsed_ns={d} " ++
            "publishes_per_s={d} deliveries_per_s={d} p50_ns={d} " ++
            "p99_ns={d} p999_ns={d} client_alloc_count={d} " ++
            "client_total_allocated_bytes={d} client_peak_live_bytes={d} " ++
            "checksum={d} complete=true\n",
        .{
            @intFromEnum(config.qos),
            config.server_implementation,
            config.server_io,
            config.server_tcp_nodelay,
            config.publishers,
            config.subscribers,
            config.overlapping_subscriptions,
            config.publisher_window,
            config.server_queue_capacity,
            config.session_expiry_seconds,
            config.warmup_messages,
            config.messages,
            measured_deliveries,
            config.payload_bytes,
            elapsed_ns,
            publishes_per_second,
            deliveries_per_second,
            latency_p50,
            latency_p99,
            latency_p999,
            stats_allocator.snapshot().alloc_count,
            stats_allocator.snapshot().total_allocated,
            stats_allocator.snapshot().peak_bytes,
            checksum,
        },
    );
}

fn connect(
    allocator: std.mem.Allocator,
    io: std.Io,
    address: std.Io.net.IpAddress,
    client_id: []const u8,
    max_outgoing_inflight: usize,
    session_expiry_seconds: u32,
) !netz.mqtt.runtime.Connection {
    const properties = [_]netz.mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = session_expiry_seconds,
    } }};
    return netz.mqtt.runtime.Client.connect(
        allocator,
        io,
        address,
        .{
            .protocol = .v5,
            .client_id = client_id,
            .limits = .{ .tcp_nodelay = true },
            .max_outgoing_inflight = @intCast(max_outgoing_inflight),
            .properties = if (session_expiry_seconds == 0)
                &.{}
            else
                &properties,
        },
    );
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
        if (std.mem.startsWith(u8, arg, "--address=")) {
            config.address = try std.Io.net.IpAddress.parseLiteral(
                arg["--address=".len..],
            );
            if (config.address.getPort() == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--publishers=",
        )) {
            config.publishers = try parsePositiveUsize(
                arg["--publishers=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--subscribers=",
        )) {
            config.subscribers = try parsePositiveUsize(
                arg["--subscribers=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--warmup-messages=",
        )) {
            config.warmup_messages = try std.fmt.parseInt(
                usize,
                arg["--warmup-messages=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--messages=",
        )) {
            config.messages = try parsePositiveUsize(
                arg["--messages=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--payload-bytes=",
        )) {
            config.payload_bytes = try parsePositiveUsize(
                arg["--payload-bytes=".len..],
            );
        } else if (std.mem.startsWith(u8, arg, "--qos=")) {
            const value = arg["--qos=".len..];
            config.qos = if (std.mem.eql(u8, value, "1"))
                .at_least_once
            else if (std.mem.eql(u8, value, "2"))
                .exactly_once
            else
                return error.InvalidArgument;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--overlapping-subscriptions=",
        )) {
            config.overlapping_subscriptions = try parsePositiveUsize(
                arg["--overlapping-subscriptions=".len..],
            );
            if (config.overlapping_subscriptions > 3) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--publisher-window=",
        )) {
            config.publisher_window = try parsePositiveUsize(
                arg["--publisher-window=".len..],
            );
            if (config.publisher_window > std.math.maxInt(u16)) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--server-queue-capacity=",
        )) {
            config.server_queue_capacity = try parsePositiveUsize(
                arg["--server-queue-capacity=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--session-expiry-seconds=",
        )) {
            config.session_expiry_seconds = try std.fmt.parseInt(
                u32,
                arg["--session-expiry-seconds=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--server-implementation=",
        )) {
            config.server_implementation =
                arg["--server-implementation=".len..];
        } else if (std.mem.startsWith(u8, arg, "--server-io=")) {
            config.server_io = arg["--server-io=".len..];
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--server-tcp-nodelay=",
        )) {
            config.server_tcp_nodelay =
                arg["--server-tcp-nodelay=".len..];
            if (!std.mem.eql(u8, config.server_tcp_nodelay, "true") and
                !std.mem.eql(u8, config.server_tcp_nodelay, "false") and
                !std.mem.eql(u8, config.server_tcp_nodelay, "unspecified"))
            {
                return error.InvalidArgument;
            }
        } else {
            return error.InvalidArgument;
        }
    }
    if (config.publishers + config.subscribers > max_clients) {
        return error.InvalidArgument;
    }
    const valid_server_identity =
        (std.mem.eql(u8, config.server_implementation, "netz") and
            std.mem.eql(u8, config.server_io, "zio-std-io")) or
        (std.mem.eql(u8, config.server_implementation, "mosquitto") and
            std.mem.eql(u8, config.server_io, "mosquitto-event-loop")) or
        (std.mem.eql(u8, config.server_implementation, "external") and
            std.mem.eql(u8, config.server_io, "external-unspecified"));
    if (!valid_server_identity) return error.InvalidArgument;
    return config;
}

fn publishWindowed(
    publishers: []netz.mqtt.runtime.Connection,
    publish_topic: []const u8,
    payload: []const u8,
    message_count: usize,
    window: usize,
    qos: netz.mqtt.QoS,
    io: std.Io,
    allocator: std.mem.Allocator,
    latency_samples: ?[]u64,
) !void {
    if (message_count == 0) return;
    const total_window = std.math.mul(
        usize,
        window,
        publishers.len,
    ) catch return error.InvalidArgument;
    const packet_ids = try allocator.alloc(u16, total_window);
    defer allocator.free(packet_ids);
    const sent_ns = try allocator.alloc(u64, total_window);
    defer allocator.free(sent_ns);
    var no_qos2_released: [0]bool = .{};
    const qos2_released = if (qos == .exactly_once)
        try allocator.alloc(bool, total_window)
    else
        no_qos2_released[0..];
    defer if (qos2_released.len != 0) allocator.free(qos2_released);
    var offset: usize = 0;
    while (offset < message_count) {
        const count = @min(total_window, message_count - offset);
        for (0..count) |index| {
            // Keep each publisher's outstanding count within the configured
            // window. A single global batch may be wider because it is spread
            // over independent connections.
            const publisher_index = index % publishers.len;
            packet_ids[index] = (try publishers[publisher_index]
                .writePublish(
                publish_topic,
                payload,
                .{ .qos = qos },
            )).?;
            sent_ns[index] = nowNs(io);
        }
        if (qos == .at_least_once) {
            for (0..count) |index| {
                const publisher_index = index % publishers.len;
                try publishers[publisher_index].completePublish(
                    packet_ids[index],
                    qos,
                );
                if (latency_samples) |samples| {
                    samples[offset + index] = nowNs(io) -| sent_ns[index];
                }
            }
        } else {
            @memset(qos2_released[0..count], false);
            for (publishers, 0..) |*publisher, publisher_index| {
                const publisher_count = if (publisher_index < count)
                    (count - 1 - publisher_index) / publishers.len + 1
                else
                    0;
                var completed: usize = 0;
                while (completed < publisher_count) {
                    var event = try publisher.readClientPacketEvent();
                    defer event.deinit(allocator);
                    switch (event) {
                        .pubrec => |pubrec| {
                            const index = findWindowPacket(
                                packet_ids[0..count],
                                publishers.len,
                                publisher_index,
                                pubrec.ack.packet_id,
                            ) orelse return error.UnexpectedPubRec;
                            if (qos2_released[index]) {
                                return error.DuplicatePubRec;
                            }
                            try publisher.applyPubRec(pubrec.ack);
                            qos2_released[index] = true;
                        },
                        .pubcomp => |pubcomp| {
                            const index = findWindowPacket(
                                packet_ids[0..count],
                                publishers.len,
                                publisher_index,
                                pubcomp.ack.packet_id,
                            ) orelse return error.UnexpectedPubComp;
                            if (!qos2_released[index]) {
                                return error.PubCompBeforePubRec;
                            }
                            try publisher.applyPubComp(pubcomp.ack);
                            packet_ids[index] = 0;
                            completed += 1;
                            if (latency_samples) |samples| {
                                samples[offset + index] =
                                    nowNs(io) -| sent_ns[index];
                            }
                        },
                        else => return error.UnexpectedPublisherPacket,
                    }
                }
            }
        }
        offset += count;
    }
}

fn findWindowPacket(
    packet_ids: []const u16,
    publisher_count: usize,
    publisher_index: usize,
    packet_id: u16,
) ?usize {
    var index = publisher_index;
    while (index < packet_ids.len) : (index += publisher_count) {
        if (packet_ids[index] == packet_id) return index;
    }
    return null;
}

fn percentile(
    sorted: []const u64,
    numerator: usize,
    denominator: usize,
) u64 {
    if (sorted.len == 0) return 0;
    const rank = std.math.divCeil(
        usize,
        sorted.len * numerator,
        denominator,
    ) catch unreachable;
    return sorted[@min(sorted.len - 1, rank -| 1)];
}

fn lessThanU64(_: void, a: u64, b: u64) bool {
    return a < b;
}

fn overlapFilter(index: usize, storage: []u8) []const u8 {
    return switch (index) {
        0 => topic,
        1 => "bench/fanout/+",
        2 => "bench/#",
        else => std.fmt.bufPrint(storage, "unused/{d}", .{index}) catch
            unreachable,
    };
}

fn parsePositiveUsize(raw: []const u8) !usize {
    const value = try std.fmt.parseInt(usize, raw, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

fn firstWorkerError(errors: []const ?anyerror) anyerror {
    for (errors) |maybe_err| {
        if (maybe_err) |err| return err;
    }
    return error.BenchmarkWorkerFailed;
}

fn ratePerSecond(count: usize, elapsed_ns: u64) u128 {
    if (elapsed_ns == 0) return 0;
    return (@as(u128, count) * std.time.ns_per_s) / elapsed_ns;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse
        std.math.maxInt(u64);
}

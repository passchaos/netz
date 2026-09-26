//! Bounded MQTT broker ordering fuzzing over real loopback TCP connections.
//!
//! Every input starts the production broker plus one publisher and two
//! subscribers. Operations mutate exact-topic subscriptions and retained
//! state; MQTT PINGREQ/PINGRESP exchanges form protocol-level barriers so the
//! observed delivery sequence can be checked without sleeps.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;
const Broker = mqtt.broker.Broker;

const max_operations = 12;
const max_sequence_bytes = max_operations;
const event_timeout = std.Io.Duration.fromSeconds(2);
const topics = [2][]const u8{
    "fuzz/live/zero",
    "fuzz/live/one",
};

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const lifecycle_seed = smithSliceSeed(&.{
    0x03, // Store retained topic zero before any subscription.
    0x00, // Subscriber zero subscribes and receives the replay.
    0x08, // Subscriber one subscribes and receives the replay.
    0x02, // Both receive a normal live publication.
    0x07, // Replace retained state and deliver it live to both.
    0x01, // Subscriber zero unsubscribes.
    0x04, // Delete retained state; subscriber one gets empty live payload.
    0x05, // Repeat subscriber zero's subscription; there is no replay.
    0x13, // Store retained topic one.
    0x10, // Subscriber zero subscribes and receives topic one's replay.
    0x09, // Subscriber one unsubscribes from topic zero.
    0x02, // No subscriber now matches this topic-zero publication.
});

const replacement_seed = smithSliceSeed(&.{
    0x1b, 0x17, // Store and replace topic one without subscribers.
    0x1d, 0x18, 0x1d, // Subscribe, then repeat twice to replay current state.
    0x19, 0x19, // Unsubscribe twice, covering "not found" acknowledgement.
    0x0c, 0x08, // Delete topic zero, then subscribe on subscriber one.
    0x12, 0x0a, 0x02, // Independent normal deliveries on both topics.
});

const corpus = &.{ &lifecycle_seed, &replacement_seed };

test "structured live MQTT broker sequence reaches routing states" {
    const summary = try runSequence(lifecycle_seed[4..]);
    try std.testing.expect(summary.subscribes >= 4);
    try std.testing.expect(summary.unsubscribes >= 2);
    try std.testing.expect(summary.normal_publishes >= 2);
    try std.testing.expect(summary.retained_writes >= 3);
    try std.testing.expect(summary.retained_replacements >= 1);
    try std.testing.expect(summary.retained_deletes >= 1);
    try std.testing.expect(summary.retained_replays >= 3);
    try std.testing.expect(summary.deliveries >= 8);

    const replacements = try runSequence(replacement_seed[4..]);
    try std.testing.expect(replacements.subscription_replacements >= 2);
}

test "fuzz bounded live MQTT broker ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic live MQTT broker mutation smoke" {
    var mutated: [max_sequence_bytes]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (0..seed.len + 1) |length| _ = try runSequence(seed[0..length]);
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try runSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [max_sequence_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x6d7174745f6c6976);
    const random = prng.random();
    for (0..4) |_| {
        const length = random.uintLessThan(usize, max_sequence_bytes + 1);
        random.bytes(random_bytes[0..length]);
        _ = try runSequence(random_bytes[0..length]);
    }
}

fn fuzzSequences(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_sequence_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try runSequence(bytes);
}

const Payload = struct {
    bytes: [3]u8,

    fn init(operation: u8, index: usize, topic_index: usize) Payload {
        return .{ .bytes = .{
            operation,
            @intCast(index),
            @intCast(0xa0 | topic_index),
        } };
    }
};

const ExpectedDelivery = struct {
    topic_index: usize,
    payload: [3]u8 = undefined,
    payload_len: usize,
    retain: bool,

    fn message(
        topic_index: usize,
        payload: Payload,
        retain: bool,
    ) ExpectedDelivery {
        return .{
            .topic_index = topic_index,
            .payload = payload.bytes,
            .payload_len = payload.bytes.len,
            .retain = retain,
        };
    }

    fn empty(topic_index: usize) ExpectedDelivery {
        return .{
            .topic_index = topic_index,
            .payload_len = 0,
            .retain = false,
        };
    }
};

const ExpectedQueue = struct {
    items: [max_operations]ExpectedDelivery = undefined,
    len: usize = 0,

    fn append(self: *ExpectedQueue, delivery: ExpectedDelivery) !void {
        if (self.len == self.items.len) return error.ExpectedQueueFull;
        self.items[self.len] = delivery;
        self.len += 1;
    }

    fn clear(self: *ExpectedQueue) void {
        self.len = 0;
    }
};

const Model = struct {
    subscribed: [2][2]bool = .{ .{ false, false }, .{ false, false } },
    retained: [2]?Payload = .{ null, null },
    expected: [2]ExpectedQueue = .{ .{}, .{} },

    fn enqueueLive(
        self: *Model,
        topic_index: usize,
        delivery: ExpectedDelivery,
    ) !void {
        for (0..self.subscribed.len) |subscriber_index| {
            if (self.subscribed[subscriber_index][topic_index]) {
                try self.expected[subscriber_index].append(delivery);
            }
        }
    }
};

const Summary = struct {
    subscribes: usize = 0,
    unsubscribes: usize = 0,
    normal_publishes: usize = 0,
    retained_writes: usize = 0,
    retained_replacements: usize = 0,
    retained_deletes: usize = 0,
    retained_replays: usize = 0,
    subscription_replacements: usize = 0,
    deliveries: usize = 0,
};

const ServeState = struct {
    broker: *Broker,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serve(3) catch |err| {
            self.err = err;
        };
    }
};

fn connect(
    allocator: std.mem.Allocator,
    io: std.Io,
    broker: Broker,
    client_id: []const u8,
) !runtime.Connection {
    return runtime.Client.connect(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = client_id,
    });
}

fn runSequence(input: []const u8) !Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 3,
                .max_queued_deliveries_per_connection = max_operations,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .max_outgoing_inflight = 16,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker };
    const server_thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) server_thread.join();

    var publisher = try connect(allocator, io, broker, "fuzz-publisher");
    defer publisher.close();
    var subscriber_zero = try connect(allocator, io, broker, "fuzz-sub-zero");
    defer subscriber_zero.close();
    var subscriber_one = try connect(allocator, io, broker, "fuzz-sub-one");
    defer subscriber_one.close();
    const subscribers = [2]*runtime.Connection{
        &subscriber_zero,
        &subscriber_one,
    };

    var model = Model{};
    var summary = Summary{};
    for (input[0..@min(input.len, max_operations)], 0..) |operation, index| {
        const subscriber_index: usize = (operation >> 3) & 0x01;
        const topic_index: usize = (operation >> 4) & 0x01;
        const payload = Payload.init(operation, index, topic_index);
        switch (operation & 0x07) {
            0 => try subscribe(
                subscribers[subscriber_index],
                &model,
                &summary,
                subscriber_index,
                topic_index,
            ),
            1, 6 => try unsubscribe(
                subscribers[subscriber_index],
                &model,
                &summary,
                subscriber_index,
                topic_index,
            ),
            2 => {
                try publisher.publish(
                    topics[topic_index],
                    &payload.bytes,
                    .{},
                );
                try model.enqueueLive(
                    topic_index,
                    ExpectedDelivery.message(topic_index, payload, false),
                );
                summary.normal_publishes += 1;
                try drainThroughPing(&publisher, null, &summary);
            },
            3, 7 => {
                if (model.retained[topic_index] != null) {
                    summary.retained_replacements += 1;
                }
                try publisher.publish(
                    topics[topic_index],
                    &payload.bytes,
                    .{ .retain = true },
                );
                model.retained[topic_index] = payload;
                try model.enqueueLive(
                    topic_index,
                    ExpectedDelivery.message(topic_index, payload, false),
                );
                summary.retained_writes += 1;
                try drainThroughPing(&publisher, null, &summary);
            },
            4 => {
                try publisher.publish(
                    topics[topic_index],
                    &.{},
                    .{ .retain = true },
                );
                model.retained[topic_index] = null;
                try model.enqueueLive(
                    topic_index,
                    ExpectedDelivery.empty(topic_index),
                );
                summary.retained_deletes += 1;
                try drainThroughPing(&publisher, null, &summary);
            },
            5 => try subscribe(
                subscribers[subscriber_index],
                &model,
                &summary,
                subscriber_index,
                topic_index,
            ),
            else => unreachable,
        }

        for (subscribers, 0..) |subscriber, subscriber_index_value| {
            try drainThroughPing(
                subscriber,
                &model.expected[subscriber_index_value],
                &summary,
            );
        }
    }

    // A second empty barrier proves the last operation left no hidden extra
    // delivery behind the first observed PINGRESP.
    try drainThroughPing(&publisher, null, &summary);
    for (subscribers, 0..) |subscriber, subscriber_index| {
        try drainThroughPing(
            subscriber,
            &model.expected[subscriber_index],
            &summary,
        );
    }

    try subscriber_one.disconnect(0);
    try subscriber_zero.disconnect(0);
    try publisher.disconnect(0);
    server_thread.join();
    joined = true;
    if (serve.err) |err| return err;
    return summary;
}

fn subscribe(
    connection: *runtime.Connection,
    model: *Model,
    summary: *Summary,
    subscriber_index: usize,
    topic_index: usize,
) !void {
    var suback = try connection.subscribe(
        &.{.{
            .topic_filter = topics[topic_index],
            .retain_handling = 0,
        }},
        .{},
    );
    defer suback.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x00},
        suback.suback.reason_codes,
    );

    const already_subscribed = model.subscribed[subscriber_index][topic_index];
    if (already_subscribed) summary.subscription_replacements += 1;
    model.subscribed[subscriber_index][topic_index] = true;
    if (model.retained[topic_index]) |payload| {
        try model.expected[subscriber_index].append(
            ExpectedDelivery.message(topic_index, payload, true),
        );
        summary.retained_replays += 1;
    }
    summary.subscribes += 1;
}

fn unsubscribe(
    connection: *runtime.Connection,
    model: *Model,
    summary: *Summary,
    subscriber_index: usize,
    topic_index: usize,
) !void {
    const existed = model.subscribed[subscriber_index][topic_index];
    var unsuback = try connection.unsubscribe(&.{topics[topic_index]}, .{});
    defer unsuback.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        if (existed) &.{0x00} else &.{0x11},
        unsuback.unsuback.reason_codes,
    );
    model.subscribed[subscriber_index][topic_index] = false;
    summary.unsubscribes += 1;
}

fn drainThroughPing(
    connection: *runtime.Connection,
    expected_queue: ?*ExpectedQueue,
    summary: *Summary,
) !void {
    try connection.writePingReq();
    var observed: usize = 0;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            event_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |delivery| {
                const queue = expected_queue orelse
                    return error.UnexpectedPublisherDelivery;
                if (observed >= queue.len) return error.UnexpectedDelivery;
                const expected = queue.items[observed];
                try std.testing.expectEqualStrings(
                    topics[expected.topic_index],
                    delivery.publish.topic,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    expected.payload[0..expected.payload_len],
                    delivery.publish.payload,
                );
                try std.testing.expectEqual(
                    mqtt.QoS.at_most_once,
                    delivery.publish.qos,
                );
                try std.testing.expectEqual(
                    expected.retain,
                    delivery.publish.retain,
                );
                try std.testing.expectEqual(
                    @as(?u16, null),
                    delivery.publish.packet_id,
                );
                observed += 1;
                summary.deliveries += 1;
            },
            .pingresp => {
                if (expected_queue) |queue| {
                    try std.testing.expectEqual(queue.len, observed);
                    queue.clear();
                } else {
                    try std.testing.expectEqual(@as(usize, 0), observed);
                }
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}

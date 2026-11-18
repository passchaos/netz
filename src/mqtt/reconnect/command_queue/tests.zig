const std = @import("std");
const command_queue_root = @import("../command_queue.zig");

const mqtt = @import("../../mod.zig");

const CommandQueue = command_queue_root.CommandQueue;
const Completion = command_queue_root.Completion;
const CompletionQueue = command_queue_root.CompletionQueue;
const EnqueueTimeoutError = command_queue_root.EnqueueTimeoutError;
const TestCompletion = command_queue_root.TestCompletion;
const checkAsyncCommandAllocationFailure = command_queue_root.checkAsyncCommandAllocationFailure;
const checkCompletionQueueAllocationFailure = command_queue_root.checkCompletionQueueAllocationFailure;

test "MQTT command queue supports zero-capacity rendezvous storage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    try std.testing.expectEqual(@as(usize, 0), queue.queue.capacity());
}

test "MQTT asynchronous command identifiers stay exhausted after overflow" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    queue.next_command_id.store(std.math.maxInt(u64), .monotonic);

    try std.testing.expectEqual(
        std.math.maxInt(u64),
        try queue.nextCommandId(),
    );
    try std.testing.expectError(
        error.CommandIdentifierExhausted,
        queue.nextCommandId(),
    );
    try std.testing.expectError(
        error.CommandIdentifierExhausted,
        queue.nextCommandId(),
    );
}

test "MQTT completion queue owns acknowledgement data" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CompletionQueue.init(std.testing.allocator, io, 2);
    defer queue.deinit();
    try std.testing.expect((try queue.tryReceive()) == null);

    var reason_codes: [2]u8 = .{ 0x00, 0x01 };
    var reason: [8]u8 = "accepted".*;
    var properties = [_]mqtt.Property{.{ .utf8 = .{
        .id = .reason_string,
        .value = &reason,
    } }};
    const handler = queue.handler();
    handler.complete(handler.context, .{
        .command_id = 41,
        .result = .{ .subscribe = .{
            .packet_id = 7,
            .reason_codes = &reason_codes,
            .properties = &properties,
        } },
    });
    @memset(&reason_codes, 0xff);
    @memcpy(&reason, "modified");
    properties[0] = .{ .byte = .{
        .id = .maximum_qos,
        .value = 0,
    } };

    var completion = try queue.receive();
    defer completion.deinit();
    try std.testing.expectEqual(@as(u64, 41), completion.command_id);
    const result = try completion.result;
    switch (result) {
        .subscribe => |ack| {
            try std.testing.expectEqual(@as(u16, 7), ack.packet_id);
            try std.testing.expectEqualSlices(
                u8,
                &.{ 0x00, 0x01 },
                ack.reason_codes,
            );
            try std.testing.expectEqualStrings(
                "accepted",
                ack.properties[0].utf8.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

test "MQTT completion queue receive timeout returns data and timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CompletionQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();

    try std.testing.expectError(
        error.Timeout,
        queue.receiveTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        queue.receiveWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );

    const handler = queue.handler();
    handler.complete(handler.context, .{
        .command_id = 45,
        .result = .{ .publish = 23 },
    });
    var completion = try queue.receiveWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer completion.deinit();
    try std.testing.expectEqual(@as(u64, 45), completion.command_id);
    const result = try completion.result;
    switch (result) {
        .publish => |packet_id| try std.testing.expectEqual(
            @as(?u16, 23),
            packet_id,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "MQTT completion queue close wakes a timed receiver" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CompletionQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();

    const Consumer = struct {
        io: std.Io,
        queue: *CompletionQueue,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            var completion = self.queue.receiveTimeout(
                .fromSeconds(30),
            ) catch |err| {
                self.err = err;
                return;
            };
            completion.deinit();
            self.err = error.TestUnexpectedResult;
        }
    };
    var consumer = Consumer{ .io = io, .queue = &queue };
    const thread = try std.Thread.spawn(.{}, Consumer.run, .{&consumer});
    consumer.started.waitUncancelable(io);
    queue.queue.close(io);
    thread.join();
    try std.testing.expectEqual(
        error.CompletionQueueClosed,
        consumer.err.?,
    );
}

test "MQTT completion queue preserves failures and close semantics" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CompletionQueue.init(
        std.testing.allocator,
        threaded.io(),
        1,
    );
    defer queue.deinit();
    const handler = queue.handler();
    handler.complete(handler.context, .{
        .command_id = 42,
        .result = error.ConnectionUnavailable,
    });

    var completion = try queue.receive();
    defer completion.deinit();
    try std.testing.expectEqual(@as(u64, 42), completion.command_id);
    try std.testing.expectError(
        error.ConnectionUnavailable,
        completion.result,
    );
    queue.close();
    handler.complete(handler.context, .{
        .command_id = 44,
        .result = .{ .subscribe = .{
            .packet_id = 10,
            .reason_codes = &.{0x00},
            .properties = &.{.{ .utf8 = .{
                .id = .reason_string,
                .value = "discarded",
            } }},
        } },
    });
    try std.testing.expectError(
        error.CompletionQueueClosed,
        queue.tryReceive(),
    );
}

test "MQTT completion queue allocation failures are owned results" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkCompletionQueueAllocationFailure,
        .{},
    );
}

test "MQTT command queue stop wakes a pending producer" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 0);
    defer queue.deinit();

    const Producer = struct {
        io: std.Io,
        queue: *CommandQueue,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            self.queue.flushPending() catch |err| {
                self.err = err;
                return;
            };
            self.err = error.TestUnexpectedResult;
        }
    };
    var producer = Producer{ .io = io, .queue = &queue };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    producer.started.waitUncancelable(io);
    queue.stop(error.CommandQueueClosed);
    thread.join();
    try std.testing.expectEqual(
        error.CommandQueueClosed,
        producer.err.?,
    );
}

test "MQTT async publish rejects a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 0);
    defer queue.deinit();
    const CompletionContext = struct {
        fn complete(_: *anyopaque, _: Completion) void {}
    };
    var context: u8 = 0;
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.publishAsync(
            "full/topic",
            "payload",
            .{ .properties = &.{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "key",
                .value = "value",
            } }} },
            .{
                .context = &context,
                .complete = CompletionContext.complete,
            },
        ),
    );
}

test "MQTT async publish deadline releases an unqueued command" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const first_id = try queue.publishAsync(
        "queued/first",
        "first",
        .{},
        completion.handler(),
    );

    try std.testing.expectError(
        error.Timeout,
        queue.publishAsyncWithDeadline(
            "queued/timeout",
            "not accepted",
            .{ .properties = &.{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "owned",
                .value = "until timeout",
            } }} },
            completion.handler(),
            .fromNow(io, .{
                .raw = .fromMilliseconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), queue.async_commands.load(
        .acquire,
    ));
    try std.testing.expectEqual(@as(usize, 0), completion.calls);

    const first = (try queue.take()).?;
    first.finishFailure(io, error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 1), completion.calls);
    try std.testing.expectEqual(first_id, completion.ids[0]);
}

test "MQTT asynchronous command timeout variants reject expired waits" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        1,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const handler = completion.handler();

    try std.testing.expectError(error.Timeout, queue.subscribeAsyncTimeout(
        &.{.{ .topic_filter = "timed/+" }},
        .{},
        handler,
        .zero,
    ));
    try std.testing.expectError(error.Timeout, queue.unsubscribeAsyncTimeout(
        &.{"timed/+"},
        .{},
        handler,
        .zero,
    ));
    try std.testing.expectError(error.Timeout, queue.disconnectAsyncTimeout(
        0,
        &.{},
        handler,
        .zero,
    ));
    try std.testing.expectError(error.Timeout, queue.acknowledgeAsyncTimeout(
        1,
        .at_least_once,
        .{},
        handler,
        .zero,
    ));
    try std.testing.expectError(error.Timeout, queue.flushPendingAsyncTimeout(
        handler,
        .zero,
    ));
    try std.testing.expectError(
        error.Timeout,
        queue.beginReauthenticationAsyncTimeout(
            &.{},
            handler,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
    try std.testing.expectEqual(@as(usize, 0), queue.async_commands.load(
        .acquire,
    ));
}

test "MQTT asynchronous command deadlines reject invalid budgets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const handler = completion.handler();
    const wrong_clock: std.Io.Clock.Timestamp = .{
        .raw = .zero,
        .clock = .real,
    };
    const expired = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .zero,
        .clock = .awake,
    });

    try std.testing.expectError(error.Timeout, queue.publishAsyncWithDeadline(
        "timed/publish",
        "payload",
        .{},
        handler,
        wrong_clock,
    ));
    try std.testing.expectError(error.Timeout, queue.subscribeAsyncWithDeadline(
        &.{.{ .topic_filter = "timed/+" }},
        .{},
        handler,
        expired,
    ));
    try std.testing.expectError(error.Timeout, queue.unsubscribeAsyncWithDeadline(
        &.{"timed/+"},
        .{},
        handler,
        wrong_clock,
    ));
    try std.testing.expectError(error.Timeout, queue.disconnectAsyncWithDeadline(
        0,
        &.{},
        handler,
        expired,
    ));
    try std.testing.expectError(error.Timeout, queue.acknowledgeAsyncWithDeadline(
        1,
        .at_least_once,
        .{},
        handler,
        wrong_clock,
    ));
    try std.testing.expectError(
        error.Timeout,
        queue.flushPendingAsyncWithDeadline(handler, expired),
    );
    try std.testing.expectError(
        error.Timeout,
        queue.beginReauthenticationAsyncWithDeadline(
            &.{},
            handler,
            wrong_clock,
        ),
    );
    // Deadline validation precedes both identifier allocation and deep-copy
    // ownership, so rejected calls cannot create hidden completion IDs.
    try std.testing.expectEqual(
        @as(u64, 1),
        queue.next_command_id.load(.monotonic),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
    try std.testing.expectEqual(@as(usize, 0), queue.async_commands.load(
        .acquire,
    ));
}

test "MQTT async publish deadline waits for bounded queue capacity" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    _ = try queue.publishAsync(
        "queued/first",
        "first",
        .{},
        completion.handler(),
    );

    const Producer = struct {
        io: std.Io,
        queue: *CommandQueue,
        completion: *TestCompletion,
        deadline: std.Io.Clock.Timestamp,
        started: std.Io.Event = .unset,
        result: ?EnqueueTimeoutError!u64 = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            self.result = self.queue.publishAsyncWithDeadline(
                "queued/second",
                "second",
                .{},
                self.completion.handler(),
                self.deadline,
            );
        }
    };
    var producer = Producer{
        .io = io,
        .queue = &queue,
        .completion = &completion,
        .deadline = .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    producer.started.waitUncancelable(io);
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);

    const first = (try queue.take()).?;
    thread.join();
    const second_id = try producer.result.?;
    const second = (try queue.take()).?;
    switch (second.operation) {
        .publish_owned => |publish| {
            try std.testing.expectEqualStrings(
                "queued/second",
                publish.topic,
            );
            try std.testing.expectEqualStrings("second", publish.payload);
        },
        else => return error.TestUnexpectedResult,
    }
    first.finishFailure(io, error.CommandQueueClosed);
    second.finishFailure(io, error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 2), completion.calls);
    try std.testing.expectEqual(second_id, completion.ids[1]);
}

test "MQTT async publish deadline observes queue close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    _ = try queue.publishAsync(
        "queued/first",
        "first",
        .{},
        completion.handler(),
    );

    const Producer = struct {
        io: std.Io,
        queue: *CommandQueue,
        completion: *TestCompletion,
        deadline: std.Io.Clock.Timestamp,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            _ = self.queue.publishAsyncWithDeadline(
                "queued/closed",
                "not accepted",
                .{},
                self.completion.handler(),
                self.deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
            self.err = error.TestUnexpectedResult;
        }
    };
    var producer = Producer{
        .io = io,
        .queue = &queue,
        .completion = &completion,
        .deadline = .fromNow(io, .{
            .raw = .fromSeconds(30),
            .clock = .awake,
        }),
    };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    producer.started.waitUncancelable(io);
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    queue.queue.close(io);
    thread.join();
    try std.testing.expectEqual(error.CommandQueueClosed, producer.err.?);
    try std.testing.expectEqual(@as(usize, 1), queue.async_commands.load(
        .acquire,
    ));
    queue.stop(error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 1), completion.calls);
}

test "MQTT async subscription commands reject a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = "key",
        .value = "value",
    } }};
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.subscribeAsync(
            &.{.{ .topic_filter = "full/+", .qos = .at_least_once }},
            .{ .properties = &properties },
            completion.handler(),
        ),
    );
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.unsubscribeAsync(
            &.{"full/+"},
            .{ .properties = &properties },
            completion.handler(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
}

test "MQTT async disconnect rejects a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.disconnectAsync(
            0x00,
            &.{.{ .utf8 = .{
                .id = .reason_string,
                .value = "queue full",
            } }},
            completion.handler(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
}

test "MQTT async acknowledgement rejects a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.acknowledgeAsync(
            7,
            .at_least_once,
            .{ .properties = &.{.{ .utf8 = .{
                .id = .reason_string,
                .value = "queue full",
            } }} },
            completion.handler(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
}

test "MQTT async control commands reject a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.flushPendingAsync(completion.handler()),
    );
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.beginReauthenticationAsync(
            &.{.{ .utf8 = .{
                .id = .authentication_method,
                .value = "mirror",
            } }},
            completion.handler(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
}

test "MQTT async acknowledgement owns properties" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    var reason: [8]u8 = "original".*;
    const properties = [_]mqtt.Property{.{ .utf8 = .{
        .id = .reason_string,
        .value = &reason,
    } }};
    _ = try queue.acknowledgeAsync(
        7,
        .at_least_once,
        .{ .reason_code = 0x10, .properties = &properties },
        completion.handler(),
    );
    @memcpy(&reason, "modified");

    const command = (try queue.take()).?;
    switch (command.operation) {
        .acknowledge_owned => |operation| {
            try std.testing.expectEqual(@as(u16, 7), operation.packet_id);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, operation.qos);
            try std.testing.expectEqual(@as(u8, 0x10), operation.reason_code);
            try std.testing.expectEqualStrings(
                "original",
                operation.properties[0].utf8.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    command.finishFailure(io, error.CommandQueueClosed);
}

test "MQTT async reauthentication owns properties" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    var authentication_data: [8]u8 = "original".*;
    const properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .authentication_method,
            .value = "mirror",
        } },
        .{ .binary = .{
            .id = .authentication_data,
            .value = &authentication_data,
        } },
    };
    _ = try queue.beginReauthenticationAsync(
        &properties,
        completion.handler(),
    );
    @memcpy(&authentication_data, "modified");

    const command = (try queue.take()).?;
    switch (command.operation) {
        .begin_reauthentication_owned => |owned| {
            try std.testing.expectEqualStrings(
                "original",
                mqtt.authenticationData(owned).?,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    command.finishFailure(io, error.CommandQueueClosed);
}

test "MQTT async disconnect owns properties" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    var reason: [8]u8 = "original".*;
    const properties = [_]mqtt.Property{.{ .utf8 = .{
        .id = .reason_string,
        .value = &reason,
    } }};
    _ = try queue.disconnectAsync(
        0x00,
        &properties,
        completion.handler(),
    );
    @memcpy(&reason, "modified");

    const command = (try queue.take()).?;
    switch (command.operation) {
        .disconnect_owned => |operation| {
            try std.testing.expectEqualStrings(
                "original",
                operation.properties[0].utf8.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    command.finishFailure(io, error.CommandQueueClosed);
}

test "MQTT async subscription commands own filters and properties" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    var filter: [11]u8 = "owned/topic".*;
    var key: [6]u8 = "source".*;
    var value: [8]u8 = "original".*;
    const properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = &key,
        .value = &value,
    } }};

    _ = try queue.subscribeAsync(
        &.{.{ .topic_filter = &filter, .qos = .exactly_once }},
        .{ .properties = &properties },
        completion.handler(),
    );
    @memcpy(&filter, "other/topic");
    @memcpy(&key, "target");
    @memcpy(&value, "modified");
    const subscribe = (try queue.take()).?;
    switch (subscribe.operation) {
        .subscribe_owned => |operation| {
            try std.testing.expectEqualStrings(
                "owned/topic",
                operation.subscriptions[0].filter,
            );
            try std.testing.expectEqual(mqtt.QoS.exactly_once, operation.subscriptions[0].qos);
            try std.testing.expectEqualStrings(
                "source",
                operation.properties[0].utf8_pair.key,
            );
            try std.testing.expectEqualStrings(
                "original",
                operation.properties[0].utf8_pair.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    subscribe.finishFailure(io, error.CommandQueueClosed);

    @memcpy(&filter, "owned/topic");
    @memcpy(&key, "source");
    @memcpy(&value, "original");
    _ = try queue.unsubscribeAsync(
        &.{&filter},
        .{ .properties = &properties },
        completion.handler(),
    );
    @memcpy(&filter, "other/topic");
    @memcpy(&key, "target");
    @memcpy(&value, "modified");
    const unsubscribe = (try queue.take()).?;
    switch (unsubscribe.operation) {
        .unsubscribe_owned => |operation| {
            try std.testing.expectEqualStrings(
                "owned/topic",
                operation.filters[0],
            );
            try std.testing.expectEqualStrings(
                "source",
                operation.properties[0].utf8_pair.key,
            );
            try std.testing.expectEqualStrings(
                "original",
                operation.properties[0].utf8_pair.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    unsubscribe.finishFailure(io, error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 2), completion.calls);
}

test "MQTT command queue completes buffered async publish on stop" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    const CompletionContext = struct {
        called: usize = 0,
        command_id: u64 = 0,
        err: ?anyerror = null,
        fn complete(
            context: *anyopaque,
            completion: Completion,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.called += 1;
            self.command_id = completion.command_id;
            _ = completion.result catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var completion: CompletionContext = .{};
    const command_id = try queue.publishAsync(
        "stopped/topic",
        "payload",
        .{},
        .{
            .context = &completion,
            .complete = CompletionContext.complete,
        },
    );
    queue.stop(error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 1), completion.called);
    try std.testing.expectEqual(command_id, completion.command_id);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.err.?);
}

test "MQTT command queue fails buffered async commands on stop" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 6);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const subscribe_id = try queue.subscribeAsync(
        &.{.{ .topic_filter = "stopped/+" }},
        .{},
        completion.handler(),
    );
    const unsubscribe_id = try queue.unsubscribeAsync(
        &.{"stopped/+"},
        .{},
        completion.handler(),
    );
    const disconnect_id = try queue.disconnectAsync(
        0x00,
        &.{.{ .utf8 = .{
            .id = .reason_string,
            .value = "stopped",
        } }},
        completion.handler(),
    );
    const acknowledge_id = try queue.acknowledgeAsync(
        7,
        .at_least_once,
        .{},
        completion.handler(),
    );
    const flush_id = try queue.flushPendingAsync(completion.handler());
    const reauthentication_id = try queue.beginReauthenticationAsync(
        &.{.{ .utf8 = .{
            .id = .authentication_method,
            .value = "mirror",
        } }},
        completion.handler(),
    );

    queue.stop(error.CommandQueueClosed);

    try std.testing.expectEqual(@as(usize, 6), completion.calls);
    try std.testing.expectEqual(subscribe_id, completion.ids[0]);
    try std.testing.expectEqual(unsubscribe_id, completion.ids[1]);
    try std.testing.expectEqual(disconnect_id, completion.ids[2]);
    try std.testing.expectEqual(acknowledge_id, completion.ids[3]);
    try std.testing.expectEqual(flush_id, completion.ids[4]);
    try std.testing.expectEqual(reauthentication_id, completion.ids[5]);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[0].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[1].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[2].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[3].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[4].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[5].?);
}

test "MQTT async command allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkAsyncCommandAllocationFailure,
        .{},
    );
}

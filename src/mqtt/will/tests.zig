const std = @import("std");
const mqtt = @import("../mod.zig");
const will = @import("mod.zig");

const Scheduler = will.Scheduler;
const second_ns: i96 = std.time.ns_per_s;

fn sampleWill(
    delay: u32,
    expiry: ?u32,
) mqtt.LastWill {
    const Properties = struct {
        var values: [2]mqtt.Property = undefined;
    };
    var count: usize = 0;
    Properties.values[count] = .{ .four_byte = .{
        .id = .will_delay_interval,
        .value = delay,
    } };
    count += 1;
    if (expiry) |value| {
        Properties.values[count] = .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = value,
        } };
        count += 1;
    }
    return .{
        .topic = "status/client",
        .payload = "offline",
        .qos = .at_least_once,
        .retain = true,
        .properties = Properties.values[0..count],
    };
}

test "will normal disconnect cancels without publication" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const handle = try scheduler.set("client", sampleWill(10, null), 60);
    try std.testing.expectEqual(
        will.CloseResult.canceled,
        try scheduler.close(
            handle,
            .normal_disconnect,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), scheduler.count());
    try std.testing.expectError(error.WillNotFound, scheduler.view(handle));
}

test "will ungraceful close schedules at min delay and session expiry" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const handle = try scheduler.set("client", sampleWill(10, null), 4);
    try std.testing.expectEqual(
        will.CloseResult.scheduled,
        try scheduler.close(handle, .ungraceful, .zero),
    );
    try std.testing.expectEqual(
        @as(i96, 4 * second_ns),
        scheduler.nextDeadline().?.nanoseconds,
    );
    var due_storage: [1]will.Handle = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        (try scheduler.pollDue(
            std.Io.Timestamp.fromNanoseconds(3 * second_ns),
            &due_storage,
        )).len,
    );
    const due = try scheduler.pollDue(
        std.Io.Timestamp.fromNanoseconds(4 * second_ns),
        &due_storage,
    );
    try std.testing.expectEqual(handle, due[0]);
    try std.testing.expectEqualStrings(
        "offline",
        (try scheduler.view(due[0])).payload,
    );
    try scheduler.releaseDue(due[0]);
}

test "will reconnect before deadline cancels continued session" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const handle = try scheduler.set("client", sampleWill(10, null), 60);
    _ = try scheduler.close(handle, .ungraceful, .zero);
    try std.testing.expectEqual(
        will.CloseResult.canceled,
        scheduler.onReconnect(
            "client",
            false,
            std.Io.Timestamp.fromNanoseconds(5 * second_ns),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), scheduler.count());
}

test "will reconnect after deadline remains due" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const handle = try scheduler.set("client", sampleWill(5, null), 60);
    _ = try scheduler.close(handle, .ungraceful, .zero);
    try std.testing.expectEqual(
        will.CloseResult.due_now,
        scheduler.onReconnect(
            "client",
            false,
            std.Io.Timestamp.fromNanoseconds(5 * second_ns),
        ),
    );
    var due: [1]will.Handle = undefined;
    try std.testing.expectEqual(
        @as(usize, 1),
        (try scheduler.pollDue(
            std.Io.Timestamp.fromNanoseconds(5 * second_ns),
            &due,
        )).len,
    );
}

test "will live takeover follows clean-start and positive-delay rules" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    _ = try scheduler.set("resume", sampleWill(5, null), 60);
    try std.testing.expectEqual(
        will.CloseResult.canceled,
        scheduler.onReconnect("resume", false, .zero),
    );

    _ = try scheduler.set("zero", sampleWill(0, null), 60);
    try std.testing.expectEqual(
        will.CloseResult.due_now,
        scheduler.onReconnect("zero", false, .zero),
    );

    _ = try scheduler.set("clean", sampleWill(5, null), 60);
    try std.testing.expectEqual(
        will.CloseResult.due_now,
        scheduler.onReconnect("clean", true, .zero),
    );
}

test "will clean start takeover and zero delay publish immediately" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const delayed = try scheduler.set("client", sampleWill(30, null), 60);
    _ = try scheduler.close(delayed, .ungraceful, .zero);
    try std.testing.expectEqual(
        will.CloseResult.due_now,
        scheduler.onReconnect("client", true, .zero),
    );

    var due: [2]will.Handle = undefined;
    var ready = try scheduler.pollDue(.zero, &due);
    try std.testing.expectEqual(@as(usize, 1), ready.len);
    try scheduler.releaseDue(ready[0]);

    const immediate = try scheduler.set("zero", sampleWill(0, null), 60);
    try std.testing.expectEqual(
        will.CloseResult.due_now,
        try scheduler.close(immediate, .ungraceful, .zero),
    );
    ready = try scheduler.pollDue(.zero, &due);
    try std.testing.expectEqual(@as(usize, 1), ready.len);
}

test "will DISCONNECT packet maps 0x00 and 0x04 actions" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const canceled = try scheduler.set("normal", sampleWill(10, null), 60);
    try std.testing.expectEqual(
        will.CloseResult.canceled,
        try scheduler.closeDisconnect(
            canceled,
            .{ .reason_code = 0 },
            .zero,
        ),
    );
    const fired = try scheduler.set("fire", sampleWill(10, null), 60);
    try std.testing.expectEqual(
        will.CloseResult.scheduled,
        try scheduler.closeDisconnect(
            fired,
            .{ .reason_code = 0x04 },
            .zero,
        ),
    );
    try std.testing.expectEqual(
        @as(i96, 10 * second_ns),
        scheduler.nextDeadline().?.nanoseconds,
    );
}

test "will DISCONNECT expiry override shortens publication deadline" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const handle = try scheduler.set("expiry", sampleWill(10, null), 60);
    try std.testing.expectEqual(
        will.CloseResult.scheduled,
        try scheduler.closeDisconnect(handle, .{
            .reason_code = 0x04,
            .properties = @constCast(&[_]mqtt.Property{
                .{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 3,
                } },
            }),
        }, .zero),
    );
    try std.testing.expectEqual(
        @as(i96, 3 * second_ns),
        scheduler.nextDeadline().?.nanoseconds,
    );

    const invalid = try scheduler.set("invalid", sampleWill(10, null), 0);
    try std.testing.expectError(
        error.InvalidProperty,
        scheduler.closeDisconnect(invalid, .{
            .reason_code = 0x04,
            .properties = @constCast(&[_]mqtt.Property{
                .{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 1,
                } },
            }),
        }, .zero),
    );
}

test "will first close fixes deadline despite duplicate transport signals" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const handle = try scheduler.set("client", sampleWill(10, null), 60);
    _ = try scheduler.close(handle, .ungraceful, .zero);
    const later = std.Io.Timestamp.fromNanoseconds(3 * second_ns);
    try std.testing.expectEqual(
        will.CloseResult.scheduled,
        try scheduler.close(handle, .ungraceful, later),
    );
    try std.testing.expectEqual(
        will.CloseResult.scheduled,
        try scheduler.close(handle, .normal_disconnect, later),
    );
    try std.testing.expectEqual(
        @as(i96, 10 * second_ns),
        scheduler.nextDeadline().?.nanoseconds,
    );
}

test "will poll order and capacity are transactional" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const late = try scheduler.set("late", sampleWill(10, null), 60);
    const early = try scheduler.set("early", sampleWill(2, null), 60);
    const middle = try scheduler.set("middle", sampleWill(5, null), 60);
    _ = try scheduler.close(late, .ungraceful, .zero);
    _ = try scheduler.close(early, .ungraceful, .zero);
    _ = try scheduler.close(middle, .ungraceful, .zero);

    var too_small: [1]will.Handle = undefined;
    try std.testing.expectError(
        error.DueBufferTooSmall,
        scheduler.pollDue(
            std.Io.Timestamp.fromNanoseconds(10 * second_ns),
            &too_small,
        ),
    );
    try std.testing.expectEqual(
        @as(i96, 2 * second_ns),
        scheduler.nextDeadline().?.nanoseconds,
    );
    var all: [3]will.Handle = undefined;
    const due = try scheduler.pollDue(
        std.Io.Timestamp.fromNanoseconds(10 * second_ns),
        &all,
    );
    try std.testing.expectEqual(early, due[0]);
    try std.testing.expectEqual(middle, due[1]);
    try std.testing.expectEqual(late, due[2]);
}

test "will setConnect owns parsed bytes and forwards publish properties" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    var properties = [_]mqtt.Property{
        .{ .four_byte = .{
            .id = .will_delay_interval,
            .value = 1,
        } },
        .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 30,
        } },
        .{ .utf8 = .{
            .id = .content_type,
            .value = "text/plain",
        } },
    };
    const connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = false,
        .keep_alive_seconds = 30,
        .client_id = "owned",
        .properties = @constCast(&[_]mqtt.Property{
            .{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 60,
            } },
        }),
        .will = .{
            .topic = "owned/status",
            .payload = "offline",
            .qos = .at_least_once,
            .retain = true,
            .properties = &properties,
        },
    };
    const handle = (try scheduler.setConnect(connect)).?;
    _ = try scheduler.close(handle, .ungraceful, .zero);
    var due_storage: [1]will.Handle = undefined;
    const due = try scheduler.pollDue(
        std.Io.Timestamp.fromNanoseconds(second_ns),
        &due_storage,
    );
    const publish = try scheduler.view(due[0]);
    try std.testing.expectEqual(@as(?u32, 30), publish.message_expiry_interval);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try publish.writePublish(&encoded, allocator, .v5, 7);
    var parsed = try mqtt.Publish.parse(allocator, .v5, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("owned/status", parsed.topic);
    try std.testing.expect(parsed.retain);
    try std.testing.expectEqual(
        @as(?u32, 30),
        mqtt.messageExpiryInterval(parsed.properties),
    );
    try std.testing.expectEqual(
        @as(?u32, null),
        mqtt.willDelayInterval(parsed.properties),
    );
}

test "will acceptConnect returns old due handle and installs new Will" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    _ = try scheduler.set("same", sampleWill(0, null), 60);
    var properties = [_]mqtt.Property{
        .{ .four_byte = .{
            .id = .will_delay_interval,
            .value = 5,
        } },
    };
    const accepted = try scheduler.acceptConnect(.{
        .protocol = .v5,
        .clean_start = false,
        .keep_alive_seconds = 30,
        .client_id = "same",
        .properties = @constCast(&[_]mqtt.Property{
            .{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 60,
            } },
        }),
        .will = .{
            .topic = "new/status",
            .payload = "new",
            .properties = &properties,
        },
    }, .zero);
    try std.testing.expectEqual(will.CloseResult.due_now, accepted.previous);
    try std.testing.expect(accepted.previous_due != null);
    try std.testing.expect(accepted.current != null);
    try std.testing.expectEqualStrings(
        "offline",
        (try scheduler.view(accepted.previous_due.?)).payload,
    );
    var due_storage: [1]will.Handle = undefined;
    const due = try scheduler.pollDue(.zero, &due_storage);
    try std.testing.expectEqual(accepted.previous_due.?, due[0]);
    try scheduler.releaseDue(due[0]);
    // Releasing the detached old Will must not remove the new ClientID index.
    try std.testing.expectEqual(
        will.CloseResult.canceled,
        scheduler.onReconnect("same", false, .zero),
    );
}

test "will claimed publication is not returned twice during reconnect" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const old = try scheduler.set("same", sampleWill(0, null), 60);
    _ = try scheduler.close(old, .ungraceful, .zero);
    var due_storage: [1]will.Handle = undefined;
    const due = try scheduler.pollDue(.zero, &due_storage);
    try std.testing.expectEqual(old, due[0]);

    var properties = [_]mqtt.Property{
        .{ .four_byte = .{
            .id = .will_delay_interval,
            .value = 5,
        } },
    };
    const accepted = try scheduler.acceptConnect(.{
        .protocol = .v5,
        .clean_start = false,
        .keep_alive_seconds = 30,
        .client_id = "same",
        .properties = @constCast(&[_]mqtt.Property{
            .{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 60,
            } },
        }),
        .will = .{
            .topic = "new/status",
            .payload = "new",
            .properties = &properties,
        },
    }, .zero);
    try std.testing.expectEqual(will.CloseResult.due_now, accepted.previous);
    try std.testing.expectEqual(@as(?will.Handle, null), accepted.previous_due);
    try std.testing.expect(accepted.current != null);
    try scheduler.releaseDue(old);
    // Releasing the detached, claimed publication must preserve the new index.
    try std.testing.expectEqual(
        will.CloseResult.canceled,
        scheduler.onReconnect("same", false, .zero),
    );
}

test "will acceptConnect rejection leaves prior lifecycle untouched" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const old = try scheduler.set("same", sampleWill(5, null), 60);
    try std.testing.expectError(
        error.InvalidTopic,
        scheduler.acceptConnect(.{
            .protocol = .v5,
            .clean_start = false,
            .keep_alive_seconds = 30,
            .client_id = "same",
            .will = .{
                .topic = "bad/+/topic",
                .payload = "new",
            },
        }, .zero),
    );
    try std.testing.expectEqualStrings(
        "offline",
        (try scheduler.view(old)).payload,
    );
    try std.testing.expectEqual(
        will.CloseResult.canceled,
        scheduler.onReconnect("same", false, .zero),
    );
}

test "will acceptConnect allocation failure leaves prior lifecycle untouched" {
    const backing = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(backing, .{});
    var scheduler = Scheduler.init(failing.allocator(), .{});
    defer scheduler.deinit();
    const old = try scheduler.set("same", sampleWill(5, null), 60);
    failing.fail_index = failing.alloc_index;

    try std.testing.expectError(
        error.OutOfMemory,
        scheduler.acceptConnect(.{
            .protocol = .v5,
            .clean_start = false,
            .keep_alive_seconds = 30,
            .client_id = "same",
            .will = .{
                .topic = "new/status",
                .payload = "new",
            },
        }, .zero),
    );
    try std.testing.expectEqualStrings(
        "offline",
        (try scheduler.view(old)).payload,
    );
    try std.testing.expectEqual(
        will.CloseResult.canceled,
        scheduler.onReconnect("same", false, .zero),
    );
}

test "will recycled slots reject stale generation handles" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{ .max_wills = 1 });
    defer scheduler.deinit();
    const old = try scheduler.set("old", sampleWill(1, null), 60);
    _ = try scheduler.close(old, .normal_disconnect, .zero);
    const current = try scheduler.set("current", sampleWill(1, null), 60);
    try std.testing.expectEqual(old.index, current.index);
    try std.testing.expect(old.generation != current.generation);
    try std.testing.expectError(error.WillNotFound, scheduler.view(old));
}

test "will limits and allocation failures leak nothing" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(allocator, .{
        .max_wills = 1,
        .max_will_bytes = 256,
        .max_total_bytes = 256,
    });
    defer scheduler.deinit();
    _ = try scheduler.set("one", sampleWill(1, null), 10);
    try std.testing.expectError(
        error.WillLimitExceeded,
        scheduler.set("two", sampleWill(1, null), 10),
    );

    try std.testing.checkAllAllocationFailures(
        allocator,
        testWillAllocationFailures,
        .{},
    );
}

fn testWillAllocationFailures(allocator: std.mem.Allocator) !void {
    var scheduler = Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    const handle = try scheduler.set(
        "allocated",
        sampleWill(2, 30),
        60,
    );
    _ = try scheduler.close(handle, .ungraceful, .zero);
}

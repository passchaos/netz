const std = @import("std");
const mqtt = @import("../mod.zig");
const will = @import("mod.zig");
const persistence = @import("../persistence/codec.zig");

test "will snapshot restores omitted delay as zero without inventing properties" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |live| {
        for ([_]?u32{ null, 0, 4 }) |delay| {
            for ([_]?u32{ null, 0, 42 }) |expiry| {
                var source = will.Scheduler.init(allocator, .{ .max_wills = 4 });
                defer source.deinit();
                var properties: std.ArrayList(mqtt.Property) = .empty;
                defer properties.deinit(allocator);
                if (delay) |value| try properties.append(allocator, .{ .four_byte = .{ .id = .will_delay_interval, .value = value } });
                if (expiry) |value| try properties.append(allocator, .{ .four_byte = .{ .id = .message_expiry_interval, .value = value } });
                const handle = try source.setWithSource("defaults", .{
                    .topic = "will/defaults",
                    .payload = "offline",
                    .qos = .at_least_once,
                    .retain = true,
                    .properties = properties.items,
                }, "writer", 7, 120);
                if (!live) _ = try source.close(handle, .ungraceful, .zero);
                var publishers: will.PublisherMap = .empty;
                defer publishers.deinit(allocator);
                try publishers.put(allocator, handle, 77);
                var encoded: std.ArrayList(u8) = .empty;
                defer encoded.deinit(allocator);
                if (live) {
                    try source.writeLiveSnapshot(&encoded, allocator, .zero, &publishers);
                } else {
                    try source.writeSnapshot(&encoded, allocator, .zero, &publishers);
                }

                var restored = will.Scheduler.init(allocator, .{ .max_wills = 4 });
                defer restored.deinit();
                var restored_publishers: will.PublisherMap = .empty;
                defer restored_publishers.deinit(allocator);
                var cursor = persistence.Cursor.init(encoded.items);
                const now = std.Io.Timestamp.fromNanoseconds(100 * std.time.ns_per_s);
                const remaining_ns = @max(@as(i96, delay orelse 0) * std.time.ns_per_s - 2 * std.time.ns_per_s, 0);
                try restored.restoreSnapshot(&cursor, now, 2 * std.time.ns_per_s, &restored_publishers);
                try std.testing.expect(cursor.eof());
                try std.testing.expectEqual(@as(usize, 1), restored.count());
                try std.testing.expectEqual(now.nanoseconds + remaining_ns, restored.nextDeadline().?.nanoseconds);
                const current = restored.handleForClient("defaults").?;
                const view = try restored.view(current);
                try std.testing.expectEqual(delay, mqtt.willDelayInterval(view.properties));
                try std.testing.expectEqual(expiry, view.message_expiry_interval);
                try std.testing.expectEqual(expiry, mqtt.messageExpiryInterval(view.properties));
                try std.testing.expectEqual(properties.items.len, view.properties.len);
                try std.testing.expectEqualStrings("writer", view.source_username.?);
                try std.testing.expectEqual(@as(?u64, 7), view.source_listener_id);
                try std.testing.expectEqual(@as(?u64, 77), restored_publishers.get(current).?);
                var due: [1]will.Handle = undefined;
                const ready = try restored.pollDue(.{ .nanoseconds = now.nanoseconds + remaining_ns }, &due);
                try std.testing.expectEqualSlices(will.Handle, &.{current}, ready);
                try std.testing.expectEqualStrings("offline", (try restored.view(current)).payload);
                try restored.releaseDue(current);
                try std.testing.expectEqual(@as(usize, 0), restored.count());
            }
        }
    }
}

test "will snapshot rejects inconsistent default and explicit metadata" {
    const allocator = std.testing.allocator;
    const Corruption = enum { absent_delay, explicit_delay, absent_expiry, zero_expiry, remaining_delay };
    for ([_]Corruption{ .absent_delay, .explicit_delay, .absent_expiry, .zero_expiry, .remaining_delay }) |corruption| {
        var source = will.Scheduler.init(allocator, .{ .max_wills = 4 });
        defer source.deinit();
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(allocator);
        if (corruption == .explicit_delay or corruption == .remaining_delay) {
            try properties.append(allocator, .{ .four_byte = .{ .id = .will_delay_interval, .value = 4 } });
        }
        if (corruption == .zero_expiry) {
            try properties.append(allocator, .{ .four_byte = .{ .id = .message_expiry_interval, .value = 0 } });
        }
        const handle = try source.set("corrupt", .{ .topic = "will/corrupt", .payload = "offline", .properties = properties.items }, 2);
        _ = try source.close(handle, .ungraceful, .zero);
        // Forge mismatches in the redundant checkpoint fields. Restoring a
        // default must not make inconsistent data or excessive delay valid.
        const entry = &source.entries.items[handle.index].?;
        switch (corruption) {
            .absent_delay => entry.will_delay_interval = 1,
            .explicit_delay => {
                entry.will_delay_interval = 0;
                entry.deadline_ns = 0;
            },
            .absent_expiry => entry.message_expiry_interval = 42,
            .zero_expiry => entry.message_expiry_interval = null,
            .remaining_delay => entry.deadline_ns = 3 * std.time.ns_per_s,
        }
        var publishers: will.PublisherMap = .empty;
        defer publishers.deinit(allocator);
        try publishers.put(allocator, handle, null);
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try source.writeSnapshot(&encoded, allocator, .zero, &publishers);
        var restored = will.Scheduler.init(allocator, .{ .max_wills = 4 });
        defer restored.deinit();
        var restored_publishers: will.PublisherMap = .empty;
        defer restored_publishers.deinit(allocator);
        var cursor = persistence.Cursor.init(encoded.items);
        try std.testing.expectError(error.CorruptSnapshot, restored.restoreSnapshot(&cursor, .zero, 0, &restored_publishers));
        try std.testing.expectEqual(@as(usize, 0), restored.count());
        try std.testing.expectEqual(@as(usize, 0), restored_publishers.count());
    }
}

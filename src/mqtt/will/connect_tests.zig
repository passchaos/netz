const std = @import("std");
const mqtt = @import("../mod.zig");
const will = @import("mod.zig");

const old_properties = [_]mqtt.Property{.{ .four_byte = .{
    .id = .will_delay_interval,
    .value = 5,
} }};

fn oldWill(properties: []mqtt.Property) mqtt.LastWill {
    return .{
        .topic = "old/status",
        .payload = "old",
        .properties = properties,
    };
}

test "will prepared CONNECT abort preserves deadline and accounting" {
    for ([_]bool{ false, true }) |clean_start| {
        try std.testing.checkAllAllocationFailures(std.testing.allocator, abortPreparedConnect, .{clean_start});
    }
}

fn abortPreparedConnect(allocator: std.mem.Allocator, clean_start: bool) !void {
    var scheduler = will.Scheduler.init(allocator, .{});
    defer scheduler.deinit();
    var old_props = old_properties;
    const old = try scheduler.set("same", oldWill(&old_props), 60);
    _ = try scheduler.close(old, .ungraceful, .zero);
    const bytes = scheduler.totalBytes();
    const deadline = scheduler.nextDeadline();
    var new_props = [_]mqtt.Property{.{ .utf8 = .{ .id = .content_type, .value = "text/plain" } }};
    {
        var prepared = scheduler.prepareConnectWithSource(.{
            .protocol = .v5,
            .clean_start = clean_start,
            .keep_alive_seconds = 30,
            .client_id = "same",
            .will = .{
                .topic = "new/status",
                .payload = "new",
                .properties = &new_props,
            },
        }, "new-user", 1883, 120, .{ .nanoseconds = std.time.ns_per_s }) catch |err| {
            try expectOldUnchanged(&scheduler, old, bytes, deadline);
            return err;
        };
        defer prepared.deinit();
        // The broker can reject Session admission after this successful resource
        // preparation. Dropping the token must leave the old lifecycle intact.
        try expectOldUnchanged(&scheduler, old, bytes, deadline);
    }
    try expectOldUnchanged(&scheduler, old, bytes, deadline);
}

fn expectOldUnchanged(
    scheduler: *will.Scheduler,
    old: will.Handle,
    bytes: usize,
    deadline: ?std.Io.Timestamp,
) !void {
    try std.testing.expectEqual(@as(usize, 1), scheduler.count());
    try std.testing.expectEqual(bytes, scheduler.totalBytes());
    try std.testing.expectEqual(deadline, scheduler.nextDeadline());
    try std.testing.expectEqual(@as(?will.Handle, old), scheduler.handleForClient("same"));
    try std.testing.expectEqualStrings("old", (try scheduler.view(old)).payload);
}

test "will prepared CONNECT commit owns inputs and never allocates" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |clean_start| {
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var scheduler = will.Scheduler.init(failing.allocator(), .{ .max_wills = 2 });
        defer scheduler.deinit();
        var old_props = old_properties;
        const old = try scheduler.set("same", oldWill(&old_props), 60);
        _ = try scheduler.close(old, .ungraceful, .zero);
        var topic = "new/status".*;
        var payload = "new".*;
        var username = "new-user".*;
        var content_type = "text/plain".*;
        var properties = [_]mqtt.Property{.{ .utf8 = .{ .id = .content_type, .value = &content_type } }};
        var prepared = try scheduler.prepareConnectWithSource(.{
            .protocol = .v5,
            .clean_start = clean_start,
            .keep_alive_seconds = 30,
            .client_id = "same",
            .will = .{ .topic = &topic, .payload = &payload, .properties = &properties },
        }, &username, 1883, 120, .{ .nanoseconds = std.time.ns_per_s });
        defer prepared.deinit();
        @memset(&topic, 'x');
        @memset(&payload, 'x');
        @memset(&username, 'x');
        @memset(&content_type, 'x');
        failing.fail_index = failing.alloc_index;
        const accepted = scheduler.commitConnect(&prepared);
        try std.testing.expect(!failing.has_induced_failure);
        const current = accepted.current.?;
        const view = try scheduler.view(current);
        try std.testing.expectEqualStrings("new/status", view.topic);
        try std.testing.expectEqualStrings("new", view.payload);
        try std.testing.expectEqualStrings("new-user", view.source_username.?);
        try std.testing.expectEqual(@as(?u64, 1883), view.source_listener_id);
        try std.testing.expectEqualStrings("text/plain", view.properties[0].utf8.value);
        if (clean_start) {
            try std.testing.expectEqual(will.CloseResult.due_now, accepted.previous);
            try std.testing.expectEqual(@as(?will.Handle, old), accepted.previous_due);
            try std.testing.expectEqual(@as(usize, 2), scheduler.count());
            var due: [2]will.Handle = undefined;
            const ready = try scheduler.pollDue(.{ .nanoseconds = std.time.ns_per_s }, &due);
            try std.testing.expectEqualSlices(will.Handle, &.{old}, ready);
            try scheduler.releaseDue(old);
        } else {
            try std.testing.expectEqual(will.CloseResult.canceled, accepted.previous);
            try std.testing.expect(accepted.previous_due == null);
            try std.testing.expectError(error.WillNotFound, scheduler.view(old));
        }
        try std.testing.expectEqual(@as(usize, 1), scheduler.count());
        try std.testing.expectEqual(@as(?will.Handle, current), scheduler.handleForClient("same"));
    }
}

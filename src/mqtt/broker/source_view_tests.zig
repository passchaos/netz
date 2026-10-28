const std = @import("std");
const mqtt = @import("../mod.zig");
const Publication = @import("publication.zig").Publication;
const Properties = @import("source_view.zig").Properties;
const allocator = std.testing.allocator;

test "MQTT adopted source properties retain scalar context and stable forwarding values" {
    var original = "application/octet-stream".*;
    var fields = [_]mqtt.Property{
        .{ .utf8 = .{ .id = .content_type, .value = &original } },
        .{ .two_byte = .{ .id = .topic_alias, .value = 7 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 29 } },
    };
    var view: Properties = .{};
    defer view.deinit(allocator);
    try view.capture(allocator, &fields);
    const owner = try Publication.createFromPublish(allocator, .{ .dup = false, .qos = .at_least_once, .retain = false, .topic = "source/topic", .packet_id = 1, .properties = &fields, .payload = "payload" }, 1, .zero);
    defer owner.release();
    // In-place adoption can overwrite every original nested slice.
    @memset(&original, 'X');
    view.bind(owner);
    try std.testing.expectEqualStrings("application/octet-stream", view.items()[0].utf8.value);
    try std.testing.expectEqual(owner.properties[0].utf8.value.ptr, view.items()[0].utf8.value.ptr);
    try std.testing.expectEqual(@as(u16, 7), view.items()[1].two_byte.value);
    try std.testing.expectEqual(@as(usize, 29), view.items()[2].varint.value);
}

test "MQTT adopted source descriptor overflow fails before mutation and is released" {
    var fields: [9]mqtt.Property = undefined;
    @memset(&fields, .{ .utf8_pair = .{ .id = .user_property, .key = "key", .value = "value" } });
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var view: Properties = .{};
    try std.testing.expectError(error.OutOfMemory, view.capture(failing.allocator(), &fields));
    try std.testing.expect(view.overflow == null);
    try std.testing.expectEqual(@as(usize, 0), view.len);
    failing.fail_index = std.math.maxInt(usize);
    try view.capture(failing.allocator(), &fields);
    try std.testing.expectEqual(@as(usize, 9), view.items().len);
    view.deinit(failing.allocator());
    try std.testing.expectEqual(failing.allocations, failing.deallocations);
}

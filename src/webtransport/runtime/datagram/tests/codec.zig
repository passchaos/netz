const std = @import("std");
const webtransport = @import("../../../mod.zig");
const codec = @import("../codec.zig");

test "WebTransport DATAGRAM codec uses stack then exact fallback" {
    const allocator = std.testing.allocator;
    var stack: [8]u8 = undefined;
    var small = try codec.encodeStackFirst(
        allocator,
        &stack,
        .init(0),
        "small",
    );
    defer small.deinit(allocator);
    try std.testing.expect(small.owned == null);
    const parsed_small = try webtransport.Datagram.parse(small.bytes);
    try std.testing.expectEqualStrings("small", parsed_small.payload);

    var large = try codec.encodeStackFirst(
        allocator,
        &stack,
        .init(4),
        "payload-larger-than-stack",
    );
    defer large.deinit(allocator);
    try std.testing.expect(large.owned != null);
    try std.testing.expectEqual(large.bytes.len, large.owned.?.len);
    const parsed_large = try webtransport.Datagram.parse(large.bytes);
    try std.testing.expectEqual(@as(u62, 4), parsed_large.session_id.value);
    try std.testing.expectEqualStrings(
        "payload-larger-than-stack",
        parsed_large.payload,
    );
}

test "WebTransport DATAGRAM codec validates before allocating" {
    var stack: [1]u8 = undefined;
    var fail = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.InvalidSessionId,
        codec.encodeStackFirst(
            fail.allocator(),
            &stack,
            .init(1),
            "large",
        ),
    );
    try std.testing.expect(!fail.has_induced_failure);
}

test "WebTransport DATAGRAM common encoding needs no allocation" {
    var stack: [codec.stack_capacity]u8 = undefined;
    var fail = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var encoded = try codec.encodeStackFirst(
        fail.allocator(),
        &stack,
        .init(0),
        "common datagram",
    );
    defer encoded.deinit(fail.allocator());
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expect(encoded.owned == null);
    const parsed = try webtransport.Datagram.parse(encoded.bytes);
    try std.testing.expectEqualStrings("common datagram", parsed.payload);
}

test "WebTransport DATAGRAM exact fallback propagates OOM" {
    var stack: [1]u8 = undefined;
    var fail = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        codec.encodeStackFirst(
            fail.allocator(),
            &stack,
            .init(0),
            "requires exact fallback",
        ),
    );
    try std.testing.expect(fail.has_induced_failure);
}

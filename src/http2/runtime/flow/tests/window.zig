const std = @import("std");
const flow = @import("../window.zig");

test "HTTP/2 flow window blocks sends and rejects receive overflow" {
    var window = flow.Window{ .value = 4 };
    try std.testing.expectEqual(@as(usize, 4), window.available());
    try window.reserve(4);
    try std.testing.expectEqual(@as(i64, 0), window.value);
    try std.testing.expectEqual(@as(usize, 0), window.available());
    try std.testing.expectError(error.FlowControlBlocked, window.reserve(1));
    try window.update(8);
    try window.reserve(3);
    try std.testing.expectEqual(@as(i64, 5), window.value);

    var receive = flow.Window{ .value = 2 };
    try std.testing.expectError(
        error.FlowControlViolation,
        receive.receive(3),
    );
    try receive.receive(2);
    try std.testing.expectEqual(@as(i64, 0), receive.value);
}

test "HTTP/2 zero-length DATA does not consume a negative window" {
    var window = flow.Window{ .value = -123 };
    try window.reserve(0);
    try window.receive(0);
    try std.testing.expectEqual(@as(i64, -123), window.value);
    try std.testing.expectEqual(@as(usize, 0), window.available());
    try std.testing.expectError(error.FlowControlBlocked, window.reserve(1));
    try std.testing.expectError(
        error.FlowControlViolation,
        window.receive(1),
    );
}

test "HTTP/2 flow window enforces signed protocol bounds transactionally" {
    var maximum = flow.Window{ .value = flow.max_value };
    try std.testing.expectError(
        error.FlowControlViolation,
        maximum.update(1),
    );
    try std.testing.expectEqual(flow.max_value, maximum.value);

    var minimum = flow.Window{ .value = flow.min_value };
    try std.testing.expectError(
        error.FlowControlViolation,
        minimum.adjust(-1),
    );
    try std.testing.expectEqual(flow.min_value, minimum.value);
    try minimum.adjust(1);
    try std.testing.expectEqual(flow.min_value + 1, minimum.value);
}

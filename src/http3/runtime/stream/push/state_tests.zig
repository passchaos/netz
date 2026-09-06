const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const PushSet = @import("state.zig").Set;

const net = std.Io.net;

test "HTTP/3 push stream set binds promise and streams response" {
    const allocator = std.testing.allocator;
    var pushes = PushSet.init(allocator, 4, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(3);
    try pushes.registerPromise(3, 0);

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "asset",
    }).write(&response, allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try quic.varint.encode(
        &bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&bytes, allocator, 3);
    try bytes.appendSlice(allocator, response.items);

    var control = http3.ControlState{ .local_max_push_id = 3 };
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    try std.testing.expect(try pushes.insert(from, .{
        .stream_id = 15,
        .data = bytes.items,
        .fin = true,
    }, control));
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var head = (try pushes.next(table, 0, null)).?;
    defer head.event.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), head.event.push_id);
    try std.testing.expectEqual(
        @as(u62, 0),
        head.event.request_stream_id,
    );
    try std.testing.expectEqual(@as(u62, 15), head.event.stream_id);
    try std.testing.expect(head.event.value == .head);
    try std.testing.expectEqual(
        @as(u16, 200),
        head.event.value.head.response.status,
    );
    try std.testing.expect((try pushes.next(table, 0, null)).?.event.value ==
        .data_available);
    var body: [8]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 5),
        try pushes.readData(3, &body),
    );
    try std.testing.expectEqualStrings("asset", body[0..5]);

    // Targeted polling uses the push-id index and should not scan unrelated
    // retained push streams first.
    try pushes.registerPromise(1, 0);
    var other_bytes: std.ArrayList(u8) = .empty;
    defer other_bytes.deinit(allocator);
    try quic.varint.encode(
        &other_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&other_bytes, allocator, 1);
    try other_bytes.appendSlice(allocator, response.items);
    try std.testing.expect(try pushes.insert(from, .{
        .stream_id = 19,
        .data = other_bytes.items,
        .fin = true,
    }, control));
    const targeted = (try pushes.next(table, 0, 3)).?;
    try std.testing.expect(targeted.event.value == .finished);
    var targeted_event = targeted.event;
    targeted_event.deinit(allocator);
    pushes.removeFinished(targeted.index);
    try std.testing.expect(pushes.findByPushId(3) == null);

    const finished = (try pushes.next(table, 0, null)).?;
    try std.testing.expect(finished.event.value == .head);
    var finished_event = finished.event;
    finished_event.deinit(allocator);

    // The same push may be promised on more than one request stream.
    try pushes.registerPromise(3, 4);
    _ = &control;
}

test "HTTP/3 push stream set retains response until promise arrives" {
    const allocator = std.testing.allocator;
    var pushes = PushSet.init(allocator, 4, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(3);
    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (http3.Response{ .status = 204 }).write(&response, allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try quic.varint.encode(
        &bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&bytes, allocator, 1);
    try bytes.appendSlice(allocator, response.items);
    const control = http3.ControlState{ .local_max_push_id = 3 };
    try std.testing.expect(try pushes.insert(
        .{ .ip4 = .loopback(443) },
        .{
            .stream_id = 15,
            .data = bytes.items,
            .fin = true,
        },
        control,
    ));
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try std.testing.expect((try pushes.next(table, 0, null)) == null);
    try pushes.registerPromise(1, 0);
    const event = (try pushes.next(table, 0, null)).?;
    try std.testing.expect(event.event.value == .head);
    var owned_event = event.event;
    owned_event.deinit(allocator);
}

test "HTTP/3 push polling rotates across busy streams" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    const control = http3.ControlState{ .local_max_push_id = 2 };

    var pushes = PushSet.init(allocator, 3, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(2);
    try pushes.registerPromise(0, 0);
    try pushes.registerPromise(1, 0);

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "busy",
    }).write(&response, allocator);
    for ([_]struct { push_id: u64, stream_id: u62 }{
        .{ .push_id = 0, .stream_id = 15 },
        .{ .push_id = 1, .stream_id = 19 },
    }) |item| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try quic.varint.encode(
            &bytes,
            allocator,
            @intFromEnum(http3.StreamType.push),
        );
        try quic.varint.encode(&bytes, allocator, item.push_id);
        try bytes.appendSlice(allocator, response.items);
        try std.testing.expect(try pushes.insert(from, .{
            .stream_id = item.stream_id,
            .data = bytes.items,
            .fin = true,
        }, control));
    }

    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var first = (try pushes.next(table, 0, null)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 15), first.event.stream_id);
    try std.testing.expect(first.event.value == .head);
    first.event.deinit(allocator);

    // Push zero can already emit DATA. Untargeted polling must nevertheless
    // give push one its first event before returning to the busy first stream.
    var second = (try pushes.next(table, 0, null)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 19), second.event.stream_id);
    try std.testing.expect(second.event.value == .head);
    second.event.deinit(allocator);

    const third = (try pushes.next(table, 0, null)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 15), third.event.stream_id);
    try std.testing.expect(third.event.value == .data_available);
    const fourth = (try pushes.next(table, 0, null)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 19), fourth.event.stream_id);
    try std.testing.expect(fourth.event.value == .data_available);
}

test "HTTP/3 push polling skips unpromised and stale cursor streams" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    const control = http3.ControlState{ .local_max_push_id = 2 };

    var pushes = PushSet.init(allocator, 3, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(2);
    try pushes.registerPromise(0, 0);
    try pushes.registerPromise(2, 0);

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "busy",
    }).write(&response, allocator);
    // Push one intentionally lacks a promise and must remain buffered without
    // preventing either promised sibling from making progress.
    for ([_]struct { push_id: u64, stream_id: u62 }{
        .{ .push_id = 0, .stream_id = 15 },
        .{ .push_id = 1, .stream_id = 19 },
        .{ .push_id = 2, .stream_id = 23 },
    }) |item| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try quic.varint.encode(
            &bytes,
            allocator,
            @intFromEnum(http3.StreamType.push),
        );
        try quic.varint.encode(&bytes, allocator, item.push_id);
        try bytes.appendSlice(allocator, response.items);
        try std.testing.expect(try pushes.insert(from, .{
            .stream_id = item.stream_id,
            .data = bytes.items,
            .fin = true,
        }, control));
    }

    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var first = (try pushes.next(table, 0, null)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 15), first.event.stream_id);
    first.event.deinit(allocator);
    // A targeted read advances only that push reader. It must not perturb the
    // cursor shared by the public whichever-push-is-ready API.
    var targeted = (try pushes.next(table, 0, 2)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 23), targeted.event.stream_id);
    try std.testing.expect(targeted.event.value == .head);
    targeted.event.deinit(allocator);
    const after_targeted = (try pushes.next(table, 0, null)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 23), after_targeted.event.stream_id);
    try std.testing.expect(after_targeted.event.value == .data_available);

    // Return to push zero, then remove it. Push two moves during swapRemove
    // while the stable cursor becomes stale; the next scan still finds it.
    const wrapped = (try pushes.next(table, 0, null)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 15), wrapped.event.stream_id);
    try std.testing.expect(wrapped.event.value == .data_available);
    pushes.removeByStreamId(15);
    const after_removal = (try pushes.next(table, 0, null)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 23), after_removal.event.stream_id);
    try std.testing.expect(after_removal.event.value == .data_available);
}

test "HTTP/3 push cancellation queue reuses consumed FIFO slots" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    const control = http3.ControlState{ .local_max_push_id = 4 };
    var pushes = PushSet.init(allocator, 4, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(4);

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (http3.Response{ .status = 204 }).write(&response, allocator);

    for ([_]struct { push_id: u64, stream_id: u62 }{
        .{ .push_id = 1, .stream_id = 15 },
        .{ .push_id = 2, .stream_id = 19 },
        .{ .push_id = 3, .stream_id = 23 },
    }) |item| {
        try pushes.registerPromise(item.push_id, 0);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try quic.varint.encode(
            &bytes,
            allocator,
            @intFromEnum(http3.StreamType.push),
        );
        try quic.varint.encode(&bytes, allocator, item.push_id);
        try bytes.appendSlice(allocator, response.items);
        try std.testing.expect(try pushes.insert(from, .{
            .stream_id = item.stream_id,
            .data = bytes.items,
            .fin = true,
        }, control));
        try pushes.observePeerCancellation(item.push_id);
    }
    try std.testing.expectEqual(@as(usize, 3), pushes.cancelledStreamCount());
    try std.testing.expectEqual(
        @as(u62, 15),
        pushes.takeCancelledStream() orelse return error.TestUnexpectedResult,
    );

    try pushes.registerPromise(4, 0);
    var final_bytes: std.ArrayList(u8) = .empty;
    defer final_bytes.deinit(allocator);
    try quic.varint.encode(
        &final_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&final_bytes, allocator, 4);
    try final_bytes.appendSlice(allocator, response.items);
    try std.testing.expect(try pushes.insert(from, .{
        .stream_id = 27,
        .data = final_bytes.items,
        .fin = true,
    }, control));
    try pushes.observePeerCancellation(4);

    for ([_]u62{ 19, 23, 27 }) |stream_id| {
        try std.testing.expectEqual(
            stream_id,
            pushes.takeCancelledStream() orelse
                return error.TestUnexpectedResult,
        );
    }
    try std.testing.expect(pushes.takeCancelledStream() == null);
    try std.testing.expectEqual(@as(usize, 0), pushes.cancelledStreamCount());
    try std.testing.expectEqual(@as(usize, 0), pushes.entryCount());
    try std.testing.expectEqual(@as(usize, 0), pushes.promiseCount());
    try std.testing.expectEqual(@as(usize, 1), pushes.completedPromiseRangeCount());
    for ([_]u64{ 1, 2, 3, 4 }) |push_id| {
        try std.testing.expect(pushes.hasPromise(push_id));
    }

    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try std.testing.expect((try pushes.next(table, 0, 4)) == null);
}

test "HTTP/3 completed push history preserves sparse IDs compactly" {
    const allocator = std.testing.allocator;
    var pushes = PushSet.init(allocator, 8, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(7);

    for ([_]u64{ 7, 1, 5, 3 }) |push_id| {
        try pushes.registerPromise(push_id, 0);
        try pushes.observePeerCancellation(push_id);
    }
    try std.testing.expectEqual(@as(usize, 0), pushes.promiseCount());
    try std.testing.expectEqual(@as(usize, 4), pushes.completedPromiseRangeCount());
    for ([_]u64{ 1, 3, 5, 7 }) |push_id| {
        try std.testing.expect(pushes.hasPromise(push_id));
        // A duplicate promise after completion is idempotently ignored.
        try pushes.registerPromise(push_id, 4);
    }
    for ([_]u64{ 0, 2, 4, 6 }) |push_id| {
        try std.testing.expect(!pushes.hasPromise(push_id));
    }
    try std.testing.expectEqual(@as(usize, 0), pushes.promiseCount());
}

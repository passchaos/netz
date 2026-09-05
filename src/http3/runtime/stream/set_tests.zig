const std = @import("std");
const http3 = @import("../../mod.zig");
const Set = @import("set.zig").Set;
const RequestStreamSet = @import("buffered/request.zig").Set;
const ResponseStreamSet = @import("buffered/response.zig").Set;

const net = std.Io.net;

test "HTTP/3 streaming request reset queue reuses consumed FIFO slots" {
    const allocator = std.testing.allocator;
    var requests = Set.init(allocator, 3, 512, .{}, .request);
    defer requests.deinit();

    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    for ([_]u62{ 0, 4, 8 }) |stream_id| {
        try std.testing.expect(try requests.prepareReset(
            from,
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
            0,
            false,
        ));
        requests.recordResetAssumeCapacity(
            from,
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        );
    }
    try std.testing.expectEqual(@as(usize, 3), requests.resetCount());
    try std.testing.expectEqual(@as(?u62, 0), requests.lowestResetStream());
    try std.testing.expect(requests.contains(4));

    const first = requests.takeFirstReset() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), first.stream_id);
    try std.testing.expectEqual(@as(usize, 2), requests.resetCount());
    try std.testing.expectEqual(@as(?u62, 4), requests.lowestResetStream());
    try std.testing.expect(!requests.contains(0));

    // The queue has consumed a head element. Adding a replacement must reuse
    // that FIFO space rather than reporting max-stream exhaustion.
    try std.testing.expect(try requests.prepareReset(
        from,
        12,
        http3.ApplicationErrorCode.request_cancelled,
        0,
        false,
    ));
    requests.recordResetAssumeCapacity(
        from,
        12,
        http3.ApplicationErrorCode.request_cancelled,
    );
    try std.testing.expectEqual(@as(usize, 3), requests.resetCount());
    try std.testing.expect(requests.contains(12));

    requests.remove(8);
    try std.testing.expect(!requests.contains(8));
    try std.testing.expectEqual(@as(usize, 2), requests.resetCount());
    try std.testing.expectEqual(@as(?u62, 4), requests.lowestResetStream());

    for ([_]u62{ 4, 12 }) |stream_id| {
        const reset = requests.takeFirstReset() orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(stream_id, reset.stream_id);
    }
    try std.testing.expect(requests.takeFirstReset() == null);
    try std.testing.expectEqual(@as(usize, 0), requests.resetCount());
}

test "HTTP/3 targeted request reset preserves unrelated FIFO entries" {
    const allocator = std.testing.allocator;
    var requests = Set.init(allocator, 3, 512, .{}, .request);
    defer requests.deinit();

    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    for ([_]u62{ 0, 4, 8 }) |stream_id| {
        try std.testing.expect(try requests.prepareReset(
            from,
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
            0,
            false,
        ));
        requests.recordResetAssumeCapacity(
            from,
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        );
    }

    const targeted = requests.takeReset(4) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 4), targeted.stream_id);
    try std.testing.expect(!requests.contains(4));
    try std.testing.expect(requests.contains(0));
    try std.testing.expect(requests.contains(8));

    const first = requests.takeFirstReset() orelse
        return error.TestUnexpectedResult;
    const second = requests.takeFirstReset() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), first.stream_id);
    try std.testing.expectEqual(@as(u62, 8), second.stream_id);
}

test "HTTP/3 streaming request reset preparation is idempotent" {
    const allocator = std.testing.allocator;
    var requests = Set.init(allocator, 1, 512, .{}, .request);
    defer requests.deinit();

    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    const code = http3.ApplicationErrorCode.request_cancelled;
    try std.testing.expect(try requests.prepareReset(
        from,
        0,
        code,
        0,
        false,
    ));
    requests.recordPreparedNewResetAssumeCapacity(from, 0, code);

    try std.testing.expect(!try requests.prepareReset(
        from,
        0,
        code,
        0,
        true,
    ));
    try std.testing.expectEqual(@as(usize, 1), requests.resetCount());
    try std.testing.expectError(
        error.UnexpectedStream,
        requests.prepareReset(from, 0, code + 1, 0, true),
    );
    try std.testing.expectError(
        error.UnexpectedStream,
        requests.prepareReset(
            .{ .ip4 = .loopback(444) },
            0,
            code,
            0,
            true,
        ),
    );
}

test "HTTP/3 streaming message set indexes active readers" {
    const allocator = std.testing.allocator;
    var responses = Set.init(allocator, 3, 512, .{}, .response);
    defer responses.deinit();
    var buffered = ResponseStreamSet.init(allocator, 512, 3);
    defer buffered.deinit();

    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    inline for (.{ @as(u62, 0), @as(u62, 4), @as(u62, 8) }) |stream_id| {
        try buffered.insert(from, .{ .stream_id = stream_id, .data = "x" });
        _ = try responses.activateResponse(&buffered, stream_id);
    }
    try std.testing.expectEqual(@as(usize, 3), responses.entryCount());
    try std.testing.expect(responses.find(4) != null);
    try std.testing.expectEqual(@as(?u62, 0), responses.lowestEntryStream());

    responses.removeEntry(4);
    try std.testing.expect(responses.find(4) == null);
    try std.testing.expect(responses.find(8) != null);
    try std.testing.expectEqual(@as(?u62, 0), responses.lowestEntryStream());

    var owned = responses.takeEntry(8) orelse
        return error.TestUnexpectedResult;
    defer owned.deinit();
    try std.testing.expect(responses.find(8) == null);
    try std.testing.expectEqual(@as(usize, 1), responses.entryCount());
    responses.removeEntry(0);
    try std.testing.expectEqual(@as(usize, 0), responses.entryCount());
    try std.testing.expectEqual(@as(?u62, null), responses.lowestEntryStream());
    try std.testing.expect(!responses.contains(0));
    responses.remove(0);
    try std.testing.expect(responses.takeEntry(0) == null);
}

test "HTTP/3 streaming request polling rotates between busy streams" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };

    var requests = Set.init(allocator, 2, 512, .{}, .request);
    defer requests.deinit();
    var buffered = RequestStreamSet.init(allocator, 512, 2);
    defer buffered.deinit();
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/fair",
        .authority = "example.test",
        .body = "busy",
    }).write(&encoded, allocator);
    for ([_]u62{ 0, 4 }) |stream_id| {
        try buffered.insert(from, .{
            .stream_id = stream_id,
            .data = encoded.items,
            .fin = true,
        });
    }

    var first = (try requests.nextRequest(&buffered, table, 0)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), first.entry.reader.streamId());
    try std.testing.expect(first.event == .head);
    first.event.deinit(allocator);

    var second = (try requests.nextRequest(&buffered, table, 0)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 4), second.entry.reader.streamId());
    try std.testing.expect(second.event == .head);
    second.event.deinit(allocator);

    const third = (try requests.nextRequest(&buffered, table, 0)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), third.entry.reader.streamId());
    try std.testing.expect(third.event == .data_available);
    const fourth = (try requests.nextRequest(&buffered, table, 0)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 4), fourth.entry.reader.streamId());
    try std.testing.expect(fourth.event == .data_available);
}

test "HTTP/3 streaming response polling skips idle and stale cursors" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };

    var responses = Set.init(allocator, 3, 512, .{}, .response);
    defer responses.deinit();
    var buffered = ResponseStreamSet.init(allocator, 512, 3);
    defer buffered.deinit();
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();

    _ = try responses.activateResponse(&buffered, 4);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Response{ .status = 200, .body = "busy" })
        .write(&encoded, allocator);
    for ([_]u62{ 0, 8 }) |stream_id| {
        try buffered.insert(from, .{
            .stream_id = stream_id,
            .data = encoded.items,
            .fin = true,
        });
    }

    var first = (try responses.nextResponse(&buffered, table, 0)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), first.entry.reader.streamId());
    try std.testing.expect(first.event == .head);
    first.event.deinit(allocator);

    var second = (try responses.nextResponse(&buffered, table, 0)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 8), second.entry.reader.streamId());
    try std.testing.expect(second.event == .head);
    second.event.deinit(allocator);

    const wrapped = (try responses.nextResponse(&buffered, table, 0)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), wrapped.entry.reader.streamId());
    try std.testing.expect(wrapped.event == .data_available);
    responses.removeEntry(0);

    const after_removal = (try responses.nextResponse(
        &buffered,
        table,
        0,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u62, 8),
        after_removal.entry.reader.streamId(),
    );
    try std.testing.expect(after_removal.event == .data_available);
}

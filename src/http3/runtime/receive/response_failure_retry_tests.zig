const std = @import("std");
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const support = @import("test_support/response_pair.zig");
const Pair = support.Pair;

const FailedSend = struct {
    delegate: std.Io,
    connection: *quic.one_rtt.Connection,
    fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (self.connection.recvStreamStats(0).?.stop_sending_sent == null) return .{ error.SystemResources, 0 };
        return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
    }
};

fn injectMissingStatus(pair: *Pair) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try support.missingStatus(&bytes);
    try pair.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items } }});
}

fn socketFailureScenario(targeted: bool, owning: bool, transfer: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try injectMissingStatus(&pair);
    const original = pair.client.established.connection.endpoint.io;
    {
        var failed = FailedSend{ .delegate = original, .connection = &pair.client.established.connection };
        pair.client.established.connection.endpoint.io = forwarded_io.observer(&failed, .{ .netSend = FailedSend.send });
        defer pair.client.established.connection.endpoint.io = original;
        if (targeted) {
            if (owning) try std.testing.expectError(error.SystemResources, pair.client.pollResponseEvent(0)) else try std.testing.expectError(error.SystemResources, pair.client.pollResponseEventOnce(0));
        } else {
            try std.testing.expectError(error.SystemResources, pair.client.pollNextResponseEventOnce());
        }
        try std.testing.expect(pair.client.request_lifecycle.contains(0));
        try std.testing.expectEqual(@as(usize, 1), pair.client.pending_response_failures.count());
        if (transfer) {
            var result = (try pair.client.pollNextResponseEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
            defer result.deinit(std.testing.allocator);
            try std.testing.expect(result == .failure and result.failure.err == error.MissingStatus);
            try std.testing.expectEqual(@as(u62, 0), result.failure.stream_id);
            try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
        }
    }
    try std.testing.expect(!pair.client.established.connection.closing());
    if (transfer) {
        try pair.client.tryCancelRequest(0, http3.ApplicationErrorCode.message_error);
    } else {
        try std.testing.expectError(error.MissingStatus, pair.client.pollResponseEventOnce(0));
    }
    try std.testing.expect(!pair.client.request_lifecycle.contains(0));
    try std.testing.expect(pair.client.request_lifecycle.contains(4));
    try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, pair.client.established.connection.recvStreamStats(0).?.stop_sending_sent.?.application_error_code);
}

test "HTTP/3 failed-response targeted polling preserves socket errors and request ownership" {
    try socketFailureScenario(true, false, false);
}

test "HTTP/3 failed-response owning polling keeps the connection reusable after socket failure" {
    try socketFailureScenario(true, true, false);
}

test "HTTP/3 failed-response multiplexed polling retries the original cause" {
    try socketFailureScenario(false, false, false);
}

test "HTTP/3 failed-response polling transfers retained cancellation ownership" {
    try socketFailureScenario(true, false, true);
}

test "HTTP/3 failed-response polling keeps a healthy response readable while cancellation is paced" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(std.testing.allocator);
    var valid: std.ArrayList(u8) = .empty;
    defer valid.deinit(std.testing.allocator);
    try support.missingStatus(&invalid);
    try (http3.Response{ .status = 204, .request_method = "GET" }).write(&valid, std.testing.allocator);
    try pair.send(&.{ .{ .stream = .{ .stream_id = 0, .data = invalid.items } }, .{ .stream = .{ .stream_id = 4, .data = valid.items, .fin = true } } });
    const connection = &pair.client.established.connection;
    _ = try connection.tryFlushPendingAck();
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingStatus, pair.client.pollNextResponseEventOnce());
    var event = (try pair.client.pollNextResponseEventOnce()) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .message and event.message.stream_id == 4 and event.message.value == .head);
    try std.testing.expectEqual(@as(u16, 204), event.message.value.head.response.status);
    try std.testing.expect(pair.client.request_lifecycle.contains(0));
    connection.pacer.enabled = false;
    try std.testing.expectError(error.MissingStatus, pair.client.pollNextResponseEventOnce());
    try std.testing.expect(!pair.client.request_lifecycle.contains(0));
}

test "HTTP/3 failed-response explicit polling transfers a fresh parser failure before cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try injectMissingStatus(&pair);
    var result = (try pair.client.pollNextResponseEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .failure and result.failure.err == error.MissingStatus);
    try std.testing.expect(pair.client.established.connection.sendStreamStats(0).?.reset == null);
    try std.testing.expect(pair.client.request_lifecycle.contains(0));
    try pair.client.tryCancelRequest(result.failure.stream_id, result.failure.application_error_code);
    try std.testing.expect(!pair.client.request_lifecycle.contains(0));
}

test "HTTP/3 failed-response default polling reserves ownership before decoding" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ true, false }) |targeted| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try injectMissingStatus(&pair);
        _ = try pair.client.established.connection.tryFlushPendingAck();
        const original = pair.client.allocator;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        {
            pair.client.allocator = failing.allocator();
            defer pair.client.allocator = original;
            if (targeted) {
                try std.testing.expectError(error.OutOfMemory, pair.client.pollResponseEventOnce(0));
            } else {
                try std.testing.expectError(error.OutOfMemory, pair.client.pollNextResponseEventOnce());
            }
        }
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
        try std.testing.expect(pair.client.request_lifecycle.contains(0));
        try std.testing.expect(!pair.client.established.connection.closing());
        try std.testing.expect(pair.client.established.connection.recvStreamStats(0).?.stop_sending_sent == null);
        try std.testing.expectError(error.MissingStatus, pair.client.pollResponseEventOnce(0));
    }
}

test "HTTP/3 failed-response polling leaves allocation failures retryable with their original bytes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]enum { targeted, multiplexed, explicit }{ .targeted, .multiplexed, .explicit }) |mode| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try injectMissingStatus(&pair);
        const entry = try pair.client.streaming_responses.activateResponse(&pair.client.response_streams, 0);
        const original = entry.reader.allocator;
        const read_offset = entry.reader.receive.read_offset;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        {
            entry.reader.allocator = failing.allocator();
            defer entry.reader.allocator = original;
            switch (mode) {
                .targeted => try std.testing.expectError(error.OutOfMemory, pair.client.pollResponseEventOnce(0)),
                .multiplexed => try std.testing.expectError(error.OutOfMemory, pair.client.pollNextResponseEventOnce()),
                .explicit => try std.testing.expectError(error.OutOfMemory, pair.client.pollNextResponseEventOnceWithFailure()),
            }
        }
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(read_offset, entry.reader.receive.read_offset);
        try std.testing.expect(!entry.message_failure_pending);
        try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
        try std.testing.expect(pair.client.request_lifecycle.contains(0));
        try std.testing.expect(!pair.client.established.connection.closing());
        var result = (try pair.client.pollNextResponseEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result == .failure and result.failure.err == error.MissingStatus);
        try pair.client.tryCancelRequest(result.failure.stream_id, result.failure.application_error_code);
    }
}

test "HTTP/3 failed-response polling keeps malformed QPACK at connection scope" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]enum { targeted, multiplexed, explicit }{ .targeted, .multiplexed, .explicit }) |mode| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try (http3.Frame{
            .frame_type = http3.FrameType.headers,
            // Valid prefix followed by an out-of-range static table index.
            .payload = &.{ 0x00, 0x00, 0xff, 0x7f },
            .consumed = 0,
        }).write(&bytes, std.testing.allocator);
        try pair.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items, .fin = true } }});
        switch (mode) {
            .targeted => try std.testing.expectError(error.QpackDecompressionFailed, pair.client.pollResponseEventOnce(0)),
            .multiplexed => try std.testing.expectError(error.QpackDecompressionFailed, pair.client.pollNextResponseEventOnce()),
            .explicit => try std.testing.expectError(error.QpackDecompressionFailed, pair.client.pollNextResponseEventOnceWithFailure()),
        }
        try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
        const close = quic.one_rtt.testing.localCloseInfo(&pair.client.established.connection) orelse return error.TestUnexpectedResult;
        try std.testing.expect(close.application);
        try std.testing.expectEqual(http3.ApplicationErrorCode.qpack_decompression_failed, close.error_code);
    }
}

test "HTTP/3 failed-response owning receives retain cancellation across their deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ true, false }) |targeted| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try injectMissingStatus(&pair);
        const connection = &pair.client.established.connection;
        _ = try connection.tryFlushPendingAck();
        connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
        connection.pacer.budget = 0;
        connection.pacer.setLastSentTimeNs(0);
        try std.testing.expectError(error.MissingStatus, pair.client.pollResponseEvent(0));
        if (targeted) {
            try std.testing.expectError(error.Timeout, pair.client.receiveResponseEventWithTimeout(0, .fromMilliseconds(5)));
        } else {
            try std.testing.expectError(error.Timeout, pair.client.receiveNextResponseEventWithTimeout(.fromMilliseconds(5)));
        }
        try std.testing.expectEqual(@as(usize, 1), pair.client.pending_response_failures.count());
        try std.testing.expect(pair.client.request_lifecycle.contains(0));
        try std.testing.expect(connection.recvStreamStats(0).?.stop_sending_sent == null);
        connection.pacer.enabled = false;
        try std.testing.expectError(error.MissingStatus, pair.client.pollResponseEvent(0));
        try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
        try std.testing.expect(!pair.client.request_lifecycle.contains(0));
    }
}

test "HTTP/3 failed-response targeted polling preserves independent parser causes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(std.testing.allocator);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(std.testing.allocator);
    try support.missingStatus(&first);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = &.{ 0x00, 0x00, 0x5f, 0x09, 0x03, 'b', 'a', 'd' },
        .consumed = 0,
    }).write(&second, std.testing.allocator);
    try pair.send(&.{ .{ .stream = .{ .stream_id = 0, .data = first.items } }, .{ .stream = .{ .stream_id = 4, .data = second.items } } });
    const connection = &pair.client.established.connection;
    _ = try connection.tryFlushPendingAck();
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingStatus, pair.client.pollResponseEventOnce(0));
    try std.testing.expectError(error.InvalidStatus, pair.client.pollResponseEventOnce(4));
    try std.testing.expectEqual(@as(usize, 2), pair.client.pending_response_failures.count());
    connection.pacer.enabled = false;
    try std.testing.expectError(error.InvalidStatus, pair.client.pollResponseEventOnce(4));
    try std.testing.expectEqual(@as(usize, 1), pair.client.pending_response_failures.count());
    try std.testing.expect(pair.client.request_lifecycle.contains(0));
    try std.testing.expectError(error.MissingStatus, pair.client.pollNextResponseEventOnce());
    try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
}

test "HTTP/3 failed-response caller cancellation retires retained ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ true, false }) |single_attempt| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try injectMissingStatus(&pair);
        const connection = &pair.client.established.connection;
        _ = try connection.tryFlushPendingAck();
        connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
        connection.pacer.budget = 0;
        connection.pacer.setLastSentTimeNs(0);
        try std.testing.expectError(error.MissingStatus, pair.client.pollResponseEventOnce(0));
        connection.pacer.enabled = false;
        if (single_attempt) {
            try pair.client.tryCancelRequest(0, http3.ApplicationErrorCode.request_cancelled);
        } else {
            try pair.client.cancelRequest(0, http3.ApplicationErrorCode.request_cancelled);
        }
        try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
        try std.testing.expect((try pair.client.pollNextResponseEventOnceWithFailure()) == null);
        try std.testing.expect(pair.client.request_lifecycle.contains(4));
    }
}

test "HTTP/3 failed-response connection termination retires retained cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try injectMissingStatus(&pair);
    const connection = &pair.client.established.connection;
    _ = try connection.tryFlushPendingAck();
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingStatus, pair.client.pollResponseEventOnce(0));
    connection.failClosedApplication(http3.ApplicationErrorCode.internal_error, "test-close");
    try std.testing.expectError(error.ConnectionClosed, pair.client.pollNextResponseEventOnceWithFailure());
    try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
}

test "HTTP/3 failed-response explicit polling returns owned healthy events" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try (http3.Response{ .status = 204, .request_method = "GET" }).write(&bytes, std.testing.allocator);
    try pair.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items, .fin = true } }});
    var result = (try pair.client.pollNextResponseEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .event and result.event == .message and result.event.message.value == .head);
    try std.testing.expectEqual(@as(u16, 204), result.event.message.value.head.response.status);
}

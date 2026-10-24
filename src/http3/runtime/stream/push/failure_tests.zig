const std = @import("std");
const http3 = @import("../../../mod.zig");
const Pair = @import("test_support/failure_pair.zig").Pair;

const FailedSend = struct {
    fn send(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []std.Io.net.OutgoingMessage, _: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        return .{ error.SystemResources, 0 };
    }
};

test "HTTP/3 failed push polls retain stream cancellation after a socket error" {
    inline for (.{ false, true }) |once| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.malformed(false);
        const connection = &pair.inner.client.established.connection;
        const original = connection.endpoint.io;
        {
            var vtable = original.vtable.*;
            vtable.netSend = FailedSend.send;
            connection.endpoint.io = .{ .userdata = original.userdata, .vtable = &vtable };
            defer connection.endpoint.io = original;
            if (once) try std.testing.expectError(error.SystemResources, pair.inner.client.pollPushEventOnce()) else try std.testing.expectError(error.SystemResources, pair.inner.client.pollPushEvent());
            try std.testing.expect(pair.inner.client.push_streams.containsStream(15));
            try std.testing.expectEqual(@as(usize, 2), pair.inner.client.push_streams.promiseCount());
        }
        try std.testing.expectError(error.MissingStatus, pair.inner.client.pollPushEventOnce());
        try std.testing.expect(!pair.inner.client.push_streams.containsStream(15));
        try std.testing.expect(connection.recvStreamStats(15).?.stop_sending_sent.?.application_error_code == http3.ApplicationErrorCode.message_error);
        try std.testing.expect(pair.inner.client.request_lifecycle.contains(0));
        try std.testing.expect(pair.inner.client.request_lifecycle.contains(4));
        try std.testing.expect(!connection.closing());
    }
}

test "HTTP/3 failed push reports the cause while cancellation is paced and selects a healthy sibling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try pair.malformed(true);
    const connection = &pair.inner.client.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingStatus, pair.inner.client.pollPushEventOnce());
    var event = (try pair.inner.client.pollPushEventOnce()) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event.push_id == 5 and event.stream_id == 19 and event.value == .head);
    connection.pacer.enabled = false;
    try std.testing.expectError(error.MissingStatus, pair.inner.client.pollPushEventOnce());
}

test "HTTP/3 failed push explicit results transfer fresh and retained rejection ownership" {
    inline for (.{ false, true }) |retained| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.malformed(true);
        const client = &pair.inner.client;
        const connection = &client.established.connection;
        if (retained) {
            const original = connection.endpoint.io;
            var vtable = original.vtable.*;
            vtable.netSend = FailedSend.send;
            connection.endpoint.io = .{ .userdata = original.userdata, .vtable = &vtable };
            defer connection.endpoint.io = original;
            try std.testing.expectError(error.SystemResources, client.pollPushEventOnce());
        }
        var result = (try client.pollPushEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result == .failure and result.failure.err == error.MissingStatus);
        try std.testing.expectEqual(@as(u64, 3), result.failure.push_id);
        try std.testing.expectEqual(@as(u62, 0), result.failure.request_stream_id);
        try std.testing.expectEqual(@as(u62, 15), result.failure.stream_id);
        try std.testing.expectEqual(@as(usize, 0), client.pending_push_failures.count());
        var healthy = (try client.pollPushEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
        defer healthy.deinit(std.testing.allocator);
        try std.testing.expect(healthy == .event and healthy.event.push_id == 5);
        try client.tryRejectPush(result.failure);
        try client.tryRejectPush(result.failure);
        try std.testing.expect(!client.push_streams.containsStream(15));
    }
}

test "HTTP/3 failed push local allocation failures preserve parser bytes and connection scope" {
    inline for (.{ false, true }) |decoding| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.malformed(false);
        const client = &pair.inner.client;
        const reader = client.push_streams.readerForStream(15).?;
        const offset = reader.readOffset();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        {
            const original = reader.allocator;
            if (decoding) reader.allocator = failing.allocator() else client.allocator = failing.allocator();
            defer {
                reader.allocator = original;
                client.allocator = std.testing.allocator;
            }
            if (decoding) try std.testing.expectError(error.OutOfMemory, client.pollPushEventOnceWithFailure()) else try std.testing.expectError(error.OutOfMemory, client.pollPushEventOnce());
        }
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(offset, reader.readOffset());
        try std.testing.expect(!client.push_streams.failurePending(15));
        try std.testing.expectEqual(@as(usize, 0), client.pending_push_failures.count());
        try std.testing.expect(!client.established.connection.closing());
        try std.testing.expectError(error.MissingStatus, client.pollPushEventOnce());
    }
}

test "HTTP/3 failed push QPACK remains a connection error in explicit polling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try @import("test_support/failure_pair.zig").prefix(&bytes, 3);
    try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = &.{ 0x00, 0x00, 0xff, 0x7f }, .consumed = 0 }).write(&bytes, std.testing.allocator);
    try pair.inner.send(&.{.{ .stream = .{ .stream_id = 15, .data = bytes.items } }});
    try std.testing.expectError(error.QpackDecompressionFailed, pair.inner.client.pollPushEventOnceWithFailure());
    try std.testing.expectEqual(@as(usize, 0), pair.inner.client.pending_push_failures.count());
    const close = @import("../../../../quic/mod.zig").one_rtt.testing.localCloseInfo(&pair.inner.client.established.connection).?;
    try std.testing.expectEqual(http3.ApplicationErrorCode.qpack_decompression_failed, close.error_code);
}

test "HTTP/3 failed push DATA readers retain cancellation across socket failure and pacing" {
    inline for (.{ false, true }) |paced| {
        inline for (.{ false, true }) |once| {
            inline for (.{ false, true }) |skip| {
                var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
                defer threaded.deinit();
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                try pair.lateFinal(false);
                const client = &pair.inner.client;
                const connection = &client.established.connection;
                const original = connection.endpoint.io;
                var out = [_]u8{0xaa} ** 4;
                {
                    var vtable = original.vtable.*;
                    if (paced) {
                        connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
                        connection.pacer.budget = 0;
                        connection.pacer.setLastSentTimeNs(0);
                    } else {
                        vtable.netSend = FailedSend.send;
                        connection.endpoint.io = .{ .userdata = original.userdata, .vtable = &vtable };
                    }
                    defer connection.endpoint.io = original;
                    const expected = if (paced) error.InvalidContentLength else error.SystemResources;
                    if (once) {
                        if (skip) try std.testing.expectError(expected, client.skipPushDataOnce(3)) else try std.testing.expectError(expected, client.readPushDataOnce(3, &out));
                    } else {
                        if (skip) try std.testing.expectError(expected, client.skipPushData(3)) else try std.testing.expectError(expected, client.readPushData(3, &out));
                    }
                    try std.testing.expectEqual(@as(usize, 1), client.pending_push_failures.count());
                    try std.testing.expect(client.push_streams.containsStream(15));
                    try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
                }
                connection.pacer.enabled = false;
                try std.testing.expectError(error.InvalidContentLength, client.pollPushEventOnce());
                try std.testing.expectEqual(@as(usize, 0), client.pending_push_failures.count());
                try std.testing.expect(client.request_lifecycle.contains(0) and client.request_lifecycle.contains(4));
            }
        }
    }
}

test "HTTP/3 failed push owning receive retains cancellation at its deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try pair.malformed(false);
    const client = &pair.inner.client;
    const connection = &client.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingStatus, client.pollPushEvent());
    try std.testing.expectError(error.Timeout, client.receivePushEventWithTimeout(.fromMilliseconds(5)));
    try std.testing.expectEqual(@as(usize, 1), client.pending_push_failures.count());
    connection.pacer.enabled = false;
    try std.testing.expectError(error.MissingStatus, client.pollPushEvent());
}

test "HTTP/3 failed push peer RESET retires retained rejection without resurrecting its stream" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try pair.malformed(false);
    const client = &pair.inner.client;
    const connection = &client.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingStatus, client.pollPushEventOnce());
    try pair.inner.send(&.{.{ .reset_stream = .{ .stream_id = 15, .application_error_code = http3.ApplicationErrorCode.request_cancelled, .final_size = connection.recvStreamStats(15).?.highest_received_offset } }});
    var failure = (try client.pollPushEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer failure.deinit(std.testing.allocator);
    try std.testing.expect(failure == .failure and failure.failure.err == error.MissingStatus);
    try client.tryRejectPush(failure.failure);
    try std.testing.expectEqual(@as(usize, 0), client.pending_push_failures.count());
    try std.testing.expectEqual(@as(usize, 1), client.push_streams.promiseCount());
    try std.testing.expect(!client.push_streams.containsStream(15));
}

test "HTTP/3 failed push explicit CANCEL_PUSH takes over retained rejection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try pair.malformed(false);
    const client = &pair.inner.client;
    const connection = &client.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingStatus, client.pollPushEventOnce());
    connection.pacer.enabled = false;
    try client.tryCancelPush(3);
    try std.testing.expectEqual(@as(usize, 0), client.pending_push_failures.count());
    try std.testing.expect((try client.pollPushEventOnce()) == null);
}

test "HTTP/3 failed push caller rejection completes after a racing peer RESET" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try pair.malformed(false);
    const client = &pair.inner.client;
    var failed = (try client.pollPushEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer failed.deinit(std.testing.allocator);
    try std.testing.expect(failed == .failure);
    try pair.inner.send(&.{.{ .reset_stream = .{ .stream_id = 15, .application_error_code = http3.ApplicationErrorCode.request_cancelled, .final_size = client.established.connection.recvStreamStats(15).?.highest_received_offset } }});
    try client.tryRejectPush(failed.failure);
    try std.testing.expectEqual(@as(usize, 1), client.push_streams.promiseCount());
    try std.testing.expect(client.push_streams.promiseCompleted(3));
    try std.testing.expect(!client.push_streams.containsStream(15));
}

test "HTTP/3 failed push cancellation queues QPACK feedback once across its socket failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try pair.malformed(false);
    const client = &pair.inner.client;
    client.qpack_decode.table.max_capacity = 256;
    const FeedbackFailure = struct {
        var target: *@import("../../../runtime.zig").HandshakeClient = undefined;
        var delegate: std.Io = undefined;
        fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            if (target.established.connection.recvStreamStats(15).?.stop_sending_sent != null) return .{ error.SystemResources, 0 };
            return delegate.vtable.netSend(userdata, socket, messages, flags);
        }
    };
    const original = client.established.connection.endpoint.io;
    FeedbackFailure.target = client;
    FeedbackFailure.delegate = original;
    var feedback_bytes: [16]u8 = undefined;
    var feedback_len: usize = 0;
    {
        var vtable = original.vtable.*;
        vtable.netSend = FeedbackFailure.send;
        client.established.connection.endpoint.io = .{ .userdata = original.userdata, .vtable = &vtable };
        defer client.established.connection.endpoint.io = original;
        try std.testing.expectError(error.MissingStatus, client.pollPushEventOnce());
        const pending = client.qpack_decode.pendingDecoderInstructions();
        feedback_len = pending.len;
        @memcpy(feedback_bytes[0..pending.len], pending);
        const decoded = try http3.Qpack.decodeDecoderInstruction(pending);
        try std.testing.expect(decoded.instruction == .stream_cancellation);
        try std.testing.expectEqual(@as(u64, 15), decoded.instruction.stream_cancellation);
        try std.testing.expectEqual(pending.len, decoded.consumed);
        try std.testing.expectError(error.SystemResources, client.pollPushEventOnce());
        try std.testing.expectEqualSlices(u8, feedback_bytes[0..feedback_len], client.qpack_decode.pendingDecoderInstructions());
        try std.testing.expectEqual(@as(usize, 0), client.pending_push_failures.count());
        try std.testing.expect(!client.push_streams.containsStream(15));
    }
    try client.flushResponsePacketFeedbackOnce();
    try std.testing.expectEqual(@as(usize, 0), client.qpack_decode.pendingDecoderInstructions().len);
}

test "HTTP/3 failed push connection termination clears retained rejection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try pair.malformed(false);
    const client = &pair.inner.client;
    const connection = &client.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingStatus, client.pollPushEventOnce());
    connection.failClosedApplication(http3.ApplicationErrorCode.internal_error, "test-close");
    try std.testing.expectError(error.ConnectionClosed, client.pollPushEventOnceWithFailure());
    try std.testing.expectEqual(@as(usize, 0), client.pending_push_failures.count());
}

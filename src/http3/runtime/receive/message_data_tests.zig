const std = @import("std");
const http3 = @import("../../mod.zig");
const support = @import("test_support/message_pair.zig");

const Operation = enum { read, available, skip, read_once, skip_once };

const FailedSend = struct {
    fn send(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []std.Io.net.OutgoingMessage, _: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        return .{ error.SystemResources, 0 };
    }
};

fn access(comptime response: bool, comptime operation: Operation, pair: *support.For(response), out: []u8) !?usize {
    const owner = pair.owner();
    if (response) return switch (operation) {
        .read => try owner.readResponseData(0, out),
        .available => try owner.availableResponseData(0),
        .skip => try owner.skipResponseData(0),
        .read_once => try owner.readResponseDataOnce(0, out),
        .skip_once => unreachable,
    };
    return switch (operation) {
        .read => try owner.readRequestData(0, out),
        .available => try owner.availableRequestData(0),
        .skip => try owner.skipRequestData(0),
        .read_once => try owner.readRequestDataOnce(0, out),
        .skip_once => try owner.skipRequestDataOnce(0),
    };
}

test "HTTP/3 message DATA failures retain request cancellation after socket errors" {
    try socketRetry(false);
}

test "HTTP/3 message DATA failures retain response cancellation after socket errors" {
    try socketRetry(true);
}

fn socketRetry(comptime response: bool) !void {
    inline for (.{ Operation.read, Operation.available, Operation.skip, Operation.read_once, Operation.skip_once }) |operation| {
        if (response and operation == .skip_once) continue;
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: support.For(response) = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.lateFinal(false);
        const original_io = pair.connection().endpoint.io;
        var out = [_]u8{0xaa} ** 4;
        {
            var vtable = original_io.vtable.*;
            vtable.netSend = FailedSend.send;
            pair.connection().endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
            defer pair.connection().endpoint.io = original_io;
            try std.testing.expectError(error.SystemResources, access(response, operation, &pair, &out));
            try std.testing.expectEqual(@as(usize, 1), pair.pendingCount());
            try std.testing.expect(pair.owner().request_lifecycle.contains(0));
            try std.testing.expect(!pair.connection().closing());
            try std.testing.expect(pair.streams().find(0).?.message_failure_pending);
        }
        try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
        try std.testing.expectError(error.InvalidContentLength, access(response, operation, &pair, &out));
        try std.testing.expectEqual(@as(usize, 0), pair.pendingCount());
        try std.testing.expect(!pair.owner().request_lifecycle.contains(0));
        try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, pair.connection().recvStreamStats(0).?.stop_sending_sent.?.application_error_code);
        var sibling = (try pair.poll(4)) orelse return error.TestUnexpectedResult;
        defer sibling.deinit(std.testing.allocator);
        try std.testing.expect(sibling == .head);
    }
}

test "HTTP/3 message DATA failures keep healthy siblings readable under cancellation pacing" {
    inline for (.{ false, true }) |response| {
        inline for (.{ Operation.read, Operation.available, Operation.skip, Operation.read_once, Operation.skip_once }) |operation| {
            if (response and operation == .skip_once) continue;
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var pair: support.For(response) = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            try pair.lateFinal(false);
            const connection = pair.connection();
            connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
            connection.pacer.budget = 0;
            connection.pacer.setLastSentTimeNs(0);
            var out = [_]u8{0xaa} ** 4;
            try std.testing.expectError(error.InvalidContentLength, access(response, operation, &pair, &out));
            try std.testing.expectEqual(@as(usize, 1), pair.pendingCount());
            const again = try access(response, operation, &pair, &out);
            if (operation == .read_once or operation == .skip_once) {
                try std.testing.expect(again == null);
            } else {
                try std.testing.expectEqual(@as(?usize, 0), again);
            }
            try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
            var sibling = if (response) (try pair.owner().pollNextResponseEventOnce()).? else (try pair.owner().pollRequestEventOnce()).?;
            defer sibling.deinit(std.testing.allocator);
            try std.testing.expect(sibling == .message and sibling.message.stream_id == 4 and sibling.message.value == .head);
            var failure = if (response) (try pair.owner().pollNextResponseEventOnceWithFailure()).? else (try pair.owner().pollRequestEventOnceWithFailure()).?;
            defer failure.deinit(std.testing.allocator);
            try std.testing.expect(failure == .failure and failure.failure.err == error.InvalidContentLength);
            try std.testing.expectEqual(@as(u62, 0), failure.failure.stream_id);
            try std.testing.expectEqual(@as(usize, 0), pair.pendingCount());
            connection.pacer.enabled = false;
            try pair.owner().tryCancelRequest(failure.failure.stream_id, failure.failure.application_error_code);
        }
    }
}

test "HTTP/3 message DATA failures leave rejection allocation retryable" {
    inline for (.{ false, true }) |response| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: support.For(response) = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.lateFinal(false);
        if (response) pair.owner().pending_response_failures.deinit(std.testing.allocator) else pair.owner().pending_request_failures.deinit(std.testing.allocator);
        const read_offset = pair.streams().find(0).?.reader.readOffset();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        {
            if (response) pair.owner().allocator = failing.allocator() else pair.connection().endpoint.allocator = failing.allocator();
            defer if (response) {
                pair.owner().allocator = std.testing.allocator;
            } else {
                pair.connection().endpoint.allocator = std.testing.allocator;
            };
            try std.testing.expectError(error.OutOfMemory, access(response, .available, &pair, &.{}));
        }
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(read_offset, pair.streams().find(0).?.reader.readOffset());
        try std.testing.expect(!pair.streams().find(0).?.message_failure_pending);
        try std.testing.expectEqual(@as(usize, 0), pair.pendingCount());
        try std.testing.expect(!pair.connection().closing());
        try std.testing.expectError(error.InvalidContentLength, access(response, .available, &pair, &.{}));
        try std.testing.expect(!pair.owner().request_lifecycle.contains(0));
    }
}

test "HTTP/3 message DATA failures preserve framing scope even when close writes fail" {
    inline for (.{ false, true }) |response| {
        inline for (.{ Operation.read, Operation.available, Operation.skip, Operation.read_once, Operation.skip_once }) |operation| {
            if (response and operation == .skip_once) continue;
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var pair: support.For(response) = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            try pair.lateFinal(true);
            const original_io = pair.connection().endpoint.io;
            var vtable = original_io.vtable.*;
            vtable.netSend = FailedSend.send;
            pair.connection().endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
            defer pair.connection().endpoint.io = original_io;
            var out = [_]u8{0xaa} ** 4;
            try std.testing.expectError(error.BufferTooShort, access(response, operation, &pair, &out));
            try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
            try std.testing.expectEqual(@as(usize, 0), pair.pendingCount());
            const close = @import("../../../quic/mod.zig").one_rtt.testing.localCloseInfo(pair.connection()).?;
            try std.testing.expect(close.application);
            try std.testing.expectEqual(http3.ApplicationErrorCode.frame_error, close.error_code);
        }
    }
}

test "HTTP/3 message DATA access rejects API state without cancelling messages" {
    inline for (.{ false, true }) |response| {
        inline for (.{ Operation.read, Operation.available, Operation.skip, Operation.read_once, Operation.skip_once }) |operation| {
            if (response and operation == .skip_once) continue;
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var pair: support.For(response) = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            try pair.bodyReady(false);
            var out = [_]u8{0xaa} ** 4;
            try std.testing.expectError(error.UnexpectedFrame, access(response, operation, &pair, &out));
            try std.testing.expectEqual(@as(usize, 0), pair.pendingCount());
            try std.testing.expect(pair.owner().request_lifecycle.contains(0));
            try std.testing.expect(!pair.connection().closing());
        }
    }
}

test "HTTP/3 message DATA reads report consumed bytes before receive credit can fail" {
    inline for (.{ false, true }) |response| {
        inline for (.{ Operation.read, Operation.skip }) |operation| {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var pair: support.For(response) = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            try pair.bodyReady(true);
            const connection = pair.connection();
            // Force the next payload consumption to advertise MAX_DATA.
            connection.recv_flow.limit = connection.recv_flow.highest_received;
            connection.recv_flow.window = 4;
            connection.recv_flow.max_window = 4;
            const original_io = connection.endpoint.io;
            var out = [_]u8{0xaa} ** 3;
            {
                var vtable = original_io.vtable.*;
                vtable.netSend = FailedSend.send;
                connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
                defer connection.endpoint.io = original_io;
                try std.testing.expectEqual(@as(?usize, 3), try access(response, operation, &pair, &out));
                if (operation == .read) try std.testing.expectEqualStrings("abc", &out);
                try std.testing.expectEqual(@as(usize, 3), pair.streams().find(0).?.reader.uncreditedConsumed());
                try std.testing.expectError(error.SystemResources, pair.poll(0));
                try std.testing.expectEqual(@as(usize, 3), pair.streams().find(0).?.reader.body_read);
            }
            var finished = (try pair.poll(0)) orelse return error.TestUnexpectedResult;
            defer finished.deinit(std.testing.allocator);
            try std.testing.expect(finished == .finished);
            try std.testing.expectEqual(@as(usize, 0), pair.pendingCount());
        }
    }
}

test "HTTP/3 message DATA failures bypass failed reader credit while siblings progress" {
    inline for (.{ false, true }) |response| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: support.For(response) = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.lateFinalAfterRead();
        const connection = pair.connection();
        for (connection.stream_recv_flows.items) |*entry| {
            if (entry.stream_id != 0) continue;
            entry.flow.limit = entry.flow.highest_received;
            entry.flow.window = 4;
            entry.flow.max_window = 4;
        }
        connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
        connection.pacer.budget = 0;
        connection.pacer.setLastSentTimeNs(0);
        try std.testing.expectError(error.InvalidContentLength, access(response, .available, &pair, &.{}));
        try std.testing.expectEqual(@as(usize, 1), pair.pendingCount());
        var sibling = if (response) (try pair.owner().pollNextResponseEventOnce()) orelse return error.TestUnexpectedResult else (try pair.owner().pollRequestEventOnce()) orelse return error.TestUnexpectedResult;
        defer sibling.deinit(std.testing.allocator);
        try std.testing.expect(sibling == .message and sibling.message.stream_id == 4 and sibling.message.value == .head);
        connection.pacer.enabled = false;
        try std.testing.expectError(error.InvalidContentLength, pair.poll(0));
    }
}

test "HTTP/3 message DATA caller cancellation retires retained request rejection" {
    inline for (.{ false, true }) |single_attempt| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: support.For(false) = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.lateFinal(false);
        const connection = pair.connection();
        connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
        connection.pacer.budget = 0;
        connection.pacer.setLastSentTimeNs(0);
        try std.testing.expectError(error.InvalidContentLength, access(false, .available, &pair, &.{}));
        try std.testing.expectEqual(@as(usize, 1), pair.pendingCount());
        try std.testing.expectError(error.PacingLimited, pair.owner().tryCancelRequest(0, http3.ApplicationErrorCode.message_error));
        try std.testing.expectEqual(@as(usize, 1), pair.pendingCount());
        connection.pacer.enabled = false;
        if (single_attempt) try pair.owner().tryCancelRequest(0, http3.ApplicationErrorCode.message_error) else try pair.owner().cancelRequest(0, http3.ApplicationErrorCode.message_error);
        try std.testing.expectEqual(@as(usize, 0), pair.pendingCount());
        var result = (try pair.owner().pollRequestEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result == .event and result.event == .message and result.event.message.stream_id == 4);
    }
}

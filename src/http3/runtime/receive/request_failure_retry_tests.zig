const std = @import("std");
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const quic = @import("../../../quic/mod.zig");
const support = @import("test_support/request_pair.zig");
const Pair = support.Pair;

const FailedSend = struct {
    delegate: std.Io,
    connection: *quic.one_rtt.Connection,

    fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (self.connection.sendStreamStats(0) != null or self.connection.sendStreamStats(4) != null) return .{ error.SystemResources, 0 };
        return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
    }
};

fn sendMissingMethod(pair: *Pair) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try support.malformed(&bytes, &.{ .{ .name = ":path", .value = "/bad" }, .{ .name = ":scheme", .value = "https" } });
    try pair.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items } }});
}

fn verifySocketRetry(owning: bool, transfer: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try sendMissingMethod(&pair);
    const original_io = pair.server_endpoint.io;
    {
        var failed = FailedSend{ .delegate = original_io, .connection = &pair.server.established.connection };
        pair.server_endpoint.io = forwarded_io.observer(&failed, .{ .netSend = FailedSend.send });
        defer pair.server_endpoint.io = original_io;
        if (owning) {
            try std.testing.expectError(error.SystemResources, pair.server.pollRequestEvent());
        } else {
            try std.testing.expectError(error.SystemResources, pair.server.pollRequestEventOnce());
        }
        try std.testing.expectEqual(@as(usize, 1), pair.server.pending_request_failures.count());
        try std.testing.expect(pair.server.established.connection.sendStreamStats(0).?.reset == null);
        if (transfer) {
            var result = (try pair.server.pollRequestEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
            defer result.deinit(std.testing.allocator);
            try std.testing.expect(result == .failure and result.failure.err == error.MissingMethod);
            try std.testing.expectEqual(@as(u62, 0), result.failure.stream_id);
            try std.testing.expectEqual(@as(usize, 0), pair.server.pending_request_failures.count());
        }
    }
    try std.testing.expect(!pair.server.established.connection.closing());
    if (transfer) {
        try pair.server.tryCancelRequest(0, http3.ApplicationErrorCode.message_error);
        try std.testing.expect((try pair.server.pollRequestEventOnce()) == null);
    } else {
        try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEventOnce());
        try std.testing.expectEqual(@as(usize, 0), pair.server.pending_request_failures.count());
    }
    try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, pair.server.established.connection.sendStreamStats(0).?.reset.?.application_error_code);
}

test "HTTP/3 default failed-request polling preserves socket errors and retries the original cause" {
    try verifySocketRetry(false, false);
}

test "HTTP/3 default failed-request owning poll preserves the connection through socket failure" {
    try verifySocketRetry(true, false);
}

test "HTTP/3 default failed-request queue transfers cancellation ownership to explicit polling" {
    try verifySocketRetry(false, true);
}

test "HTTP/3 default failed-request polling keeps a healthy sibling readable while cancellation is paced" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(std.testing.allocator);
    var valid: std.ArrayList(u8) = .empty;
    defer valid.deinit(std.testing.allocator);
    try support.malformed(&invalid, &.{ .{ .name = ":path", .value = "/bad" }, .{ .name = ":scheme", .value = "https" } });
    try (http3.Request{ .method = "GET", .path = "/healthy", .authority = "localhost" }).write(&valid, std.testing.allocator);
    try pair.send(&.{ .{ .stream = .{ .stream_id = 0, .data = invalid.items } }, .{ .stream = .{ .stream_id = 4, .data = valid.items } } });
    const connection = &pair.server.established.connection;
    _ = try connection.tryFlushPendingAck();
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEventOnce());
    var sibling = (try pair.server.pollRequestEventOnce()) orelse return error.TestUnexpectedResult;
    defer sibling.deinit(std.testing.allocator);
    try std.testing.expect(sibling == .message and sibling.message.stream_id == 4 and sibling.message.value == .head);
    try std.testing.expectEqualStrings("/healthy", sibling.message.value.head.request.path);
    try std.testing.expectEqual(@as(usize, 1), pair.server.pending_request_failures.count());
    connection.pacer.enabled = false;
    try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEventOnce());
}

test "HTTP/3 default failed-request polling retains independent failures for targeted requests" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(std.testing.allocator);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(std.testing.allocator);
    try support.malformed(&first, &.{ .{ .name = ":path", .value = "/bad" }, .{ .name = ":scheme", .value = "https" } });
    try support.malformed(&second, &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = "/bad" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":method", .value = "duplicate" } });
    try pair.send(&.{ .{ .stream = .{ .stream_id = 0, .data = first.items } }, .{ .stream = .{ .stream_id = 4, .data = second.items } } });
    const original_io = pair.server_endpoint.io;
    {
        var failed = FailedSend{ .delegate = original_io, .connection = &pair.server.established.connection };
        pair.server_endpoint.io = forwarded_io.observer(&failed, .{ .netSend = FailedSend.send });
        defer pair.server_endpoint.io = original_io;
        try std.testing.expectError(error.SystemResources, pair.server.pollRequestEventForOnce(0));
        try std.testing.expectError(error.SystemResources, pair.server.pollRequestEventForOnce(4));
    }
    try std.testing.expectEqual(@as(usize, 2), pair.server.pending_request_failures.count());
    try std.testing.expectError(error.InvalidHeader, pair.server.pollRequestEventForOnce(4));
    try std.testing.expectEqual(@as(usize, 1), pair.server.pending_request_failures.count());
    try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEventOnce());
    try std.testing.expectEqual(@as(usize, 0), pair.server.pending_request_failures.count());
}

test "HTTP/3 default failed-request ownership is reserved before decoding" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try sendMissingMethod(&pair);
    _ = try pair.server.established.connection.tryFlushPendingAck();
    const original = pair.server_endpoint.allocator;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    {
        pair.server_endpoint.allocator = failing.allocator();
        defer pair.server_endpoint.allocator = original;
        try std.testing.expectError(error.OutOfMemory, pair.server.pollRequestEventOnce());
    }
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), pair.server.pending_request_failures.count());
    try std.testing.expect(pair.server.established.connection.sendStreamStats(0) == null);
    try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEventOnce());
}

test "HTTP/3 default failed-request owning receive retains cancellation at its deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try sendMissingMethod(&pair);
    const connection = &pair.server.established.connection;
    _ = try connection.tryFlushPendingAck();
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEvent());
    try std.testing.expectError(error.Timeout, pair.server.receiveRequestEventWithTimeout(.fromMilliseconds(5)));
    try std.testing.expectEqual(@as(usize, 1), pair.server.pending_request_failures.count());
    try std.testing.expect(connection.sendStreamStats(0).?.reset == null);
    connection.pacer.enabled = false;
    try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEvent());
    try std.testing.expectEqual(@as(usize, 0), pair.server.pending_request_failures.count());
}

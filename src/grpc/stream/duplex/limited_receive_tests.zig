const std = @import("std");
const grpc = @import("../../mod.zig");
const http2 = @import("../../../http2/mod.zig");
const codec = @import("../codec.zig");
const duplex = @import("../duplex.zig");
const allocator = std.testing.allocator;

test "gRPC bounded message decoder resumes every split and compressed suffix exactly" {
    const third = "compressed-third-" ** 32;
    var compressed = try grpc.compression.compressAlloc(allocator, .gzip, third, 1);
    defer compressed.deinit(allocator);
    try std.testing.expect(compressed.compressed);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try grpc.wire.writeMessage(&bytes, allocator, "first", false);
    try grpc.wire.writeMessage(&bytes, allocator, "", false);
    try grpc.wire.writeMessage(&bytes, allocator, compressed.bytes, true);
    const Collector = struct {
        calls: usize = 0,
        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            const expected = switch (self.calls) {
                0 => "first",
                1 => "",
                2 => third,
                else => return error.ExtraMessage,
            };
            try std.testing.expectEqualStrings(expected, message.payload);
            try std.testing.expectEqual(self.calls == 2, message.was_compressed);
            self.calls += 1;
        }
    };
    for (0..bytes.items.len + 1) |split| {
        var decoder = try codec.Decoder.init(allocator, 1024, "gzip", .{ .gzip = true });
        defer decoder.deinit();
        var collector: Collector = .{};
        try std.testing.expectError(error.InvalidStreamState, decoder.feedLimited(bytes.items, 0, &collector, Collector.consume));
        for ([_][]const u8{ bytes.items[0..split], bytes.items[split..] }) |part| {
            var offset: usize = 0;
            while (offset < part.len) {
                const before = collector.calls;
                const progress = try decoder.feedLimited(part[offset..], 1, &collector, Collector.consume);
                try std.testing.expect(progress.consumed > 0);
                try std.testing.expect(progress.messages <= 1);
                try std.testing.expectEqual(progress.messages, collector.calls - before);
                offset += progress.consumed;
            }
        }
        try decoder.finish();
        try std.testing.expectEqual(@as(usize, 3), collector.calls);
    }
}

test "gRPC bounded message poll retains one DATA suffix while a sibling finishes" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *http2.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            const Ignore = struct {
                fn consume(_: void, _: u31, _: []const u8) !void {}
            };
            var requests: [2]http2.runtime.StreamingRequest = undefined;
            try connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(5), {}, Ignore.consume);
            defer for (&requests) |*request| request.deinit(allocator);
            const a = requests[0];
            const b = requests[1];
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(allocator);
            try grpc.wire.writeMessage(&body, allocator, "one", false);
            try grpc.wire.writeMessage(&body, allocator, "", false);
            try grpc.wire.writeMessage(&body, allocator, "three", false);
            var writer = try connection.startResponseWithTimeout(a.stream_id, .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }} }, .fromSeconds(5));
            defer writer.deinit();
            // One small DATA frame contains all three messages.
            try writer.writeWithTimeout(body.items, .fromSeconds(5));
            try writer.finishTrailersWithTimeout(&.{.{ .name = "grpc-status", .value = "0" }}, .fromSeconds(5));
            body.clearRetainingCapacity();
            try grpc.wire.writeMessage(&body, allocator, "sibling", false);
            try connection.writeResponseWithTimeout(b.stream_id, .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }}, .body = body.items, .trailers = &.{.{ .name = "grpc-status", .value = "0" }} }, .fromSeconds(5));
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var connection = try http2.runtime.Client.connectWithTimeout(allocator, io, server.address(), .{}, .fromSeconds(5));
    defer connection.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    var a = try duplex.startDuplexWithDeadlines(&connection, allocator, .{ .path = "/demo.Echo/A" }, deadline, deadline);
    defer a.deinit();
    var b = try duplex.startDuplexWithIoDeadline(&connection, allocator, .{ .path = "/demo.Echo/B" }, deadline);
    defer b.deinit();
    const written = a.transport.requestCommittedBytes();
    try a.stageMessage("a", .{});
    try std.testing.expectEqual(written, a.transport.requestCommittedBytes());
    try std.testing.expectError(error.Timeout, a.pollResumeMessageWithDeadline(.{ .raw = .zero, .clock = .real }, 2));
    try std.testing.expectEqual(written, a.transport.requestCommittedBytes());
    while (try a.pollResumeMessageWithDeadline(deadline, 2) != .complete) {}
    try std.testing.expectEqual(duplex.WriteResult.complete, try a.finishRequestWithDeadline(deadline));
    try std.testing.expectEqual(duplex.WriteResult.complete, try b.writeFinalMessage("b"));
    const Collector = struct {
        calls: usize = 0,
        sibling: bool = false,
        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            const expected = if (self.sibling) "sibling" else switch (self.calls) {
                0 => "one",
                1 => "",
                2 => "three",
                else => return error.ExtraMessage,
            };
            try std.testing.expectEqualStrings(expected, message.payload);
            self.calls += 1;
        }
    };
    var a_messages: Collector = .{};
    try std.testing.expectError(error.InvalidStreamState, a.pollResponseEventLimitedWithDeadline(0, deadline, &a_messages, Collector.consume));
    while (a_messages.calls == 0) {
        if (try a.pollResponseEventLimitedWithDeadline(1, deadline, &a_messages, Collector.consume)) |ready| {
            var event = ready;
            defer event.deinit(allocator);
            if (event == .terminal) return error.EarlyTerminal;
        } else _ = try connection.pumpClientDuplexWithDeadline(deadline);
    }
    try std.testing.expectEqual(@as(usize, 1), a_messages.calls);
    const expired = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) });
    try std.testing.expectError(error.Timeout, a.pollResponseEventLimitedWithDeadline(1, expired, &a_messages, Collector.consume));
    try std.testing.expectEqual(@as(usize, 1), a_messages.calls);
    var b_messages = Collector{ .sibling = true };
    while (true) {
        if (try b.pollResponseEventWithDeadline(deadline, &b_messages, Collector.consume)) |ready| {
            var event = ready;
            defer event.deinit(allocator);
            if (event == .terminal) {
                try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
                break;
            }
        } else _ = try connection.pumpClientDuplexWithDeadline(deadline);
    }
    try std.testing.expectEqual(@as(usize, 1), b_messages.calls);
    while (true) {
        const before = a_messages.calls;
        if (try a.pollResponseEventLimitedWithDeadline(1, deadline, &a_messages, Collector.consume)) |ready| {
            var event = ready;
            defer event.deinit(allocator);
            try std.testing.expect(a_messages.calls - before <= 1);
            if (event == .terminal) {
                try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
                break;
            }
        } else _ = try connection.pumpClientDuplexWithDeadline(deadline);
    }
    try std.testing.expectEqual(@as(usize, 3), a_messages.calls);
    try peer.await(io);
}

test "gRPC bounded message callback failure releases held DATA and preserves reuse" {
    for ([_]anyerror{ error.RejectSecond, error.Canceled, error.ConcurrencyUnavailable }) |failure| {
        try exerciseCallbackFailure(failure);
    }
}

fn exerciseCallbackFailure(failure: anyerror) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        fn reply(connection: *http2.runtime.Connection, id: u31, values: []const []const u8) !void {
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(allocator);
            for (values) |value| try grpc.wire.writeMessage(&body, allocator, value, false);
            try connection.writeResponseWithTimeout(id, .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }}, .body = body.items, .trailers = &.{.{ .name = "grpc-status", .value = "0" }} }, .fromSeconds(5));
        }
        fn run(server_ptr: *http2.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            var first = try connection.readRequestWithTimeout(.fromSeconds(5));
            defer first.deinit(allocator);
            try reply(&connection, first.stream_id, &.{ "one", "reject", "unread" });
            var reset = try connection.readResetStreamWithTimeout(.fromSeconds(5));
            defer reset.deinit(allocator);
            try std.testing.expectEqual(first.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.internal_error, reset.reset.error_code);
            var next = try connection.readRequestWithTimeout(.fromSeconds(5));
            defer next.deinit(allocator);
            try reply(&connection, next.stream_id, &.{"reused"});
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var connection = try http2.runtime.Client.connectWithTimeout(allocator, io, server.address(), .{ .terminal_cleanup_timeout = .fromSeconds(1) }, .fromSeconds(5));
    defer connection.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    var first = try duplex.startDuplexWithIoDeadline(&connection, allocator, .{ .path = "/demo.Echo/Reject" }, deadline);
    defer first.deinit();
    try std.testing.expectEqual(duplex.WriteResult.complete, try first.writeFinalMessage("first"));
    const Collector = struct {
        count: usize = 0,
        reject: bool,
        failure: anyerror,
        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            if (self.reject and self.count != 0) return self.failure;
            try std.testing.expectEqualStrings(if (self.reject) "one" else "reused", message.payload);
            self.count += 1;
        }
    };
    var collector = Collector{ .reject = true, .failure = failure };
    while (collector.count == 0) {
        if (try first.pollResponseEventLimitedWithDeadline(1, deadline, &collector, Collector.consume)) |ready| {
            var event = ready;
            defer event.deinit(allocator);
            if (event == .terminal) return error.EarlyTerminal;
        } else _ = try connection.pumpClientDuplexWithDeadline(deadline);
    }
    try std.testing.expectError(failure, first.pollResponseEventLimitedWithDeadline(1, deadline, &collector, Collector.consume));
    try std.testing.expectError(error.ConnectionClosed, first.pollResponseEventLimitedWithDeadline(1, deadline, &collector, Collector.consume));
    var next = try duplex.startDuplexWithIoDeadline(&connection, allocator, .{ .path = "/demo.Echo/Reuse" }, deadline);
    defer next.deinit();
    try std.testing.expectEqual(duplex.WriteResult.complete, try next.writeFinalMessage("next"));
    var reused = Collector{ .reject = false, .failure = failure };
    while (true) {
        if (try next.pollResponseEventWithDeadline(deadline, &reused, Collector.consume)) |ready| {
            var event = ready;
            defer event.deinit(allocator);
            if (event == .terminal) {
                try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
                break;
            }
        } else _ = try connection.pumpClientDuplexWithDeadline(deadline);
    }
    try std.testing.expectEqual(@as(usize, 1), reused.count);
    try peer.await(io);
}

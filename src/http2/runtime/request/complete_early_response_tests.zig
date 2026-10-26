//! Early responses preserve the upload cursor, terminal result, and reuse.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;
const body = "0123456789abcdefghijklmnop";
const Mode = enum { aggregate, callbacks };
const Scenario = enum { terminal, server_reset, interim, incomplete_reset, reject_head, reject_data };

const Observer = struct {
    reject_head: bool = false,
    reject_data: bool = false,
    head_count: usize = 0,
    status: ?u16 = null,
    interim_count: usize = 0,
    interim_status: ?u16 = null,
    bytes: [64]u8 = undefined,
    length: usize = 0,

    fn begin(self: *@This(), head: runtime.StreamingResponseHead) !void {
        self.head_count += 1;
        self.status = head.status;
        if (self.reject_head) return error.CallbackRejected;
    }
    fn consume(self: *@This(), data: []const u8) !void {
        if (self.reject_data) return error.CallbackRejected;
        if (self.length + data.len > self.bytes.len) return error.MessageTooLarge;
        @memcpy(self.bytes[self.length..][0..data.len], data);
        self.length += data.len;
    }
    fn interim(context: *anyopaque, head: runtime.StreamingResponseHead) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.interim_count += 1;
        self.interim_status = head.status;
    }
};

fn request(connection: *runtime.Connection, mode: Mode, bounded: bool, trailers: bool, observer: *Observer) !void {
    const options: runtime.RequestOptions = .{
        .method = "POST",
        .path = "/early",
        .authority = "localhost",
        .body = body,
        .trailers = if (trailers) &.{.{ .name = "x-upload-done", .value = "yes" }} else &.{},
    };
    const informational: runtime.InformationalObserver = .{ .context = observer, .on_response = Observer.interim };
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromSeconds(2), .clock = .awake });
    switch (mode) {
        .aggregate => {
            var response = if (bounded)
                try connection.requestWithInformationalAndDeadline(options, informational, deadline)
            else
                try connection.requestWithInformational(options, informational);
            defer response.deinit(allocator);
            try observer.begin(.{ .headers = response.headers, .status = response.status, .body_allowed = response.body_allowed });
            try observer.consume(response.body);
        },
        .callbacks => {
            var response = if (bounded)
                try connection.requestStreamingWithInformationalAndHeadAndDeadline(options, informational, deadline, observer, Observer.begin, Observer.consume)
            else
                try connection.requestStreamingWithInformationalAndHead(options, informational, observer, Observer.begin, Observer.consume);
            defer response.deinit(allocator);
        },
    }
}

fn exercise(mode: Mode, bounded: bool, trailers: bool, scenario: Scenario) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .initial_window_size = 8, .max_concurrent_streams = 1 });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        scenario: Scenario,
        trailers: bool,
        received: [body.len]u8 = undefined,
        length: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            {
                var stream = try connection.acceptDuplexRequestWithTimeout(.fromSeconds(2));
                defer stream.deinit();
                if (self.scenario == .interim) try connection.writeInformationalResponseWithTimeout(stream.stream_id, 103, &.{}, .fromSeconds(2));
                if (self.scenario == .reject_head) {
                    try stream.finishResponseHeadersWithTimeout(.{ .status = 403 }, .fromSeconds(2));
                } else try stream.startResponseWithTimeout(.{ .status = if (self.scenario == .interim) 200 else 403 }, .fromSeconds(2));
                if (self.scenario == .interim) {
                    while (true) {
                        var event = try stream.readRequestEventWithTimeout(.fromSeconds(2));
                        defer event.deinit(allocator);
                        switch (event) {
                            .data => |data| {
                                if (self.length + data.data.len > self.received.len) return error.UploadRepeated;
                                @memcpy(self.received[self.length..][0..data.data.len], data.data);
                                self.length += data.data.len;
                            },
                            .trailers => |fields| {
                                try std.testing.expect(self.trailers);
                                try std.testing.expectEqualStrings("yes", header(fields, "x-upload-done").?);
                                break;
                            },
                            .finished => break,
                            .reset => return error.UploadCanceledBeforeCompletion,
                        }
                    }
                    try std.testing.expectEqualStrings(body, self.received[0..self.length]);
                    _ = try stream.finishResponseDataWithTimeout("accepted", .fromSeconds(2));
                } else if (self.scenario == .incomplete_reset) {
                    _ = try stream.writeResponseWithTimeout("part", .fromSeconds(2));
                    try stream.reset(.no_error);
                } else {
                    if (self.scenario != .reject_head) _ = try stream.finishResponseDataWithTimeout("denied", .fromSeconds(2));
                    if (self.scenario == .server_reset) {
                        try stream.reset(.no_error);
                    } else {
                        while (true) {
                            var event = try stream.readRequestEventWithTimeout(.fromSeconds(2));
                            defer event.deinit(allocator);
                            switch (event) {
                                .data => |data| self.length += data.data.len,
                                .reset => |reset| {
                                    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
                                    break;
                                },
                                .trailers, .finished => return error.ShortUploadFin,
                            }
                        }
                        try std.testing.expectEqual(@as(usize, 8), self.length);
                    }
                }
            }
            var healthy = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer healthy.deinit(allocator);
            try std.testing.expectEqualStrings("next", healthy.body);
            try connection.writeResponse(healthy.stream_id, .{ .body = "healthy" });
        }
    };
    var peer: Peer = .{ .server = &server, .scenario = scenario, .trailers = trailers };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var observer: Observer = .{ .reject_head = scenario == .reject_head, .reject_data = scenario == .reject_data };
    const result = request(&client, mode, bounded, trailers, &observer);
    if (scenario == .incomplete_reset) {
        try std.testing.expectError(error.StreamReset, result);
    } else if (scenario == .reject_head or scenario == .reject_data) {
        try std.testing.expectError(error.CallbackRejected, result);
    } else {
        try result;
        try std.testing.expectEqual(@as(usize, 1), observer.head_count);
        try std.testing.expectEqual(@as(?u16, if (scenario == .interim) 200 else 403), observer.status);
        try std.testing.expectEqualStrings(if (scenario == .interim) "accepted" else "denied", observer.bytes[0..observer.length]);
        try std.testing.expectEqual(@as(usize, @intFromBool(scenario == .interim)), observer.interim_count);
        if (scenario == .interim) try std.testing.expectEqual(@as(?u16, 103), observer.interim_status);
    }
    try std.testing.expect(!client.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());
    var healthy = try client.requestWithTimeout(.{ .method = "POST", .path = "/healthy", .authority = "localhost", .body = "next" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    try std.testing.expect(client.isReusable());
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn header(fields: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (fields) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

test "HTTP/2 complete request consumes an early terminal response and reuses the channel" {
    for (std.enums.values(Mode)) |mode| for ([_]bool{ false, true }) |bounded| for ([_]bool{ false, true }) |trailers| try exercise(mode, bounded, trailers, .terminal);
}
test "HTTP/2 complete request preserves a response followed by server NO_ERROR reset" {
    for (std.enums.values(Mode)) |mode| for ([_]bool{ false, true }) |bounded| try exercise(mode, bounded, false, .server_reset);
}
test "HTTP/2 complete request resumes exact upload after 1xx and early final headers" {
    for (std.enums.values(Mode)) |mode| for ([_]bool{ false, true }) |bounded| for ([_]bool{ false, true }) |trailers| try exercise(mode, bounded, trailers, .interim);
}
test "HTTP/2 complete request rejects an incomplete response reset without poisoning reuse" {
    for (std.enums.values(Mode)) |mode| for ([_]bool{ false, true }) |bounded| try exercise(mode, bounded, false, .incomplete_reset);
}

test "HTTP/2 complete request callback rejection cancels an unfinished upload after END_STREAM" {
    for ([_]bool{ false, true }) |bounded| {
        try exercise(.callbacks, bounded, false, .reject_head);
        try exercise(.callbacks, bounded, false, .reject_data);
    }
}

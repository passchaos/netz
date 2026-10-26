//! Complete request APIs include output and upload flow control in one budget.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const frame_io = @import("../frame/io.zig");
const wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

const Mode = enum { aggregate, callbacks };
const Phase = enum { opening, batched, data, trailers, flow_control };

const Observer = struct {
    heads: usize = 0,
    bytes: usize = 0,

    fn begin(self: *@This(), _: runtime.StreamingResponseHead) !void {
        self.heads += 1;
    }

    fn consume(self: *@This(), bytes: []const u8) !void {
        self.bytes += bytes.len;
    }
};

fn request(connection: *runtime.Connection, mode: Mode, options: runtime.RequestOptions, deadline: std.Io.Clock.Timestamp, observer: *Observer) !void {
    switch (mode) {
        .aggregate => {
            var response = try connection.requestWithInformationalAndDeadline(options, null, deadline);
            defer response.deinit(allocator);
        },
        .callbacks => {
            var response = try connection.requestStreamingWithInformationalAndHeadAndDeadline(options, null, deadline, observer, Observer.begin, Observer.consume);
            defer response.deinit(allocator);
        },
    }
}

fn exercise(mode: Mode, phase: Phase) !void {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    const connection = &fixture.connection;
    const large = "x" ** (256 * 1024);
    var options: runtime.RequestOptions = .{ .method = "POST", .path = "/blocked", .authority = "localhost" };
    switch (phase) {
        .opening => options.headers = &.{.{ .name = "x-large", .value = large }},
        .batched => options.body = large,
        .data => {
            options.body = large;
            options.trailers = &.{.{ .name = "x-done", .value = "yes" }};
        },
        .trailers => {
            options.body = "upload";
            options.trailers = &.{.{ .name = "x-large", .value = large }};
        },
        .flow_control => {
            options.body = "upload";
            connection.peer_initial_stream_window = 1;
        },
    }
    try fixture.startRescue();
    var observer: Observer = .{};
    const started = std.Io.Clock.awake.now(connection.io);
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromMilliseconds(30), .clock = .awake });
    try std.testing.expectError(error.Timeout, request(connection, mode, options, deadline, &observer));
    try std.testing.expect(started.untilNow(connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), observer.heads);
    try std.testing.expectEqual(@as(usize, 0), observer.bytes);
    try std.testing.expectError(error.ConnectionClosed, connection.request(options));
    if (phase == .flow_control) {
        // Complete HEADERS and the one permitted DATA byte precede the exact
        // CANCEL. A flow-control timeout must never renew the upload budget.
        var head = try frame_io.readOwned(allocator, connection.io, fixture.peer, 16_384);
        defer head.deinit(allocator);
        try std.testing.expectEqual(http2.FrameType.headers, head.frame.header.frame_type);
        var data = try frame_io.readOwned(allocator, connection.io, fixture.peer, 16_384);
        defer data.deinit(allocator);
        try std.testing.expectEqual(http2.FrameType.data, data.frame.header.frame_type);
        try std.testing.expectEqualStrings("u", data.frame.payload);
        var terminal = try frame_io.readOwned(allocator, connection.io, fixture.peer, 16_384);
        defer terminal.deinit(allocator);
        const reset = try http2.ResetStreamPayload.parse(terminal.frame);
        try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
        try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
    } else {
        // No cleanup frame can follow an indeterminate HEADERS/DATA prefix.
        try std.testing.expect(connection.terminal_write_failed);
    }
}

test "HTTP/2 complete request deadline bounds every blocked output phase" {
    for (std.enums.values(Mode)) |mode| {
        for ([_]Phase{ .opening, .batched, .data, .trailers }) |phase| try exercise(mode, phase);
    }
}

test "HTTP/2 complete request deadline bounds upload flow control and cancellation" {
    for (std.enums.values(Mode)) |mode| try exercise(mode, .flow_control);
}

test "HTTP/2 complete request deadline rejects unusable budgets before mutation" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Mode)) |mode| {
        for ([_]std.Io.Clock{ .awake, .real }) |clock| {
            var fixture = try BlockedOutput.init(threaded.io(), .client);
            defer fixture.deinit();
            var observer: Observer = .{};
            const connection = &fixture.connection;
            const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .clock = clock, .raw = .fromMilliseconds(if (clock == .awake) -1 else 1000) });
            try std.testing.expectError(error.Timeout, request(connection, mode, .{ .body = "upload" }, deadline, &observer));
            try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
            try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
            try std.testing.expect(!connection.aggregate_timeout_unusable);
            try std.testing.expectEqual(@as(usize, 0), connection.hpack_encoder.dynamic_table.used);
        }
    }
}

test "HTTP/2 complete request allocation failure before output preserves channel reuse" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Mode)) |mode| {
        var fixture = try BlockedOutput.init(threaded.io(), .client);
        defer fixture.deinit();
        const connection = &fixture.connection;
        var fields: [20]http2.Hpack.HeaderField = @splat(.{ .name = "x-field", .value = "value" });
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        connection.allocator = failing.allocator();
        var observer: Observer = .{};
        const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromSeconds(1), .clock = .awake });
        const result = request(connection, mode, .{ .headers = &fields }, deadline, &observer);
        connection.allocator = allocator;
        try std.testing.expectError(error.OutOfMemory, result);
        try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
        try std.testing.expect(!connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 0x05, 1, &.{0x88});
        try request(connection, mode, .{ .authority = "localhost" }, deadline, &observer);
        var sent = try frame_io.readOwned(allocator, connection.io, fixture.peer, 16_384);
        defer sent.deinit(allocator);
        try std.testing.expectEqual(http2.FrameType.headers, sent.frame.header.frame_type);
        try std.testing.expectEqual(@as(u31, 1), sent.frame.header.stream_id);
        try std.testing.expect(!connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    }
}

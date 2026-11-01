//! Complete request APIs include output and upload flow control in one budget.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const frame_io = @import("../frame/io.zig");
const wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const stream_io = @import("../../../internal/stream_io.zig");
const allocator = std.testing.allocator;

const PeerInput = struct {
    io: std.Io,
    stream: std.Io.net.Stream,

    pub fn read(self: @This(), buffer: []u8) !usize {
        var buffers = [_][]u8{buffer};
        return self.io.vtable.netRead(self.io.userdata, self.stream.socket.handle, &buffers);
    }

    pub fn readWithDeadline(self: @This(), buffer: []u8, deadline: std.Io.Clock.Timestamp) !usize {
        return stream_io.readSomeWithDeadline(self.io, self.stream, buffer, deadline);
    }
};

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
            // This test requires successful CANCEL output. Do not race the
            // executor against the small production default cleanup cap.
            connection.limits.terminal_cleanup_timeout = .fromMilliseconds(200);
        },
    }
    try fixture.startRescue();
    var observer: Observer = .{};
    const started = std.Io.Clock.awake.now(connection.io);
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromMilliseconds(30), .clock = .awake });
    errdefer |err| if (phase == .flow_control) {
        std.debug.print("flow cleanup mode={} error={s} write_failed={} elapsed_ns={} remaining_ns={}\n", .{ mode, @errorName(err), connection.terminal_write_failed, started.untilNow(connection.io, .awake).nanoseconds, std.Io.Clock.Timestamp.now(connection.io, .awake).durationTo(deadline).raw.nanoseconds });
    };
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
        try std.testing.expect(!connection.terminal_write_failed);
        const input: PeerInput = .{ .io = connection.io, .stream = fixture.peer };
        const input_deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromSeconds(1), .clock = .awake });
        var head = try frame_io.readOwnedTransportWithDeadline(allocator, input, 16_384, input_deadline);
        defer head.deinit(allocator);
        try std.testing.expectEqual(http2.FrameType.headers, head.frame.header.frame_type);
        var data = try frame_io.readOwnedTransportWithDeadline(allocator, input, 16_384, input_deadline);
        defer data.deinit(allocator);
        try std.testing.expectEqual(http2.FrameType.data, data.frame.header.frame_type);
        try std.testing.expectEqualStrings("u", data.frame.payload);
        var terminal = try frame_io.readOwnedTransportWithDeadline(allocator, input, 16_384, input_deadline);
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
        var sent = try frame_io.readOwnedTransportWithDeadline(allocator, PeerInput{ .io = connection.io, .stream = fixture.peer }, 16_384, deadline);
        defer sent.deinit(allocator);
        try std.testing.expectEqual(http2.FrameType.headers, sent.frame.header.frame_type);
        try std.testing.expectEqual(@as(u31, 1), sent.frame.header.stream_id);
        try std.testing.expect(!connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    }
}

test "HTTP/2 complete request cleanup separates premature timeout from OOM budget" {
    const Complete = @import("complete.zig");
    const Connection = struct {
        io: std.Io,
        allocator: std.mem.Allocator = allocator,
        role: runtime.Role = .client,
        last_peer_reset: ?http2.ResetStreamPayload = null,
        default_scheme: ?[]const u8 = null,
        peer_enable_connect_protocol: bool = true,
        aggregate_timeout_unusable: bool = false,
        terminal_write_failed: bool = false,
        limits: runtime.Limits = .{ .terminal_cleanup_timeout = .fromMilliseconds(200) },
        failure: anyerror,
        upload_deadline: ?std.Io.Clock.Timestamp = null,
        cleanup_deadline: ?std.Io.Clock.Timestamp = null,
        released: bool = false,
        forgotten: bool = false,
    };
    const Hooks = struct {
        pub const ErrorType = anyerror;
        pub const PendingType = struct {
            stream_id: u31,
            request_method: []const u8,
            extended_connect: bool,
            upload: ?@import("upload.zig").Upload,
        };
        pub fn synchronize(_: *Connection, _: ?std.Io.Clock.Timestamp) !void {}
        pub fn resolveAuthority(_: *Connection, authority: ?[]const u8, _: []const http2.Hpack.HeaderField) ?[]const u8 {
            return authority;
        }
        pub fn reserve(_: *Connection) !u31 {
            return 1;
        }
        pub fn burst(self: *Connection, _: u31, _: []const http2.Hpack.HeaderField, _: []const u8, _: bool, deadline: ?std.Io.Clock.Timestamp, head_committed: *bool, body_written: *usize) anyerror!void {
            self.upload_deadline = deadline;
            head_committed.* = true;
            body_written.* = 1;
            // A transport can report Timeout before its clock's exact
            // timestamp (e.g. when an OS poll timeout rounds milliseconds).
            return self.failure;
        }
        pub fn headers(_: *Connection, _: u31, _: []const http2.Hpack.HeaderField, _: bool, _: ?std.Io.Clock.Timestamp) !void {
            return error.UnexpectedFrame;
        }
        pub fn data(_: *Connection, _: u31, _: []const u8, _: bool, _: *usize, _: ?std.Io.Clock.Timestamp) !void {
            return error.UnexpectedFrame;
        }
        pub fn discard(self: *Connection, _: u31, before: ?std.Io.Clock.Timestamp) void {
            self.cleanup_deadline = before;
        }
        pub fn release(self: *Connection, _: u31) void {
            self.released = true;
        }
        pub fn forgetWindows(self: *Connection, _: u31) void {
            self.forgotten = true;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ error.Timeout, error.OutOfMemory }) |failure| {
        var connection: Connection = .{ .io = io, .failure = failure };
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(100), .clock = .awake });
        try std.testing.expectError(failure, Complete.send(&connection, runtime.RequestOptions{ .method = "POST", .authority = "localhost", .body = "u" }, deadline, Hooks));
        try std.testing.expect(std.Io.Clock.Timestamp.compare(deadline, .eq, connection.upload_deadline.?));
        try std.testing.expect(std.Io.Clock.Timestamp.compare(connection.cleanup_deadline.?, if (failure == error.Timeout) .gt else .eq, deadline));
        try std.testing.expect(connection.released and connection.forgotten);
    }
}

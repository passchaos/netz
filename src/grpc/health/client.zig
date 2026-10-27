//! Single-owner client transport for grpc.health.v1.Health/Watch.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const health = @import("../health.zig");
const compression = @import("../compression.zig");
const metadata_mod = @import("../metadata.zig");
const duplex = @import("../stream/duplex.zig");
const stream_codec = @import("../stream/codec.zig");
const Response = health.Response;
const Error = health.Error;
const watch_path = health.watch_path;
const encodeRequestAlloc = health.encodeRequestAlloc;
const decodeResponse = health.decodeResponse;

pub const WatchOptions = struct {
    service: []const u8 = "",
    authority: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    metadata: []const http2.Hpack.HeaderField = &.{},
    binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    accepted_encodings: compression.AlgorithmSet = .supported,
    max_message_size: usize = 16 * 1024 * 1024,
};

pub const WatchEvent = union(enum) {
    status: Response,
    terminal: duplex.Response,

    pub fn deinit(self: *WatchEvent) void {
        switch (self.*) {
            .terminal => |*terminal| terminal.deinit(),
            .status => {},
        }
        self.* = undefined;
    }
};

pub const WatchError = Error || duplex.Error || error{
    NotHealthWatchRequest,
};

/// One active server-streaming Health `Watch`. The value exclusively owns the
/// underlying HTTP/2 connection reader until cancellation, terminal status,
/// or deinitialization.
pub const ClientWatch = struct {
    allocator: std.mem.Allocator,
    stream: duplex.ClientDuplex,
    pending: std.ArrayList(Response) = .empty,
    pending_head: usize = 0,
    request_pending: bool = false,
    terminal_seen: bool = false,

    pub fn deinit(self: *ClientWatch) void {
        self.pending.deinit(self.allocator);
        self.stream.deinit();
        self.* = undefined;
    }

    /// Send RST_STREAM(CANCEL). The owning HTTP/2 connection is reusable once
    /// this succeeds and the watch is deinitialized.
    pub fn cancel(self: *ClientWatch) WatchError!void {
        if (self.terminal_seen) return error.ConnectionClosed;
        try self.stream.reset(.cancel);
        self.terminal_seen = true;
    }

    pub fn next(self: *ClientWatch) WatchError!WatchEvent {
        return self.nextUntil(null);
    }

    pub fn nextWithTimeout(
        self: *ClientWatch,
        timeout: std.Io.Duration,
    ) WatchError!WatchEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.nextWithDeadline(.fromNow(
            self.stream.transport.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn nextWithDeadline(
        self: *ClientWatch,
        deadline: std.Io.Clock.Timestamp,
    ) WatchError!WatchEvent {
        return self.nextUntil(deadline);
    }

    fn nextUntil(
        self: *ClientWatch,
        deadline: ?std.Io.Clock.Timestamp,
    ) WatchError!WatchEvent {
        if (self.takePending()) |response| {
            return .{ .status = response };
        }
        if (self.terminal_seen) return error.ConnectionClosed;
        try self.resumeRequestIfNeeded(deadline);

        while (true) {
            var event = if (deadline) |absolute|
                try self.stream.readResponseEventWithDeadline(
                    absolute,
                    self,
                    collectResponse,
                )
            else
                try self.stream.readResponseEvent(
                    self,
                    collectResponse,
                );
            switch (event) {
                .terminal => |terminal| {
                    event = undefined;
                    self.terminal_seen = true;
                    return .{ .terminal = terminal };
                },
                .informational, .initial_metadata => {
                    event.deinit(self.allocator);
                    try self.resumeRequestIfNeeded(deadline);
                },
                .messages => {
                    event.deinit(self.allocator);
                    if (self.takePending()) |response| {
                        return .{ .status = response };
                    }
                    try self.resumeRequestIfNeeded(deadline);
                },
            }
        }
    }

    fn collectResponse(
        self: *ClientWatch,
        message: stream_codec.DecodedMessage,
    ) WatchError!void {
        try self.pending.append(
            self.allocator,
            try decodeResponse(message.payload),
        );
    }

    fn resumeRequestIfNeeded(
        self: *ClientWatch,
        deadline: ?std.Io.Clock.Timestamp,
    ) WatchError!void {
        if (!self.request_pending) return;
        self.stream.deadline = deadline;
        defer self.stream.deadline = null;
        self.request_pending = switch (self.stream.resumeMessage() catch |err| {
            self.terminal_seen = true;
            return err;
        }) {
            .complete => false,
            .peer_event => true,
        };
    }

    fn takePending(self: *ClientWatch) ?Response {
        if (self.pending_head == self.pending.items.len) return null;
        const result = self.pending.items[self.pending_head];
        self.pending_head += 1;
        if (self.pending_head == self.pending.items.len) {
            self.pending.clearRetainingCapacity();
            self.pending_head = 0;
        }
        return result;
    }
};

pub fn startWatch(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: WatchOptions,
) WatchError!ClientWatch {
    return startWatchUntil(connection, allocator, options, null);
}

pub fn startWatchWithTimeout(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: WatchOptions,
    timeout: std.Io.Duration,
) WatchError!ClientWatch {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return startWatchWithDeadline(connection, allocator, options, .fromNow(
        connection.io,
        .{ .raw = timeout, .clock = .awake },
    ));
}

/// The deadline bounds request output, including flow control. Watch has no
/// grpc-timeout and remains active after this operation budget expires.
pub fn startWatchWithDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: WatchOptions,
    deadline: std.Io.Clock.Timestamp,
) WatchError!ClientWatch {
    if (deadline.clock != .awake or
        deadline.durationFromNow(connection.io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    return startWatchUntil(connection, allocator, options, deadline);
}

fn startWatchUntil(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: WatchOptions,
    deadline: ?std.Io.Clock.Timestamp,
) WatchError!ClientWatch {
    const request = try encodeRequestAlloc(allocator, .{
        .service = options.service,
    });
    defer allocator.free(request);
    const request_options: duplex.RequestOptions = .{
        .path = watch_path,
        .authority = options.authority,
        .scheme = options.scheme,
        .accepted_encodings = options.accepted_encodings,
        .metadata = options.metadata,
        .binary_metadata = options.binary_metadata,
        .max_message_size = options.max_message_size,
    };
    var stream = if (deadline) |absolute|
        try duplex.startDuplexWithIoDeadline(connection, allocator, request_options, absolute)
    else
        try duplex.startDuplex(connection, allocator, request_options);
    errdefer stream.deinit();
    stream.deadline = deadline;
    defer stream.deadline = null;
    const write_result = try stream.writeFinalMessage(request);
    // Clear before copying the stream into the returned Watch.
    stream.deadline = null;
    return .{
        .allocator = allocator,
        .stream = stream,
        .request_pending = write_result == .peer_event,
    };
}

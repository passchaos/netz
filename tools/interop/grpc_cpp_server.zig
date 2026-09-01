//! One-shot netz server for focused upstream gRPC C++ client scenarios.

const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

const service_path = "/grpc.testing.TestService/FullDuplexCall";
const message_limit = messages.max_payload_size + 64;
const canonical_request_sizes = [_]usize{ 27_182, 8, 1_828, 45_904 };
const canonical_response_sizes = [_]usize{ 31_415, 9, 2_653, 58_979 };

const Scenario = enum {
    ping_pong,
    empty_stream,
    cancel_after_first_response,
    timeout_on_sleeping_server,

    fn parse(raw: []const u8) !Scenario {
        return std.meta.stringToEnum(Scenario, raw) orelse error.InvalidArgument;
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const scenario = try Scenario.parse(args[2]);

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .max_frame_payload = 64 * 1024,
            .max_body_bytes = message_limit,
            .initial_window_size = 512 * 1024,
            .initial_connection_window_size = 2 * 1024 * 1024,
            .handshake_timeout = .fromSeconds(5),
        },
        message_limit,
    );
    defer server.deinit();

    std.debug.print(
        "netz grpc server ready: port={d} scenario={s}\n",
        .{ port, @tagName(scenario) },
    );

    var connection = try server.accept();
    defer connection.deinit();
    var stream = try connection.acceptDuplex();
    defer stream.deinit();
    if (!std.mem.eql(u8, stream.path, service_path)) {
        try stream.finish(.unimplemented, null, &.{}, &.{});
        return error.UnexpectedMethod;
    }

    try serveScenario(allocator, io, &stream, scenario);
    std.debug.print(
        "netz grpc server completed: scenario={s}\n",
        .{@tagName(scenario)},
    );
}

const RequestQueue = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(messages.RequestOptions) = .empty,

    fn deinit(self: *@This()) void {
        self.items.deinit(self.allocator);
    }

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        try self.items.append(
            self.allocator,
            try messages.decodeStreamingOutputCallRequest(message.payload),
        );
    }
};

fn serveScenario(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: *netz.grpc.ServerDuplex,
    scenario: Scenario,
) !void {
    var queue = RequestQueue{ .allocator = allocator };
    defer queue.deinit();

    const deadline = if (stream.timeout) |timeout|
        std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = timeout.duration(),
            .clock = .awake,
        })
    else
        null;

    switch (scenario) {
        .ping_pong => try servePingPong(io, stream, &queue, deadline),
        .empty_stream => try serveEmpty(stream, &queue, deadline),
        .cancel_after_first_response => try serveCancellation(io, stream, &queue, deadline),
        .timeout_on_sleeping_server => try serveSleepingDeadline(stream, &queue, deadline),
    }
}

fn servePingPong(
    io: std.Io,
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    try stream.startResponse(.{
        .request_accepted_encodings = stream.accepted_encodings,
        .max_message_size = message_limit,
    });
    for (canonical_request_sizes, canonical_response_sizes) |request_size, response_size| {
        const request = try nextRequest(stream, queue, deadline);
        try expectRequest(request, request_size, response_size);
        try maybeSleep(io, request.interval_us, deadline);
        try writeResponse(stream, queue, deadline, response_size);
    }
    try expectFinished(stream, queue, deadline);
    try stream.finishOk();
}

fn serveEmpty(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    try expectFinished(stream, queue, deadline);
    try stream.finishOk();
}

fn serveCancellation(
    io: std.Io,
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    try stream.startResponse(.{
        .request_accepted_encodings = stream.accepted_encodings,
        .max_message_size = message_limit,
    });
    const request = try nextRequest(stream, queue, deadline);
    try expectRequest(request, 27_182, 31_415);
    try maybeSleep(io, request.interval_us, deadline);
    writeResponse(stream, queue, deadline, 31_415) catch |err| switch (err) {
        // Cancellation can race the last flow-control slice of the first
        // response. Observing the peer's CANCEL there is equivalent to seeing
        // it in the receive loop below.
        error.PeerCancelled => return,
        else => return err,
    };

    while (true) {
        var event = try readEvent(stream, queue, deadline);
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => return error.ExpectedCancellation,
            .reset => |reset| {
                if (reset.error_code != .cancel) return error.UnexpectedReset;
                return;
            },
        }
    }
}

fn serveSleepingDeadline(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    const absolute = deadline orelse return error.MissingTimeout;
    const request = nextRequest(stream, queue, absolute) catch |err| switch (err) {
        error.Timeout => {
            try stream.finish(.deadline_exceeded, null, &.{}, &.{});
            return;
        },
        else => return err,
    };
    if (request.response_size != null or request.request_body_size != 27_182) {
        return error.UnexpectedRequest;
    }

    var event = readEvent(stream, queue, absolute) catch |err| switch (err) {
        error.Timeout => {
            try stream.finish(.deadline_exceeded, null, &.{}, &.{});
            return;
        },
        else => return err,
    };
    defer event.deinit();
    return error.ExpectedDeadline;
}

fn nextRequest(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: anytype,
) !messages.RequestOptions {
    while (queue.items.items.len == 0) {
        var event = try readEvent(stream, queue, deadline);
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => return error.UnexpectedEndOfStream,
            .reset => return error.UnexpectedReset,
        }
    }
    return queue.items.orderedRemove(0);
}

fn expectFinished(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (queue.items.items.len != 0) return error.UnexpectedRequest;
    while (true) {
        var event = try readEvent(stream, queue, deadline);
        defer event.deinit();
        switch (event) {
            .messages => if (queue.items.items.len != 0) return error.UnexpectedRequest,
            .finished => return,
            .reset => return error.UnexpectedReset,
        }
    }
}

fn readEvent(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !netz.grpc.ServerDuplexEvent {
    return if (deadline) |absolute|
        stream.readRequestEventWithDeadline(
            absolute,
            queue,
            RequestQueue.consume,
        )
    else
        stream.readRequestEvent(queue, RequestQueue.consume);
}

fn expectRequest(
    request: messages.RequestOptions,
    request_size: usize,
    response_size: usize,
) !void {
    if (request.request_body_size != request_size or
        request.response_size != @as(u32, @intCast(response_size)))
    {
        return error.UnexpectedRequest;
    }
}

fn writeResponse(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
    response_size: usize,
) !void {
    const encoded = try messages.encodeStreamingOutputCallResponseAlloc(
        queue.allocator,
        response_size,
    );
    defer queue.allocator.free(encoded);

    var result = try stream.writeMessage(encoded);
    while (result == .peer_event) {
        var event = try readEvent(stream, queue, deadline);
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => {},
            .reset => |reset| {
                if (reset.error_code == .cancel) return error.PeerCancelled;
                return error.UnexpectedReset;
            },
        }
        result = try stream.resumeMessage();
    }
}

fn maybeSleep(
    io: std.Io,
    interval_us: u32,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (interval_us == 0) return;
    var duration = std.Io.Duration.fromMicroseconds(interval_us);
    if (deadline) |absolute| {
        const remaining = absolute.durationFromNow(io).raw;
        if (remaining.nanoseconds <= 0) return error.Timeout;
        if (remaining.nanoseconds < duration.nanoseconds) duration = remaining;
    }
    try std.Io.sleep(io, duration, .awake);
    if (deadline) |absolute| {
        if (absolute.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
    }
}

//! Standard ORCA out-of-band server-streaming transport.
//!
//! One request selects the report interval and optional request-cost names;
//! the server then emits `OrcaLoadReport` messages until the client cancels.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const compression = @import("../compression.zig");
const metadata = @import("../metadata.zig");
const protobuf = @import("../protobuf.zig");
const report_mod = @import("../orca.zig");
const duplex = @import("../stream/duplex.zig");
const stream_codec = @import("../stream/codec.zig");

pub const path =
    "/xds.service.orca.v3.OpenRcaService/StreamCoreMetrics";
pub const service = "xds.service.orca.v3.OpenRcaService";
pub const method = "StreamCoreMetrics";
const max_duration_seconds: u64 = 315_576_000_000;

pub const Error = report_mod.Error || duplex.Error || error{
    InvalidReportInterval,
    InvalidRequest,
    NotOrcaOobRequest,
};

pub const Request = struct {
    report_interval: std.Io.Duration = .zero,
    request_cost_names: []const []const u8 = &.{},
};

pub const OwnedRequest = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    names: [][]const u8,
    request: Request,

    pub fn deinit(self: *OwnedRequest) void {
        self.allocator.free(self.names);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn encodeRequestAlloc(
    allocator: std.mem.Allocator,
    request: Request,
) Error![]u8 {
    try validateRequest(request);
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    if (request.report_interval.nanoseconds != 0) {
        const ns: u96 = @intCast(request.report_interval.nanoseconds);
        const seconds: u64 = @intCast(ns / std.time.ns_per_s);
        const nanos: u32 = @intCast(ns % std.time.ns_per_s);
        var duration: std.ArrayList(u8) = .empty;
        defer duration.deinit(allocator);
        if (seconds != 0) try appendVarint(&duration, allocator, 1, seconds);
        if (nanos != 0) try appendVarint(&duration, allocator, 2, nanos);
        try appendBytes(&output, allocator, 1, duration.items);
    }
    for (request.request_cost_names) |name_value| {
        try appendBytes(&output, allocator, 2, name_value);
    }
    return output.toOwnedSlice(allocator);
}

pub fn decodeRequestAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!OwnedRequest {
    const owned = try allocator.dupe(u8, bytes);
    errdefer allocator.free(owned);
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(allocator);
    var interval: std.Io.Duration = .zero;
    var reader: protobuf.Reader = .{ .bytes = owned };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            interval = try decodeDuration(try reader.bytesValue());
        } else if (field.number == 2 and field.wire_type == 2) {
            try names.append(allocator, try reader.string());
        } else try reader.skip(field);
    }
    const owned_names = try names.toOwnedSlice(allocator);
    errdefer allocator.free(owned_names);
    const request = Request{
        .report_interval = interval,
        .request_cost_names = owned_names,
    };
    try validateRequest(request);
    return .{
        .allocator = allocator,
        .bytes = owned,
        .names = owned_names,
        .request = request,
    };
}

pub const ClientOptions = struct {
    report_interval: std.Io.Duration = .zero,
    request_cost_names: []const []const u8 = &.{},
    authority: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    metadata: []const http2.Hpack.HeaderField = &.{},
    binary_metadata: []const metadata.BinaryMetadata = &.{},
    accepted_encodings: compression.AlgorithmSet = .supported,
    max_message_size: usize = 16 * 1024 * 1024,
};

pub const ClientEvent = union(enum) {
    report: report_mod.OwnedLoadReport,
    terminal: duplex.Response,

    pub fn deinit(self: *ClientEvent) void {
        switch (self.*) {
            .report => |*report| report.deinit(),
            .terminal => |*terminal| terminal.deinit(),
        }
        self.* = undefined;
    }
};

pub const ClientStream = struct {
    allocator: std.mem.Allocator,
    stream: duplex.ClientDuplex,
    pending: std.ArrayList(report_mod.OwnedLoadReport) = .empty,
    pending_head: usize = 0,
    request_pending: bool = false,
    terminal_seen: bool = false,

    pub fn deinit(self: *ClientStream) void {
        for (self.pending.items[self.pending_head..]) |*report| {
            report.deinit();
        }
        self.pending.deinit(self.allocator);
        self.stream.deinit();
        self.* = undefined;
    }

    pub fn cancel(self: *ClientStream) Error!void {
        if (self.terminal_seen) return error.ConnectionClosed;
        try self.stream.reset(.cancel);
        self.terminal_seen = true;
    }

    pub fn next(self: *ClientStream) Error!ClientEvent {
        return self.nextUntil(null);
    }

    pub fn nextWithTimeout(
        self: *ClientStream,
        timeout: std.Io.Duration,
    ) Error!ClientEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.nextWithDeadline(.fromNow(
            self.stream.transport.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn nextWithDeadline(
        self: *ClientStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ClientEvent {
        if (deadline.clock != .awake) return error.Timeout;
        return self.nextUntil(deadline);
    }

    fn nextUntil(
        self: *ClientStream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ClientEvent {
        if (self.takePending()) |report| return .{ .report = report };
        if (self.terminal_seen) return error.ConnectionClosed;
        try self.resumeRequestIfNeeded(deadline);
        while (true) {
            var event = if (deadline) |absolute|
                try self.stream.readResponseEventWithDeadline(
                    absolute,
                    self,
                    collectReport,
                )
            else
                try self.stream.readResponseEvent(self, collectReport);
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
                    try self.resumeRequestIfNeeded(deadline);
                    if (self.takePending()) |report| {
                        return .{ .report = report };
                    }
                },
            }
        }
    }

    fn collectReport(
        self: *ClientStream,
        message: stream_codec.DecodedMessage,
    ) Error!void {
        var report = try report_mod.decodeAlloc(
            self.allocator,
            message.payload,
        );
        errdefer report.deinit();
        try self.pending.append(self.allocator, report);
    }

    fn resumeRequestIfNeeded(
        self: *ClientStream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (!self.request_pending) return;
        self.stream.deadline = deadline;
        defer self.stream.deadline = null;
        self.request_pending = switch (try self.stream.resumeMessage()) {
            .complete => false,
            .peer_event => true,
        };
    }

    fn takePending(self: *ClientStream) ?report_mod.OwnedLoadReport {
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

pub fn start(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: ClientOptions,
) Error!ClientStream {
    return startUntil(connection, allocator, options, null);
}

pub fn startWithTimeout(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: ClientOptions,
    timeout: std.Io.Duration,
) Error!ClientStream {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return startWithDeadline(connection, allocator, options, .fromNow(
        connection.io,
        .{ .raw = timeout, .clock = .awake },
    ));
}

/// The deadline bounds request output only. The OOB stream remains active and
/// individual report reads use their own deadlines.
pub fn startWithDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: ClientOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!ClientStream {
    if (deadline.clock != .awake or
        deadline.durationFromNow(connection.io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    return startUntil(connection, allocator, options, deadline);
}

fn startUntil(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: ClientOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!ClientStream {
    const request = try encodeRequestAlloc(allocator, .{
        .report_interval = options.report_interval,
        .request_cost_names = options.request_cost_names,
    });
    defer allocator.free(request);
    const request_options: duplex.RequestOptions = .{
        .path = path,
        .authority = options.authority,
        .scheme = options.scheme,
        .accepted_encodings = options.accepted_encodings,
        .metadata = options.metadata,
        .binary_metadata = options.binary_metadata,
        .max_message_size = options.max_message_size,
    };
    var stream = if (deadline) |absolute|
        try duplex.startDuplexWithIoDeadline(
            connection,
            allocator,
            request_options,
            absolute,
        )
    else
        try duplex.startDuplex(connection, allocator, request_options);
    errdefer stream.deinit();
    stream.deadline = deadline;
    defer stream.deadline = null;
    const write_result = try stream.writeFinalMessage(request);
    stream.deadline = null;
    return .{
        .allocator = allocator,
        .stream = stream,
        .request_pending = write_result == .peer_event,
    };
}

pub const ServerSession = struct {
    stream: duplex.ServerDuplex,
    request: OwnedRequest,
    report_pending: bool = false,

    pub fn deinit(self: *ServerSession) void {
        self.request.deinit();
        self.stream.deinit();
        self.* = undefined;
    }

    pub fn writeReport(
        self: *ServerSession,
        report: report_mod.LoadReport,
    ) Error!duplex.WriteResult {
        if (self.report_pending) return error.InvalidStreamState;
        var filtered: std.ArrayList(report_mod.Metric) = .empty;
        defer filtered.deinit(self.stream.allocator);
        var selected = report;
        if (self.request.request.request_cost_names.len != 0) {
            for (report.request_cost) |metric| {
                if (self.requestsCost(metric.name)) {
                    try filtered.append(self.stream.allocator, metric);
                }
            }
            selected.request_cost = filtered.items;
        }
        const encoded = try report_mod.encodeAlloc(
            self.stream.allocator,
            selected,
        );
        defer self.stream.allocator.free(encoded);
        const result = try self.stream.writeMessage(encoded);
        self.report_pending = result == .peer_event;
        return result;
    }

    pub fn resumeReport(self: *ServerSession) Error!duplex.WriteResult {
        if (!self.report_pending) return error.InvalidStreamState;
        const result = try self.stream.resumeMessage();
        self.report_pending = result == .peer_event;
        return result;
    }

    pub fn finish(self: *ServerSession) Error!void {
        if (self.report_pending) return error.InvalidStreamState;
        try self.stream.finishOk();
    }

    pub fn waitForPeerResetWithTimeout(
        self: *ServerSession,
        timeout: std.Io.Duration,
    ) Error!http2.ResetStreamPayload {
        return self.stream.waitForPeerResetWithTimeout(timeout);
    }

    fn requestsCost(self: *const ServerSession, name_value: []const u8) bool {
        for (self.request.request.request_cost_names) |requested| {
            if (std.mem.eql(u8, requested, name_value)) return true;
        }
        return false;
    }
};

/// Validate the one-message request and start a server-streaming response.
/// The returned session exposes the requested cadence; scheduling remains with
/// the connection owner so sibling RPCs can be driven without concurrent frame
/// readers.
pub fn accept(accepted: duplex.ServerDuplex) Error!ServerSession {
    var stream = accepted;
    errdefer stream.deinit();
    if (!std.mem.eql(u8, stream.path, path) or
        !std.mem.eql(u8, stream.service, service) or
        !std.mem.eql(u8, stream.method, method))
    {
        return error.NotOrcaOobRequest;
    }
    const Collector = struct {
        allocator: std.mem.Allocator,
        request: ?OwnedRequest = null,
        invalid: bool = false,

        fn deinit(self: *@This()) void {
            if (self.request) |*request| request.deinit();
        }

        fn consume(
            self: *@This(),
            message: stream_codec.DecodedMessage,
        ) Error!void {
            if (self.request != null) {
                self.invalid = true;
                return;
            }
            self.request = decodeRequestAlloc(
                self.allocator,
                message.payload,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    self.invalid = true;
                    return;
                },
            };
        }
    };
    var collector = Collector{ .allocator = stream.allocator };
    defer collector.deinit();
    while (true) {
        var event = try stream.readRequestEvent(
            &collector,
            Collector.consume,
        );
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => |terminal| {
                if (terminal.message_count != 1 or
                    collector.request == null or collector.invalid)
                {
                    try stream.finish(
                        .invalid_argument,
                        "could not parse ORCA OOB request",
                        &.{},
                        &.{},
                    );
                    return error.InvalidRequest;
                }
                break;
            },
            .reset => return error.ConnectionClosed,
        }
    }
    try stream.startResponse(.{
        .request_accepted_encodings = stream.accepted_encodings,
    });
    const request = collector.request.?;
    collector.request = null;
    return .{ .stream = stream, .request = request };
}

fn validateRequest(request: Request) Error!void {
    if (request.report_interval.nanoseconds < 0) {
        return error.InvalidReportInterval;
    }
    const seconds: u96 = @intCast(
        @divFloor(request.report_interval.nanoseconds, std.time.ns_per_s),
    );
    if (seconds > max_duration_seconds) {
        return error.InvalidReportInterval;
    }
    for (request.request_cost_names) |name_value| {
        if (!std.unicode.utf8ValidateSlice(name_value)) {
            return error.InvalidRequest;
        }
    }
}

fn decodeDuration(bytes: []const u8) Error!std.Io.Duration {
    var seconds: u64 = 0;
    var nanos: u32 = 0;
    var reader: protobuf.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw > max_duration_seconds) {
                return error.InvalidReportInterval;
            }
            seconds = raw;
        } else if (field.number == 2 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw >= std.time.ns_per_s) {
                return error.InvalidReportInterval;
            }
            nanos = @intCast(raw);
        } else try reader.skip(field);
    }
    const total = std.math.add(
        i96,
        std.math.mul(i96, seconds, std.time.ns_per_s) catch
            return error.InvalidReportInterval,
        nanos,
    ) catch return error.InvalidReportInterval;
    return .fromNanoseconds(total);
}

fn appendVarint(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    number: u8,
    value: anytype,
) std.mem.Allocator.Error!void {
    try output.append(allocator, number << 3);
    try appendRawVarint(output, allocator, value);
}

fn appendBytes(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    number: u8,
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    try output.append(allocator, (number << 3) | 2);
    try appendRawVarint(output, allocator, bytes.len);
    try output.appendSlice(allocator, bytes);
}

fn appendRawVarint(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    raw: anytype,
) std.mem.Allocator.Error!void {
    var value: u64 = @intCast(raw);
    while (value >= 128) : (value >>= 7) {
        try output.append(allocator, @as(u8, @truncate(value)) | 128);
    }
    try output.append(allocator, @intCast(value));
}

test {
    _ = @import("oob_tests.zig");
}

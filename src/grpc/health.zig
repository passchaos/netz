//! Standard `grpc.health.v1.Health` messages and service-status registry.
//!
//! The registry provides the state and wakeup semantics required by both the
//! unary `Check` method and the server-streaming `Watch` method. Transport
//! adapters live separately so applications can use this state with any
//! `std.Io`-backed gRPC endpoint.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const call = @import("call.zig");
const compression = @import("compression.zig");
const metadata_mod = @import("metadata.zig");
const duplex = @import("stream/duplex.zig");
const stream_codec = @import("stream/codec.zig");
const wire = @import("wire.zig");

pub const check_path = "/grpc.health.v1.Health/Check";
pub const watch_path = "/grpc.health.v1.Health/Watch";
pub const max_service_name_len = 200;

pub const Error = std.mem.Allocator.Error || error{
    InvalidFieldNumber,
    InvalidServingStatus,
    InvalidUtf8,
    MalformedMessage,
    ServiceNameTooLong,
    TruncatedMessage,
    VarintOverflow,
};

pub const ServingStatus = enum(u8) {
    unknown = 0,
    serving = 1,
    not_serving = 2,
    service_unknown = 3,
};

pub const Request = struct {
    service: []const u8 = "",
};

pub const Response = struct {
    status: ServingStatus = .unknown,
};

pub const CheckOptions = struct {
    service: []const u8 = "",
    authority: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    timeout: ?wire.Timeout = null,
    metadata: []const http2.Hpack.HeaderField = &.{},
    binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    max_message_size: usize = 16 * 1024 * 1024,
};

pub const CheckResult = union(enum) {
    response: Response,
    rpc_failure: wire.Status,
};

pub const CheckError = Error || call.Error || error{
    NotHealthCheckRequest,
};

const client = @import("health/client.zig");
pub const WatchOptions = client.WatchOptions;
pub const WatchEvent = client.WatchEvent;
pub const WatchError = client.WatchError;
pub const ClientWatch = client.ClientWatch;
pub const startWatch = client.startWatch;
pub const startWatchWithTimeout = client.startWatchWithTimeout;
pub const startWatchWithDeadline = client.startWatchWithDeadline;
pub const reconnecting = @import("health/reconnecting.zig");
pub const ReconnectingWatch = reconnecting.ReconnectingWatch;
pub const ReconnectingWatchOptions = reconnecting.Options;
pub const ReconnectingWatchEvent = reconnecting.Event;

test {
    _ = client;
    _ = reconnecting;
    _ = @import("health/multiplex_tests.zig");
}

pub fn encodeRequestAlloc(
    allocator: std.mem.Allocator,
    request: Request,
) Error![]u8 {
    try validateServiceName(request.service);
    if (request.service.len == 0) return allocator.alloc(u8, 0);

    const length_len = varintLen(request.service.len);
    const result = try allocator.alloc(
        u8,
        1 + length_len + request.service.len,
    );
    result[0] = 0x0a;
    const end = writeVarint(result[1..], request.service.len);
    @memcpy(result[1 + end ..], request.service);
    return result;
}

pub fn decodeRequest(bytes: []const u8) Error!Request {
    var request: Request = .{};
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const key = try readVarint(bytes, &cursor);
        const field_number = try fieldNumber(key);
        const wire_type: u3 = @intCast(key & 0x07);
        if (field_number == 1 and wire_type == 2) {
            const service = try readLengthDelimited(bytes, &cursor);
            try validateServiceName(service);
            request.service = service;
        } else {
            try skipValue(bytes, &cursor, field_number, wire_type, 0);
        }
    }
    return request;
}

pub fn encodeResponseAlloc(
    allocator: std.mem.Allocator,
    response: Response,
) Error![]u8 {
    if (response.status == .unknown) return allocator.alloc(u8, 0);
    const result = try allocator.alloc(u8, 2);
    result[0] = 0x08;
    result[1] = @intFromEnum(response.status);
    return result;
}

pub fn decodeResponse(bytes: []const u8) Error!Response {
    var response: Response = .{};
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const key = try readVarint(bytes, &cursor);
        const field_number = try fieldNumber(key);
        const wire_type: u3 = @intCast(key & 0x07);
        if (field_number == 1 and wire_type == 0) {
            const raw = try readVarint(bytes, &cursor);
            if (raw > std.math.maxInt(u8)) {
                return error.InvalidServingStatus;
            }
            response.status = std.enums.fromInt(
                ServingStatus,
                @as(u8, @intCast(raw)),
            ) orelse return error.InvalidServingStatus;
        } else {
            try skipValue(bytes, &cursor, field_number, wire_type, 0);
        }
    }
    return response;
}

/// Perform the standard unary Health `Check` RPC over an existing HTTP/2
/// connection. A non-OK gRPC status is returned as `rpc_failure`; malformed
/// successful payloads remain protocol errors.
pub fn check(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: CheckOptions,
) CheckError!CheckResult {
    const request = try encodeRequestAlloc(allocator, .{
        .service = options.service,
    });
    defer allocator.free(request);
    var response = try call.unaryCall(connection, allocator, .{
        .path = check_path,
        .authority = options.authority,
        .scheme = options.scheme,
        .message = request,
        .timeout = options.timeout,
        .metadata = options.metadata,
        .binary_metadata = options.binary_metadata,
        .max_message_size = options.max_message_size,
    });
    defer response.deinit();

    if (response.status != .ok) {
        if (response.message != null) return error.InvalidMessageCount;
        return .{ .rpc_failure = response.status };
    }
    const message = response.message orelse return error.InvalidMessageCount;
    const decoded = try decodeResponse(message.payload);
    if (decoded.status == .service_unknown) {
        return error.InvalidServingStatus;
    }
    return .{ .response = decoded };
}

/// Validate and answer one already-decoded unary Health `Check` request.
/// Unknown services use the standard trailers-only `NOT_FOUND` response;
/// malformed protobuf requests use `INVALID_ARGUMENT`.
pub fn writeCheckResponse(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    registry: *Registry,
    request: *const call.UnaryRequest,
) CheckError!void {
    if (!std.mem.eql(u8, request.path, check_path) or
        !std.mem.eql(u8, request.service, "grpc.health.v1.Health") or
        !std.mem.eql(u8, request.method, "Check"))
    {
        return error.NotHealthCheckRequest;
    }
    const decoded = decodeRequest(request.message.payload) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return call.writeUnaryResponse(
                connection,
                allocator,
                request.stream_id,
                .{
                    .status = .invalid_argument,
                    .status_message = "could not parse request",
                    .trailers_only = true,
                },
            ),
        };
    const status_value = (try registry.status(decoded.service)) orelse {
        return call.writeUnaryResponse(connection, allocator, request.stream_id, .{
            .status = .not_found,
            .status_message = "service name unknown",
            .trailers_only = true,
        });
    };
    const encoded = try encodeResponseAlloc(allocator, .{
        .status = status_value,
    });
    defer allocator.free(encoded);
    return call.writeUnaryResponse(connection, allocator, request.stream_id, .{
        .message = encoded,
        .request_accepted_encodings = request.accepted_encodings,
    });
}

/// Serve one accepted Health `Watch` until the client cancels it. The request
/// must contain exactly one message and reach END_STREAM before the response
/// starts. Registry updates and peer cancellation are awaited concurrently so
/// an idle watch never hides a canceled HTTP/2 stream.
pub fn serveWatch(
    stream: *duplex.ServerDuplex,
    registry: *Registry,
) (WatchError || std.Io.ConcurrentError)!void {
    if (!std.mem.eql(u8, stream.path, watch_path) or
        !std.mem.eql(u8, stream.service, "grpc.health.v1.Health") or
        !std.mem.eql(u8, stream.method, "Watch"))
    {
        return error.NotHealthWatchRequest;
    }

    const RequestCollector = struct {
        service: [max_service_name_len]u8 = undefined,
        service_len: usize = 0,
        message_seen: bool = false,
        invalid: bool = false,

        fn consume(
            self: *@This(),
            message: stream_codec.DecodedMessage,
        ) Error!void {
            if (self.message_seen) {
                self.invalid = true;
                return;
            }
            self.message_seen = true;
            const request = decodeRequest(message.payload) catch {
                self.invalid = true;
                return;
            };
            @memcpy(self.service[0..request.service.len], request.service);
            self.service_len = request.service.len;
        }
    };
    var collector: RequestCollector = .{};
    while (true) {
        var event = stream.readRequestEvent(
            &collector,
            RequestCollector.consume,
        ) catch |err| return err;
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => |terminal| {
                if (terminal.message_count != 1 or
                    !collector.message_seen or collector.invalid)
                {
                    try stream.finish(
                        .internal,
                        "could not parse request",
                        &.{},
                        &.{},
                    );
                    return;
                }
                break;
            },
            .reset => return,
        }
    }

    var cursor = try registry.watch(collector.service[0..collector.service_len]);
    defer cursor.deinit();
    try stream.startResponse(.{
        .request_accepted_encodings = stream.accepted_encodings,
    });
    if (!try writeWatchSnapshot(stream, try cursor.next())) return;

    while (true) {
        const UpdateResult = WatchCursor.WaitError!Snapshot;
        const ResetResult = duplex.Error!http2.ResetStreamPayload;
        const Wake = union(enum) {
            update: UpdateResult,
            reset: ResetResult,
        };
        var storage: [2]Wake = undefined;
        var select: std.Io.Select(Wake) = .init(registry.io, &storage);
        var select_done = false;
        defer if (!select_done) select.cancelDiscard();
        try select.concurrent(.update, WatchCursor.next, .{&cursor});
        try select.concurrent(
            .reset,
            duplex.ServerDuplex.waitForPeerReset,
            .{stream},
        );
        switch (try select.await()) {
            .update => |result| {
                const snapshot = try result;
                while (select.cancel()) |remaining| switch (remaining) {
                    .update => |other| _ = other catch |err| switch (err) {
                        error.Canceled => {},
                        else => return err,
                    },
                    .reset => |other| {
                        _ = other catch |err| switch (err) {
                            error.Canceled => continue,
                            else => return err,
                        };
                        select_done = true;
                        return;
                    },
                };
                select_done = true;
                if (!try writeWatchSnapshot(stream, snapshot)) return;
            },
            .reset => |result| {
                _ = try result;
                select.cancelDiscard();
                select_done = true;
                return;
            },
        }
    }
}

fn writeWatchSnapshot(
    stream: *duplex.ServerDuplex,
    snapshot: Snapshot,
) WatchError!bool {
    const encoded = try encodeResponseAlloc(stream.allocator, .{
        .status = snapshot.status,
    });
    defer stream.allocator.free(encoded);
    if (try stream.writeMessage(encoded) == .complete) return true;
    _ = try stream.waitForPeerReset();
    return false;
}

pub const Snapshot = struct {
    status: ServingStatus,
    generation: u64,
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    statuses: std.StringHashMapUnmanaged(ServingStatus) = .empty,
    generation: u64 = 1,
    wake_epoch: std.atomic.Value(u32) = .init(1),
    shutdown: bool = false,

    /// Create a registry whose overall server status (the empty service name)
    /// is `SERVING`, as required by the standard health implementation.
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
    ) std.mem.Allocator.Error!Registry {
        var self = Registry{ .allocator = allocator, .io = io };
        errdefer self.statuses.deinit(allocator);
        const service = try allocator.dupe(u8, "");
        errdefer allocator.free(service);
        try self.statuses.put(allocator, service, .serving);
        return self;
    }

    /// The registry must outlive every cursor created from it.
    pub fn deinit(self: *Registry) void {
        var keys = self.statuses.keyIterator();
        while (keys.next()) |key| self.allocator.free(key.*);
        self.statuses.deinit(self.allocator);
        self.* = undefined;
    }

    /// Return the status used by `Check`, where null means an unknown service.
    pub fn status(
        self: *Registry,
        service: []const u8,
    ) Error!?ServingStatus {
        try validateServiceName(service);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.statuses.get(service);
    }

    /// Set a known service status. `service_unknown` is reserved for Watch
    /// snapshots and cannot be stored. Returns false when the value was
    /// unchanged or graceful shutdown has frozen the registry.
    pub fn setStatus(
        self: *Registry,
        service: []const u8,
        status_value: ServingStatus,
    ) Error!bool {
        try validateServiceName(service);
        if (status_value == .service_unknown) {
            return error.InvalidServingStatus;
        }

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.shutdown) return false;
        if (self.statuses.getPtr(service)) |existing| {
            if (existing.* == status_value) return false;
            existing.* = status_value;
        } else {
            const owned = try self.allocator.dupe(u8, service);
            errdefer self.allocator.free(owned);
            try self.statuses.put(self.allocator, owned, status_value);
        }
        self.notifyLocked();
        return true;
    }

    /// Remove a service. Existing Watch cursors observe `service_unknown`.
    pub fn clearStatus(self: *Registry, service: []const u8) Error!bool {
        try validateServiceName(service);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.shutdown) return false;
        const removed = self.statuses.fetchRemove(service) orelse return false;
        self.allocator.free(removed.key);
        self.notifyLocked();
        return true;
    }

    /// Permanently freeze status mutation and mark every currently known
    /// service as `NOT_SERVING`. Repeated calls are idempotent.
    pub fn enterGracefulShutdown(self: *Registry) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.shutdown) return false;
        self.shutdown = true;
        var values = self.statuses.valueIterator();
        while (values.next()) |value| value.* = .not_serving;
        self.notifyLocked();
        return true;
    }

    pub fn isShutdown(self: *Registry) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.shutdown;
    }

    pub fn watch(
        self: *Registry,
        service: []const u8,
    ) Error!WatchCursor {
        try validateServiceName(service);
        return .{
            .registry = self,
            .service = try self.allocator.dupe(u8, service),
        };
    }

    fn notifyLocked(self: *Registry) void {
        self.generation += 1;
        _ = self.wake_epoch.fetchAdd(1, .release);
        self.io.futexWake(
            u32,
            &self.wake_epoch.raw,
            std.math.maxInt(u32),
        );
    }
};

pub const WatchCursor = struct {
    registry: *Registry,
    service: []u8,
    observed_generation: u64 = 0,
    last_status: ServingStatus = .unknown,
    emitted: bool = false,

    pub const WaitError = error{Timeout} || std.Io.Cancelable;

    pub fn deinit(self: *WatchCursor) void {
        self.registry.allocator.free(self.service);
        self.* = undefined;
    }

    /// Return the initial snapshot immediately, then block until this service's
    /// effective status changes. Changes to other services are not emitted.
    pub fn next(self: *WatchCursor) std.Io.Cancelable!Snapshot {
        return self.nextTimeout(.none) catch |err| switch (err) {
            error.Timeout => unreachable,
            error.Canceled => return error.Canceled,
        };
    }

    pub fn nextWithTimeout(
        self: *WatchCursor,
        timeout: std.Io.Duration,
    ) WaitError!Snapshot {
        return self.nextTimeout(.{ .duration = .{
            .raw = timeout,
            .clock = .awake,
        } });
    }

    pub fn nextWithDeadline(
        self: *WatchCursor,
        deadline: std.Io.Clock.Timestamp,
    ) WaitError!Snapshot {
        return self.nextTimeout(.{ .deadline = deadline });
    }

    pub fn nextTimeout(
        self: *WatchCursor,
        timeout: std.Io.Timeout,
    ) WaitError!Snapshot {
        const deadline = timeout.toDeadline(self.registry.io);
        while (true) {
            self.registry.mutex.lockUncancelable(self.registry.io);
            const generation = self.registry.generation;
            const status_value = self.registry.statuses.get(self.service) orelse
                ServingStatus.service_unknown;
            if (!self.emitted or
                (generation != self.observed_generation and
                    status_value != self.last_status))
            {
                self.emitted = true;
                self.observed_generation = generation;
                self.last_status = status_value;
                self.registry.mutex.unlock(self.registry.io);
                return .{
                    .status = status_value,
                    .generation = generation,
                };
            }
            self.observed_generation = generation;
            const epoch = self.registry.wake_epoch.load(.acquire);
            self.registry.mutex.unlock(self.registry.io);

            if (deadlineExpired(self.registry.io, deadline)) {
                return error.Timeout;
            }
            try self.registry.io.futexWaitTimeout(
                u32,
                &self.registry.wake_epoch.raw,
                epoch,
                deadline,
            );
        }
    }
};

fn validateServiceName(service: []const u8) Error!void {
    if (service.len > max_service_name_len) return error.ServiceNameTooLong;
    if (!std.unicode.utf8ValidateSlice(service)) return error.InvalidUtf8;
}

fn deadlineExpired(io: std.Io, timeout: std.Io.Timeout) bool {
    return switch (timeout) {
        .none => false,
        .duration => unreachable,
        .deadline => |deadline| deadline.durationFromNow(io).raw.nanoseconds <= 0,
    };
}

fn fieldNumber(key: u64) Error!u32 {
    const number = key >> 3;
    if (number == 0 or number > 0x1fffffff) {
        return error.InvalidFieldNumber;
    }
    return @intCast(number);
}

fn readVarint(bytes: []const u8, cursor: *usize) Error!u64 {
    var value: u64 = 0;
    var shift: u6 = 0;
    for (0..10) |index| {
        if (cursor.* == bytes.len) return error.TruncatedMessage;
        const byte = bytes[cursor.*];
        cursor.* += 1;
        if (index == 9 and byte > 1) return error.VarintOverflow;
        value |= @as(u64, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) return value;
        if (index != 9) shift += 7;
    }
    return error.VarintOverflow;
}

fn readLengthDelimited(
    bytes: []const u8,
    cursor: *usize,
) Error![]const u8 {
    const raw_len = try readVarint(bytes, cursor);
    if (raw_len > std.math.maxInt(usize)) return error.TruncatedMessage;
    const len: usize = @intCast(raw_len);
    if (len > bytes.len - cursor.*) return error.TruncatedMessage;
    const value = bytes[cursor.*..][0..len];
    cursor.* += len;
    return value;
}

fn skipValue(
    bytes: []const u8,
    cursor: *usize,
    field_number: u32,
    wire_type: u3,
    depth: u8,
) Error!void {
    switch (wire_type) {
        0 => _ = try readVarint(bytes, cursor),
        1 => try skipBytes(bytes, cursor, 8),
        2 => _ = try readLengthDelimited(bytes, cursor),
        3 => {
            if (depth == 100) return error.MalformedMessage;
            while (cursor.* < bytes.len) {
                const key = try readVarint(bytes, cursor);
                const nested_number = try fieldNumber(key);
                const nested_wire: u3 = @intCast(key & 0x07);
                if (nested_wire == 4) {
                    if (nested_number != field_number) {
                        return error.MalformedMessage;
                    }
                    return;
                }
                try skipValue(
                    bytes,
                    cursor,
                    nested_number,
                    nested_wire,
                    depth + 1,
                );
            }
            return error.TruncatedMessage;
        },
        4 => return error.MalformedMessage,
        5 => try skipBytes(bytes, cursor, 4),
        6, 7 => return error.MalformedMessage,
    }
}

fn skipBytes(bytes: []const u8, cursor: *usize, len: usize) Error!void {
    if (len > bytes.len - cursor.*) return error.TruncatedMessage;
    cursor.* += len;
}

fn varintLen(value: usize) usize {
    var remaining = value;
    var len: usize = 1;
    while (remaining >= 0x80) : (remaining >>= 7) len += 1;
    return len;
}

fn writeVarint(out: []u8, value: usize) usize {
    var remaining = value;
    var cursor: usize = 0;
    while (remaining >= 0x80) {
        out[cursor] = @as(u8, @truncate(remaining)) | 0x80;
        cursor += 1;
        remaining >>= 7;
    }
    out[cursor] = @intCast(remaining);
    return cursor + 1;
}

test "gRPC health request codec validates names and skips unknown fields" {
    const allocator = std.testing.allocator;
    const encoded = try encodeRequestAlloc(allocator, .{
        .service = "netz.echo.v1.Echo",
    });
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings(
        "netz.echo.v1.Echo",
        (try decodeRequest(encoded)).service,
    );
    try std.testing.expectEqualStrings(
        "echo",
        (try decodeRequest(&.{
            0x10, 0x96, 0x01,
            0x0a, 0x04, 'e',
            'c',  'h',  'o',
            0x1d, 1,    2,
            3,    4,
        })).service,
    );
    try std.testing.expectEqualStrings(
        "",
        (try decodeRequest(&.{})).service,
    );

    const too_long = "x" ** (max_service_name_len + 1);
    try std.testing.expectError(
        error.ServiceNameTooLong,
        encodeRequestAlloc(allocator, .{ .service = too_long }),
    );
    var oversized: [3 + max_service_name_len + 1]u8 = undefined;
    oversized[0] = 0x0a;
    oversized[1] = 0xc9;
    oversized[2] = 0x01;
    @memset(oversized[3..], 'x');
    try std.testing.expectError(
        error.ServiceNameTooLong,
        decodeRequest(&oversized),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        decodeRequest(&.{ 0x0a, 0x01, 0xff }),
    );
}

test "gRPC health response codec rejects malformed values" {
    const allocator = std.testing.allocator;
    const encoded = try encodeResponseAlloc(allocator, .{
        .status = .not_serving,
    });
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x02 }, encoded);
    try std.testing.expectEqual(
        ServingStatus.not_serving,
        (try decodeResponse(encoded)).status,
    );
    try std.testing.expectError(
        error.InvalidServingStatus,
        decodeResponse(&.{ 0x08, 0x04 }),
    );
    try std.testing.expectError(
        error.TruncatedMessage,
        decodeRequest(&.{ 0x0a, 0x02, 'x' }),
    );
    try std.testing.expectError(
        error.VarintOverflow,
        decodeResponse(&.{
            0x08, 0x80, 0x80, 0x80, 0x80, 0x80,
            0x80, 0x80, 0x80, 0x80, 0x02,
        }),
    );
}

test "gRPC health registry snapshots changes and graceful shutdown" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = try Registry.init(allocator, io);
    defer registry.deinit();

    try std.testing.expectEqual(
        ServingStatus.serving,
        (try registry.status("")).?,
    );
    var watch = try registry.watch("echo");
    defer watch.deinit();
    try std.testing.expectEqual(
        ServingStatus.service_unknown,
        (try watch.next()).status,
    );
    try std.testing.expect(try registry.setStatus("echo", .serving));
    try std.testing.expectEqual(
        ServingStatus.serving,
        (try watch.next()).status,
    );
    try std.testing.expect(try registry.clearStatus("echo"));
    try std.testing.expectEqual(
        ServingStatus.service_unknown,
        (try watch.next()).status,
    );
    try std.testing.expect(registry.enterGracefulShutdown());
    try std.testing.expectEqual(
        ServingStatus.not_serving,
        (try registry.status("")).?,
    );
    try std.testing.expect(!(try registry.setStatus("echo", .serving)));
    try std.testing.expect(registry.isShutdown());
}

test "gRPC health watch ignores unrelated changes and honors timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = try Registry.init(allocator, io);
    defer registry.deinit();
    var watch = try registry.watch("echo");
    defer watch.deinit();
    _ = try watch.next();

    try std.testing.expect(try registry.setStatus("other", .serving));
    try std.testing.expectError(
        error.Timeout,
        watch.nextWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        watch.nextWithDeadline(.fromNow(io, .{
            .raw = .zero,
            .clock = .awake,
        })),
    );
}

test "gRPC health watch wakes concurrently on service registration" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = try Registry.init(allocator, io);
    defer registry.deinit();

    const Shared = struct {
        cursor: WatchCursor,
        status: ?ServingStatus = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const snapshot = self.cursor.nextWithTimeout(
                .fromSeconds(2),
            ) catch |err| {
                self.err = err;
                return;
            };
            self.status = snapshot.status;
        }
    };
    var shared = Shared{ .cursor = try registry.watch("echo") };
    defer shared.cursor.deinit();
    try std.testing.expectEqual(
        ServingStatus.service_unknown,
        (try shared.cursor.next()).status,
    );
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    try std.testing.expect(try registry.setStatus("echo", .serving));
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(ServingStatus.serving, shared.status.?);
}

test "gRPC health registry wakes every cursor" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var registry = try Registry.init(allocator, io);
    defer registry.deinit();

    const Worker = struct {
        cursor: WatchCursor,
        status: ?ServingStatus = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const snapshot = self.cursor.nextWithTimeout(
                .fromSeconds(2),
            ) catch |err| {
                self.err = err;
                return;
            };
            self.status = snapshot.status;
        }
    };
    var first = Worker{ .cursor = try registry.watch("echo") };
    defer first.cursor.deinit();
    var second = Worker{ .cursor = try registry.watch("echo") };
    defer second.cursor.deinit();
    _ = try first.cursor.next();
    _ = try second.cursor.next();
    const first_thread = try std.Thread.spawn(.{}, Worker.run, .{&first});
    const second_thread = try std.Thread.spawn(.{}, Worker.run, .{&second});
    try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    try std.testing.expect(try registry.setStatus("echo", .serving));
    first_thread.join();
    second_thread.join();
    if (first.err) |err| return err;
    if (second.err) |err| return err;
    try std.testing.expectEqual(ServingStatus.serving, first.status.?);
    try std.testing.expectEqual(ServingStatus.serving, second.status.?);
}

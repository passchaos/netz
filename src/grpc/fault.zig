//! Envoy HTTP fault-injection policy decoding and per-attempt evaluation.
//!
//! Implements the client-side subset used by grpc-core's fault injection
//! filter: fixed or header-driven abort, fixed or header-driven delay,
//! FractionalPercent, and `max_active_faults`. A policy is immutable after
//! decode; the active-fault counter is atomic because one xDS publication is
//! shared by concurrent calls.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const wire = @import("wire.zig");
const response_metadata = @import("response_metadata.zig");
const routing = @import("xds/routing/mod.zig");
const pb = @import("protobuf.zig");

pub const Error = std.mem.Allocator.Error || pb.Error || error{
    InvalidFaultResource,
    UnsupportedFaultFeature,
    FaultLimitExceeded,
};

pub const Limits = struct {
    max_text_bytes: usize = 4096,
    max_headers: usize = 64,
    /// A fixed delay above this bound is rejected and a header delay is
    /// clamped. The default prevents an unbounded sleep from a hostile
    /// control plane when the RPC has no deadline.
    max_delay: std.Io.Duration = .fromSeconds(86400),
};

pub const Percentage = struct { numerator: u32, denominator: u32 };

pub const AbortKind = union(enum) {
    grpc_status: wire.Status,
    http_status: u16,
    header,
};

pub const AbortConfig = struct { kind: AbortKind, percentage: Percentage };

pub const DelayConfig = struct {
    fixed: ?std.Io.Duration = null,
    header: bool = false,
    percentage: Percentage,
};

pub const Policy = struct {
    abort: ?AbortConfig = null,
    delay: ?DelayConfig = null,
    max_active_faults: ?u32 = null,
    /// Restrict injection to requests routed to this xDS cluster. Borrowed
    /// from the projection arena that decoded the policy.
    upstream_cluster: ?[]const u8 = null,
    /// Every configured HeaderMatcher must match. Owned by the projection
    /// arena that decoded the policy.
    headers: []const routing.header.Match = &.{},
    max_delay: std.Io.Duration = .fromSeconds(86400),
    active: std.atomic.Value(u32) = .init(0),

    pub fn evaluate(self: *Policy, gpa: std.mem.Allocator, io: std.Io, request: routing.header.Request, cluster: ?[]const u8) std.mem.Allocator.Error!Decision {
        var seed: u64 = undefined;
        io.random(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);
        return self.evaluateWith(gpa, request, cluster, prng.random());
    }

    pub fn evaluateWith(self: *Policy, gpa: std.mem.Allocator, request: routing.header.Request, cluster: ?[]const u8, random: std.Random) std.mem.Allocator.Error!Decision {
        if (self.abort == null and self.delay == null) return .{};
        if (self.upstream_cluster) |required| {
            const selected = cluster orelse return .{};
            if (!std.mem.eql(u8, required, selected)) return .{};
        }
        for (self.headers) |matcher| {
            const matched = matcher.matches(gpa, request) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => false,
            };
            if (!matched) return .{};
        }
        const maximum = self.max_active_faults orelse std.math.maxInt(u32);
        if (self.active.load(.acquire) >= maximum) return .{};
        const metadata = request.metadata;

        var delay: ?std.Io.Duration = null;
        if (self.delay) |config| {
            var duration = config.fixed orelse std.Io.Duration.zero;
            var numerator = config.percentage.numerator;
            if (config.fixed == null and config.header) {
                if (headerValue(metadata, delay_header)) |raw| {
                    duration = parseDelay(raw, self.max_delay);
                }
                if (headerValue(metadata, delay_percentage_header)) |raw| {
                    if (parseUnsigned(raw)) |value| numerator = @min(numerator, value);
                }
            }
            if (duration.nanoseconds > 0 and under(random, numerator, config.percentage.denominator)) {
                _ = self.active.fetchAdd(1, .acq_rel);
                delay = duration;
            }
        }

        var abort: ?Abort = null;
        if (self.abort) |config| {
            var status: ?wire.Status = null;
            var numerator = config.percentage.numerator;
            switch (config.kind) {
                .grpc_status => |code| {
                    if (code != .ok) status = code;
                },
                .http_status => |code| {
                    if (code != 200) status = response_metadata.statusFromHttp(code);
                },
                .header => {
                    if (headerValue(metadata, abort_grpc_header)) |raw| {
                        if (parseUnsigned(raw)) |value| {
                            const parsed = std.enums.fromInt(wire.Status, value) orelse .unknown;
                            if (parsed != .ok) status = parsed;
                        }
                    } else if (headerValue(metadata, abort_http_header)) |raw| {
                        if (parseUnsigned(raw)) |value| {
                            status = if (value >= 200 and value <= 599)
                                if (value == 200) null else response_metadata.statusFromHttp(@intCast(value))
                            else
                                .unknown;
                        }
                    }
                    if (headerValue(metadata, abort_percentage_header)) |raw| {
                        if (parseUnsigned(raw)) |value| numerator = @min(numerator, value);
                    }
                },
            }
            if (status != null and under(random, numerator, config.percentage.denominator)) {
                abort = .{ .status = status.?, .message = "Fault injected" };
            }
        }
        return .{ .delay = delay, .abort = abort, .counted = delay != null };
    }
};

pub const Abort = struct { status: wire.Status, message: []const u8 };

pub const Decision = struct {
    delay: ?std.Io.Duration = null,
    abort: ?Abort = null,
    counted: bool = false,

    /// Release the active-delay slot. Idempotent, so a deferred call may
    /// follow an explicit release after the sleep.
    pub fn release(self: *Decision, policy: *Policy) void {
        if (!self.counted) return;
        self.counted = false;
        _ = policy.active.fetchSub(1, .acq_rel);
    }
};

pub fn sleepBounded(io: std.Io, delay: std.Io.Duration, deadline: ?std.Io.Clock.Timestamp) (std.Io.Cancelable || error{Timeout})!void {
    if (delay.nanoseconds <= 0) return;
    if (deadline) |until| {
        if (until.clock != .awake) return error.Timeout;
        const remaining = until.durationFromNow(io).raw;
        if (remaining.nanoseconds <= 0) return error.Timeout;
        if (delay.nanoseconds >= remaining.nanoseconds) {
            try std.Io.sleep(io, remaining, .awake);
            return error.Timeout;
        }
    }
    try std.Io.sleep(io, delay, .awake);
}

const delay_header = "x-envoy-fault-delay-request";
const delay_percentage_header = "x-envoy-fault-delay-request-percentage";
const abort_grpc_header = "x-envoy-fault-abort-grpc-request";
const abort_http_header = "x-envoy-fault-abort-request";
const abort_percentage_header = "x-envoy-fault-abort-request-percentage";

fn headerValue(metadata: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (metadata) |field| if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    return null;
}

fn parseUnsigned(raw: []const u8) ?u32 {
    return std.fmt.parseInt(u32, raw, 10) catch null;
}

fn parseDelay(raw: []const u8, maximum: std.Io.Duration) std.Io.Duration {
    const value = std.fmt.parseInt(i64, raw, 10) catch return std.Io.Duration.zero;
    if (value <= 0) return std.Io.Duration.zero;
    return .fromMilliseconds(@min(value, maximum.toMilliseconds()));
}

fn under(random: std.Random, numerator: u32, denominator: u32) bool {
    if (numerator == 0) return false;
    if (denominator == 0 or numerator >= denominator) return true;
    return random.uintLessThan(u32, denominator) < numerator;
}

/// Decode `envoy.extensions.filters.http.fault.v3.HTTPFault`.
pub fn decode(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Policy {
    var reader = pb.Reader{ .bytes = bytes };
    var policy = Policy{ .max_delay = limits.max_delay };
    var delay_seen = false;
    var abort_seen = false;
    var headers: std.ArrayList(routing.header.Match) = .empty;
    while (try reader.next()) |field| {
        switch (field.number) {
            1 => if (field.wire_type == 2) {
                if (delay_seen) return error.InvalidFaultResource;
                delay_seen = true;
                policy.delay = try decodeDelay(try reader.bytesValue(), limits);
            } else try reader.skip(field),
            2 => if (field.wire_type == 2) {
                if (abort_seen) return error.InvalidFaultResource;
                abort_seen = true;
                policy.abort = try decodeAbort(try reader.bytesValue());
            } else try reader.skip(field),
            3 => if (field.wire_type == 2) {
                const value = try text(&reader, limits.max_text_bytes);
                if (value.len == 0) return error.InvalidFaultResource;
                policy.upstream_cluster = try arena.dupe(u8, value);
            } else try reader.skip(field),
            4 => if (field.wire_type == 2) {
                if (headers.items.len >= limits.max_headers) return error.FaultLimitExceeded;
                try headers.append(arena, routing.header.decode(arena, try reader.bytesValue(), .{
                    .max_text_bytes = limits.max_text_bytes,
                }) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.HeaderMatcherLimitExceeded => return error.FaultLimitExceeded,
                    error.InvalidHeaderMatcher => return error.InvalidFaultResource,
                    else => return @errorCast(err),
                });
            } else try reader.skip(field),
            // Downstream-node matching and response rate limiting change which
            // requests or bytes are affected. They are rejected instead of
            // silently applying a broader fault.
            5, 7 => return error.UnsupportedFaultFeature,
            6 => if (field.wire_type == 2) {
                policy.max_active_faults = try uint32Wrapper(try reader.bytesValue());
            } else try reader.skip(field),
            else => try reader.skip(field),
        }
    }
    if (!delay_seen and !abort_seen) return error.InvalidFaultResource;
    policy.headers = try headers.toOwnedSlice(arena);
    return policy;
}

fn text(reader: *pb.Reader, limit: usize) Error![]const u8 {
    const value = try reader.string();
    if (value.len > limit) return error.FaultLimitExceeded;
    return value;
}

fn decodeAbort(bytes: []const u8) Error!AbortConfig {
    var reader = pb.Reader{ .bytes = bytes };
    var kind: ?AbortKind = null;
    var kind_seen = false;
    var percentage: ?Percentage = null;
    while (try reader.next()) |field| {
        switch (field.number) {
            2 => if (field.wire_type == 0) {
                if (kind_seen) return error.InvalidFaultResource;
                kind_seen = true;
                const raw = try reader.varint();
                if (raw < 200 or raw > 599) return error.InvalidFaultResource;
                kind = .{ .http_status = @intCast(raw) };
            } else try reader.skip(field),
            5 => if (field.wire_type == 0) {
                if (kind_seen) return error.InvalidFaultResource;
                kind_seen = true;
                const raw = try reader.varint();
                kind = .{ .grpc_status = std.enums.fromInt(wire.Status, raw) orelse return error.InvalidFaultResource };
            } else try reader.skip(field),
            4 => if (field.wire_type == 2) {
                if (kind_seen) return error.InvalidFaultResource;
                kind_seen = true;
                var marker = pb.Reader{ .bytes = try reader.bytesValue() };
                while (try marker.next()) |nested| try marker.skip(nested);
                kind = .header;
            } else try reader.skip(field),
            3 => if (field.wire_type == 2) {
                percentage = try decodePercentage(try reader.bytesValue());
            } else try reader.skip(field),
            else => try reader.skip(field),
        }
    }
    return .{
        .kind = kind orelse return error.InvalidFaultResource,
        .percentage = percentage orelse return error.InvalidFaultResource,
    };
}

fn decodeDelay(bytes: []const u8, limits: Limits) Error!DelayConfig {
    var reader = pb.Reader{ .bytes = bytes };
    var fixed: ?std.Io.Duration = null;
    var header = false;
    var specifier_seen = false;
    var percentage: ?Percentage = null;
    while (try reader.next()) |field| {
        switch (field.number) {
            3 => if (field.wire_type == 2) {
                if (specifier_seen) return error.InvalidFaultResource;
                specifier_seen = true;
                const duration = try decodeDuration(try reader.bytesValue());
                if (duration.nanoseconds <= 0) return error.InvalidFaultResource;
                if (duration.nanoseconds > limits.max_delay.nanoseconds) return error.FaultLimitExceeded;
                fixed = duration;
            } else try reader.skip(field),
            5 => if (field.wire_type == 2) {
                if (specifier_seen) return error.InvalidFaultResource;
                specifier_seen = true;
                var marker = pb.Reader{ .bytes = try reader.bytesValue() };
                while (try marker.next()) |nested| try marker.skip(nested);
                header = true;
            } else try reader.skip(field),
            4 => if (field.wire_type == 2) {
                percentage = try decodePercentage(try reader.bytesValue());
            } else try reader.skip(field),
            else => try reader.skip(field),
        }
    }
    if (!specifier_seen) return error.InvalidFaultResource;
    return .{
        .fixed = fixed,
        .header = header,
        .percentage = percentage orelse return error.InvalidFaultResource,
    };
}

fn decodePercentage(bytes: []const u8) Error!Percentage {
    var reader = pb.Reader{ .bytes = bytes };
    var numerator: u32 = 0;
    var denominator: u32 = 100;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw > std.math.maxInt(u32)) return error.InvalidFaultResource;
            numerator = @intCast(raw);
        } else if (field.number == 2 and field.wire_type == 0) {
            denominator = switch (try reader.varint()) {
                0 => 100,
                1 => 10_000,
                2 => 1_000_000,
                else => return error.InvalidFaultResource,
            };
        } else try reader.skip(field);
    }
    if (numerator > denominator) numerator = denominator;
    return .{ .numerator = numerator, .denominator = denominator };
}

fn decodeDuration(bytes: []const u8) Error!std.Io.Duration {
    var reader = pb.Reader{ .bytes = bytes };
    var seconds: i64 = 0;
    var nanos: i32 = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            seconds = @bitCast(try reader.varint());
        } else if (field.number == 2 and field.wire_type == 0) {
            nanos = @bitCast(@as(u32, @truncate(try reader.varint())));
        } else try reader.skip(field);
    }
    if (seconds < 0 or seconds > 315576000000 or nanos < 0 or nanos > 999999999) return error.InvalidFaultResource;
    return .fromNanoseconds(@as(i96, seconds) * std.time.ns_per_s + nanos);
}

fn uint32Wrapper(bytes: []const u8) Error!u32 {
    var reader = pb.Reader{ .bytes = bytes };
    var value: u32 = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw > std.math.maxInt(u32)) return error.InvalidFaultResource;
            value = @intCast(raw);
        } else try reader.skip(field);
    }
    return value;
}

const TestBuilder = struct {
    data: std.ArrayList(u8) = .empty,
    fn deinit(self: *TestBuilder) void {
        self.data.deinit(std.testing.allocator);
    }
    fn varint(self: *TestBuilder, value: u64) !void {
        var remaining = value;
        while (remaining >= 0x80) {
            try self.data.append(std.testing.allocator, @as(u8, @truncate(remaining)) | 0x80);
            remaining >>= 7;
        }
        try self.data.append(std.testing.allocator, @intCast(remaining));
    }
    fn bytes(self: *TestBuilder, field: u32, value: []const u8) !void {
        try self.varint((@as(u64, field) << 3) | 2);
        try self.varint(value.len);
        try self.data.appendSlice(std.testing.allocator, value);
    }
    fn number(self: *TestBuilder, field: u32, value: u64) !void {
        try self.varint(@as(u64, field) << 3);
        try self.varint(value);
    }
};

fn percentageBytes(numerator: u32, denominator: u64) ![]u8 {
    var value = TestBuilder{};
    defer value.deinit();
    try value.number(1, numerator);
    try value.number(2, denominator);
    return value.data.toOwnedSlice(std.testing.allocator);
}

fn abortBytes(kind_field: u32, kind_value: u64, numerator: u32) ![]u8 {
    var abort = TestBuilder{};
    defer abort.deinit();
    if (kind_field == 4) {
        var marker = TestBuilder{};
        defer marker.deinit();
        try abort.bytes(4, marker.data.items);
    } else try abort.number(kind_field, kind_value);
    const percentage = try percentageBytes(numerator, 0);
    defer std.testing.allocator.free(percentage);
    try abort.bytes(3, percentage);
    return abort.data.toOwnedSlice(std.testing.allocator);
}

fn faultBytes(abort: ?[]const u8, delay: ?[]const u8, max_active: ?u32) ![]u8 {
    var fault = TestBuilder{};
    errdefer fault.deinit();
    if (delay) |value| try fault.bytes(1, value);
    if (abort) |value| try fault.bytes(2, value);
    if (max_active) |value| {
        var wrapper = TestBuilder{};
        defer wrapper.deinit();
        try wrapper.number(1, value);
        try fault.bytes(6, wrapper.data.items);
    }
    return fault.data.toOwnedSlice(std.testing.allocator);
}

fn testRequest(metadata: []const http2.Hpack.HeaderField) routing.header.Request {
    return .{ .path = "/demo.Service/Get", .authority = "backend.test", .metadata = metadata };
}

test "fault decodes a fixed gRPC abort and evaluates it" {
    const abort = try abortBytes(5, 14, 100);
    defer std.testing.allocator.free(abort);
    const bytes = try faultBytes(abort, null, null);
    defer std.testing.allocator.free(bytes);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var policy = try decode(arena.allocator(), bytes, .{});
    var prng = std.Random.DefaultPrng.init(7);
    const decision = try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random());
    try std.testing.expect(decision.delay == null);
    try std.testing.expectEqual(wire.Status.unavailable, decision.abort.?.status);
    try std.testing.expectEqualStrings("Fault injected", decision.abort.?.message);
}

test "fault fixed HTTP status maps through the gRPC fallback" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const abort = try abortBytes(2, 403, 100);
    defer std.testing.allocator.free(abort);
    const bytes = try faultBytes(abort, null, null);
    defer std.testing.allocator.free(bytes);
    var policy = try decode(arena.allocator(), bytes, .{});
    var prng = std.Random.DefaultPrng.init(7);
    try std.testing.expectEqual(wire.Status.permission_denied, (try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).abort.?.status);

    // HTTP 200 and gRPC OK are success codes and never abort.
    const ok_http = try abortBytes(2, 200, 100);
    defer std.testing.allocator.free(ok_http);
    const ok_bytes = try faultBytes(ok_http, null, null);
    defer std.testing.allocator.free(ok_bytes);
    var ok_policy = try decode(arena.allocator(), ok_bytes, .{});
    try std.testing.expect((try ok_policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).abort == null);

    const ok_grpc = try abortBytes(5, 0, 100);
    defer std.testing.allocator.free(ok_grpc);
    const ok_grpc_bytes = try faultBytes(ok_grpc, null, null);
    defer std.testing.allocator.free(ok_grpc_bytes);
    var ok_grpc_policy = try decode(arena.allocator(), ok_grpc_bytes, .{});
    try std.testing.expect((try ok_grpc_policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).abort == null);
}

test "fault header abort honors gRPC, HTTP and percentage headers" {
    const abort = try abortBytes(4, 0, 100);
    defer std.testing.allocator.free(abort);
    const bytes = try faultBytes(abort, null, null);
    defer std.testing.allocator.free(bytes);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var policy = try decode(arena.allocator(), bytes, .{});
    var prng = std.Random.DefaultPrng.init(9);
    const grpc_headers = [_]http2.Hpack.HeaderField{.{ .name = abort_grpc_header, .value = "7" }};
    try std.testing.expectEqual(wire.Status.permission_denied, (try policy.evaluateWith(std.testing.allocator, testRequest(&grpc_headers), null, prng.random())).abort.?.status);

    const http_headers = [_]http2.Hpack.HeaderField{.{ .name = abort_http_header, .value = "503" }};
    try std.testing.expectEqual(wire.Status.unavailable, (try policy.evaluateWith(std.testing.allocator, testRequest(&http_headers), null, prng.random())).abort.?.status);

    const zero_percent = [_]http2.Hpack.HeaderField{
        .{ .name = abort_grpc_header, .value = "14" },
        .{ .name = abort_percentage_header, .value = "0" },
    };
    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&zero_percent), null, prng.random())).abort == null);

    const invalid_code = [_]http2.Hpack.HeaderField{.{ .name = abort_grpc_header, .value = "99" }};
    try std.testing.expectEqual(wire.Status.unknown, (try policy.evaluateWith(std.testing.allocator, testRequest(&invalid_code), null, prng.random())).abort.?.status);

    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).abort == null);
}

test "fault upstream_cluster scopes injection to the selected cluster" {
    const abort = try abortBytes(5, 14, 100);
    defer std.testing.allocator.free(abort);
    var fault = TestBuilder{};
    defer fault.deinit();
    try fault.bytes(2, abort);
    try fault.bytes(3, "cluster:a");
    const bytes = try fault.data.toOwnedSlice(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var policy = try decode(arena.allocator(), bytes, .{});
    var prng = std.Random.DefaultPrng.init(5);
    try std.testing.expectEqual(wire.Status.unavailable, (try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), "cluster:a", prng.random())).abort.?.status);
    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), "cluster:b", prng.random())).abort == null);
    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).abort == null);

    var empty = TestBuilder{};
    defer empty.deinit();
    try empty.bytes(2, abort);
    try empty.bytes(3, "");
    try std.testing.expectError(error.InvalidFaultResource, decode(arena.allocator(), empty.data.items, .{}));
}

test "fault header matchers gate injection" {
    const abort = try abortBytes(5, 14, 100);
    defer std.testing.allocator.free(abort);
    var matcher = TestBuilder{};
    defer matcher.deinit();
    try matcher.bytes(1, "x-fault");
    try matcher.number(7, 1);
    var fault = TestBuilder{};
    defer fault.deinit();
    try fault.bytes(2, abort);
    try fault.bytes(4, matcher.data.items);
    const bytes = try fault.data.toOwnedSlice(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var policy = try decode(arena.allocator(), bytes, .{});
    var prng = std.Random.DefaultPrng.init(3);
    const present = [_]http2.Hpack.HeaderField{.{ .name = "x-fault", .value = "1" }};
    try std.testing.expectEqual(wire.Status.unavailable, (try policy.evaluateWith(std.testing.allocator, testRequest(&present), null, prng.random())).abort.?.status);
    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).abort == null);
}

test "fault fixed delay and max_active_faults bound concurrent faults" {
    var delay = TestBuilder{};
    defer delay.deinit();
    var nanos = TestBuilder{};
    defer nanos.deinit();
    try nanos.number(2, 25 * std.time.ns_per_ms);
    try delay.bytes(3, nanos.data.items);
    const percentage = try percentageBytes(100, 0);
    defer std.testing.allocator.free(percentage);
    try delay.bytes(4, percentage);

    const bytes = try faultBytes(null, delay.data.items, 1);
    defer std.testing.allocator.free(bytes);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var policy = try decode(arena.allocator(), bytes, .{});
    var prng = std.Random.DefaultPrng.init(11);

    var first = try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random());
    defer first.release(&policy);
    try std.testing.expectEqual(@as(i96, 25 * std.time.ns_per_ms), first.delay.?.nanoseconds);
    try std.testing.expect(first.counted);
    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).delay == null);
    first.release(&policy);
    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).delay.?.nanoseconds == 25 * std.time.ns_per_ms);
}

test "fault header delay uses the delay and percentage headers" {
    var delay = TestBuilder{};
    defer delay.deinit();
    var marker = TestBuilder{};
    defer marker.deinit();
    try delay.bytes(5, marker.data.items);
    const percentage = try percentageBytes(100, 0);
    defer std.testing.allocator.free(percentage);
    try delay.bytes(4, percentage);

    const bytes = try faultBytes(null, delay.data.items, null);
    defer std.testing.allocator.free(bytes);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var policy = try decode(arena.allocator(), bytes, .{});
    var prng = std.Random.DefaultPrng.init(13);

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = delay_header, .value = "25" },
        .{ .name = delay_percentage_header, .value = "100" },
    };
    var decision = try policy.evaluateWith(std.testing.allocator, testRequest(&headers), null, prng.random());
    defer decision.release(&policy);
    try std.testing.expectEqual(@as(i96, 25 * std.time.ns_per_ms), decision.delay.?.nanoseconds);

    const disabled = [_]http2.Hpack.HeaderField{
        .{ .name = delay_header, .value = "25" },
        .{ .name = delay_percentage_header, .value = "0" },
    };
    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&disabled), null, prng.random())).delay == null);
    try std.testing.expect((try policy.evaluateWith(std.testing.allocator, testRequest(&.{}), null, prng.random())).delay == null);
}

test "fault rejects missing percentages, multiple abort kinds and unsupported fields" {
    var abort = TestBuilder{};
    defer abort.deinit();
    try abort.number(5, 14);
    const bytes = try faultBytes(abort.data.items, null, null);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(error.InvalidFaultResource, decode(std.testing.allocator, bytes, .{}));

    var both = TestBuilder{};
    defer both.deinit();
    try both.number(5, 14);
    try both.number(2, 503);
    const percentage = try percentageBytes(100, 0);
    defer std.testing.allocator.free(percentage);
    try both.bytes(3, percentage);
    const both_bytes = try faultBytes(both.data.items, null, null);
    defer std.testing.allocator.free(both_bytes);
    try std.testing.expectError(error.InvalidFaultResource, decode(std.testing.allocator, both_bytes, .{}));

    var unsupported = TestBuilder{};
    defer unsupported.deinit();
    try unsupported.bytes(5, "x");
    try std.testing.expectError(error.UnsupportedFaultFeature, decode(std.testing.allocator, unsupported.data.items, .{}));

    const empty = try faultBytes(null, null, null);
    defer std.testing.allocator.free(empty);
    try std.testing.expectError(error.InvalidFaultResource, decode(std.testing.allocator, empty, .{}));
}

test "fault rejects a fixed delay above the configured bound" {
    var delay = TestBuilder{};
    defer delay.deinit();
    var duration = TestBuilder{};
    defer duration.deinit();
    try duration.number(1, 7200);
    try delay.bytes(3, duration.data.items);
    const percentage = try percentageBytes(100, 0);
    defer std.testing.allocator.free(percentage);
    try delay.bytes(4, percentage);
    const bytes = try faultBytes(null, delay.data.items, null);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(error.FaultLimitExceeded, decode(std.testing.allocator, bytes, .{ .max_delay = .fromSeconds(3600) }));
}

test "fault bounded sleep returns timeout instead of sleeping past the deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.Timeout, sleepBounded(io, .fromMilliseconds(50), std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5) })));
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 50 * std.time.ns_per_ms);
}

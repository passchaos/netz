const std = @import("std");
const fault_root = @import("../fault.zig");

const http2 = @import("../../http2/mod.zig");
const wire = @import("../wire.zig");

const TestBuilder = fault_root.TestBuilder;
const abortBytes = fault_root.abortBytes;
const abort_grpc_header = fault_root.abort_grpc_header;
const abort_http_header = fault_root.abort_http_header;
const abort_percentage_header = fault_root.abort_percentage_header;
const decode = fault_root.decode;
const delay_header = fault_root.delay_header;
const delay_percentage_header = fault_root.delay_percentage_header;
const faultBytes = fault_root.faultBytes;
const percentageBytes = fault_root.percentageBytes;
const sleepBounded = fault_root.sleepBounded;
const testRequest = fault_root.testRequest;

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

test "fault decoded empty header matching honors missing-as-empty flags" {
    // A fixed 100% abort makes header matching the only injection condition.
    const abort = try abortBytes(5, 14, 100);
    defer std.testing.allocator.free(abort);
    const flags = [_]?bool{ null, false, true };
    const values = [_]?[]const u8{ null, "", "nonempty" };
    for (flags) |as_empty| {
        var matcher = TestBuilder{};
        defer matcher.deinit();
        try matcher.bytes(1, "x-fault");
        try matcher.bytes(4, ""); // exact_match is a present empty oneof value.
        if (as_empty) |enabled| try matcher.number(14, @intFromBool(enabled));
        var fault = TestBuilder{};
        defer fault.deinit();
        try fault.bytes(2, abort);
        try fault.bytes(4, matcher.data.items);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var policy = try decode(arena.allocator(), fault.data.items, .{});
        try std.testing.expectEqual(@as(usize, 1), policy.headers.len);
        try std.testing.expectEqual(as_empty orelse false, policy.headers[0].treat_missing_header_as_empty);
        var prng = std.Random.DefaultPrng.init(3);
        for (values) |value| {
            const metadata = [_]http2.Hpack.HeaderField{.{ .name = "x-fault", .value = value orelse "" }};
            const request = testRequest(if (value != null) &metadata else &.{});
            const decision = try policy.evaluateWith(std.testing.allocator, request, null, prng.random());
            const should_abort = if (value) |text_value| text_value.len == 0 else as_empty orelse false;
            try std.testing.expectEqual(should_abort, decision.abort != null);
            if (decision.abort) |injected| {
                try std.testing.expectEqual(wire.Status.unavailable, injected.status);
                try std.testing.expectEqualStrings("Fault injected", injected.message);
            }
            try std.testing.expect(decision.delay == null and !decision.counted);
        }
    }
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

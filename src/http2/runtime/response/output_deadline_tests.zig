//! Stream HEADERS/trailers share DATA's budget and half-close ownership rules.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

const Operation = enum { aggregate_response, informational, response_start, duplex_start, duplex_headers, request_trailers, response_trailers, client_trailers, server_trailers, client_fin };

fn serverStream(connection: *runtime.Connection) runtime.ServerDuplexStream {
    return .{ .connection = connection, .stream_id = 1, .headers = &.{}, .method = "POST", .path = "/output", .scheme = "http", .authority = "localhost", .protocol = null, .priority = .{}, .expected_request_length = null };
}

fn exercise(connection: *runtime.Connection, operation: Operation, fields: []const http2.Hpack.HeaderField, timeout: std.Io.Duration) !void {
    switch (operation) {
        .aggregate_response => try connection.writeResponseWithTimeout(
            1,
            .{ .headers = fields },
            timeout,
        ),
        .informational => try connection.writeInformationalResponseWithTimeout(
            1,
            103,
            fields,
            timeout,
        ),
        .response_start => {
            _ = try connection.startResponseWithTimeout(1, .{ .headers = fields }, timeout);
        },
        .duplex_start => {
            var stream = serverStream(connection);
            try stream.startResponseWithTimeout(.{ .headers = fields }, timeout);
        },
        .duplex_headers => {
            var stream = serverStream(connection);
            try stream.finishResponseHeadersWithTimeout(.{ .headers = fields }, timeout);
        },
        .request_trailers => {
            var writer: runtime.RequestWriter = .{ .connection = connection, .stream_id = 1, .expected_length = 0, .head_request = false };
            try writer.finishTrailersWithTimeout(fields, timeout);
        },
        .response_trailers => {
            var writer: runtime.ResponseWriter = .{ .connection = connection, .stream_id = 1, .expected_length = 0 };
            try writer.finishTrailersWithTimeout(fields, timeout);
        },
        .client_trailers => {
            var stream: runtime.ClientDuplexStream = .{ .connection = connection, .stream_id = 1, .expected_request_length = 0 };
            try stream.finishRequestTrailersWithTimeout(fields, timeout);
        },
        .server_trailers => {
            var stream = serverStream(connection);
            stream.response_started = true;
            try stream.finishResponseTrailersWithTimeout(fields, timeout);
        },
        .client_fin => {
            var stream: runtime.ClientDuplexStream = .{ .connection = connection, .stream_id = 1, .expected_request_length = 0, .response_finished = true };
            try stream.closeRequestAfterResponseWithTimeout(timeout);
        },
    }
}

fn blocked(operation: Operation) !void {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const client = switch (operation) {
        .request_trailers, .client_trailers, .client_fin => true,
        else => false,
    };
    var fixture = try BlockedOutput.init(threaded.io(), if (client) .client else .server);
    defer fixture.deinit();
    if (client) {
        _ = try runtime.testing.reserveNextClientStreamId(&fixture.connection);
    } else try runtime.testing.addActivePeerStream(&fixture.connection, 1);
    if (operation == .client_fin) try fixture.saturate();
    try fixture.startRescue();
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    try std.testing.expectError(error.Timeout, exercise(&fixture.connection, operation, &.{.{ .name = "x-large", .value = "x" ** (256 * 1024) }}, .fromMilliseconds(30)));
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
}

test "HTTP/2 stream output deadline bounds blocked response start" {
    try blocked(.response_start);
}
test "HTTP/2 stream output deadline bounds blocked aggregate response" {
    try blocked(.aggregate_response);
}
test "HTTP/2 stream output deadline bounds blocked informational response" {
    try blocked(.informational);
}
test "HTTP/2 stream output deadline bounds blocked duplex response start" {
    try blocked(.duplex_start);
}
test "HTTP/2 stream output deadline bounds blocked duplex final HEADERS" {
    try blocked(.duplex_headers);
}
test "HTTP/2 stream output deadline bounds blocked request trailers" {
    try blocked(.request_trailers);
}
test "HTTP/2 stream output deadline bounds blocked response trailers" {
    try blocked(.response_trailers);
}
test "HTTP/2 stream output deadline bounds blocked duplex request trailers" {
    try blocked(.client_trailers);
}
test "HTTP/2 stream output deadline bounds blocked duplex response trailers" {
    try blocked(.server_trailers);
}
test "HTTP/2 stream output deadline bounds blocked explicit early-response FIN" {
    try blocked(.client_fin);
}

test "HTTP/2 stream output deadline preserves trailer half-close ownership" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const fields = &[_]http2.Hpack.HeaderField{.{ .name = "x-done", .value = "yes" }};
    for ([_]bool{ false, true }) |other_finished| {
        var client = try BlockedOutput.init(threaded.io(), .client);
        defer client.deinit();
        _ = try runtime.testing.reserveNextClientStreamId(&client.connection);
        var upload: runtime.ClientDuplexStream = .{ .connection = &client.connection, .stream_id = 1, .expected_request_length = 0, .response_finished = other_finished };
        try upload.finishRequestTrailersWithDeadline(fields, .fromNow(client.connection.io, .{ .raw = .fromSeconds(1), .clock = .awake }));
        try std.testing.expect(upload.request_finished);
        try std.testing.expectEqual(other_finished, upload.released);
        try std.testing.expectEqual(@as(usize, @intFromBool(!other_finished)), client.connection.activeLocalStreamCount());
        var server = try BlockedOutput.init(threaded.io(), .server);
        defer server.deinit();
        try runtime.testing.addActivePeerStream(&server.connection, 1);
        var response = serverStream(&server.connection);
        response.request_finished = other_finished;
        try response.startResponseWithTimeout(.{}, .fromSeconds(1));
        try response.finishResponseTrailersWithDeadline(fields, .fromNow(server.connection.io, .{ .raw = .fromSeconds(1), .clock = .awake }));
        try std.testing.expect(response.response_finished);
        try std.testing.expectEqual(other_finished, response.released);
        try std.testing.expectEqual(@as(usize, @intFromBool(!other_finished)), server.connection.activePeerStreamCount());
    }
}

test "HTTP/2 aggregate and informational deadlines preserve response ownership" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    try runtime.testing.addActivePeerStream(connection, 1);
    const deadline = std.Io.Clock.Timestamp.fromNow(
        connection.io,
        .{ .clock = .awake, .raw = .fromSeconds(1) },
    );
    try connection.writeInformationalResponseWithDeadline(
        1,
        103,
        &.{.{ .name = "link", .value = "</asset>; rel=preload" }},
        deadline,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.activePeerStreamCount(),
    );
    try connection.writeResponseWithDeadline(
        1,
        .{ .body = "ok" },
        deadline,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activePeerStreamCount(),
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
}

test "HTTP/2 stream output deadline validates before trailer or response mutation" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (std.meta.tags(Operation)) |operation| {
        var fixture = try BlockedOutput.init(threaded.io(), .server);
        defer fixture.deinit();
        try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        try std.testing.expectError(error.Timeout, exercise(&fixture.connection, operation, &.{}, .fromMilliseconds(0)));
        try std.testing.expectEqual(@as(usize, 1), fixture.connection.activePeerStreamCount());
        try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(@as(usize, 0), fixture.connection.hpack_encoder.dynamic_table.used);
    }
}

test "HTTP/2 stream output deadline rejects expired and non-awake budgets before state changes" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    for ([_]std.Io.Clock{ .awake, .real }) |clock| {
        var fixture = try BlockedOutput.init(threaded.io(), .server);
        defer fixture.deinit();
        const connection = &fixture.connection;
        try runtime.testing.addActivePeerStream(connection, 1);
        const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .clock = clock, .raw = .fromMilliseconds(if (clock == .awake) -1 else 1000) });
        var duplex = serverStream(connection);
        try std.testing.expectError(error.Timeout, connection.startResponseWithDeadline(1, .{}, deadline));
        try std.testing.expectError(error.Timeout, duplex.startResponseWithDeadline(.{}, deadline));
        try std.testing.expectError(error.Timeout, duplex.finishResponseHeadersWithDeadline(.{}, deadline));
        duplex.response_started = true;
        try std.testing.expectError(error.Timeout, duplex.finishResponseTrailersWithDeadline(&.{}, deadline));
        var response: runtime.ResponseWriter = .{ .connection = connection, .stream_id = 1, .expected_length = 0 };
        try std.testing.expectError(error.Timeout, response.finishTrailersWithDeadline(&.{}, deadline));
        var request: runtime.RequestWriter = .{ .connection = connection, .stream_id = 1, .expected_length = 0, .head_request = false };
        try std.testing.expectError(error.Timeout, request.finishTrailersWithDeadline(&.{}, deadline));
        var upload: runtime.ClientDuplexStream = .{ .connection = connection, .stream_id = 1, .expected_request_length = 0, .response_finished = true };
        try std.testing.expectError(error.Timeout, upload.finishRequestTrailersWithDeadline(&.{}, deadline));
        try std.testing.expectError(error.Timeout, upload.closeRequestAfterResponseWithDeadline(deadline));
        try std.testing.expect(!duplex.response_finished and !duplex.released);
        try std.testing.expect(!response.finished and !request.body_finished and !upload.request_finished);
        try std.testing.expectEqual(@as(usize, 1), connection.activePeerStreamCount());
        try std.testing.expect(!connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(@as(usize, 0), connection.hpack_encoder.dynamic_table.used);
    }
}

test "HTTP/2 stream output deadline rejects incomplete lengths and invalid trailers transactionally" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    try runtime.testing.addActivePeerStream(connection, 1);
    var request: runtime.RequestWriter = .{ .connection = connection, .stream_id = 1, .expected_length = 1, .head_request = false };
    var response: runtime.ResponseWriter = .{ .connection = connection, .stream_id = 1, .expected_length = 1 };
    var upload: runtime.ClientDuplexStream = .{ .connection = connection, .stream_id = 1, .expected_request_length = 1 };
    var duplex = serverStream(connection);
    duplex.response_started = true;
    duplex.response_expected_length = 1;
    try std.testing.expectError(error.InvalidContentLength, request.finishTrailersWithTimeout(&.{}, .fromSeconds(1)));
    try std.testing.expectError(error.InvalidContentLength, response.finishTrailersWithTimeout(&.{}, .fromSeconds(1)));
    try std.testing.expectError(error.InvalidContentLength, upload.finishRequestTrailersWithTimeout(&.{}, .fromSeconds(1)));
    try std.testing.expectError(error.InvalidContentLength, duplex.finishResponseTrailersWithTimeout(&.{}, .fromSeconds(1)));
    request.expected_length = 0;
    response.expected_length = 0;
    upload.expected_request_length = 0;
    duplex.response_expected_length = 0;
    const pseudo = &[_]http2.Hpack.HeaderField{.{ .name = ":status", .value = "200" }};
    try std.testing.expectError(error.InvalidHeader, request.finishTrailersWithTimeout(pseudo, .fromSeconds(1)));
    try std.testing.expectError(error.InvalidHeader, response.finishTrailersWithTimeout(pseudo, .fromSeconds(1)));
    try std.testing.expectError(error.InvalidHeader, upload.finishRequestTrailersWithTimeout(pseudo, .fromSeconds(1)));
    try std.testing.expectError(error.InvalidHeader, duplex.finishResponseTrailersWithTimeout(pseudo, .fromSeconds(1)));
    try std.testing.expect(!request.body_finished and !response.finished and !upload.request_finished and !duplex.response_finished);
    try std.testing.expectEqual(@as(usize, 1), connection.activePeerStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.hpack_encoder.dynamic_table.used);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
}

test "HTTP/2 stream response start allocation failure keeps admitted stream retryable" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var failures: usize = 0;
    for (0..32) |fail_index| {
        var fixture = try BlockedOutput.init(threaded.io(), .server);
        defer fixture.deinit();
        try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        fixture.connection.allocator = failing.allocator();
        const result = fixture.connection.startResponseWithTimeout(1, .{ .headers = &.{.{ .name = "x-owned", .value = "y" ** 512 }} }, .fromSeconds(1));
        fixture.connection.allocator = allocator;
        if (result) |_| {
            try std.testing.expect(failures > 0);
            return;
        } else |err| {
            failures += 1;
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
            try std.testing.expectEqual(@as(usize, 1), fixture.connection.activePeerStreamCount());
            try std.testing.expectEqual(@as(usize, 0), fixture.connection.hpack_encoder.dynamic_table.used);
            _ = try fixture.connection.startResponseWithTimeout(1, .{}, .fromSeconds(1));
        }
    }
    return error.TestUnexpectedResult;
}

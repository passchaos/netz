//! A capacity-refused request cannot poison sibling HTTP message ownership.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

const allocator = std.testing.allocator;
const Path = enum { aggregate, streaming, batch, duplex, extended_connect };
const Fault = enum { field_value, content_length, field_count, list_size, continuations };

const Fixture = struct {
    client: runtime.Connection,
    server: runtime.Connection,

    fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const accepted = try listener.accept(io);
        return .{
            .client = .{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .next_client_stream_id = 7 },
            .server = .{ .io = io, .allocator = allocator, .stream = accepted, .role = .server, .limits = .{
                .max_concurrent_streams = 1,
                .max_header_fields = 8,
                .max_header_list_size = 512,
                .max_continuation_frames = 1,
                .enable_connect_protocol = true,
            } },
        };
    }

    fn deinit(self: *@This()) void {
        self.server.close();
        self.client.close();
    }
};

test "HTTP/2 capacity refusal isolates request field validation errors" {
    for ([_]Path{ .aggregate, .streaming, .batch, .duplex, .extended_connect }) |path| {
        for ([_]Fault{ .field_value, .content_length }) |fault| try exercise(path, fault);
    }
}

test "HTTP/2 capacity refusal isolates complete field and continuation limits" {
    for ([_]Path{ .aggregate, .streaming, .batch, .duplex, .extended_connect }) |path| {
        for ([_]Fault{ .field_count, .list_size, .continuations }) |fault| try exercise(path, fault);
    }
}

fn addRequest(connection: *runtime.Connection, encoder: *http2.Hpack.Encoder, id: u31, extended: bool, end_stream: bool, fault: ?Fault) !void {
    var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer fields.deinit(allocator);
    try fields.appendSlice(allocator, &.{
        .{ .name = ":method", .value = if (extended) "CONNECT" else "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = if (id == 1) "/held" else "/healthy" },
        .{ .name = ":authority", .value = "localhost" },
    });
    if (extended) try fields.append(allocator, .{ .name = ":protocol", .value = "websocket" });
    if (fault) |value| switch (value) {
        .field_value => try fields.append(allocator, .{ .name = "x-invalid", .value = " leading" }),
        .content_length => try fields.append(allocator, .{ .name = "content-length", .value = "NaN" }),
        .field_count => for (0..16) |_| {
            try fields.append(allocator, .{ .name = "x-count", .value = "a", .never_index = true });
        },
        .list_size => try fields.append(allocator, .{ .name = "x-list", .value = "~" ** 600, .never_index = true }),
        .continuations => {},
    };
    if (id != 1) try fields.append(allocator, .{ .name = "x-shared", .value = "from-refused" });
    const block = try encoder.encodeBlockRetained(allocator, fields.items);
    const end: u8 = @intFromBool(end_stream);
    if (fault == .continuations) {
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, end, id, block[0..1]);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 0, id, &.{});
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 4, id, block[1..]);
    } else {
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4 | end, id, block);
    }
}

fn checkAccepted(id: u31, fields: []const http2.Hpack.HeaderField) !void {
    try std.testing.expectEqual(@as(u31, 5), id);
    try std.testing.expectEqualStrings("from-refused", runtime.testing.findHeader(fields, "x-shared").?);
}

fn consume(_: void, _: []const u8) !void {}
fn consumeBatch(_: void, _: u31, _: []const u8) !void {}

fn expectReset(client: *runtime.Connection, fault: Fault) !void {
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), reset.reset.stream_id);
    try std.testing.expectEqual(if (fault == .field_value or fault == .content_length) http2.ErrorCode.protocol_error else http2.ErrorCode.refused_stream, reset.reset.error_code);
}

fn exercise(path: Path, fault: Fault) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    const client = &fixture.client;
    const server = &fixture.server;
    if (fault == .field_count) server.limits.max_header_list_size = 4096;
    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    try addRequest(server, &encoder, 1, false, path != .streaming and path != .batch, null);
    var held: ?runtime.OwnedRequest = null;
    defer if (held) |*request| request.deinit(allocator);
    if (path != .streaming and path != .batch) {
        held = try server.readRequestWithTimeout(.fromSeconds(1));
        try std.testing.expect(runtime.testing.hasActivePeerStream(server, 1));
    }
    if (path == .aggregate) server.serve_read_stream_error = .{ .stream_id = 1, .code = .flow_control_error };
    try addRequest(server, &encoder, 3, false, true, fault);
    if (path == .duplex) {
        // No new stream was admitted. Return from the empty receive boundary,
        // finish the held response, then let the same duplex API accept again.
        try std.testing.expectError(error.Timeout, server.acceptDuplexRequestWithTimeout(.fromMilliseconds(20)));
        try expectReset(client, fault);
        try server.writeResponse(1, .{ .status = 204 });
        var response = try client.readResponseWithTimeout(1, "GET", false, .fromSeconds(1));
        defer response.deinit(allocator);
    } else if (path == .streaming) {
        try wire.appendFrame(&server.frame_reader.buffer, allocator, .data, 1, 1, "body");
        var first = try server.readRequestStreamingWithTimeout(.fromSeconds(1), {}, consume);
        defer first.deinit(allocator);
        try std.testing.expectEqual(@as(u31, 1), first.stream_id);
        try expectReset(client, fault);
        try server.writeResponse(1, .{ .status = 204 });
        var response = try client.readResponseWithTimeout(1, "GET", false, .fromSeconds(1));
        defer response.deinit(allocator);
    } else {
        try wire.appendFrame(&server.frame_reader.buffer, allocator, .rst_stream, 0, 1, &.{ 0, 0, 0, 8 });
    }
    try addRequest(server, &encoder, 5, path == .extended_connect, path != .extended_connect, null);
    switch (path) {
        .aggregate => {
            var request = try server.readRequestWithTimeout(.fromSeconds(1));
            defer request.deinit(allocator);
            try checkAccepted(request.stream_id, request.headers);
        },
        .streaming => {
            var request = try server.readRequestStreamingWithTimeout(.fromSeconds(1), {}, consume);
            defer request.deinit(allocator);
            try checkAccepted(request.stream_id, request.headers);
        },
        .batch => {
            var requests: [1]runtime.StreamingRequest = undefined;
            try server.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(1), {}, consumeBatch);
            defer requests[0].deinit(allocator);
            try checkAccepted(requests[0].stream_id, requests[0].headers);
        },
        .duplex => {
            var request = try server.acceptDuplexRequestWithTimeout(.fromSeconds(1));
            defer request.deinit();
            try checkAccepted(request.stream_id, request.headers);
            try request.startResponse(.{});
            _ = try request.finishResponseData("healthy");
        },
        .extended_connect => {
            var request = try server.readExtendedConnectRequestWithTimeout("websocket", .fromSeconds(1));
            defer request.deinit(allocator);
            try checkAccepted(request.stream_id, request.headers);
        },
    }
    try std.testing.expect(!server.aggregate_timeout_unusable);
    if (path == .aggregate) {
        try std.testing.expectEqual(@as(u31, 1), server.serve_read_stream_error.?.stream_id);
        try std.testing.expectEqual(http2.ErrorCode.flow_control_error, server.serve_read_stream_error.?.code);
    }
    try std.testing.expectEqual(@as(usize, 1), runtime.testing.localErrorResetCount(server));
    try std.testing.expect(!runtime.testing.hasActivePeerStream(server, 3));
    try std.testing.expect(!runtime.testing.hasStreamWindow(server, 3));
    try std.testing.expect(!runtime.testing.hasResponseSemantics(server, 3));
    if (path != .duplex and path != .streaming) try expectReset(client, fault);
    if (path != .duplex) try server.writeResponse(5, .{ .status = if (path == .extended_connect) 403 else 200, .body = "healthy" });
    var response = try client.readResponseWithTimeout(5, if (path == .extended_connect) "CONNECT" else "GET", path == .extended_connect, .fromSeconds(1));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", response.body);
}

test "HTTP/2 capacity refusal preserves connection errors after output limits" {
    const Fatal = enum { compression, allocation, unfinished_limit };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]Fatal{ .compression, .allocation, .unfinished_limit }) |fault| {
        var fixture = try Fixture.init(threaded.io());
        defer fixture.deinit();
        const server = &fixture.server;
        var encoder = http2.Hpack.Encoder{};
        defer encoder.deinit(allocator);
        try addRequest(server, &encoder, 1, false, true, null);
        var held = try server.readRequestWithTimeout(.fromSeconds(1));
        defer held.deinit(allocator);
        // Reserve refusal tracking before injecting a decoder allocation fault.
        try server.locally_reset_streams.ensureTotalCapacity(allocator, 1);
        try server.locally_reset_stream_index.ensureTotalCapacity(allocator, 1);
        const payload = if (fault == .compression) "\x88" ** 64 ++ "\x80" else if (fault == .allocation) "\x40\x01x\x01y" else "\x82";
        try wire.appendFrame(&server.frame_reader.buffer, allocator, .headers, if (fault == .unfinished_limit) 0 else 4, 3, payload);
        if (fault == .unfinished_limit) for (0..2) |_| {
            try wire.appendFrame(&server.frame_reader.buffer, allocator, .continuation, 0, 3, &.{0x82});
        };
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        if (fault == .allocation) server.allocator = failing.allocator();
        const result = server.readRequestWithTimeout(.fromSeconds(1));
        server.allocator = allocator;
        try std.testing.expectError(if (fault == .allocation) error.OutOfMemory else if (fault == .compression) error.InvalidEncoding else error.MessageTooLarge, result);
        if (fault == .allocation) try std.testing.expect(failing.has_induced_failure);
        try std.testing.expect(server.aggregate_timeout_unusable);
        try std.testing.expectError(error.ConnectionClosed, server.readRequestWithTimeout(.fromSeconds(1)));
        try std.testing.expectEqual(@as(usize, 0), runtime.testing.localErrorResetCount(server));
    }
}

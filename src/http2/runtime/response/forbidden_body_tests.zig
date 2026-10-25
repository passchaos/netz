const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;

const Mode = enum { aggregate, streaming, connect };
const Kind = enum { head, no_content, not_modified };
const Ending = enum { empty, padding, content, trailers, fragmented_trailers, reset };

test {
    _ = @import("forbidden_failure_tests.zig");
    _ = @import("forbidden_transport_tests.zig");
}

test "HTTP/2 forbidden response body returns padding credit on successful drain" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Kind)) |kind| {
            if (mode == .connect and kind != .not_modified) continue;
            for ([_]bool{ false, true }) |bounded| {
                try exercise(mode, kind, .empty, bounded);
                try exercise(mode, kind, .padding, bounded);
            }
        }
    }
}

test "HTTP/2 forbidden response body preserves credit and HPACK after rejection" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Kind)) |kind| {
            if (mode == .connect and kind != .not_modified) continue;
            for ([_]bool{ false, true }) |bounded| {
                for ([_]Ending{ .content, .trailers, .fragmented_trailers, .reset }) |ending| try exercise(mode, kind, ending, bounded);
            }
        }
    }
}

fn consume(count: *usize, bytes: []const u8) !void {
    count.* += bytes.len;
}

fn exercise(mode: Mode, kind: Kind, ending: Ending, bounded: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .next_client_stream_id = if (mode == .connect) 1 else 5, .peer_enable_connect_protocol = true };
    defer connection.close();
    if (mode != .connect) try runtime.testing.addActiveLocalStream(&connection, 1);
    try runtime.testing.addActiveLocalStream(&connection, 3);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = ":status", .value = switch (kind) {
        .head => "200",
        .no_content => "204",
        .not_modified => "304",
    } }});
    if (kind != .no_content) try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = "content-length", .value = "999" }});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, block.items);
    // Pure padding contains no HTTP content, but charges four flow-control
    // octets. No application DATA event exists to release that capacity.
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 8, 1, "\x03\x00\x00\x00");
    switch (ending) {
        .empty => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 1, 1, ""),
        .padding => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 9, 1, "\x02\x00\x00"),
        .content => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 9, 1, "\x02ab\x00\x00"),
        .trailers, .fragmented_trailers => {
            const trailer = "\x40\x01x\x01y";
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, if (ending == .trailers) 5 else 1, 1, if (ending == .trailers) trailer else trailer[0..2]);
            if (ending == .fragmented_trailers) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 4, 1, trailer[2..]);
        },
        .reset => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .rst_stream, 0, 1, &.{ 0, 0, 0, 8 }),
    }
    const dynamic = ending == .trailers or ending == .fragmented_trailers;
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 3, if (dynamic) "\x88\xbe" else "\x88");
    var delivered: usize = 0;
    var request = runtime.RequestWriter{ .connection = &connection, .stream_id = 1, .expected_length = 0, .head_request = kind == .head, .body_finished = true };
    const success = ending == .empty or ending == .padding;
    const expected = if (ending == .reset) error.StreamReset else error.InvalidContentLength;
    switch (mode) {
        .aggregate => {
            const result = if (bounded) request.readResponseWithTimeout(.fromSeconds(1)) else request.readResponse();
            if (success) {
                var response = try result;
                defer response.deinit(allocator);
                try std.testing.expectEqual(@as(usize, 0), response.body.len);
                try std.testing.expect(!response.body_allowed);
            } else try std.testing.expectError(expected, result);
        },
        .streaming => {
            const result = if (bounded) request.readResponseStreamingWithTimeout(.fromSeconds(1), &delivered, consume) else request.readResponseStreaming(&delivered, consume);
            if (success) {
                var response = try result;
                defer response.deinit(allocator);
                try std.testing.expectEqual(@as(usize, 0), response.body_bytes);
            } else try std.testing.expectError(expected, result);
        },
        .connect => {
            const options = runtime.RequestOptions{ .method = "CONNECT", .protocol = "websocket", .authority = "localhost" };
            const result = if (bounded) connection.openExtendedConnectAttemptWithTimeout(options, .fromSeconds(1)) else connection.openExtendedConnectAttempt(options);
            if (success) {
                var response = try result;
                defer response.deinit(allocator);
                try std.testing.expect(!response.accepted());
                try std.testing.expectEqual(@as(usize, 0), response.body.len);
            } else try std.testing.expectError(expected, result);
        },
    }
    try std.testing.expectEqual(@as(usize, 0), delivered);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
    var healthy = try connection.readResponseWithTimeout(3, "POST", false, .fromSeconds(1));
    defer healthy.deinit(allocator);
    if (dynamic) try std.testing.expectEqualStrings("y", runtime.testing.findHeader(healthy.headers, "x").?);
    // Read cleanup frames on the actual peer socket to prove that logical
    // refunds reached the wire and the message error stayed stream-local.
    try connection.stream.shutdown(io, .send);
    const frame_io = @import("../frame/io.zig");
    var reader: frame_io.Reader = .{};
    defer reader.deinit(allocator);
    var connection_credit: usize = 0;
    var stream_credit: usize = 0;
    var resets: usize = 0;
    while (true) {
        const incoming = reader.read(allocator, io, peer, 16_384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        switch (incoming.frame.header.frame_type) {
            .headers => {
                // CONNECT submitted its request HEADERS to this raw peer.
                try std.testing.expect(mode == .connect);
            },
            .window_update => {
                const update = try http2.WindowUpdatePayload.parse(incoming.frame);
                if (update.stream_id == 0) connection_credit += update.increment else {
                    try std.testing.expectEqual(@as(u31, 1), update.stream_id);
                    stream_credit += update.increment;
                }
            },
            .rst_stream => {
                const reset = try http2.ResetStreamPayload.parse(incoming.frame);
                try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
                try std.testing.expectEqual(if (mode == .connect) http2.ErrorCode.cancel else http2.ErrorCode.protocol_error, reset.error_code);
                resets += 1;
            },
            else => return error.UnexpectedCleanupFrame,
        }
    }
    try std.testing.expectEqual(@as(usize, 4) + @as(usize, switch (ending) {
        .padding => 3,
        .content => 5,
        else => 0,
    }), connection_credit);
    try std.testing.expectEqual(@as(usize, 4), stream_credit);
    try std.testing.expectEqual(@as(usize, if (success or ending == .reset) 0 else 1), resets);
}

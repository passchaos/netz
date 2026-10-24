const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime = @import("../../runtime.zig");

const Operation = enum { read, available, skip, read_once };

test "HTTP/3 late FIN DATA errors install exact wire policy before delivery" {
    inline for (.{ Operation.read, Operation.available, Operation.skip, Operation.read_once }) |operation| {
        try exercise(operation, false);
        try exercise(operation, true);
    }
}

fn exercise(comptime operation: Operation, truncated: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 };
    const client_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const server_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
    var server = try runtime.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{}, .{
        .handshake = .{ .local_connection_id = &server_cid, .random = [_]u8{0xe1} ** 32, .x25519_secret_key = [_]u8{0xe2} ** 32 },
    });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.HandshakeServer,
        truncated: bool,
        prefix_read: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(allocator);
            var second = try session.receiveRequest();
            defer second.deinit(allocator);
            try session.sendOrigins(&.{});
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(allocator);
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(allocator);
            try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
                .{ .name = ":status", .value = "200" }, .{ .name = "content-length", .value = "3" },
            });
            try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
            try quic.varint.encode(&bytes, allocator, http3.FrameType.data);
            try quic.varint.encode(&bytes, allocator, if (self.truncated) 3 else 2);
            try bytes.append(allocator, 'a');
            try session.established.connection.send(&.{.{ .stream = .{ .stream_id = first.stream_id, .data = bytes.items } }});
            try self.prefix_read.wait(self.server.quic_server.endpoint.io);
            var sibling: std.ArrayList(u8) = .empty;
            defer sibling.deinit(allocator);
            try (http3.Response{ .status = 204 }).write(&sibling, allocator);
            try session.established.connection.send(&.{
                .{ .stream = .{ .stream_id = first.stream_id, .offset = bytes.items.len, .data = "b", .fin = true } },
                .{ .stream = .{ .stream_id = second.stream_id, .data = sibling.items, .fin = true } },
            });
            while (true) {
                var packet = try session.established.connection.receivePacketTimeout(.{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } });
                defer packet.deinit(allocator);
                for (packet.frames) |frame| switch (frame) {
                    .application_close => |close| if (self.truncated) {
                        try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.frame_error), close.error_code);
                        return;
                    },
                    .stop_sending => |stop| if (!self.truncated and stop.stream_id == first.stream_id) {
                        try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), stop.application_error_code);
                        return;
                    },
                    else => {},
                };
            }
        }
    };
    var peer = Peer{ .server = &server, .truncated = truncated };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.prefix_read.set(io);
        thread.join();
    };
    var client = try runtime.HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{}, .{
        .handshake = .{ .original_destination_connection_id = &original_dcid, .local_connection_id = &client_cid, .server_name = "localhost", .random = [_]u8{0xe3} ** 32, .x25519_secret_key = [_]u8{0xe4} ** 32 },
    });
    defer client.deinit();
    const first = try client.sendRequest(.{ .method = "GET", .path = "/partial", .authority = "localhost" });
    const second = try client.sendRequest(.{ .method = "GET", .path = "/sibling", .authority = "localhost" });
    var read_prefix = false;
    while (!read_prefix) {
        var event = (try client.receiveResponseEventWithTimeout(first, .fromSeconds(2))) orelse continue;
        defer event.deinit(allocator);
        if (event == .data_available) {
            var byte: [1]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 1), try client.readResponseData(first, &byte));
            try std.testing.expectEqualStrings("a", &byte);
            read_prefix = true;
        }
    }
    peer.prefix_read.set(io);
    // Pump a sibling to make FIN visible without re-polling the first reader.
    var sibling_head = (try client.receiveResponseEventWithTimeout(second, .fromSeconds(2))) orelse return error.TestUnexpectedResult;
    defer sibling_head.deinit(allocator);
    try std.testing.expect(sibling_head == .head);
    const expected = if (truncated) error.BufferTooShort else error.InvalidContentLength;
    var out = [_]u8{0xaa} ** 4;
    switch (operation) {
        .read => try std.testing.expectError(expected, client.readResponseData(first, &out)),
        .available => try std.testing.expectError(expected, client.availableResponseData(first)),
        .skip => try std.testing.expectError(expected, client.skipResponseData(first)),
        .read_once => try std.testing.expectError(expected, client.readResponseDataOnce(first, &out)),
    }
    try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
    if (!truncated) {
        try std.testing.expect(!client.request_lifecycle.contains(first));
        var completed = (try client.receiveResponseEventWithTimeout(second, .fromSeconds(2))) orelse return error.TestUnexpectedResult;
        defer completed.deinit(allocator);
        try std.testing.expect(completed == .finished);
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

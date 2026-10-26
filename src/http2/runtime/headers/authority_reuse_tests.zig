const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

test "HTTP/2 authority rejection preserves HPACK and accepts normalized sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_concurrent_streams = 1 });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        calls: usize = 0,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn handler(self: *@This(), request: runtime.OwnedRequest) runtime.Error!runtime.ResponseOptions {
            self.calls += 1;
            if (!std.mem.eql(u8, "preserved", runtime.testing.findHeader(request.headers, "x-sync") orelse "")) return error.InvalidHeader;
            return .{ .body = "normalized" };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            try std.testing.expectError(error.InvalidHeader, connection.serveOne(@This(), self, @This().handler));
            try std.testing.expectEqual(@as(usize, 0), self.calls);
            _ = try connection.serveOne(@This(), self, @This().handler);
            try std.testing.expectEqual(@as(usize, 1), self.calls);
        }
    };
    var peer: Peer = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    const block = try client.hpack_encoder.encodeBlockRetained(allocator, &.{
        .{ .name = ":method", .value = "GET" },    .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/bad" },     .{ .name = ":authority", .value = "[invalid]" },
        .{ .name = "host", .value = "[invalid]" }, .{ .name = "x-sync", .value = "preserved" },
    });
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try wire.appendFrame(&bytes, allocator, .headers, 0x05, 1, block);
    var writer = client.stream.writer(io, &.{});
    try writer.interface.writeAll(bytes.items);
    client.next_client_stream_id = 3;
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(3));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);
    const sync = try client.hpack_encoder.encodeBlockRetained(allocator, &.{.{ .name = "x-sync", .value = "preserved" }});
    try std.testing.expectEqual(@as(usize, 1), sync.len);
    try std.testing.expect(sync[0] & 0x80 != 0);
    var response = try client.requestWithTimeout(.{ .path = "/healthy", .scheme = "https", .authority = "LocalHOST", .headers = &.{ .{ .name = "host", .value = "localhost:443" }, .{ .name = "x-sync", .value = "preserved" } } }, .fromSeconds(3));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("normalized", response.body);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

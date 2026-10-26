const std = @import("std");
const runtime = @import("../../runtime.zig");
const pool_mod = @import("../../client_pool.zig");

test "HTTP/2 IP authority URI pool binding rejects a different Host" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const authority = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{server.address().ip4.port});
    defer allocator.free(authority);
    const uri = try std.fmt.allocPrint(allocator, "http://{s}/bound", .{authority});
    defer allocator.free(uri);
    const Shared = struct {
        server: *runtime.Server,
        authority: []const u8,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            for (0..2) |_| {
                var request = try connection.readRequestWithTimeout(.fromSeconds(3));
                defer request.deinit(self.server.allocator);
                for (request.headers) |header| if (std.mem.eql(u8, header.name, ":authority")) try std.testing.expectEqualStrings(self.authority, header.value);
                try connection.writeResponse(request.stream_id, .{ .body = "bound" });
            }
        }
    };
    var shared: Shared = .{ .server = &server, .authority = authority };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    var lease = try pool.acquireUri(uri);
    defer lease.release();
    const connection = lease.connection();
    try std.testing.expect(!connection.default_authority_is_ip);
    try std.testing.expectEqualStrings(authority, connection.resolveRequestAuthority(null).?);
    try std.testing.expectError(error.InvalidHeader, connection.request(.{ .path = "/wrong-host", .headers = &.{.{ .name = "host", .value = "different.test" }} }));
    for (0..2) |_| {
        var response = try connection.requestWithTimeout(.{ .path = "/bound" }, .fromSeconds(3));
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("bound", response.body);
    }
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

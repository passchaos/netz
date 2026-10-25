//! Wire validation and live request scheduling use the same Dictionary values.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const vectors = @import("../../../internal/priority/test_vectors.zig");
const allocator = std.testing.allocator;

test "HTTP/2 Priority Dictionaries match request headers and live PRIORITY_UPDATE state" {
    for (vectors.dictionaries) |case| try exercise(case);
}

fn exercise(case: vectors.Case) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .no_rfc7540_priorities = true });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        case: vectors.Case,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn expectPriority(self: *@This(), priority: http2.ExtensiblePriority) !void {
            try std.testing.expectEqual(self.case.urgency, priority.urgency);
            try std.testing.expectEqual(self.case.incremental, priority.incremental);
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            var updated = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer updated.deinit(allocator);
            try self.expectPriority(updated.priority);
            try self.expectPriority(connection.peerPriority(updated.stream_id).?);
            try std.testing.expectEqualStrings(self.case.field, connection.peerPriorityFieldValue(updated.stream_id).?);
            try connection.writeResponse(updated.stream_id, .{ .body = "update" });
            var header = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer header.deinit(allocator);
            try self.expectPriority(header.priority);
            try connection.writeResponse(header.stream_id, .{ .body = "header" });
        }
    };
    var peer = Peer{ .server = &server, .case = case };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    try client.sendPriorityUpdateRaw(1, case.field);
    var updated = try client.requestWithTimeout(.{ .path = "/update", .authority = "localhost", .priority = .{ .urgency = 7, .incremental = true } }, .fromSeconds(2));
    defer updated.deinit(allocator);
    try std.testing.expectEqualStrings("update", updated.body);
    var header = try client.requestWithTimeout(.{ .path = "/header", .authority = "localhost", .headers = &.{.{ .name = "priority", .value = case.field }} }, .fromSeconds(2));
    defer header.deinit(allocator);
    try std.testing.expectEqualStrings("header", header.body);
    try std.testing.expect(client.isReusable());
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

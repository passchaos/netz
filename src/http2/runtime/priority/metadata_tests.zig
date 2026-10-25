//! Priority field lines form one scheduling Dictionary, never a message error.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const vectors = @import("../../../internal/priority/test_vectors.zig");
const allocator = std.testing.allocator;

test "HTTP/2 Priority metadata combines repeated field lines and ignores whole malformed hints" {
    inline for ([_]bool{ false, true }) |streaming| {
        for ([_]bool{ false, true }) |override| {
            for (vectors.field_sections) |case| try exercise(streaming, override, case);
        }
    }
}

fn exercise(comptime streaming: bool, override: bool, case: vectors.FieldsCase) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .no_rfc7540_priorities = true });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        case: vectors.FieldsCase,
        override: bool,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            var request = if (streaming) try connection.readRequestStreamingWithTimeout(.fromSeconds(2), {}, struct {
                fn consume(_: void, bytes: []const u8) !void {
                    try std.testing.expectEqual(@as(usize, 0), bytes.len);
                }
            }.consume) else try connection.readRequestWithTimeout(.fromSeconds(2));
            defer request.deinit(allocator);
            try std.testing.expectEqual(@as(u3, if (self.override) 2 else self.case.urgency), request.priority.urgency);
            try std.testing.expectEqual(self.override or self.case.incremental, request.priority.incremental);
            var count: usize = 0;
            for (request.headers) |field| if (std.mem.eql(u8, field.name, "priority")) {
                try std.testing.expectEqualStrings(self.case.values[count], field.value);
                count += 1;
            };
            try std.testing.expectEqual(self.case.values.len, count);
            try connection.writeResponse(request.stream_id, .{ .body = "ok" });
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(allocator);
            try std.testing.expectEqual(http2.ExtensiblePriority{}, next.priority);
            try connection.writeResponse(next.stream_id, .{ .body = "next" });
        }
    };
    var peer = Peer{ .server = &server, .case = case, .override = override };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer headers.deinit(allocator);
    for (case.values) |value| try headers.append(allocator, .{ .name = "priority", .value = value });
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    if (override) try client.sendPriorityUpdate(1, .{ .urgency = 2, .incremental = true });
    var response = try client.requestWithTimeout(.{ .path = "/priority", .authority = "localhost", .headers = headers.items }, .fromSeconds(2));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.body);
    var next = try client.requestWithTimeout(.{ .path = "/next", .authority = "localhost" }, .fromSeconds(2));
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("next", next.body);
    try std.testing.expect(client.isReusable());
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

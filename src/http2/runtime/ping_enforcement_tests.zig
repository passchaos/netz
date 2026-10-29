const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const allocator = std.testing.allocator;

fn payload(index: u8) [8]u8 {
    return .{ 'A', 'B', 'U', 'S', 'E', 0, 0, index };
}

const strict_policy: runtime.PingEnforcementPolicy = .{
    .min_interval = .fromSeconds(1),
    .idle_interval = .fromSeconds(1),
    .max_strikes = 2,
};

test "HTTP/2 PING enforcement sends exact too_many_pings GOAWAY" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ping_enforcement = strict_policy },
    );
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            for (0..3) |index| {
                const received = try connection.readPingWithTimeout(.fromSeconds(2));
                try std.testing.expectEqual(payload(@intCast(index)), received);
            }
            try std.testing.expectError(
                error.ConnectionGoAway,
                connection.readPingWithTimeout(.fromSeconds(2)),
            );
            try std.testing.expectEqualDeep(
                runtime.PingEnforcementStats{
                    .pings_received = 4,
                    .current_strikes = 3,
                    .violations = 1,
                },
                connection.pingEnforcementStats(),
            );
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    for (0..3) |index| {
        try std.testing.expectEqual(
            payload(@intCast(index)),
            try client.pingWithTimeout(payload(@intCast(index)), .fromSeconds(2)),
        );
    }
    try runtime.testing.writeRawFrame(
        &client,
        .ping,
        0,
        0,
        &payload(3),
    );
    var goaway = try client.readGoAwayWithTimeout(.fromSeconds(2));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.enhance_your_calm, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("too_many_pings", goaway.goaway.debug_data);
    try peer.await(io);
}

test "HTTP/2 response HEADERS reset peer PING strikes" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ping_enforcement = .{
            .min_interval = .fromSeconds(1),
            .idle_interval = .fromSeconds(1),
            .max_strikes = 1,
        } },
    );
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            _ = try connection.readPingWithTimeout(.fromSeconds(2));
            _ = try connection.readPingWithTimeout(.fromSeconds(2));
            try std.testing.expectEqual(@as(usize, 1), connection.pingEnforcementStats().current_strikes);

            var request = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer request.deinit(allocator);
            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "reset",
            });
            try std.testing.expectEqual(@as(usize, 0), connection.pingEnforcementStats().current_strikes);

            _ = try connection.readPingWithTimeout(.fromSeconds(2));
            _ = try connection.readPingWithTimeout(.fromSeconds(2));
            try std.testing.expectEqualDeep(
                runtime.PingEnforcementStats{
                    .pings_received = 4,
                    .current_strikes = 1,
                    .violations = 0,
                },
                connection.pingEnforcementStats(),
            );
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    _ = try client.pingWithTimeout(payload(0), .fromSeconds(2));
    _ = try client.pingWithTimeout(payload(1), .fromSeconds(2));
    var response = try client.request(.{ .path = "/reset" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("reset", response.body);
    _ = try client.pingWithTimeout(payload(2), .fromSeconds(2));
    _ = try client.pingWithTimeout(payload(3), .fromSeconds(2));
    try peer.await(io);
}

const std = @import("std");
const websocket = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const support = @import("directional_support.zig");
const allocator = std.testing.allocator;

test "WebSocket directional takeover HTTP1 accepts an ignored client hint and keeps stateless sends" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]?websocket.ContextTakeover{ null, .none, .server }) |mode| {
        var server = try runtime.Server.listen(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{ .max_frame_bytes = 4096, .max_message_bytes = 4096 });
        defer server.deinit();
        const Peer = struct {
            server: *runtime.Server,
            mode: ?websocket.ContextTakeover,
            err: ?anyerror = null,
            fn run(self: *@This()) void {
                self.serve() catch |err| {
                    self.err = err;
                };
            }
            fn serve(self: *@This()) !void {
                var pending = try self.server.receiveUpgradeRequestWithTimeout(.{ .enable_permessage_deflate = true, .context_takeover = .both, .compression_threshold = 0 }, support.timeout);
                var owns_pending = true;
                defer if (owns_pending) pending.deinit();
                // Emulate a standards-compliant peer that keeps receive
                // history and omits the optional client hint from its reply.
                const response = if (self.mode == .server) "permessage-deflate" else "permessage-deflate; server_no_context_takeover";
                const replacement = try allocator.dupe(u8, response);
                if (pending.selected_extension) |previous| allocator.free(previous);
                pending.selected_extension = replacement;
                pending.negotiated_extension = try websocket.ExtensionNegotiation.validateResponseWithPolicy(response, .{ .enable_permessage_deflate = true, .allow_context_takeover = true });
                var connection = try pending.accept();
                owns_pending = false;
                defer connection.close();
                try std.testing.expect(connection.compression_receive_context_takeover);
                try support.receive(&connection, false);
                try support.send(&connection);
                try support.finishPeer(&connection);
            }
        };
        var peer = Peer{ .server = &server, .mode = mode };
        const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
        var joined = false;
        defer if (!joined) thread.join();
        var connection = try runtime.Client.connectWithTimeout(allocator, threaded.io(), server.address(), .{
            .host = "localhost",
            .enable_permessage_deflate = true,
            .context_takeover = mode,
            .compression_threshold = 0,
            .limits = .{ .max_frame_bytes = 4096, .max_message_bytes = 4096 },
        }, support.timeout);
        defer connection.close();
        try support.client(&connection, mode orelse .none);
        thread.join();
        joined = true;
        if (peer.err) |err| return err;
    }
}

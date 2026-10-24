const std = @import("std");
const websocket = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../../http2/runtime.zig");
const support = @import("directional_support.zig");
const allocator = std.testing.allocator;

test "WebSocket directional takeover HTTP1 uses selected histories from either endpoint" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |server_policy| {
        for (support.modes) |mode| {
            var server = try runtime.Server.listen(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{ .max_frame_bytes = 4096, .max_message_bytes = 4096 });
            defer server.deinit();
            const Peer = struct {
                server: *runtime.Server,
                mode: websocket.ContextTakeover,
                selected: websocket.ContextTakeover,
                err: ?anyerror = null,
                fn run(self: *@This()) void {
                    self.serve() catch |err| {
                        self.err = err;
                    };
                }
                fn serve(self: *@This()) !void {
                    var connection = try self.server.acceptWithTimeout(.{ .enable_permessage_deflate = true, .context_takeover = self.mode, .compression_threshold = 0 }, support.timeout);
                    defer connection.close();
                    try support.peer(&connection, self.selected);
                }
            };
            var peer = Peer{ .server = &server, .mode = if (server_policy) mode else .both, .selected = mode };
            const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
            var joined = false;
            defer if (!joined) thread.join();
            var connection = try runtime.Client.connectWithTimeout(allocator, threaded.io(), server.address(), .{
                .host = "localhost",
                .enable_permessage_deflate = true,
                .context_takeover = if (server_policy) .both else mode,
                .compression_threshold = 0,
                .limits = .{ .max_frame_bytes = 4096, .max_message_bytes = 4096 },
            }, support.timeout);
            defer connection.close();
            try support.client(&connection, mode);
            thread.join();
            joined = true;
            if (peer.err) |err| return err;
        }
    }
}

test "WebSocket directional takeover HTTP2 uses selected histories from either endpoint" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |server_policy| {
        for (support.modes) |mode| {
            var server = try http2.Server.listen(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{ .enable_connect_protocol = true, .max_frame_payload = 4096, .max_body_bytes = 4096 });
            defer server.deinit();
            const Peer = struct {
                server: *http2.Server,
                mode: websocket.ContextTakeover,
                selected: websocket.ContextTakeover,
                err: ?anyerror = null,
                fn run(self: *@This()) void {
                    self.serve() catch |err| {
                        self.err = err;
                    };
                }
                fn serve(self: *@This()) !void {
                    var h2 = try self.server.accept();
                    defer h2.close();
                    var pending = try runtime.H2Server.receiveUpgradeRequestWithTimeout(allocator, &h2, .{ .enable_permessage_deflate = true, .context_takeover = self.mode, .compression_threshold = 0 }, support.timeout);
                    var owns_pending = true;
                    defer if (owns_pending) pending.deinit();
                    var connection = try pending.accept();
                    owns_pending = false;
                    defer connection.close();
                    try support.peer(&connection, self.selected);
                }
            };
            var peer = Peer{ .server = &server, .mode = if (server_policy) mode else .both, .selected = mode };
            const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
            var joined = false;
            defer if (!joined) thread.join();
            var h2 = try http2.Client.connect(allocator, threaded.io(), server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
            defer h2.close();
            var connection = try runtime.H2Client.openWithTimeout(allocator, &h2, .{
                .authority = "localhost",
                .enable_permessage_deflate = true,
                .context_takeover = if (server_policy) .both else mode,
                .compression_threshold = 0,
                .limits = .{ .max_frame_bytes = 4096, .max_message_bytes = 4096 },
            }, support.timeout);
            defer connection.close();
            try support.client(&connection, mode);
            thread.join();
            joined = true;
            if (peer.err) |err| return err;
        }
    }
}

test "WebSocket directional takeover HTTP3 URI uses selected histories from either endpoint" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |server_policy| {
        for (support.modes) |mode| {
            var server = try runtime.h3.Server.bind(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{ .quic = .{ .max_datagram_size = 4096 } }, .{ .handshake = .{ .local_connection_id = "directional-server", .initial_one_rtt_config = .{ .enable_pacing = false } } });
            defer server.deinit();
            const Peer = struct {
                server: *runtime.h3.Server,
                mode: websocket.ContextTakeover,
                selected: websocket.ContextTakeover,
                err: ?anyerror = null,
                fn run(self: *@This()) void {
                    self.serve() catch |err| {
                        self.err = err;
                    };
                }
                fn serve(self: *@This()) !void {
                    var connection = try self.server.acceptWithTimeout(.{ .enable_permessage_deflate = true, .context_takeover = self.mode, .compression_threshold = 0 }, support.timeout);
                    defer connection.deinit();
                    try support.peer(&connection, self.selected);
                }
            };
            var peer = Peer{ .server = &server, .mode = if (server_policy) mode else .both, .selected = mode };
            const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
            var joined = false;
            defer if (!joined) thread.join();
            var uri_storage: [128]u8 = undefined;
            const uri = try std.fmt.bufPrint(&uri_storage, "https://127.0.0.1:{d}/directional", .{server.address().getPort()});
            var connection = try runtime.h3.Client.connectUriWithTimeout(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, uri, .{
                .enable_permessage_deflate = true,
                .context_takeover = if (server_policy) .both else mode,
                .compression_threshold = 0,
                .limits = .{ .max_frame_bytes = 4096, .max_message_bytes = 4096 },
                .h3_limits = .{ .quic = .{ .max_datagram_size = 4096 } },
                .h3 = .{ .handshake = .{ .original_destination_connection_id = "directional-origin", .local_connection_id = "directional-client", .initial_one_rtt_config = .{ .enable_pacing = false } } },
            }, support.timeout);
            defer connection.deinit();
            try support.client(&connection, mode);
            thread.join();
            joined = true;
            if (peer.err) |err| return err;
        }
    }
}

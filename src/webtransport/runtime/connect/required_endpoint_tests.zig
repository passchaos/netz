const std = @import("std");
const runtime = @import("../../runtime.zig");
const quic = @import("../../../quic/mod.zig");

test "WebTransport required Session flow control serve loop survives refused peer" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bindForEndpoint(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{
        .require_session_flow_control = true,
        .max_sessions_per_connection = 2,
    }, .{ .handshake = .{ .local_connection_id = "required-endpoint" } });
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{ .max_pending_handshakes = 2, .handshake_timeout_ms = 2000 });
    defer endpoint.deinit();
    var shutdown: std.Io.Event = .unset;
    const Worker = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        shutdown: *std.Io.Event,
        refused: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
                self.shutdown.set(self.io);
            };
        }

        fn serve(self: *@This()) !void {
            // A valid peer explicitly opts out of Session flow control.
            {
                var client = try runtime.EndpointClient.connectWithTimeout(std.testing.allocator, self.io, .{ .ip4 = .loopback(0) }, self.address, .{
                    .initial_flow_limits = .{},
                    .h3 = .{ .handshake = .{
                        .original_destination_connection_id = "no-flow-origin",
                        .local_connection_id = "no-flow-client",
                    } },
                }, .fromSeconds(2));
                defer client.deinit();
                try std.testing.expectError(error.RequestRejected, client.openSessionWithTimeout(.{ .authority = "localhost" }, .fromSeconds(2)));
                self.refused = true;
            }
            // The same server must continue to accept a qualifying peer.
            var client = try runtime.EndpointClient.connectWithTimeout(std.testing.allocator, self.io, .{ .ip4 = .loopback(0) }, self.address, .{
                .require_session_flow_control = true,
                .h3 = .{ .handshake = .{
                    .original_destination_connection_id = "flow-origin",
                    .local_connection_id = "flow-client",
                } },
            }, .fromSeconds(2));
            defer client.deinit();
            const session = try client.openSessionWithTimeout(.{ .authority = "localhost" }, .fromSeconds(2));
            try session.sendDatagramWithTimeout(&client, "accepted", .fromSeconds(1));
            self.shutdown.waitUncancelable(self.io);
        }
    };
    var worker = Worker{ .io = io, .address = endpoint.address(), .shutdown = &shutdown };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };
    const Handler = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        accepted: usize = 0,
        refused: usize = 0,
        received: bool = false,

        fn handle(self: *@This(), endpoint_server: *runtime.EndpointServer, event: runtime.ServeEvent) !void {
            switch (event) {
                .connect_rejected => |failure| {
                    try std.testing.expectEqual(runtime.ConnectRejectionReason.session_flow_control_required, failure.reason);
                    self.refused += 1;
                },
                .session_request => |pending| {
                    _ = try endpoint_server.accept(pending.handle);
                    self.accepted += 1;
                },
                .session_event => |value| {
                    if (value.event.* != .datagram) return;
                    try std.testing.expectEqualStrings("accepted", value.event.datagram.datagram.payload);
                    self.received = true;
                    self.shutdown.set(self.io);
                },
                else => {},
            }
        }
    };
    var handler = Handler{ .io = io, .shutdown = &shutdown };
    try endpoint.serveUntil(Handler, &handler, Handler.handle, .{
        .shutdown = &shutdown,
        .supported_versions = &.{quic.Version.version_1.wireValue()},
    });
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expect(worker.refused);
    try std.testing.expectEqual(@as(usize, 1), handler.accepted);
    try std.testing.expectEqual(@as(usize, 1), handler.refused);
    try std.testing.expect(handler.received);
}

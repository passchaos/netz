const std = @import("std");
const webtransport = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const quic = @import("../../../quic/mod.zig");

test "WebTransport explicit initial quotas survive public constructors and require wire grants" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb9} ** quic.protection.secret_len);
    var server = try runtime.StatefulProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .initial_flow_limits = .{ .data = 0, .bidi = 1, .uni = 0 },
        .require_session_flow_control = true,
    }, .{}, .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "quota-server",
        .peer_connection_id = "quota-client",
        .local_transport_parameters = quic.practical_transport_parameters,
        .peer_transport_parameters = quic.practical_transport_parameters,
        .one_rtt = .{ .enable_pacing = false },
    });
    defer server.deinit();
    var ready: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const Peer = struct {
        server: *runtime.StatefulProtectedServer,
        ready: *std.Io.Event,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.ready.set(self.server.endpoint.io);
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer session.deinit();
            try std.testing.expectEqual(@as(u64, 0), session.streams.flow.?.send_limit.data);
            try std.testing.expectEqual(@as(u64, 0), session.streams.flow.?.send_limit.bidi);
            try std.testing.expectEqual(@as(u64, 1), session.streams.flow.?.send_limit.uni);
            try std.testing.expectError(error.FlowControlBlocked, session.openBidirectionalStream());
            self.ready.set(self.server.endpoint.io);
            self.release.waitUncancelable(self.server.endpoint.io);
            try session.grantData(4);
            var storage: [16]u8 = undefined;
            const incoming = try session.readStreamWithTimeout(&storage, .fromSeconds(2));
            try std.testing.expect(incoming == .data);
            try std.testing.expectEqualStrings("ping", storage[0..incoming.data.bytes]);
            const outgoing = try session.openBidirectionalStreamWithTimeout(.fromSeconds(2));
            try session.sendStream(outgoing, "pong", true);
        }
    };
    var peer = Peer{ .server = &server, .ready = &ready, .release = &release };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        release.set(io);
        thread.join();
    };
    var client = try runtime.HandshakeClientSession.connectPreconfiguredWithTimeout(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/initial-quotas",
        .limits = .{ .initial_flow_limits = .{ .data = 0, .bidi = 0, .uni = 1 }, .require_session_flow_control = true },
        .h3 = .{},
        .transport = .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "quota-client",
            .peer_connection_id = "quota-server",
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    }, .fromSeconds(2));
    defer client.deinit();
    ready.waitUncancelable(io);
    if (peer.err) |err| return err;
    try std.testing.expectEqual(@as(u64, 0), client.streams.flow.?.send_limit.data);
    try std.testing.expectEqual(@as(u64, 1), client.streams.flow.?.send_limit.bidi);
    try std.testing.expectEqual(@as(u64, 0), client.streams.flow.?.send_limit.uni);
    const outgoing = try client.openBidirectionalStream();
    var committed: usize = 0;
    try std.testing.expectError(error.Timeout, client.sendStreamWithTimeout(outgoing, "ping", true, &committed, .fromMilliseconds(5)));
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(u64, 0), client.streams.flow.?.sent.data);
    try client.grantData(4);
    try client.grantStreams(.bidirectional, 1);
    release.set(io);
    try client.sendStreamWithTimeout(outgoing, "ping", true, &committed, .fromSeconds(2));
    try std.testing.expectEqual(@as(usize, 4), committed);
    var storage: [16]u8 = undefined;
    const incoming = try client.readStreamWithTimeout(&storage, .fromSeconds(2));
    try std.testing.expect(incoming == .data);
    try std.testing.expectEqualStrings("pong", storage[0..incoming.data.bytes]);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

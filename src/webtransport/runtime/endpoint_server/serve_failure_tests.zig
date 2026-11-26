const std = @import("std");
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");
const runtime = @import("../../runtime.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("test_support.zig").Fixture;
const versions = [_]u32{quic.Version.version_1.wireValue()};

fn bufferMalformedConnect(fixture: *Fixture) !void {
    _ = try fixture.addSession();
    const id = try fixture.client.startRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/bad",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
    }, null);
    try std.testing.expectEqual(@as(u62, 4), id);
    try fixture.routeTransport();
}

test "WebTransport serve loop propagates a callback error even when it matches a peer rejection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try bufferMalformedConnect(&fixture);
    var shutdown: std.Io.Event = .unset;
    const Handler = struct {
        calls: usize = 0,
        fn handle(self: *@This(), server: *runtime.EndpointServer, event: runtime.ServeEvent) !void {
            try std.testing.expect(event == .connect_rejected);
            try std.testing.expect(server.serve_failure_sink == null);
            self.calls += 1;
            return error.InvalidConnect;
        }
    };
    var handler: Handler = .{};
    try std.testing.expectError(error.InvalidConnect, fixture.endpoint.serveUntil(Handler, &handler, Handler.handle, .{ .shutdown = &shutdown, .supported_versions = &versions }));
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expect(fixture.endpoint.serve_failure_sink == null);
}

test "WebTransport serve loop keeps socket errors fatal and retains unsubmitted rejection" {
    const FailedSend = struct {
        delegate: std.Io,
        connection: *quic.one_rtt.Connection,
        fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            if (self.connection.sendStreamStats(4) != null) return .{ error.SystemResources, 0 };
            return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
        }
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    try bufferMalformedConnect(&fixture);
    var shutdown: std.Io.Event = .unset;
    const Handler = struct {
        calls: usize = 0,
        fn handle(self: *@This(), _: *runtime.EndpointServer, _: runtime.ServeEvent) !void {
            self.calls += 1;
        }
    };
    var handler: Handler = .{};
    const connection = &fixture.connectionSession().established.connection;
    const original_io = fixture.server.h3.quic_server.endpoint.io;
    {
        var failed = FailedSend{ .delegate = original_io, .connection = connection };
        fixture.server.h3.quic_server.endpoint.io = forwarded_io.observer(&failed, .{ .netSend = FailedSend.send });
        defer fixture.server.h3.quic_server.endpoint.io = original_io;
        try std.testing.expectError(error.SystemResources, fixture.endpoint.serveUntil(Handler, &handler, Handler.handle, .{ .shutdown = &shutdown, .supported_versions = &versions }));
    }
    try std.testing.expectEqual(@as(usize, 0), handler.calls);
    try std.testing.expect(fixture.endpoint.serve_failure_sink == null);
    try std.testing.expect(fixture.endpoint.request_rejection_pending.contains(fixture.handle));
    try std.testing.expect(!connection.closed());
    var bytes: [1]u8 = undefined;
    // Ordinary receives still return the original request error after retry.
    try std.testing.expectError(error.InvalidConnect, fixture.endpoint.receiveOnce(&versions, .{ .clock = .awake, .raw = .fromMilliseconds(1) }, &bytes));
}

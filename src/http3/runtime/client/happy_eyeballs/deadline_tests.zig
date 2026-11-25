//! Owning H3 deadlines include startup; started handshakes remain cancelable.
const std = @import("std");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

const Peers = struct {
    first: quic.runtime.Endpoint,
    second: quic.runtime.Endpoint,
    fn init(allocator: std.mem.Allocator, io: std.Io) !Peers {
        var first = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        errdefer first.deinit();
        const second = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        return .{ .first = first, .second = second };
    }
    fn deinit(self: *Peers) void {
        self.second.deinit();
        self.first.deinit();
    }
    fn resolve(context: *anyopaque, allocator: std.mem.Allocator, _: std.Io, host: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
        const self: *Peers = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, host, "deadline.happy.test")) return error.UnknownHostName;
        return allocator.dupe(std.Io.net.IpAddress, &.{ self.first.address(), self.second.address() });
    }
    fn options(self: *Peers) runtime.HandshakeClientOptions {
        return .{
            .handshake = .{ .original_destination_connection_id = "deadline-original", .local_connection_id = "deadline-client" },
            .address_attempt_timeout = .fromSeconds(5),
            .address_connect_policy = .{ .happy_eyeballs = .{ .attempt_delay = .fromMilliseconds(10), .max_in_flight = 2 } },
            .address_resolver = .{ .context = self, .resolve = resolve },
        };
    }
};

test "HTTP3 Happy Eyeballs total deadline bounds startup and pending handshakes" {
    const allocator = std.testing.allocator;
    var backend = try @import("zio").Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var peers = try Peers.init(allocator, io);
    defer peers.deinit();
    const uri = try std.Uri.parse("https://deadline.happy.test/");
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.HandshakeTimeout, runtime.HandshakeClient.connectUriWithTimeout(allocator, io, .{ .ip4 = .loopback(0) }, uri, .{}, peers.options(), .fromMilliseconds(100)));
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds < 500 * std.time.ns_per_ms);
}

test "HTTP3 Happy Eyeballs cancellation joins both emitted handshakes" {
    const allocator = std.testing.allocator;
    var backend = try @import("zio").Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var peers = try Peers.init(allocator, io);
    defer peers.deinit();
    const uri = try std.Uri.parse("https://deadline.happy.test/");
    const Worker = struct {
        io: std.Io,
        uri: std.Uri,
        peers: *Peers,
        result: ?runtime.Error!runtime.HandshakeClient = null,
        fn run(self: *@This()) void {
            self.result = runtime.HandshakeClient.connectUriWithTimeout(std.testing.allocator, self.io, .{ .ip4 = .loopback(0) }, self.uri, .{}, self.peers.options(), .fromSeconds(5));
        }
    };
    var worker: Worker = .{ .io = io, .uri = uri, .peers = &peers };
    var connecting = try std.Io.concurrent(io, Worker.run, .{&worker});
    var active = true;
    defer if (active) {
        connecting.cancel(io);
        if (worker.result) |result| if (result) |client_value| {
            var client = client_value;
            client.deinit();
        } else |_| {};
    };
    var first_initial = try peers.first.receiveBytesWithTimeout(.fromSeconds(2));
    defer first_initial.deinit(allocator);
    var second_initial = try peers.second.receiveBytesWithTimeout(.fromSeconds(2));
    defer second_initial.deinit(allocator);
    try std.testing.expect(first_initial.bytes.len >= 1200);
    try std.testing.expect(second_initial.bytes.len >= 1200);
    connecting.cancel(io);
    active = false;
    const result = worker.result orelse return error.MissingHandshakeResult;
    if (result) |client_value| {
        var client = client_value;
        client.deinit();
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.Canceled), err);
}

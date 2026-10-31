//! Shared owner recovery and retained transport against the independent peer.
const std = @import("std");
const netz = @import("netz");

const Connector = struct {
    endpoint: netz.grpc.ChannelEndpoint,
    attempts: std.atomic.Value(usize) = .init(0),

    fn connect(context: ?*anyopaque, allocator: std.mem.Allocator, io: std.Io, deadline: std.Io.Clock.Timestamp) netz.http2.runtime.Error!netz.http2.runtime.Connection {
        const self: *Connector = @ptrCast(@alignCast(context.?));
        if (self.attempts.fetchAdd(1, .acq_rel) == 0) return error.ConnectionRefused;
        return switch (self.endpoint) {
            .cleartext_ip => |value| netz.http2.runtime.Client.connectWithDeadline(allocator, io, value.address, value.limits, deadline),
            .tls_address => |value| netz.http2.runtime.Client.connectTlsAddressWithDeadline(allocator, io, value.address, value.tls_host, value.authority, value.limits, value.tls, deadline),
            else => unreachable,
        };
    }
};

pub fn run(allocator: std.mem.Allocator, io: std.Io, endpoint: netz.grpc.ChannelEndpoint, request: netz.grpc.call.UnaryCallOptions) !usize {
    var connector = Connector{ .endpoint = endpoint };
    var channel = try netz.grpc.SharedChannel.init(allocator, io, .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } }, .{
        .channel = .{ .backoff = .{
            .initial_backoff = .fromSeconds(60),
            .max_backoff = .fromSeconds(60),
            .jitter = 0,
            .min_connect_timeout = .fromSeconds(2),
        } },
    });
    defer channel.deinit();
    var watch = channel.watchConnectivity();
    defer watch.deinit();
    try channel.connectWithTimeout(.fromSeconds(2));
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (watch.snapshot().state != .transient_failure) _ = try watch.nextWithDeadline(deadline);
    try channel.resetConnectionBackoffWithTimeout(.fromSeconds(1));
    try watch.waitForReadyWithTimeout(.fromSeconds(2));
    var sender = channel.sender();
    defer sender.deinit();
    for (0..2) |_| {
        var response = try sender.unary(request);
        defer response.deinit();
        try std.testing.expectEqual(netz.grpc.Status.ok, response.status);
        try std.testing.expectEqualStrings("pong", response.message.?.payload);
        try channel.resetConnectionBackoff();
    }
    try std.testing.expectEqual(@as(usize, 2), connector.attempts.load(.acquire));
    return 2;
}

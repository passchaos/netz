//! Background shared senders against the pinned C++ unary/health services.
const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

fn call(sender: netz.grpc.SharedChannelSender, request: []const u8) !netz.grpc.UnaryResponse {
    return sender.unary(.{ .path = "/grpc.testing.TestService/UnaryCall", .message = request, .timeout = .{ .value = 10, .unit = .second }, .wait_for_ready = true });
}

fn resolve(_: *anyopaque, allocator: std.mem.Allocator, _: std.Io, host: []const u8, port: u16, _: ?std.Io.Clock.Timestamp) netz.grpc.ChannelAddressResolver.ResolveError![]std.Io.net.IpAddress {
    if (!std.mem.eql(u8, host, "localhost") and !std.mem.eql(u8, host, "foo.test.google.fr")) return error.NameServerFailure;
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    return allocator.dupe(std.Io.net.IpAddress, &.{ address, address });
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, port: u16, tls: bool, bundle: *std.crypto.Certificate.Bundle, lock: *std.Io.RwLock, limits: netz.http2.runtime.Limits) !void {
    const target: netz.grpc.ChannelTarget = if (tls) .{ .tls_host = .{
        .host = "foo.test.google.fr",
        .port = port,
        .limits = limits,
        .tls = .{ .ca_bundle = .{ .bundle = bundle, .lock = lock } },
    } } else .{ .cleartext_host = .{ .host = "localhost", .port = port, .limits = limits } };
    var resolver_context: u8 = 0;
    var channel = try netz.grpc.SharedChannel.init(allocator, io, target, .{
        .service_config_json = "{\"healthCheckConfig\":{\"serviceName\":\"\"}}",
        .channel = .{ .address_resolver = .{ .context = &resolver_context, .resolve = resolve }, .resolver_min_refresh_interval = .zero },
    });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    const request_a = try messages.encodeSimpleRequestAlloc(allocator, .{ .response_size = 65553, .request_body_size = 127 });
    defer allocator.free(request_a);
    const request_b = try messages.encodeSimpleRequestAlloc(allocator, .{ .response_size = 131101, .request_body_size = 257 });
    defer allocator.free(request_b);
    var a = try io.concurrent(call, .{ sender, request_a });
    defer _ = a.cancel(io) catch {};
    var b = try io.concurrent(call, .{ sender, request_b });
    defer _ = b.cancel(io) catch {};
    var response_b = try b.await(io);
    defer response_b.deinit();
    var response_a = try a.await(io);
    defer response_a.deinit();
    if (response_a.status != .ok or response_b.status != .ok) return error.InvalidSharedUnaryStatus;
    try messages.validateStreamingOutputCallResponse(response_a.message.?.payload, 65553);
    try messages.validateStreamingOutputCallResponse(response_b.message.?.payload, 131101);
    if (channel.endpointCount() != 1 or try channel.refreshNameResolutionWithTimeout(.fromSeconds(10)) != 1) return error.InvalidSharedAddressMembership;
}

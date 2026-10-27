//! Background shared senders against the pinned C++ unary/health services.
const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

fn call(sender: netz.grpc.SharedChannelSender, request: []const u8) !netz.grpc.UnaryResponse {
    return sender.unary(.{ .path = "/grpc.testing.TestService/UnaryCall", .message = request, .timeout = .{ .value = 10, .unit = .second }, .wait_for_ready = true });
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, port: u16, tls: bool, bundle: *std.crypto.Certificate.Bundle, lock: *std.Io.RwLock, limits: netz.http2.runtime.Limits) !void {
    const target: netz.grpc.ChannelTarget = if (tls) .{ .tls_address = .{
        .address = .{ .ip4 = .loopback(port) },
        .tls_host = "foo.test.google.fr",
        .authority = "localhost",
        .limits = limits,
        .tls = .{ .ca_bundle = .{ .bundle = bundle, .lock = lock } },
    } } else .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(port) }, .authority = "localhost", .limits = limits } };
    var channel = try netz.grpc.SharedChannel.init(allocator, io, target, .{ .service_config_json = "{\"healthCheckConfig\":{\"serviceName\":\"\"}}" });
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
}

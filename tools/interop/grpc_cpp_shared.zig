//! Background shared senders against the pinned C++ unary/health services.
const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

fn call(sender: netz.grpc.SharedChannelSender, request: []const u8) !netz.grpc.UnaryResponse {
    return sender.unary(.{ .path = "/grpc.testing.TestService/UnaryCall", .message = request, .timeout = .{ .value = 10, .unit = .second }, .wait_for_ready = true });
}

fn verifyAdmission(sender: netz.grpc.SharedChannelSender, io: std.Io) !void {
    sender.state.mutex.lockUncancelable(io);
    defer sender.state.mutex.unlock(io);
    try std.testing.expectError(error.Timeout, sender.unary(.{ .path = "/grpc.testing.TestService/UnaryCall", .message = &.{}, .timeout = .{ .value = 10, .unit = .millisecond } }));
    try std.testing.expectError(error.Timeout, sender.startDuplex(.{ .path = "/grpc.testing.TestService/FullDuplexCall", .timeout = .{ .value = 10, .unit = .millisecond } }));
    if (sender.state.mutex.tryLock()) return error.SharedAdmissionReleasedOwner;
    if (sender.state.head != null or sender.state.queued != 0) return error.SharedAdmissionQueuedExpiredCall;
}

fn readShared(reader: netz.grpc.SharedStreamReader, size: usize, allocator: std.mem.Allocator) !void {
    var count: usize = 0;
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(10));
        defer event.deinit(allocator);
        switch (event) {
            .message => |message| {
                try messages.validateStreamingOutputCallResponse(message.payload, size);
                count += 1;
            },
            .terminal => |response| {
                if (response.status != .ok or count != 1) return error.InvalidSharedDuplexResponse;
                return;
            },
            else => {},
        }
    }
}

fn runDuplex(allocator: std.mem.Allocator, io: std.Io, sender: netz.grpc.SharedChannelSender) !void {
    const options: netz.grpc.StreamingRequestOptions = .{ .path = "/grpc.testing.TestService/FullDuplexCall", .wait_for_ready = true, .timeout = .{ .value = 10, .unit = .second } };
    var a = try sender.startDuplex(options);
    defer a.deinit();
    var b = try sender.startDuplex(options);
    defer b.deinit();
    var aw = a.writer();
    defer aw.deinit();
    var bw = b.writer();
    defer bw.deinit();
    var ar = a.reader();
    defer ar.deinit();
    var br = b.reader();
    defer br.deinit();
    const request_a = try messages.encodeStreamingOutputCallRequestAlloc(allocator, .{ .response_size = 65553, .request_body_size = 127 });
    defer allocator.free(request_a);
    const request_b = try messages.encodeStreamingOutputCallRequestAlloc(allocator, .{ .response_size = 131101, .request_body_size = 257 });
    defer allocator.free(request_b);
    var wa = try io.concurrent(netz.grpc.SharedStreamWriter.writeFinalMessage, .{ aw, request_a });
    defer _ = wa.cancel(io) catch {};
    var wb = try io.concurrent(netz.grpc.SharedStreamWriter.writeFinalMessage, .{ bw, request_b });
    defer _ = wb.cancel(io) catch {};
    var ra = try io.concurrent(readShared, .{ ar, 65553, allocator });
    defer _ = ra.cancel(io) catch {};
    var rb = try io.concurrent(readShared, .{ br, 131101, allocator });
    defer _ = rb.cancel(io) catch {};
    try wa.await(io);
    try wb.await(io);
    try rb.await(io);
    try ra.await(io);
}

fn runOperationDeadlinesAndCancellation(allocator: std.mem.Allocator, io: std.Io, sender: netz.grpc.SharedChannelSender) !void {
    const request = try messages.encodeStreamingOutputCallRequestAlloc(allocator, .{
        .response_size = 33,
        .request_body_size = 17,
    });
    defer allocator.free(request);
    {
        var operation = try sender.startDuplex(.{
            .path = "/grpc.testing.TestService/FullDuplexCall",
            .wait_for_ready = true,
            .timeout = .{ .value = 10, .unit = .second },
        });
        defer operation.deinit();
        var writer = operation.writer();
        defer writer.deinit();
        var reader = operation.reader();
        defer reader.deinit();
        {
            sender.state.mutex.lockUncancelable(io);
            defer sender.state.mutex.unlock(io);
            try std.testing.expectError(error.Timeout, writer.writeMessageWithTimeout(request, .fromMilliseconds(10)));
            if (sender.state.mutex.tryLock()) return error.SharedWriteAdmissionReleasedOwner;
        }
        try writer.writeFinalMessage(request);
        {
            sender.state.mutex.lockUncancelable(io);
            defer sender.state.mutex.unlock(io);
            try std.testing.expectError(error.Timeout, reader.nextWithTimeout(.fromMilliseconds(10)));
            if (sender.state.mutex.tryLock()) return error.SharedReadAdmissionReleasedOwner;
        }
        try readShared(reader, 33, allocator);
    }

    var stream = try sender.startDuplex(.{
        .path = "/grpc.testing.TestService/FullDuplexCall",
        .wait_for_ready = true,
        .timeout = .{ .value = 10, .unit = .second },
    });
    defer stream.deinit();
    stream.requestCancel();
    try stream.cancelWithTimeout(.fromSeconds(10));

    const unary_request = try messages.encodeSimpleRequestAlloc(allocator, .{
        .response_size = 33,
        .request_body_size = 17,
    });
    defer allocator.free(unary_request);
    var response = try call(sender, unary_request);
    defer response.deinit();
    if (response.status != .ok) return error.InvalidSharedCancelReuseStatus;
    try messages.validateStreamingOutputCallResponse(response.message.?.payload, 33);
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
    try verifyAdmission(sender, io);
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
    try runDuplex(allocator, io, sender);
    try runOperationDeadlinesAndCancellation(allocator, io, sender);
}

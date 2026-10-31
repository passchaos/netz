const std = @import("std");
const netz = @import("netz");
const Mode = enum { h2c, tls12, tls13 };
const Phase = enum { stagger, ordered, deadline, immediate, shared_reset, shared_update };
const allocator = std.heap.c_allocator;

fn refuse(_: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) netz.http2.runtime.Error!netz.http2.runtime.Connection {
    return error.ConnectionRefused;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 7) return error.InvalidArgument;
    const mode = std.meta.stringToEnum(Mode, args[1]) orelse return error.InvalidArgument;
    const phase = std.meta.stringToEnum(Phase, args[2]) orelse return error.InvalidArgument;
    const ports = [_]u16{ try std.fmt.parseInt(u16, args[3], 10), try std.fmt.parseInt(u16, args[4], 10), try std.fmt.parseInt(u16, args[5], 10) };
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    var lock: std.Io.RwLock = .init;
    if (mode != .h2c) try bundle.addCertsFromFilePathAbsolute(allocator, io, std.Io.Clock.real.now(io), args[6]);
    var endpoints: [3]netz.grpc.ChannelEndpoint = undefined;
    for (&endpoints, ports) |*endpoint, port| {
        endpoint.* = if (mode == .h2c) .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(port) } } } else .{ .tls_address = .{
            .address = .{ .ip4 = .loopback(port) },
            .tls_host = "fixture.test",
            .authority = "fixture.test",
            .tls = .{ .ca_bundle = .{ .bundle = &bundle, .lock = &lock }, .protocol_policy = if (mode == .tls12) .tls12_only else .tls13_only },
        } };
    }
    const immediate = [_]netz.grpc.ChannelEndpoint{ .{ .custom = .{ .context = null, .connect_fn = refuse } }, endpoints[2] };
    const selected: []const netz.grpc.ChannelEndpoint = switch (phase) {
        .immediate => &immediate,
        .deadline => endpoints[0..2],
        else => &endpoints,
    };
    var channel = if (phase != .shared_reset and phase != .shared_update) try netz.grpc.Channel.init(allocator, io, .{ .resolved = .{ .endpoints = selected } }, .{
        .connection_attempt_delay = switch (phase) {
            .ordered => null,
            .immediate => .fromSeconds(5),
            else => .fromMilliseconds(250),
        },
    }) else null;
    defer if (channel) |*value| value.deinit();
    const metadata = [_]netz.http2.Hpack.HeaderField{ .{ .name = "x-fixture-client", .value = "netz" }, .{ .name = "x-fixture-phase", .value = args[2] } };
    const options: netz.grpc.call.UnaryCallOptions = .{
        .path = "/fixture.Race/Unary",
        .authority = "fixture.test",
        .message = "ping",
        .metadata = &metadata,
        .wait_for_ready = true,
        .timeout = .{ .value = switch (phase) {
            .ordered => 400,
            .deadline => 80,
            else => 2000,
        }, .unit = .millisecond },
    };
    var rpcs: usize = 0;
    if (phase == .shared_reset) {
        rpcs = try @import("shared_backoff.zig").run(allocator, io, endpoints[2], options);
    } else if (phase == .shared_update) {
        rpcs = try @import("shared_update.zig").run(allocator, io, endpoints[2], options);
    } else if (phase == .ordered or phase == .deadline) {
        try std.testing.expectError(error.Timeout, channel.?.unary(options));
        try std.testing.expectEqual(netz.grpc.ChannelConnectivityState.transient_failure, channel.?.connectivityState());
    } else {
        for (0..2) |_| {
            var response = try channel.?.unary(options);
            defer response.deinit();
            try std.testing.expectEqual(netz.grpc.Status.ok, response.status);
            try std.testing.expectEqualStrings("pong", response.message.?.payload);
            rpcs += 1;
        }
        try std.testing.expectEqual(@as(?usize, if (phase == .stagger) 2 else 1), channel.?.selected_index);
        if (mode != .h2c) try std.testing.expectEqualStrings("h2", channel.?.negotiatedAlpn().?);
    }
    var buffer: [512]u8 = undefined;
    var output = std.Io.File.stdout().writer(io, &buffer);
    try output.interface.print("{{\"io\":\"zio-std-io\",\"mode\":\"{s}\",\"phase\":\"{s}\",\"rpcs\":{d}}}\n", .{ args[1], args[2], rpcs });
    try output.interface.flush();
}

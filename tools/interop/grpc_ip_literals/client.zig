//! Numeric endpoint conformance against an independently encoded HTTP/2 peer.
const std = @import("std");
const netz = @import("netz");
const Mode = enum { cleartext, tls12, tls13 };
const Kind = enum { h2_host, h2_host_timeout, h2_host_deadline, h2_tls_address, h2_tls_address_timeout, h2_tls_address_deadline, channel, resolved_channel, shared, resolved_shared };
const allocator = std.heap.c_allocator;
const limits: netz.http2.runtime.Limits = .{ .connect_timeout = .fromSeconds(3), .handshake_timeout = .fromSeconds(3) };
const timeout: std.Io.Duration = .fromSeconds(5);

fn check(response: netz.grpc.UnaryResponse) !void {
    try std.testing.expectEqual(netz.grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings("numeric", response.message.?.payload);
}

fn connected(io: std.Io, kind: Kind, host: []const u8, address: std.Io.net.IpAddress, mode: Mode, tls: netz.http2.runtime.TlsConnectOptions) !netz.http2.runtime.Connection {
    const Client = netz.http2.runtime.Client;
    const port = address.getPort();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = timeout, .clock = .awake });
    if (mode == .cleartext) return switch (kind) {
        .h2_host => Client.connectHost(allocator, io, host, port, limits),
        .h2_host_timeout => Client.connectHostWithTimeout(allocator, io, host, port, limits, timeout),
        .h2_host_deadline => Client.connectHostWithDeadline(allocator, io, host, port, limits, deadline),
        else => unreachable,
    };
    const authority = try std.fmt.allocPrint(allocator, "{f}", .{address});
    defer allocator.free(authority);
    return switch (kind) {
        .h2_host => Client.connectTlsHost(allocator, io, host, port, limits, tls),
        .h2_host_timeout => Client.connectTlsHostWithTimeout(allocator, io, host, port, limits, tls, timeout),
        .h2_host_deadline => Client.connectTlsHostWithDeadline(allocator, io, host, port, limits, tls, deadline),
        .h2_tls_address => Client.connectTlsAddress(allocator, io, address, host, authority, limits, tls),
        .h2_tls_address_timeout => Client.connectTlsAddressWithTimeout(allocator, io, address, host, authority, limits, tls, timeout),
        .h2_tls_address_deadline => Client.connectTlsAddressWithDeadline(allocator, io, address, host, authority, limits, tls, deadline),
        else => unreachable,
    };
}

fn probe(io: std.Io, kind: Kind, host: []const u8, address: std.Io.net.IpAddress, mode: Mode, tls: netz.http2.runtime.TlsConnectOptions, reject: bool) !void {
    const metadata = [_]netz.http2.Hpack.HeaderField{
        .{ .name = "x-fixture-client", .value = "netz" },
        .{ .name = "x-fixture-kind", .value = @tagName(kind) },
        .{ .name = "x-fixture-host", .value = host },
    };
    const request: netz.grpc.call.UnaryCallOptions = .{ .path = "/fixture.Numeric/Unary", .message = "numeric", .timeout = .{ .value = 5, .unit = .second }, .metadata = &metadata };
    if (@intFromEnum(kind) < @intFromEnum(Kind.channel)) {
        const result = connected(io, kind, host, address, mode, tls);
        if (reject) return std.testing.expectError(error.CertificateUntrusted, result);
        var connection = try result;
        defer connection.close();
        if (mode != .cleartext) try std.testing.expectEqualStrings("h2", connection.negotiatedAlpn().?);
        for (0..2) |_| {
            var response = try netz.grpc.unaryCall(&connection, allocator, request);
            defer response.deinit();
            try check(response);
        }
        return;
    }
    const endpoint: netz.grpc.ChannelEndpoint = if (mode == .cleartext)
        .{ .cleartext_host = .{ .host = host, .port = address.getPort(), .limits = limits } }
    else
        .{ .tls_host = .{ .host = host, .port = address.getPort(), .limits = limits, .tls = tls } };
    const endpoints = [_]netz.grpc.ChannelEndpoint{endpoint};
    const target: netz.grpc.ChannelTarget = if (kind == .resolved_channel or kind == .resolved_shared)
        .{ .resolved = .{ .endpoints = &endpoints } }
    else if (mode == .cleartext)
        .{ .cleartext_host = endpoint.cleartext_host }
    else
        .{ .tls_host = endpoint.tls_host };
    if (kind == .shared or kind == .resolved_shared) {
        var channel = try netz.grpc.SharedChannel.init(allocator, io, target, .{});
        defer channel.deinit();
        var sender = channel.sender();
        defer sender.deinit();
        if (reject) return std.testing.expectError(error.ConnectionUnavailable, sender.unary(request));
        for (0..2) |_| {
            var response = try sender.unary(request);
            defer response.deinit();
            try check(response);
        }
    } else {
        var channel = try netz.grpc.Channel.init(allocator, io, target, .{});
        defer channel.deinit();
        if (reject) return std.testing.expectError(error.CertificateUntrusted, channel.unary(request));
        for (0..2) |_| {
            var response = try channel.unary(request);
            defer response.deinit();
            try check(response);
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 6) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[2], 10);
    const mode = std.meta.stringToEnum(Mode, args[3]) orelse return error.InvalidArgument;
    const reject = std.mem.eql(u8, args[5], "reject");
    const address = try std.Io.net.IpAddress.parse(args[1], port);
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    var lock: std.Io.RwLock = .init;
    if (mode != .cleartext) try bundle.addCertsFromFilePathAbsolute(allocator, io, std.Io.Clock.real.now(io), args[4]);
    const tls: netz.http2.runtime.TlsConnectOptions = .{
        .ca_bundle = .{ .bundle = &bundle, .lock = &lock },
        .protocol_policy = if (mode == .tls12) .tls12_only else .tls13_only,
    };
    const hosts: []const []const u8 = if (address == .ip6) &.{ "::1", "[::1]", "0:0:0:0:0:0:0:1" } else &.{"127.0.0.1"};
    var connections: usize = 0;
    for (hosts) |host| {
        inline for (std.meta.tags(Kind)) |kind| {
            if (!(mode == .cleartext and @intFromEnum(kind) >= @intFromEnum(Kind.h2_tls_address) and @intFromEnum(kind) <= @intFromEnum(Kind.h2_tls_address_deadline))) {
                try probe(io, kind, host, address, mode, tls, reject);
                connections += 1;
            }
        }
    }
    var output_buffer: [512]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &output_buffer);
    try stdout.interface.print("io=zio-std-io mode={s} rejected={} connections={d} rpcs={d}\n", .{ args[3], reject, connections, if (reject) @as(usize, 0) else connections * 2 });
    try stdout.interface.flush();
}

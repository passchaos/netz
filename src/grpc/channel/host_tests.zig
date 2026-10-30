const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const shared = @import("shared.zig");
const support = @import("shared/resolution/test_support.zig");
const allocator = std.testing.allocator;

test "gRPC IP host targets reuse IPv4 and IPv6 connections in both channel owners" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const cases = [_]struct { host: []const u8, address: std.Io.net.IpAddress }{
        .{ .host = "127.0.0.1", .address = .{ .ip4 = .loopback(0) } },
        .{ .host = "::1", .address = .{ .ip6 = .loopback(0) } },
        .{ .host = "[::1]", .address = .{ .ip6 = .loopback(0) } },
        .{ .host = "0:0:0:0:0:0:0:1", .address = .{ .ip6 = .loopback(0) } },
    };
    for (cases) |case| {
        for ([_]bool{ false, true }) |background| {
            for ([_]bool{ false, true }) |resolved| {
                var server = try grpc.runtime.Server.listen(allocator, io, case.address, .{}, 4096);
                defer server.deinit();
                const authority = try std.fmt.allocPrint(allocator, "{f}", .{server.address()});
                defer allocator.free(authority);
                var peer = support.Peer{ .server = &server, .authority = authority, .reply = "numeric", .requests = 2 };
                var task = io.async(support.Peer.run, .{&peer});
                defer _ = task.cancel(io) catch {};
                const endpoint: channel.Endpoint = .{ .cleartext_host = .{ .host = case.host, .port = server.address().getPort() } };
                const endpoints = [_]channel.Endpoint{endpoint};
                const target: channel.Target = if (resolved)
                    .{ .resolved = .{ .endpoints = &endpoints } }
                else
                    .{ .cleartext_host = endpoint.cleartext_host };
                if (background) {
                    var client = try shared.SharedChannel.init(allocator, io, target, .{});
                    var live = true;
                    defer if (live) client.deinit();
                    var sender = client.sender();
                    defer sender.deinit();
                    for (0..2) |_| {
                        var response = try support.unary(sender, "request");
                        defer response.deinit();
                        try std.testing.expectEqualStrings("numeric", response.message.?.payload);
                    }
                    client.deinit();
                    live = false;
                } else {
                    var client = try channel.Channel.init(allocator, io, target, .{});
                    var live = true;
                    defer if (live) client.deinit();
                    for (0..2) |_| {
                        var response = try client.unary(.{ .path = "/demo.Shared/Unary", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
                        defer response.deinit();
                        try std.testing.expectEqualStrings("numeric", response.message.?.payload);
                    }
                    client.deinit();
                    live = false;
                }
                try task.await(io);
            }
        }
    }
}

test "gRPC IP host targets retain configured resolver overrides and normalized identity" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Resolver = struct {
        address: std.Io.net.IpAddress,
        calls: std.atomic.Value(usize) = .init(0),
        fn resolve(context: *anyopaque, gpa: std.mem.Allocator, _: std.Io, host: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) channel.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, "2001:db8::1", host)) return error.InvalidHostName;
            _ = self.calls.fetchAdd(1, .monotonic);
            return gpa.dupe(std.Io.net.IpAddress, &.{self.address});
        }
    };
    for ([_]bool{ false, true }) |background| {
        var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
        defer server.deinit();
        const port = server.address().getPort();
        const authority = try std.fmt.allocPrint(allocator, "[2001:db8::1]:{d}", .{port});
        defer allocator.free(authority);
        var peer = support.Peer{ .server = &server, .authority = authority, .reply = "routed", .requests = 1 };
        var task = io.async(support.Peer.run, .{&peer});
        defer _ = task.cancel(io) catch {};
        var resolver = Resolver{ .address = server.address() };
        const options: channel.Options = .{ .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve } };
        const target: channel.Target = .{ .cleartext_host = .{ .host = "[2001:db8::1]", .port = port } };
        if (background) {
            var client = try shared.SharedChannel.init(allocator, io, target, .{ .channel = options });
            var live = true;
            defer if (live) client.deinit();
            var sender = client.sender();
            defer sender.deinit();
            var response = try support.unary(sender, "request");
            defer response.deinit();
            try std.testing.expectEqualStrings("routed", response.message.?.payload);
            client.deinit();
            live = false;
        } else {
            var client = try channel.Channel.init(allocator, io, target, options);
            var live = true;
            defer if (live) client.deinit();
            var response = try client.unary(.{ .path = "/demo.Shared/Unary", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
            defer response.deinit();
            try std.testing.expectEqualStrings("routed", response.message.?.payload);
            client.deinit();
            live = false;
        }
        try task.await(io);
        try std.testing.expectEqual(@as(usize, 1), resolver.calls.load(.acquire));
    }
}

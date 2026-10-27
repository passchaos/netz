const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");
const reconnecting = @import("reconnecting.zig");
const allocator = std.testing.allocator;

const Unavailable = struct {
    calls: usize = 0,
    fn connect(context: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        return error.ConnectionRefused;
    }
    fn target(self: *@This()) grpc.ChannelTarget {
        return .{ .custom = .{ .context = self, .connect_fn = connect } };
    }
};

test "gRPC configured health Watch skips allocation and connection when disabled" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var unavailable: Unavailable = .{};
    for ([_][]const u8{ "{}", "{\"healthCheckConfig\":{}}", "{\"healthCheckConfig\":{\"serviceName\":null}}" }) |json| {
        var config = try grpc.ServiceConfig.parse(allocator, json);
        defer config.deinit();
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        const watch = try reconnecting.ReconnectingWatch.initWithServiceConfig(failing.allocator(), threaded.io(), unavailable.target(), .{}, &config);
        try std.testing.expect(watch == null);
        try std.testing.expect(!failing.has_induced_failure);
    }
    try std.testing.expectEqual(@as(usize, 0), unavailable.calls);
}

test "gRPC configured health Watch owns its name and inherits channel balancing" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var unavailable: Unavailable = .{};
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"healthCheckConfig":{"serviceName":"demo.Echo"},
        \\ "loadBalancingConfig":[{"round_robin":{}}]}
    );
    var config_live = true;
    defer if (config_live) config.deinit();
    var watch = (try reconnecting.ReconnectingWatch.initWithServiceConfig(allocator, threaded.io(), unavailable.target(), .{}, &config)).?;
    defer watch.deinit();
    config.deinit();
    config_live = false;
    try std.testing.expectEqualStrings("demo.Echo", watch.service);
    try std.testing.expectEqual(grpc.ChannelSelectionPolicy.round_robin, watch.owner.selectionPolicy());
    const retry = try watch.nextWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(error.ConnectionRefused, retry.retrying.failure.transport);
    try std.testing.expectEqual(@as(usize, 1), unavailable.calls);
}

test "gRPC configured health Watch honors explicit service and balancing overrides" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var unavailable: Unavailable = .{};
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"healthCheckConfig":{"serviceName":"config.Service"},
        \\ "loadBalancingConfig":[{"round_robin":{}}]}
    );
    defer config.deinit();
    const Case = struct { options: reconnecting.Options, expected: []const u8 };
    for ([_]Case{
        .{ .options = .{}, .expected = "config.Service" },
        .{ .options = .{ .watch = .{ .service = "watch.Service" } }, .expected = "watch.Service" },
        .{ .options = .{ .watch = .{ .service = "watch.Service" }, .service_override = "explicit.Service" }, .expected = "explicit.Service" },
        .{ .options = .{ .watch = .{ .service = "watch.Service" }, .service_override = "" }, .expected = "" },
    }) |case| {
        var options = case.options;
        options.channel_options.selection_policy = .pick_first;
        var watch = (try reconnecting.ReconnectingWatch.initWithServiceConfig(allocator, threaded.io(), unavailable.target(), options, &config)).?;
        defer watch.deinit();
        try std.testing.expectEqualStrings(case.expected, watch.service);
        try std.testing.expectEqual(grpc.ChannelSelectionPolicy.pick_first, watch.owner.selectionPolicy());
        if (options.service_override != null) try std.testing.expect(watch.service.ptr == watch.options.service_override.?.ptr);
    }
    var disabled_config = try grpc.ServiceConfig.parse(allocator, "{}");
    defer disabled_config.deinit();
    var overall = (try reconnecting.ReconnectingWatch.initWithServiceConfig(allocator, threaded.io(), unavailable.target(), .{ .service_override = "" }, &disabled_config)).?;
    defer overall.deinit();
    try std.testing.expectEqualStrings("", overall.service);
}

test "gRPC configured health Watch construction is transactional on allocation failure" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, io: std.Io) !void {
            var unavailable: Unavailable = .{};
            var config = try grpc.ServiceConfig.parse(gpa, "{\"healthCheckConfig\":{\"serviceName\":\"demo.Echo\"}}");
            defer config.deinit();
            var watch = (try reconnecting.ReconnectingWatch.initWithServiceConfig(gpa, io, unavailable.target(), .{}, &config)).?;
            defer watch.deinit();
            try std.testing.expectEqualStrings("demo.Echo", watch.service);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{threaded.io()});
}

test "gRPC configured health Watch validates service wire bounds before allocation or I/O" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var unavailable: Unavailable = .{};
    const json = "{\"healthCheckConfig\":{\"serviceName\":\"" ++
        "x" ** (grpc.health.max_service_name_len + 1) ++ "\"}}";
    var config = try grpc.ServiceConfig.parse(allocator, json);
    defer config.deinit();
    // Core's JSON field is a general string. The protocol constructor applies
    // its message bound without performing an allocator or connector call.
    try std.testing.expectEqual(grpc.health.max_service_name_len + 1, config.healthCheckServiceName().?.len);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.ServiceNameTooLong, reconnecting.ReconnectingWatch.initWithServiceConfig(
        failing.allocator(),
        threaded.io(),
        unavailable.target(),
        .{},
        &config,
    ));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), unavailable.calls);
}

test "gRPC configured health Watch sends named and overall requests after config destruction" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Case = struct { json: []const u8, name: []const u8 };
    for ([_]Case{
        .{ .json = "{\"healthCheckConfig\":{\"serviceName\":\"demo.Echo\"}}", .name = "demo.Echo" },
        .{ .json = "{\"healthCheckConfig\":{\"serviceName\":\"\"}}", .name = "" },
    }) |case| {
        var registry = try grpc.health.Registry.init(allocator, io);
        defer registry.deinit();
        _ = try registry.setStatus(case.name, .serving);
        var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
        defer server.deinit();
        const Peer = struct {
            fn run(server_ptr: *grpc.runtime.Server, registry_ptr: *grpc.health.Registry) !void {
                var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
                defer connection.deinit();
                var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
                defer stream.deinit();
                try std.testing.expect(stream.timeout == null);
                try connection.serveHealthWatch(registry_ptr, &stream);
            }
        };
        var peer = io.async(Peer.run, .{ &server, &registry });
        defer _ = peer.cancel(io) catch {};
        var config = try grpc.ServiceConfig.parse(allocator, case.json);
        var config_live = true;
        defer if (config_live) config.deinit();
        var watch = (try reconnecting.ReconnectingWatch.initWithServiceConfig(allocator, io, .{
            .cleartext_ip = .{ .address = server.address() },
        }, .{}, &config)).?;
        defer watch.deinit();
        config.deinit();
        config_live = false;
        try watch.waitForServingWithTimeout(.fromSeconds(3));
        try std.testing.expectEqualStrings(case.name, watch.service);
        try watch.cancel();
        try peer.await(io);
    }
}

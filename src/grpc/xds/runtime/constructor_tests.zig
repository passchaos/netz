//! Starting discovery must not partially install names on allocation failure.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const gpa = std.testing.allocator;
test "gRPC xDS runtime constructors and startup preserve destination on allocation failure" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Harness = struct {
        fn run(allocator: std.mem.Allocator, active_io: std.Io) !void {
            var channel = try grpc.SharedChannel.init(gpa, active_io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
            defer channel.deinit();
            var sender = channel.sender();
            defer sender.deinit();
            var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
            defer client.deinit();
            const controller = try runtime.Controller.create(allocator, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
            defer controller.deinit();
            const revision = channel.configurationRevision();
            _ = controller.startWithDeadline(&client, channel, .fromNow(active_io, .{ .clock = .awake, .raw = .fromSeconds(3) })) catch |err| {
                try std.testing.expectEqual(revision, channel.configurationRevision());
                try std.testing.expectEqual(@as(usize, 0), client.subscriptions.entries.items.len);
                try std.testing.expect(controller.latest == null and controller.entries.items.len == 0);
                return err;
            };
            try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
            try std.testing.expectEqualStrings("frontend", client.subscriptions.entries.items[0].names[0]);
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{io});
}
test "gRPC xDS runtime preserves local service config and enforces cache memory limits" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .service_config_json = "{\"retryThrottling\":{\"maxTokens\":10,\"tokenRatio\":1},\"methodConfig\":[{\"name\":[{}],\"timeout\":\"2s\"}]}" });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    const config = channel.state.retainConfig().?;
    defer config.release();
    try std.testing.expect(config.config.retry_throttler != null);
    const resolved = try config.config.resolveUnary(.{ .path = "/demo.Service/Get", .message = "request" });
    try std.testing.expectEqual(@as(i96, 2 * std.time.ns_per_s), resolved.options.timeout.?.duration().nanoseconds);
    const bounded = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" }, .limits = .{ .max_storage_bytes = 1 } });
    defer bounded.deinit();
    const revision = channel.configurationRevision();
    try std.testing.expectError(error.XdsLimitExceeded, bounded.startWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    try std.testing.expectEqual(revision, channel.configurationRevision());
    try std.testing.expect(bounded.latest == null);
    try std.testing.expectError(error.Timeout, bounded.startWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
    try std.testing.expectEqual(revision, channel.configurationRevision());
}

test "gRPC xDS bootstrap server features populate runtime options" {
    const bootstrap = @import("../bootstrap.zig");
    const json =
        \\{"xds_servers":[{"server_uri":"http://127.0.0.1:8080",
        \\"channel_creds":[{"type":"insecure"}],
        \\"server_features":["ignore_resource_deletion","fail_on_data_errors",
        \\"trusted_xds_server","resource_timer_is_transient_error"]}]}
    ;
    const parsed = try bootstrap.parse(gpa, json, .{});
    defer parsed.deinit();
    var options: runtime.Options = .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
    };
    options.applyServerFeatures(parsed.servers[0]);
    try std.testing.expect(options.ignore_resource_deletion);
    try std.testing.expect(options.fail_on_data_errors);
    try std.testing.expect(options.trusted_xds_server);
    try std.testing.expect(options.resource_timer_is_transient_error);
}

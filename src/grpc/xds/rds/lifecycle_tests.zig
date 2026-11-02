//! Selector epochs, rollback and admission priority independent of live peers.
const std = @import("std");
const grpc = @import("../../mod.zig");
const rds = @import("../rds.zig");
const fixture = @import("testing.zig");
const gpa = std.testing.allocator;
const manager = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"cluster:a\":{\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
fn destination(allocator: std.mem.Allocator, io: std.Io) !grpc.SharedChannel {
    return grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }} } }, .{ .service_config_json = manager });
}
test "gRPC RDS selector epochs share configuration storage without retaining a version chain" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try destination(gpa, io);
    defer channel.deinit();
    const first = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/" }}, null);
    defer gpa.free(first);
    const initial = try rds.Snapshot.create(gpa, first, .{}, .{ .authority = "backend.test" });
    defer initial.release();
    _ = try initial.publishWithDeadline(channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    const retained = channel.state.retainConfig().?;
    defer retained.release();
    const storage = retained.storage;
    for (0..64) |_| {
        const snapshot = try rds.Snapshot.create(gpa, first, .{}, .{ .authority = "backend.test" });
        _ = snapshot.publishWithDeadline(channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })) catch |err| {
            snapshot.release();
            return err;
        };
        snapshot.release();
    }
    try std.testing.expect(channel.state.config.load(.acquire).?.storage == storage);
    try std.testing.expect(storage.refs.load(.acquire) < 10);
    try std.testing.expect(retained.call_selector.?.context == @as(*anyopaque, @ptrCast(initial)));
    try std.testing.expect(channel.state.config.load(.acquire).?.call_selector.?.context != @as(*anyopaque, @ptrCast(initial)));
}
test "gRPC RDS selector allocation and topology failures retain the active configuration" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var channel = try destination(failing.allocator(), io);
    defer channel.deinit();
    const first = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/" }}, null);
    defer gpa.free(first);
    const initial = try rds.Snapshot.create(gpa, first, .{}, .{ .authority = "backend.test" });
    defer initial.release();
    _ = try initial.publishWithDeadline(channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    const revision = channel.configurationRevision();
    const next = try rds.Snapshot.create(gpa, first, .{}, .{ .authority = "backend.test" });
    defer next.release();
    failing.fail_index = failing.alloc_index;
    const result = next.publishWithDeadline(channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expectEqual(revision, channel.configurationRevision());
    try std.testing.expectEqual(@as(usize, 1), next.refs.load(.acquire));
    try std.testing.expect(channel.state.config.load(.acquire).?.call_selector.?.context == @as(*anyopaque, @ptrCast(initial)));
    const other = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "missing" }}, null);
    defer gpa.free(other);
    const unknown = try rds.Snapshot.create(gpa, other, .{}, .{ .authority = "backend.test" });
    defer unknown.release();
    try std.testing.expectError(error.InvalidSharedOptions, unknown.publishWithDeadline(channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    try std.testing.expectEqual(revision, channel.configurationRevision());
    try std.testing.expectEqual(@as(usize, 1), unknown.refs.load(.acquire));
}
test "gRPC RDS selector preserves closed and expired admission before local no-route status" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try destination(gpa, io);
    var live = true;
    defer if (live) channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var bytes = fixture.Builder{ .allocator = gpa };
    defer bytes.deinit();
    try bytes.bytes(1, "routes");
    const empty = try rds.Snapshot.create(gpa, bytes.data.items, .{}, .{ .authority = "backend.test" });
    defer empty.release();
    _ = try empty.publishWithDeadline(channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    channel.deinit();
    live = false;
    try std.testing.expectError(error.SharedChannelClosed, sender.unary(.{ .path = "/demo.Service/Get", .message = "request" }));
    try std.testing.expectError(error.SharedChannelClosed, sender.startDuplex(.{ .path = "/demo.Service/Stream" }));
    try std.testing.expectError(error.Timeout, sender.unary(.{ .path = "/demo.Service/Get", .message = "request", .timeout = .{ .value = 0, .unit = .nanosecond } }));
    try std.testing.expectError(error.Timeout, sender.startDuplexWithDeadline(.{ .path = "/demo.Service/Stream" }, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
}

test "gRPC RDS initial selector constructor retains and rolls back borrowed resource owners" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/" }}, null);
    defer gpa.free(bytes);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    defer snapshot.release();
    const Harness = struct {
        fn run(allocator: std.mem.Allocator, active_io: std.Io, resource: *rds.Snapshot) !void {
            var channel = grpc.SharedChannel.init(allocator, active_io, .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }} } }, .{ .service_config_json = manager, .call_selector = resource.descriptor() }) catch |err| {
                try std.testing.expectEqual(@as(usize, 1), resource.refs.load(.acquire));
                return err;
            };
            try std.testing.expectEqual(@as(usize, 2), resource.refs.load(.acquire));
            channel.deinit();
            try std.testing.expectEqual(@as(usize, 1), resource.refs.load(.acquire));
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{ io, snapshot });
}

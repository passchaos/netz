//! Shared registry identity must follow RPC selection and actual completion.
const std = @import("std");
const grpc = @import("../../mod.zig");
const fixture = @import("tests.zig");
const gpa = std.testing.allocator;
const Peer = @import("../shared/weighted_target/test_support.zig").Peer;
fn finishShared(reader: grpc.SharedStreamReader) !void {
    var count: usize = 0;
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(3));
        defer event.deinit(gpa);
        switch (event) {
            .message => |message| {
                try std.testing.expectEqualStrings("a", message.payload);
                count += 1;
            },
            .terminal => |terminal| {
                try std.testing.expectEqual(grpc.Status.ok, terminal.status);
                try std.testing.expectEqual(@as(usize, 1), count);
                return;
            },
            else => {},
        }
    }
}
test "gRPC cluster impl ordinary and shared stream permits saturate only the selected cluster" {
    for ([_]bool{ false, true }) |is_shared| {
        var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var a = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
        defer a.deinit();
        var b = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
        defer b.deinit();
        var stop: std.Io.Event = .unset;
        var a_peer = io.async(Peer.run, .{ &a, &stop, "a", std.Io.Duration.fromMilliseconds(150) });
        defer _ = a_peer.cancel(io) catch {};
        var b_peer = io.async(Peer.run, .{ &b, &stop, "b", null });
        defer _ = b_peer.cancel(io) catch {};
        const a_target: grpc.ChannelTarget = .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = a.address(), .hierarchical_path = &.{"a"} } }} } };
        const b_target: grpc.ChannelTarget = .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &.{"b"} } }} } };
        var config = try grpc.ServiceConfig.parse(gpa, fixture.limited);
        defer config.deinit();
        var ordinary_a = if (!is_shared) try grpc.Channel.initWithServiceConfig(gpa, io, a_target, .{}, &config) else null;
        defer if (ordinary_a) |*value| value.deinit();
        var ordinary_b = if (!is_shared) try grpc.Channel.initWithServiceConfig(gpa, io, b_target, .{}, &config) else null;
        defer if (ordinary_b) |*value| value.deinit();
        var shared_a = if (is_shared) try grpc.SharedChannel.init(gpa, io, a_target, .{ .service_config_json = fixture.limited }) else null;
        defer if (shared_a) |*value| value.deinit();
        var shared_b = if (is_shared) try grpc.SharedChannel.init(gpa, io, b_target, .{ .service_config_json = fixture.limited }) else null;
        defer if (shared_b) |*value| value.deinit();
        var a_sender = if (shared_a) |value| value.sender() else null;
        defer if (a_sender) |*value| value.deinit();
        var b_sender = if (shared_b) |value| value.sender() else null;
        defer if (b_sender) |*value| value.deinit();
        const options: grpc.StreamingRequestOptions = .{ .path = "/demo.Impl/Stream", .xds_cluster = "a", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } };
        var duplex_shared = if (a_sender) |sender| try sender.startDuplex(options) else null;
        defer if (duplex_shared) |*value| value.deinit();
        var duplex_ordinary = if (ordinary_a) |*value| try value.startDuplex(options) else null;
        defer if (duplex_ordinary) |*value| value.deinit();
        if (duplex_shared) |value| {
            var writer = value.writer();
            defer writer.deinit();
            try writer.writeFinalMessage("request");
        } else try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try duplex_ordinary.?.writeFinalMessage("request"));
        const failed: grpc.UnaryCallOptions = .{ .path = "/demo.Impl/Unary", .xds_cluster = "a", .message = "request" };
        var saturated = if (b_sender) |value| try value.unary(failed) else try ordinary_b.?.unary(failed);
        defer saturated.deinit();
        try std.testing.expect(saturated.was_dropped and saturated.transport == null);
        const good: grpc.UnaryCallOptions = .{ .path = "/demo.Impl/Unary", .xds_cluster = "b", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } };
        var independent = if (b_sender) |value| try value.unary(good) else try ordinary_b.?.unary(good);
        defer independent.deinit();
        try std.testing.expectEqualStrings("b", independent.message.?.payload);
        if (duplex_shared) |value| {
            var reader = value.reader();
            defer reader.deinit();
            try finishShared(reader);
            try std.testing.expectEqual(@as(u32, 0), (try shared_b.?.clusterCircuitStats("a")).active);
        } else {
            const Consumer = struct {
                fn consume(_: *@This(), message: grpc.StreamingMessage) !void {
                    try std.testing.expectEqualStrings("a", message.payload);
                }
            };
            var consumer: Consumer = .{};
            while (true) {
                var event = try duplex_ordinary.?.readResponseEventWithTimeout(.fromSeconds(3), &consumer, Consumer.consume);
                defer event.deinit(gpa);
                if (event == .terminal) break;
            }
            try std.testing.expectEqual(@as(u32, 0), (try ordinary_b.?.clusterCircuitStats("a")).active);
        }
        stop.set(io);
        try a_peer.await(io);
        try b_peer.await(io);
    }
}

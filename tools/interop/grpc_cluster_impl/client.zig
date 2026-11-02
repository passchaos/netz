//! Select cluster-local admission while retaining active stream permits.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const gpa = std.heap.c_allocator;
fn config(maximum: u32, full: bool) ![]u8 {
    return std.fmt.allocPrint(gpa, "{{\"loadBalancingConfig\":[{{\"xds_cluster_manager_experimental\":{{\"children\":{{\"a\":{{\"childPolicy\":[{{\"xds_cluster_impl_experimental\":{{\"clusterName\":\"wire-impl-a\",\"edsServiceName\":\"wire-a\",\"maxConcurrentRequests\":{d},\"dropCategories\":[{{\"category\":\"full\",\"requestsPerMillion\":{d}}}],\"childPolicy\":[{{\"round_robin\":{{}}}}]}}}}]}},\"b\":{{\"childPolicy\":[{{\"xds_cluster_impl_experimental\":{{\"clusterName\":\"wire-impl-b\",\"childPolicy\":[{{\"round_robin\":{{}}}}]}}}}]}}}}}}}}]}}", .{ maximum, @as(u32, if (full) 1000000 else 0) });
}
fn ordinary(io: std.Io, target: grpc.ChannelTarget, json: []const u8) !grpc.Channel {
    var parsed = try grpc.ServiceConfig.parse(gpa, json);
    defer parsed.deinit();
    return grpc.Channel.initWithServiceConfig(gpa, io, target, .{}, &parsed);
}
fn call(client: anytype, cluster: []const u8, text: []const u8) !grpc.UnaryResponse {
    return client.unary(.{ .path = "/fixture.Impl/Unary", .xds_cluster = cluster, .message = text, .wait_for_ready = true, .timeout = .{ .value = 4, .unit = .second } });
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArguments;
    const shared_mode = std.mem.eql(u8, args[1], "shared");
    var backend = try netz.runtime.Backend.initZio(gpa);
    defer backend.deinit();
    const io = backend.io();
    const a = grpc.ChannelEndpoint{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[2], 10)) }, .hierarchical_path = &.{"a"} } };
    const b = grpc.ChannelEndpoint{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[3], 10)) }, .hierarchical_path = &.{"b"} } };
    const a_target: grpc.ChannelTarget = .{ .resolved = .{ .endpoints = &.{a} } };
    const mixed: grpc.ChannelTarget = .{ .resolved = .{ .endpoints = &.{ a, b } } };
    const json = try config(1, false);
    defer gpa.free(json);
    const raised = try config(2, false);
    defer gpa.free(raised);
    const dropped = try config(2, true);
    defer gpa.free(dropped);
    var main_ord = if (!shared_mode) try ordinary(io, a_target, json) else null;
    defer if (main_ord) |*value| value.deinit();
    var other_ord = if (!shared_mode) try ordinary(io, mixed, json) else null;
    defer if (other_ord) |*value| value.deinit();
    var main_shared = if (shared_mode) try grpc.SharedChannel.init(gpa, io, a_target, .{ .service_config_json = json }) else null;
    defer if (main_shared) |*value| value.deinit();
    var other_shared = if (shared_mode) try grpc.SharedChannel.init(gpa, io, mixed, .{ .service_config_json = json }) else null;
    defer if (other_shared) |*value| value.deinit();
    var main_sender = if (main_shared) |value| value.sender() else null;
    defer if (main_sender) |*value| value.deinit();
    var other_sender = if (other_shared) |value| value.sender() else null;
    defer if (other_sender) |*value| value.deinit();
    const options: grpc.StreamingRequestOptions = .{ .path = "/fixture.Impl/Stream", .xds_cluster = "a", .wait_for_ready = true, .timeout = .{ .value = 6, .unit = .second } };
    var stream_ord = if (main_ord) |*value| try value.startDuplex(options) else null;
    defer if (stream_ord) |*value| value.deinit();
    var stream_shared = if (main_sender) |value| try value.startDuplex(options) else null;
    defer if (stream_shared) |*value| value.deinit();
    if (stream_shared) |value| {
        var writer = value.writer();
        defer writer.deinit();
        try writer.writeFinalMessage("stream");
        var reader = value.reader();
        defer reader.deinit();
        while (true) {
            var event = try reader.nextWithTimeout(.fromSeconds(3));
            defer event.deinit(gpa);
            if (event == .message) break;
        }
    } else {
        try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream_ord.?.writeFinalMessage("stream"));
        const Consumer = struct {
            fn read(_: *@This(), message: grpc.StreamingMessage) !void {
                try std.testing.expectEqualStrings("held", message.payload);
            }
        };
        var consumer: Consumer = .{};
        var event = try stream_ord.?.readResponseEventWithTimeout(.fromSeconds(3), &consumer, Consumer.read);
        event.deinit(gpa);
    }
    var blocked = if (other_sender) |value| try call(value, "a", "blocked") else try call(&other_ord.?, "a", "blocked");
    defer blocked.deinit();
    try std.testing.expect(blocked.was_dropped and blocked.transport == null);
    var independent = if (other_sender) |value| try call(value, "b", "independent") else try call(&other_ord.?, "b", "independent");
    defer independent.deinit();
    var extra_ord = if (!shared_mode) try ordinary(io, a_target, raised) else null;
    defer if (extra_ord) |*value| value.deinit();
    if (other_shared) |value| _ = try value.updateWithTimeout(.{ .service_config = .{ .replace = raised } }, .fromSeconds(3));
    var extra = if (other_sender) |value| try call(value, "a", "extra-a") else try call(&extra_ord.?, "a", "extra-a");
    defer extra.deinit();
    var drop_ord = if (!shared_mode) try ordinary(io, mixed, dropped) else null;
    defer if (drop_ord) |*value| value.deinit();
    if (other_shared) |value| _ = try value.updateWithTimeout(.{ .service_config = .{ .replace = dropped } }, .fromSeconds(3));
    var policy_drop = if (other_sender) |value| try call(value, "a", "blocked") else try call(&drop_ord.?, "a", "blocked");
    defer policy_drop.deinit();
    try std.testing.expect(policy_drop.was_dropped and std.mem.startsWith(u8, policy_drop.status_message, "EDS-configured drop:"));
    if (other_sender) |value| try std.testing.expectError(error.CallDropped, value.startDuplex(options)) else try std.testing.expectError(error.CallDropped, drop_ord.?.startDuplex(options));
    var release = if (other_sender) |value| try call(value, "b", "release") else try call(&other_ord.?, "b", "release");
    defer release.deinit();
    if (stream_shared) |value| {
        var reader = value.reader();
        defer reader.deinit();
        while (true) {
            var event = try reader.nextWithTimeout(.fromSeconds(3));
            defer event.deinit(gpa);
            if (event == .terminal) break;
        }
    } else {
        const Consumer = struct {
            fn read(_: *@This(), _: grpc.StreamingMessage) !void {}
        };
        var consumer: Consumer = .{};
        while (true) {
            var event = try stream_ord.?.readResponseEventWithTimeout(.fromSeconds(3), &consumer, Consumer.read);
            defer event.deinit(gpa);
            if (event == .terminal) break;
        }
    }
    if (other_shared) |value| _ = try value.updateWithTimeout(.{ .service_config = .{ .replace = json } }, .fromSeconds(3));
    var resumed = if (other_sender) |value| try call(value, "a", "resumed-a") else try call(&other_ord.?, "a", "resumed-a");
    defer resumed.deinit();
    const stats = if (other_shared) |value| try value.clusterCircuitStats("a") else try other_ord.?.clusterCircuitStats("a");
    try std.testing.expectEqual(@as(u32, 0), stats.active);
    std.debug.print("IMPL_RESULT {{\"status\":\"passed\",\"mode\":\"{s}\",\"independent_cluster\":true,\"limit_replacement\":true,\"category_before_circuit\":true,\"stream_completion\":true}}\n", .{args[1]});
}

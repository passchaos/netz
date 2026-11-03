//! Load Reporting Service against an independent official-schema peer.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const lrs = grpc.xds.lrs;
const gpa = std.heap.c_allocator;

fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.initZio(gpa);
    defer backend.deinit();
    const io = backend.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try lrs.Client.init(gpa, sender, .{ .node = .{ .id = "netz-lrs", .client_features = &.{"envoy.lrs.supports_send_all_clusters"} } });
    defer client.deinit();
    try client.connectWithDeadline(until(io));
    var first = try client.nextWithDeadline(until(io));
    defer first.deinit();
    try std.testing.expect(first == .response);
    try std.testing.expectEqual(@as(usize, 2), first.response.value.clusters.len);
    try std.testing.expectEqualStrings("a", first.response.value.clusters[0]);
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), first.response.value.interval_ns.?);
    try std.testing.expect(first.response.value.report_endpoint_granularity);

    const localities = [_]lrs.codec.LocalityStats{.{
        .locality = .{ .region = "r", .zone = "z" },
        .successful = 1,
        .in_progress = 0,
        .error_requests = 1,
        .issued = 1,
    }};
    const dropped = [_]lrs.codec.Dropped{.{ .category = "throttle", .count = 1 }};
    const clusters = [_]lrs.codec.ClusterStats{.{
        .name = "a",
        .service_name = "eds-a",
        .localities = &localities,
        .total_dropped = 1,
        .dropped = &dropped,
        .interval_ns = 100 * std.time.ns_per_ms,
    }};
    try client.reportWithDeadline(&clusters, until(io));
    var second = try client.nextWithDeadline(until(io));
    defer second.deinit();
    try std.testing.expect(second == .response and second.response.value.send_all_clusters);
    var terminal = try client.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    std.debug.print("LRS_RESULT {{\"status\":\"passed\",\"initial_subscription\":true,\"report_counters\":true,\"send_all\":true}}\n", .{});
}

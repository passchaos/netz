//! Load Reporting Service against an independent official-schema peer.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const lrs = grpc.xds.lrs;
const gpa = std.heap.c_allocator;

const metrics_a = [_]lrs.codec.NamedMetric{
    .{ .name = "load", .count = 4, .value = 2.0 },
    .{ .name = "other", .count = 1, .value = 3.0 },
};
const metrics_b = [_]lrs.codec.NamedMetric{
    .{ .name = "load", .count = 8, .value = 4.5 },
    .{ .name = "other", .count = 9, .value = 5.5 },
};
const endpoints_a = [_]lrs.codec.EndpointStats{.{ .host = "127.0.0.1", .port = 1001, .successful = 1, .issued = 1 }};
const endpoints_b = [_]lrs.codec.EndpointStats{.{ .host = "127.0.0.2", .port = 1002, .successful = 2, .in_progress = 1, .error_requests = 2, .issued = 4 }};
const localities_a = [_]lrs.codec.LocalityStats{.{
    .locality = .{ .region = "r", .zone = "z" },
    .successful = 1,
    .error_requests = 1,
    .issued = 1,
    .cpu_utilization = .{ .count = 1, .value = 0.5 },
    .memory_utilization = .{ .count = 2, .value = 0.25 },
    .application_utilization = .{ .count = 3, .value = 1.0 },
    .load_metrics = &metrics_a,
    .endpoints = &endpoints_a,
}};
const localities_b = [_]lrs.codec.LocalityStats{.{
    .locality = .{ .region = "r", .zone = "z-alt", .sub_zone = "sub" },
    .successful = 2,
    .in_progress = 1,
    .error_requests = 2,
    .issued = 4,
    .cpu_utilization = .{ .count = 5, .value = 1.25 },
    .memory_utilization = .{ .count = 6, .value = 1.5 },
    .application_utilization = .{ .count = 7, .value = 3.5 },
    .load_metrics = &metrics_b,
    .endpoints = &endpoints_b,
}};
const dropped_a = [_]lrs.codec.Dropped{.{ .category = "throttle", .count = 1 }};
const dropped_b = [_]lrs.codec.Dropped{.{ .category = "circuit", .count = 2 }};
const reports = [_]lrs.codec.ClusterStats{
    .{ .name = "a", .service_name = "eds-a", .localities = &localities_a, .total_dropped = 1, .dropped = &dropped_a, .interval_ns = 100 * std.time.ns_per_ms },
    .{ .name = "a", .service_name = "eds-other", .localities = &localities_b, .total_dropped = 2, .dropped = &dropped_b, .interval_ns = 200 * std.time.ns_per_ms },
};

fn verifyOfficialRequest(base64: []const u8) !void {
    const bytes = try gpa.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(base64));
    defer gpa.free(bytes);
    try std.base64.standard.Decoder.decode(bytes, base64);
    // This input comes from Node's official Envoy request serializer, not
    // from the native encoder whose output is checked on the live stream.
    var decoded = try lrs.codec.decodeRequest(gpa, bytes, .{});
    defer decoded.deinit();
    try std.testing.expect(decoded.value.node == null);
    try std.testing.expectEqual(reports.len, decoded.value.clusters.len);
    for (reports, decoded.value.clusters) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqualStrings(expected.service_name, actual.service_name);
        try std.testing.expectEqual(expected.total_dropped, actual.total_dropped);
        try std.testing.expectEqual(expected.interval_ns, actual.interval_ns);
        try std.testing.expectEqual(@as(usize, 1), actual.dropped.len);
        try std.testing.expectEqualStrings(expected.dropped[0].category, actual.dropped[0].category);
        try std.testing.expectEqual(expected.dropped[0].count, actual.dropped[0].count);
        try std.testing.expectEqual(@as(usize, 1), actual.localities.len);
        const wanted = expected.localities[0];
        const locality = actual.localities[0];
        try std.testing.expectEqualStrings(wanted.locality.region, locality.locality.region);
        try std.testing.expectEqualStrings(wanted.locality.zone, locality.locality.zone);
        try std.testing.expectEqualStrings(wanted.locality.sub_zone, locality.locality.sub_zone);
        try std.testing.expectEqual(wanted.successful, locality.successful);
        try std.testing.expectEqual(wanted.in_progress, locality.in_progress);
        try std.testing.expectEqual(wanted.error_requests, locality.error_requests);
        try std.testing.expectEqual(wanted.issued, locality.issued);
        try std.testing.expectEqualDeep(wanted.cpu_utilization, locality.cpu_utilization);
        try std.testing.expectEqualDeep(wanted.memory_utilization, locality.memory_utilization);
        try std.testing.expectEqualDeep(wanted.application_utilization, locality.application_utilization);
        try std.testing.expectEqual(wanted.load_metrics.len, locality.load_metrics.len);
        for (wanted.load_metrics, locality.load_metrics) |metric, actual_metric| {
            try std.testing.expectEqualStrings(metric.name, actual_metric.name);
            try std.testing.expectEqual(metric.count, actual_metric.count);
            try std.testing.expectEqual(metric.value, actual_metric.value);
        }
        try std.testing.expectEqual(@as(usize, 1), locality.endpoints.len);
        const endpoint = locality.endpoints[0];
        const wanted_endpoint = wanted.endpoints[0];
        try std.testing.expectEqualStrings(wanted_endpoint.host, endpoint.host);
        try std.testing.expectEqual(wanted_endpoint.port, endpoint.port);
        try std.testing.expectEqual(wanted_endpoint.successful, endpoint.successful);
        try std.testing.expectEqual(wanted_endpoint.in_progress, endpoint.in_progress);
        try std.testing.expectEqual(wanted_endpoint.error_requests, endpoint.error_requests);
        try std.testing.expectEqual(wanted_endpoint.issued, endpoint.issued);
    }
}

fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArguments;
    try verifyOfficialRequest(args[2]);
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
    try std.testing.expectEqualStrings("b", first.response.value.clusters[1]);
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), first.response.value.interval_ns.?);
    try std.testing.expect(first.response.value.report_endpoint_granularity);

    try client.reportWithDeadline(&reports, until(io));
    var second = try client.nextWithDeadline(until(io));
    defer second.deinit();
    try std.testing.expect(second == .response and second.response.value.send_all_clusters);
    try std.testing.expectEqual(@as(usize, 0), second.response.value.clusters.len);
    var terminal = try client.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expect(terminal == .terminal);
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    std.debug.print("LRS_RESULT {{\"status\":\"passed\",\"initial_subscription\":true,\"report_counters\":true,\"send_all\":true,\"clean_terminal\":true,\"request_decoder\":true,\"request_encoder\":true,\"utilization_metrics\":true,\"named_metrics\":true,\"distinct_service_identities\":true,\"report_cluster_count\":2,\"named_metrics_per_locality\":2}}\n", .{});
}

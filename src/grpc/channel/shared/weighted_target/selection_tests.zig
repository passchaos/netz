//! Cached pending priority choices follow current priority state.
const std = @import("std");
const service = @import("../../../service_config.zig");
const channel = @import("../../../channel.zig");
const connectivity = @import("../../connectivity.zig");
const outlier = @import("../../outlier_detection.zig");
const Source = struct {
    endpoint: channel.Endpoint,
    suspended: bool = false,
    resolver: ?*anyopaque = null,
    generation: u64 = 1,
};
const FakeWorker = struct {
    source: *Source,
    eligible: bool = true,
    retired: bool = false,
    published: connectivity.State = .ready,
    capacity: usize = 1,
    weighted_outliers: []outlier.Endpoint = &.{},
};
const State = struct {
    pub const Worker = FakeWorker;
    io: std.Io,
    workers: std.ArrayList(*Worker),
    sources: []*Source,
};
test "gRPC priority cached pending pick becomes invalid when higher priority recovers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var config = try service.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{"config":[{"round_robin":{}}]},"low":{"config":[{"round_robin":{}}]}},
        \\ "priorities":["high","low"]}}]}
    );
    defer config.deinit();
    var runtime = try @import("../weighted_target.zig").Runtime(State).init(allocator, config.loadBalancingConfig().root.?);
    defer runtime.deinit();
    var high_source = Source{ .endpoint = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"high"} } } };
    var low_source = Source{ .endpoint = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) }, .hierarchical_path = &.{"low"} } } };
    var high = FakeWorker{ .source = &high_source };
    var low = FakeWorker{ .source = &low_source };
    var sources = [_]*Source{ &high_source, &low_source };
    var workers = [_]*FakeWorker{ &high, &low };
    var state = State{ .io = threaded.io(), .workers = .{ .items = &workers, .capacity = workers.len }, .sources = &sources };
    const Stream = struct { options: struct { xds_cluster: ?[]const u8 = null } };
    const job = .{ .stream = @as(?*Stream, null), .options = .{ .xds_cluster = @as(?[]const u8, null) } };
    try std.testing.expect(runtime.selectable(&state, &high, job));
    try std.testing.expect(!runtime.selectable(&state, &low, job));
    high.published = .transient_failure;
    try std.testing.expect(runtime.selectable(&state, &low, job));
    high.published = .ready;
    try std.testing.expect(!runtime.selectable(&state, &low, job));
    try std.testing.expect(runtime.selectable(&state, &high, job));
}

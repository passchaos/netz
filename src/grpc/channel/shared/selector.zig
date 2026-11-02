//! Resolve from one retained selector while preserving admission error priority.
const std = @import("std");
const selected = @import("../call_selector.zig");
const service = @import("../../service_config.zig");
const call = @import("../../call.zig");
pub fn validateLayout(runtime: anytype, selector: selected.Selector) error{InvalidSharedOptions}!void {
    if (selector.required_clusters.len == 0) return;
    const value = runtime orelse return error.InvalidSharedOptions;
    const route = @import("../cluster_route.zig");
    if (!route.contains(value.root)) return error.InvalidSharedOptions;
    for (selector.required_clusters) |name| route.validate(value.root, name) catch return error.InvalidSharedOptions;
}
fn context(state: anytype, options: anytype, entered: std.Io.Timestamp, admission: ?std.Io.Clock.Timestamp) selected.Context {
    return .{ .allocator = state.allocator, .io = state.io, .channel_id = state.channel_id, .deadline = @import("../../../internal/deadline.zig").earlier(admission, if (options.timeout) |timeout| .{ .raw = entered.addDuration(timeout.duration()), .clock = .awake } else null) };
}
fn open(state: anytype, active: selected.Context) @TypeOf(state.*).Failure!void {
    try active.check();
    try state.lockBefore(active.deadline);
    const closed = state.closed;
    state.unlock();
    if (closed) return error.SharedChannelClosed;
}
fn validate(options: anytype) call.Error!void {
    _ = try call.parseRequestMetadata("POST", options.path, &.{ .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "te", .value = "trailers" } });
    try call.validateCustomMetadata(options.metadata);
    try call.validateCustomBinaryMetadata(options.binary_metadata);
}
pub fn unary(state: anytype, selector: selected.Selector, base: service.ResolvedUnary, entered: std.Io.Timestamp, config: *const service.ServiceConfig) @TypeOf(state.*).Failure!service.ResolvedUnary {
    var active = context(state, base.options, entered, null);
    active.service_config = config;
    try open(state, active);
    try validate(base.options);
    const result = selector.unary_fn(selector.context, active, base) catch |err| {
        try open(state, active);
        return err;
    };
    try active.check();
    return result;
}
pub fn streaming(state: anytype, selector: selected.Selector, base: service.ResolvedStreaming, entered: std.Io.Timestamp, admission: ?std.Io.Clock.Timestamp) @TypeOf(state.*).Failure!service.ResolvedStreaming {
    const active = context(state, base.options, entered, admission);
    try open(state, active);
    try validate(base.options);
    const result = selector.streaming_fn(selector.context, active, base) catch |err| {
        try open(state, active);
        return err;
    };
    try active.check();
    return result;
}

//! Opening retains request metadata until the background owner commits HEADERS.
const std = @import("std");
const streaming = @import("../../../stream/runtime.zig");
const service_config = @import("../../../service_config.zig");
const call = @import("../../../call.zig");
const Job = @import("../job.zig").Job;

pub fn open(state: anytype, options: streaming.RequestOptions, entered: std.Io.Timestamp) @TypeOf(state.*).Failure!*@TypeOf(state.*).StreamCall {
    const State = @TypeOf(state.*);
    state.lock();
    const closed = state.closed;
    state.unlock();
    if (closed) return error.SharedChannelClosed;
    _ = try call.parseRequestMetadata("POST", options.path, &.{ .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "te", .value = "trailers" } });
    try call.validateCustomMetadata(options.metadata);
    try call.validateCustomBinaryMetadata(options.binary_metadata);
    var resolved: service_config.ResolvedStreaming = .{ .options = options, .wait_for_ready = options.wait_for_ready orelse false };
    if (state.config) |*config| resolved = try config.resolveStreaming(options);
    resolved.options.wait_for_ready = resolved.wait_for_ready;
    const deadline: ?std.Io.Clock.Timestamp = if (resolved.options.timeout) |timeout| .{ .raw = entered.addDuration(timeout.duration()), .clock = .awake } else null;
    const stream = try State.StreamCall.create(state, resolved.options, deadline);
    errdefer stream.release();
    var job: Job = .{ .options = .{ .path = options.path, .message = &.{} }, .deadline = deadline, .wait_for_ready = resolved.wait_for_ready, .previous_attempts = null, .stream = stream };
    state.enqueue(&job) catch |err| {
        state.lock();
        stream.retireLocked(err);
        state.unlock();
        return err;
    };
    state.awaitJob(&job) catch |err| {
        state.lock();
        if (job.phase == .queued) stream.retireLocked(err);
        state.unlock();
        stream.cancel();
        return err;
    };
    return stream;
}
